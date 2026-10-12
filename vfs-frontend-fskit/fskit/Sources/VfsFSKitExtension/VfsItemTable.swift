import FSKit
import Foundation
import SwiftJava

/// Sendable projection of `FskitNodeMetadata`, translated inside the actor so
/// no Java wrapper crosses an isolation boundary.
struct NodeAttributes: Sendable {
	let type: FSItem.ItemType
	let size: Int64
	let mode: UInt32
	let modified: timespec
	let accessed: timespec
	let created: timespec
}

struct EnumeratedEntry: Sendable {
	let name: String
	let id: FSItem.Identifier
	let attributes: NodeAttributes
}

struct VolumeStatistics: Sendable {
	let blockSize: Int64
	let totalBlocks: Int64
	let freeBlocks: Int64
	let availableBlocks: Int64
	let maxNameLength: Int64
}

/// Owns the item table and the Java facade. Runs on a dedicated single-thread
/// executor: JNI environments are thread-bound, and serializing all facade
/// calls also protects the UVF middleware's read-modify-write file I/O, which
/// the FUSE wiring sidesteps by mounting single-threaded.
actor VfsItemTable {

	// must match the macOS O_* encodings decoded by FskitVfsAdapter.toOpenOptions
	private static let openFlagWrite: Int32 = 0x1
	private static let openFlagReadWrite: Int32 = 0x2
	private static let openFlagCreate: Int32 = 0x200
	private static let openFlagExclusive: Int32 = 0x800

	// must match FskitNodeMetadata.TYPE_* constants
	private static let nodeTypeDirectory: Int32 = 2
	private static let nodeTypeSymbolicLink: Int32 = 3

	private static let maxEnumerationSnapshots = 16

	private let executor = JavaThreadExecutor()
	nonisolated var unownedExecutor: UnownedSerialExecutor {
		executor.asUnownedSerialExecutor()
	}

	private let vaultURL: URL
	private var adapter: FskitVfsAdapter?
	private var itemsByID: [UInt64: VfsItem] = [:]
	private var itemsByPath: [String: VfsItem] = [:]
	private var snapshots: [UInt64: (directoryID: UInt64, entries: [EnumeratedEntry])] = [:]
	private var nextItemID: UInt64 = 64
	private var nextVerifier: UInt64 = 1

	init(vaultURL: URL) {
		self.vaultURL = vaultURL
	}

	// MARK: - Volume lifecycle

	func activate() throws -> (root: VfsItem, statistics: VolumeStatistics) {
		let environment = try JavaRuntime.shared().vm.environment(asDaemon: true)
		guard let adapter = try JavaClass<FskitVfsBootstrap>(environment: environment).create(vaultURL.path) else {
			throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
		}
		self.adapter = adapter

		let root = VfsItem(id: .rootDirectory, parentID: .parentOfRoot, path: "/", type: .directory)
		itemsByID[root.id.rawValue] = root
		itemsByPath[root.path] = root
		return (root, try statistics())
	}

	func statistics() throws -> VolumeStatistics {
		guard let metadata = try requireAdapter().readVfsMetadata("/") else {
			throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
		}
		try checkError(metadata.errorCode())
		return VolumeStatistics(
			blockSize: metadata.blockSize(),
			totalBlocks: metadata.totalBlocks(),
			freeBlocks: metadata.freeBlocks(),
			availableBlocks: metadata.availableBlocks(),
			maxNameLength: metadata.maxNameLength()
		)
	}

	func synchronize() throws {
		let adapter = try requireAdapter()
		var firstError: (any Error)?
		for item in itemsByID.values where item.javaHandle != 0 {
			do {
				try checkError(adapter.force(item.javaHandle, false))
			} catch {
				firstError = firstError ?? error
			}
		}
		if let firstError {
			throw firstError
		}
	}

	func deactivate() {
		adapter?.destroy()
		itemsByID.removeAll()
		itemsByPath.removeAll()
		snapshots.removeAll()
	}

	// MARK: - Item lookup and attributes

	func lookup(named name: String, in directory: VfsItem) throws -> VfsItem {
		let path = childPath(of: directory, named: name)
		guard let metadata = try requireAdapter().readNodeMetadata(path) else {
			throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
		}
		let attributes = try nodeAttributes(metadata)
		let item = itemsByPath[path] ?? makeItem(path: path, type: attributes.type, parent: directory)
		item.type = attributes.type
		item.lastKnownAttributes = attributes
		return item
	}

	func attributes(of item: VfsItem) throws -> NodeAttributes {
		if item.unlinked {
			guard let lastKnown = item.lastKnownAttributes else {
				throw fs_errorForPOSIXError(POSIXError.ENOENT.rawValue)
			}
			return lastKnown
		}
		guard let metadata = try requireAdapter().readNodeMetadata(item.path) else {
			throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
		}
		let attributes = try nodeAttributes(metadata)
		item.lastKnownAttributes = attributes
		return attributes
	}

	func setAttributes(of item: VfsItem, size: UInt64?, accessTime: timespec?, modifyTime: timespec?) throws -> NodeAttributes {
		let adapter = try requireAdapter()
		if let size {
			try checkError(adapter.truncate(item.path, Int64(size)))
		}
		if accessTime != nil || modifyTime != nil {
			try checkError(adapter.setTimes(
				item.path,
				accessTime.map { Int64($0.tv_sec) } ?? Int64.min, Int32(accessTime?.tv_nsec ?? 0),
				modifyTime.map { Int64($0.tv_sec) } ?? Int64.min, Int32(modifyTime?.tv_nsec ?? 0)
			))
		}
		return try attributes(of: item)
	}

	func reclaim(_ item: VfsItem) {
		if item.javaHandle != 0 {
			_ = adapter?.close(item.javaHandle)
			item.javaHandle = 0
		}
		itemsByID.removeValue(forKey: item.id.rawValue)
		if itemsByPath[item.path] === item {
			itemsByPath.removeValue(forKey: item.path)
		}
	}

	// MARK: - Directory enumeration

	func enumerationSnapshot(of directory: VfsItem, startingFresh: Bool, expectedVerifier: UInt64) throws -> (verifier: UInt64, entries: [EnumeratedEntry]) {
		if !startingFresh {
			// snapshots are keyed by verifier so concurrent enumerations of one directory don't clobber each other
			guard let snapshot = snapshots[expectedVerifier], snapshot.directoryID == directory.id.rawValue else {
				throw FSError(.invalidDirectoryCookie)
			}
			return (expectedVerifier, snapshot.entries)
		}
		guard let listing = try requireAdapter().listDirectory(directory.path) else {
			throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
		}
		try checkError(listing.errorCode())
		var entries: [EnumeratedEntry] = []
		for entry in listing.entries() {
			guard let entry, let metadata = entry.metadata() else {
				continue
			}
			let name = entry.name()
			let attributes = try nodeAttributes(metadata)
			let path = childPath(of: directory, named: name)
			let item = itemsByPath[path] ?? makeItem(path: path, type: attributes.type, parent: directory)
			item.lastKnownAttributes = attributes
			entries.append(EnumeratedEntry(name: name, id: item.id, attributes: attributes))
		}
		let verifier = nextVerifier
		nextVerifier += 1
		snapshots[verifier] = (directoryID: directory.id.rawValue, entries: entries)
		if snapshots.count > Self.maxEnumerationSnapshots, let oldest = snapshots.keys.min() {
			snapshots.removeValue(forKey: oldest)
		}
		return (verifier, entries)
	}

	// MARK: - Open, close, read, write

	func open(item: VfsItem, modes: FSVolume.OpenModes) throws {
		guard item.type != .directory else {
			// directories carry no Java file handle; enumeration works by path
			return
		}
		let requested = modes.intersection([.read, .write])
		let union = item.grantedModes.union(requested)
		if item.javaHandle == 0 || union != item.grantedModes {
			try reopen(item, modes: union)
		}
		item.grantedModes = union
	}

	func close(item: VfsItem, keeping modes: FSVolume.OpenModes) throws {
		guard item.type != .directory else {
			return
		}
		let kept = modes.intersection([.read, .write])
		item.grantedModes = kept
		if kept.isEmpty && item.javaHandle != 0 {
			let handle = item.javaHandle
			item.javaHandle = 0
			try checkError(try requireAdapter().close(handle))
		}
	}

	func read(item: VfsItem, offset: Int64, length: Int) throws -> Data {
		let handle = try ensureHandle(item, including: .read)
		guard let result = try requireAdapter().read(handle, offset, Int32(length)) else {
			throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
		}
		try checkError(result.errorCode())
		let bytes = result.data()
		return bytes.withUnsafeBytes { Data($0) }
	}

	func write(item: VfsItem, contents: Data, offset: Int64) throws -> Int {
		guard contents.count <= Int32.max else {
			// the facade takes Int32 lengths; reject instead of trapping in the narrowing conversion
			throw fs_errorForPOSIXError(POSIXError.EINVAL.rawValue)
		}
		let handle = try ensureHandle(item, including: .write)
		let bytes = contents.withUnsafeBytes { [Int8]($0.bindMemory(to: Int8.self)) }
		let written = try requireAdapter().write(handle, offset, bytes, Int32(bytes.count))
		try checkError(written)
		return Int(written)
	}

	// MARK: - Mutating operations

	func create(named name: String, in directory: VfsItem, type: FSItem.ItemType, mode: UInt32) throws -> (VfsItem, NodeAttributes) {
		let adapter = try requireAdapter()
		let path = childPath(of: directory, named: name)
		if type == .directory {
			try checkError(adapter.createDirectory(path, Int32(mode)))
		} else {
			guard let result = adapter.createFile(path, Self.openFlagReadWrite | Self.openFlagCreate | Self.openFlagExclusive, Int32(mode)) else {
				throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
			}
			try checkError(result.errorCode())
			try checkError(adapter.close(result.handle()))
		}
		invalidateSnapshots(of: directory)
		let item = makeItem(path: path, type: type, parent: directory)
		return (item, try attributes(of: item))
	}

	func remove(item: VfsItem, from directory: VfsItem) throws {
		let adapter = try requireAdapter()
		if item.type == .directory {
			try checkError(adapter.deleteDirectory(item.path))
		} else {
			try checkError(adapter.deleteFile(item.path))
		}
		retire(item)
		invalidateSnapshots(of: directory)
	}

	func rename(item: VfsItem, named name: String, to destinationName: String, inDirectory destinationDirectory: VfsItem, over replaced: VfsItem?) throws {
		let destinationPath = childPath(of: destinationDirectory, named: destinationName)
		try checkError(try requireAdapter().rename(item.path, destinationPath))

		// the facade rename succeeded; only now publish the item-table changes
		if let replaced {
			retire(replaced)
		}
		let sourcePath = item.path
		itemsByPath.removeValue(forKey: sourcePath)
		item.path = destinationPath
		item.parentID = destinationDirectory.id
		itemsByPath[destinationPath] = item
		if item.type == .directory {
			let sourcePrefix = sourcePath + "/"
			for (path, descendant) in itemsByPath where path.hasPrefix(sourcePrefix) {
				itemsByPath.removeValue(forKey: path)
				descendant.path = destinationPath + "/" + String(path.dropFirst(sourcePrefix.count))
				itemsByPath[descendant.path] = descendant
			}
		}
		// a rename invalidates the source and destination parent listings; flush broadly instead of tracking both
		snapshots.removeAll()
	}

	// MARK: - Helpers

	private func invalidateSnapshots(of directory: VfsItem) {
		snapshots = snapshots.filter { $0.value.directoryID != directory.id.rawValue }
	}

	private func retire(_ item: VfsItem) {
		item.unlinked = true
		if itemsByPath[item.path] === item {
			itemsByPath.removeValue(forKey: item.path)
		}
	}

	private func reopen(_ item: VfsItem, modes: FSVolume.OpenModes) throws {
		if item.unlinked {
			// the path is gone, so the retained handle cannot be upgraded
			throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
		}
		guard let result = try requireAdapter().openFile(item.path, openFlags(modes)) else {
			throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
		}
		try checkError(result.errorCode())
		let oldHandle = item.javaHandle
		item.javaHandle = result.handle()
		if oldHandle != 0 {
			_ = adapter?.close(oldHandle)
		}
	}

	private func ensureHandle(_ item: VfsItem, including mode: FSVolume.OpenModes) throws -> Int64 {
		guard item.type != .directory else {
			throw fs_errorForPOSIXError(POSIXError.EISDIR.rawValue)
		}
		if item.javaHandle == 0 || !item.grantedModes.contains(mode) {
			try open(item: item, modes: item.grantedModes.union(mode))
		}
		return item.javaHandle
	}

	private func makeItem(path: String, type: FSItem.ItemType, parent: VfsItem) -> VfsItem {
		let id = FSItem.Identifier(rawValue: nextItemID)!
		nextItemID += 1
		let item = VfsItem(id: id, parentID: parent.id, path: path, type: type)
		itemsByID[id.rawValue] = item
		itemsByPath[path] = item
		return item
	}

	private func childPath(of directory: VfsItem, named name: String) -> String {
		directory.path == "/" ? "/" + name : directory.path + "/" + name
	}

	private func requireAdapter() throws -> FskitVfsAdapter {
		guard let adapter else {
			throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
		}
		return adapter
	}

	private func nodeAttributes(_ metadata: FskitNodeMetadata) throws -> NodeAttributes {
		try checkError(metadata.errorCode())
		return NodeAttributes(
			type: itemType(metadata.type()),
			size: metadata.size(),
			mode: UInt32(metadata.posixMode()),
			modified: timespec(tv_sec: Int(metadata.modifiedSeconds()), tv_nsec: Int(metadata.modifiedNanos())),
			accessed: timespec(tv_sec: Int(metadata.accessedSeconds()), tv_nsec: Int(metadata.accessedNanos())),
			created: timespec(tv_sec: Int(metadata.createdSeconds()), tv_nsec: Int(metadata.createdNanos()))
		)
	}

	private func itemType(_ type: Int32) -> FSItem.ItemType {
		switch type {
		case Self.nodeTypeDirectory: .directory
		case Self.nodeTypeSymbolicLink: .symlink
		default: .file
		}
	}

	private func openFlags(_ modes: FSVolume.OpenModes) -> Int32 {
		if modes.contains([.read, .write]) {
			Self.openFlagReadWrite
		} else if modes.contains(.write) {
			Self.openFlagWrite
		} else {
			0x0 // O_RDONLY
		}
	}

	private func checkError(_ code: Int32) throws {
		if code < 0 {
			throw fs_errorForPOSIXError(-code)
		}
	}
}
