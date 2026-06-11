import FSKit
import Foundation
import os

final class VfsVolume: FSVolume {

	private let core: VfsItemTable
	private let statistics = OSAllocatedUnfairLock<VolumeStatistics?>(initialState: nil)
	private let logger = Logger(subsystem: "org.cryptomator.vfs.fskit", category: "VfsVolume")

	init(vaultURL: URL) {
		self.core = VfsItemTable(vaultURL: vaultURL)
		super.init(
			volumeID: FSVolume.Identifier(uuid: UUID()),
			volumeName: FSFileName(string: vaultURL.lastPathComponent)
		)
	}

	private func requireVfsItem(_ item: FSItem) throws -> VfsItem {
		guard let vfsItem = item as? VfsItem else {
			throw fs_errorForPOSIXError(POSIXError.EIO.rawValue)
		}
		return vfsItem
	}

	private func fsAttributes(_ node: NodeAttributes, id: FSItem.Identifier, parentID: FSItem.Identifier) -> FSItem.Attributes {
		let attributes = FSItem.Attributes()
		attributes.fileID = id
		attributes.parentID = parentID
		attributes.type = node.type
		attributes.uid = getuid()
		attributes.gid = getgid()
		attributes.linkCount = node.type == .directory ? 2 : 1
		attributes.size = UInt64(node.size)
		attributes.allocSize = UInt64(node.size)
		switch node.type {
		case .directory:
			attributes.mode = node.mode | UInt32(S_IFDIR)
		case .symlink:
			attributes.mode = node.mode | UInt32(S_IFLNK)
		default:
			attributes.mode = node.mode | UInt32(S_IFREG)
		}
		attributes.modifyTime = node.modified
		attributes.changeTime = node.modified
		attributes.accessTime = node.accessed
		attributes.birthTime = node.created
		return attributes
	}
}

extension VfsVolume: FSVolume.PathConfOperations {

	var maximumLinkCount: Int {
		1
	}

	var maximumNameLength: Int {
		Int(statistics.withLock { $0?.maxNameLength } ?? 255)
	}

	var restrictsOwnershipChanges: Bool {
		true
	}

	var truncatesLongNames: Bool {
		false
	}

	var maximumXattrSize: Int {
		0 // xattrs deferred
	}

	var maximumFileSize: UInt64 {
		// the Java facade takes Int64 sizes
		UInt64(Int64.max)
	}
}

extension VfsVolume: FSVolume.Operations {

	var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
		let capabilities = FSVolume.SupportedCapabilities()
		capabilities.supportsHardLinks = false
		capabilities.supportsSymbolicLinks = false
		capabilities.supportsPersistentObjectIDs = false
		capabilities.caseFormat = .sensitive
		return capabilities
	}

	var volumeStatistics: FSStatFSResult {
		let result = FSStatFSResult(fileSystemTypeName: "vfsfs")
		if let stats = statistics.withLock({ $0 }) {
			result.blockSize = Int(stats.blockSize)
			result.ioSize = Int(stats.blockSize)
			result.totalBlocks = UInt64(stats.totalBlocks)
			result.freeBlocks = UInt64(stats.freeBlocks)
			result.availableBlocks = UInt64(stats.availableBlocks)
		}
		return result
	}

	func activate(options: FSTaskOptions) async throws -> FSItem {
		logger.debug("activate")
		let (root, stats) = try await core.activate()
		statistics.withLock { $0 = stats }
		return root
	}

	func deactivate(options: FSDeactivateOptions = []) async throws {
		logger.debug("deactivate")
		await core.deactivate()
	}

	func mount(options: FSTaskOptions) async throws {
		logger.debug("mount")
	}

	func unmount() async {
		logger.debug("unmount")
	}

	func synchronize(flags: FSSyncFlags) async throws {
		try await core.synchronize()
	}

	func attributes(_ desiredAttributes: FSItem.GetAttributesRequest, of item: FSItem) async throws -> FSItem.Attributes {
		let vfsItem = try requireVfsItem(item)
		let node = try await core.attributes(of: vfsItem)
		return fsAttributes(node, id: vfsItem.id, parentID: vfsItem.parentID)
	}

	func setAttributes(_ newAttributes: FSItem.SetAttributesRequest, on item: FSItem) async throws -> FSItem.Attributes {
		let vfsItem = try requireVfsItem(item)
		let size: UInt64? = newAttributes.isValid(.size) ? newAttributes.size : nil
		let accessTime: timespec? = newAttributes.isValid(.accessTime) ? newAttributes.accessTime : nil
		let modifyTime: timespec? = newAttributes.isValid(.modifyTime) ? newAttributes.modifyTime : nil
		let node = try await core.setAttributes(of: vfsItem, size: size, accessTime: accessTime, modifyTime: modifyTime)
		if size != nil {
			newAttributes.consumedAttributes.insert(.size)
		}
		if accessTime != nil {
			newAttributes.consumedAttributes.insert(.accessTime)
		}
		if modifyTime != nil {
			newAttributes.consumedAttributes.insert(.modifyTime)
		}
		return fsAttributes(node, id: vfsItem.id, parentID: vfsItem.parentID)
	}

	func lookupItem(named name: FSFileName, inDirectory directory: FSItem) async throws -> (FSItem, FSFileName) {
		guard let nameString = name.string else {
			throw fs_errorForPOSIXError(POSIXError.EINVAL.rawValue)
		}
		let item = try await core.lookup(named: nameString, in: requireVfsItem(directory))
		return (item, name)
	}

	func reclaimItem(_ item: FSItem) async throws {
		await core.reclaim(try requireVfsItem(item))
	}

	func readSymbolicLink(_ item: FSItem) async throws -> FSFileName {
		throw fs_errorForPOSIXError(POSIXError.ENOTSUP.rawValue)
	}

	func createItem(named name: FSFileName, type: FSItem.ItemType, inDirectory directory: FSItem, attributes newAttributes: FSItem.SetAttributesRequest) async throws -> (FSItem, FSFileName) {
		guard let nameString = name.string else {
			throw fs_errorForPOSIXError(POSIXError.EINVAL.rawValue)
		}
		guard type == .file || type == .directory else {
			throw fs_errorForPOSIXError(POSIXError.ENOTSUP.rawValue)
		}
		let mode = newAttributes.isValid(.mode) ? newAttributes.mode & 0o777 : (type == .directory ? 0o755 : 0o644)
		let (item, _) = try await core.create(named: nameString, in: requireVfsItem(directory), type: type, mode: mode)
		if newAttributes.isValid(.mode) {
			newAttributes.consumedAttributes.insert(.mode)
		}
		return (item, name)
	}

	func createSymbolicLink(named name: FSFileName, inDirectory directory: FSItem, attributes newAttributes: FSItem.SetAttributesRequest, linkContents contents: FSFileName) async throws -> (FSItem, FSFileName) {
		throw fs_errorForPOSIXError(POSIXError.ENOTSUP.rawValue)
	}

	func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem) async throws -> FSFileName {
		throw fs_errorForPOSIXError(POSIXError.ENOTSUP.rawValue)
	}

	func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem) async throws {
		try await core.remove(item: requireVfsItem(item), from: requireVfsItem(directory))
	}

	func renameItem(_ item: FSItem, inDirectory sourceDirectory: FSItem, named sourceName: FSFileName, to destinationName: FSFileName, inDirectory destinationDirectory: FSItem, overItem: FSItem?) async throws -> FSFileName {
		guard let sourceNameString = sourceName.string, let destinationNameString = destinationName.string else {
			throw fs_errorForPOSIXError(POSIXError.EINVAL.rawValue)
		}
		let replaced = try overItem.map { try requireVfsItem($0) }
		try await core.rename(
			item: requireVfsItem(item),
			named: sourceNameString,
			to: destinationNameString,
			inDirectory: requireVfsItem(destinationDirectory),
			over: replaced
		)
		return destinationName
	}

	func enumerateDirectory(_ directory: FSItem, startingAt cookie: FSDirectoryCookie, verifier: FSDirectoryVerifier, attributes: FSItem.GetAttributesRequest?, packer: FSDirectoryEntryPacker) async throws -> FSDirectoryVerifier {
		let vfsDirectory = try requireVfsItem(directory)
		let snapshot = try await core.enumerationSnapshot(
			of: vfsDirectory,
			startingFresh: cookie.rawValue == 0,
			expectedVerifier: verifier.rawValue
		)
		// FSKit expects "." and ".." for name-only enumerations, but not when attributes are requested
		let dotEntries: [(name: String, id: FSItem.Identifier)] = attributes == nil
			? [(".", vfsDirectory.id), ("..", vfsDirectory.parentID)]
			: []
		var index = Int(cookie.rawValue)
		while index < dotEntries.count + snapshot.entries.count {
			let packed: Bool
			if index < dotEntries.count {
				let dotEntry = dotEntries[index]
				packed = packer.packEntry(
					name: FSFileName(string: dotEntry.name),
					itemType: .directory,
					itemID: dotEntry.id,
					nextCookie: FSDirectoryCookie(UInt64(index + 1)),
					attributes: nil
				)
			} else {
				let entry = snapshot.entries[index - dotEntries.count]
				packed = packer.packEntry(
					name: FSFileName(string: entry.name),
					itemType: entry.attributes.type,
					itemID: entry.id,
					nextCookie: FSDirectoryCookie(UInt64(index + 1)),
					attributes: attributes != nil ? fsAttributes(entry.attributes, id: entry.id, parentID: vfsDirectory.id) : nil
				)
			}
			if !packed {
				break
			}
			index += 1
		}
		return FSDirectoryVerifier(snapshot.verifier)
	}
}

extension VfsVolume: FSVolume.OpenCloseOperations {

	func openItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
		try await core.open(item: requireVfsItem(item), modes: modes)
	}

	func closeItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
		try await core.close(item: requireVfsItem(item), keeping: modes)
	}
}

extension VfsVolume: FSVolume.ReadWriteOperations {

	func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer) async throws -> Int {
		let vfsItem = try requireVfsItem(item)
		let data = try await core.read(item: vfsItem, offset: Int64(offset), length: min(length, buffer.length))
		guard !data.isEmpty else {
			return 0
		}
		data.withUnsafeBytes { (source: UnsafeRawBufferPointer) in
			_ = buffer.withUnsafeMutableBytes { destination in
				memcpy(destination.baseAddress, source.baseAddress, data.count)
			}
		}
		return data.count
	}

	func write(contents: Data, to item: FSItem, at offset: off_t) async throws -> Int {
		let vfsItem = try requireVfsItem(item)
		return try await core.write(item: vfsItem, contents: contents, offset: Int64(offset))
	}
}
