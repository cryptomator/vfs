import FSKit
import Foundation
import os

final class VfsUnaryFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations {

	private static let containerID = UUID(uuidString: "8C1B5E26-5F0F-4F1A-9B6A-2C0F4D5E6A71")!

	private let logger = Logger(subsystem: "org.cryptomator.vfs.fskit", category: "VfsUnaryFileSystem")

	func probeResource(
		resource: FSResource,
		replyHandler: @escaping (FSProbeResult?, (any Error)?) -> Void
	) {
		logger.debug("probeResource: \(resource, privacy: .private)")
		guard resource is FSPathURLResource else {
			replyHandler(FSProbeResult.notRecognized, nil)
			return
		}
		replyHandler(
			FSProbeResult.usable(
				name: "vfsfs",
				containerID: FSContainerIdentifier(uuid: Self.containerID)
			),
			nil
		)
	}

	func loadResource(
		resource: FSResource,
		options: FSTaskOptions,
		replyHandler: @escaping (FSVolume?, (any Error)?) -> Void
	) {
		guard let urlResource = resource as? FSPathURLResource else {
			logger.error("loadResource: not a path URL resource")
			replyHandler(nil, fs_errorForPOSIXError(POSIXError.EINVAL.rawValue))
			return
		}
		logger.debug("loadResource: \(urlResource.url.path, privacy: .private)")
		guard urlResource.url.startAccessingSecurityScopedResource() else {
			logger.error("loadResource: cannot access security-scoped resource \(urlResource.url.path, privacy: .private)")
			replyHandler(nil, fs_errorForPOSIXError(POSIXError.EACCES.rawValue))
			return
		}
		do {
			_ = try JavaRuntime.shared()
			containerStatus = .ready
			replyHandler(VfsVolume(vaultURL: urlResource.url), nil)
		} catch {
			urlResource.url.stopAccessingSecurityScopedResource()
			logger.error("loadResource: JVM boot failed: \(error, privacy: .public)")
			replyHandler(nil, fs_errorForPOSIXError(POSIXError.EIO.rawValue))
		}
	}

	func unloadResource(
		resource: FSResource,
		options: FSTaskOptions,
		replyHandler reply: @escaping ((any Error)?) -> Void
	) {
		logger.debug("unloadResource: \(resource, privacy: .private)")
		if let urlResource = resource as? FSPathURLResource {
			urlResource.url.stopAccessingSecurityScopedResource()
		}
		reply(nil)
	}
}
