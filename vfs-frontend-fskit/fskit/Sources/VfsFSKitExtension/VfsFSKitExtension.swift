import FSKit
import Foundation

@main
struct VfsFSKitExtension: UnaryFileSystemExtension {

	var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
		VfsUnaryFileSystem()
	}
}
