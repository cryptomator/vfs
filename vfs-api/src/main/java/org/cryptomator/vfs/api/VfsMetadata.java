package org.cryptomator.vfs.api;

/**
 * Space information for a VFS path.
 */
public record VfsMetadata(
		long blockSize,
		long totalBlocks,
		long freeBlocks,
		long availableBlocks,
		long maxNameLength
) {
}
