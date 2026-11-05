package org.cryptomator.vfs.frontend.fskit;

/**
 * Space information for the mounted volume, holding an error code plus flat primitive fields.
 */
public record FskitVfsMetadata(
		int errorCode,
		long blockSize,
		long totalBlocks,
		long freeBlocks,
		long availableBlocks,
		long maxNameLength
) {

	public static FskitVfsMetadata failure(int errorCode) {
		return new FskitVfsMetadata(errorCode, 0L, 0L, 0L, 0L, 0L);
	}
}
