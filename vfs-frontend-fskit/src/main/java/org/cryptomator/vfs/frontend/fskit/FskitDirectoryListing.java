package org.cryptomator.vfs.frontend.fskit;

/**
 * Result of listing a directory, holding an error code plus the entries.
 */
public record FskitDirectoryListing(int errorCode, FskitDirectoryEntry[] entries) {

	public static FskitDirectoryListing failure(int errorCode) {
		return new FskitDirectoryListing(errorCode, new FskitDirectoryEntry[0]);
	}
}
