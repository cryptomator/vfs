package org.cryptomator.vfs.frontend.fskit;

/**
 * Result of opening a file, holding an error code plus the issued handle ({@code 0} = invalid).
 */
public record FskitFileHandle(int errorCode, long handle) {

	public static FskitFileHandle failure(int errorCode) {
		return new FskitFileHandle(errorCode, 0L);
	}
}
