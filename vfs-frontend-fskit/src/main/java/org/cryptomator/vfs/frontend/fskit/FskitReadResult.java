package org.cryptomator.vfs.frontend.fskit;

/**
 * Result of reading from a file, holding an error code plus the bytes read
 * (empty = EOF). Data is returned instead of filling a caller buffer because
 * the Swift bindings pass arrays by value, without copy-back.
 */
public record FskitReadResult(int errorCode, byte[] data) {

	private static final byte[] NO_DATA = new byte[0];

	public static FskitReadResult failure(int errorCode) {
		return new FskitReadResult(errorCode, NO_DATA);
	}

	public static FskitReadResult endOfFile() {
		return new FskitReadResult(0, NO_DATA);
	}
}
