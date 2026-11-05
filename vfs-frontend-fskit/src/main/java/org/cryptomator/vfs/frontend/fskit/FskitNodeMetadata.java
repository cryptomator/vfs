package org.cryptomator.vfs.frontend.fskit;

/**
 * Binding-friendly projection of node metadata, holding an error code plus flat primitive fields.
 */
public record FskitNodeMetadata(
		int errorCode,
		int type,
		long size,
		int posixMode,
		long modifiedSeconds,
		int modifiedNanos,
		long accessedSeconds,
		int accessedNanos,
		long createdSeconds,
		int createdNanos
) {

	public static final int TYPE_FILE = 1;
	public static final int TYPE_DIRECTORY = 2;
	public static final int TYPE_SYMBOLIC_LINK = 3;

	public static FskitNodeMetadata failure(int errorCode) {
		return new FskitNodeMetadata(errorCode, 0, 0L, 0, 0L, 0, 0L, 0, 0L, 0);
	}
}
