package org.cryptomator.vfs.api;

/**
 * Static feature set of a {@link VfsFileSystem}, queried by frontends once at mount time to negotiate with the host.
 *
 * @param caseSensitive whether lookups distinguish names by case
 * @param normalizationSensitive whether lookups distinguish names that differ only in their Unicode normalization form; when {@code false}, every form of a name
 * denotes the same node and frontends may normalize names freely, when {@code true} they must pass names through unchanged
 * @param supportsSymbolicLinks whether {@link VfsFileSystem#readSymbolicLink} and {@link VfsFileSystem#createSymbolicLink} are implemented
 * @param supportsXattrs whether the extended attribute methods of {@link VfsFileSystem} are implemented
 * @param maxXattrValueSize maximum size in bytes of a single extended attribute value, or {@link #NO_LIMIT}
 */
public record VfsCapabilities(
		boolean caseSensitive,
		boolean normalizationSensitive,
		boolean supportsSymbolicLinks,
		boolean supportsXattrs,
		long maxXattrValueSize
) {

	/**
	 * Sentinel for size limits that do not apply.
	 */
	public static final long NO_LIMIT = -1;

	/**
	 * Capabilities of a case- and normalization-sensitive file system without any optional features.
	 */
	public static final VfsCapabilities MINIMAL = new VfsCapabilities(true, true, false, false, 0);
}
