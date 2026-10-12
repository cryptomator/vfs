package org.cryptomator.vfs.api;

/**
 * Static feature set of a {@link VfsFileSystem}, queried by frontends once at mount time to negotiate with the host.
 *
 * @param caseSensitive whether lookups distinguish names by case
 * @param supportsSymbolicLinks whether {@link VfsFileSystem#readSymbolicLink} and {@link VfsFileSystem#createSymbolicLink} are implemented
 * @param supportsXattrs whether the extended attribute methods of {@link VfsFileSystem} are implemented
 * @param maxXattrValueSize maximum size in bytes of a single extended attribute value, or {@link #NO_LIMIT}
 */
public record VfsCapabilities(
		boolean caseSensitive,
		boolean supportsSymbolicLinks,
		boolean supportsXattrs,
		long maxXattrValueSize
) {

	/**
	 * Sentinel for size limits that do not apply.
	 */
	public static final long NO_LIMIT = -1;

	/**
	 * Capabilities of a case-sensitive file system without any optional features.
	 */
	public static final VfsCapabilities MINIMAL = new VfsCapabilities(true, false, false, 0);
}
