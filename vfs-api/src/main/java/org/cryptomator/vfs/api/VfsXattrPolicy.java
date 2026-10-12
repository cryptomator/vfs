package org.cryptomator.vfs.api;

/**
 * Precondition for {@link VfsFileSystem#setXattr}, mirroring {@code XATTR_CREATE} / {@code XATTR_REPLACE}.
 */
public enum VfsXattrPolicy {
	/** Create the attribute or replace its existing value. */
	CREATE_OR_REPLACE,
	/** Fail if the attribute already exists. */
	CREATE_ONLY,
	/** Fail if the attribute does not exist yet. */
	REPLACE_ONLY
}
