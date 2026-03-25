package org.cryptomator.vfs.api;

import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.Set;

/**
 * Metadata required by frontends such as FUSE.
 */
public record VfsNodeMetadata(
		VfsNodeType type,
		long size,
		Set<PosixFilePermission> permissions,
		Instant lastModifiedTime,
		Instant lastAccessTime,
		Instant creationTime
) {

	public VfsNodeMetadata {
		permissions = Set.copyOf(permissions);
	}
}
