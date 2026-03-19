package org.cryptomator.vfs.api;

import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.Objects;
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
		type = Objects.requireNonNull(type);
		permissions = Set.copyOf(Objects.requireNonNull(permissions));
		lastModifiedTime = Objects.requireNonNull(lastModifiedTime);
		lastAccessTime = Objects.requireNonNull(lastAccessTime);
		creationTime = Objects.requireNonNull(creationTime);
	}
}
