package org.cryptomator.vfs.api;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * Optional file time updates; {@code null} fields are left unchanged.
 *
 * @param lastAccessTime new access time (atime)
 * @param lastModifiedTime new modification time (mtime)
 * @param creationTime new creation time (birth time); silently ignored by file systems that cannot store it
 */
public record VfsTimes(@Nullable Instant lastAccessTime, @Nullable Instant lastModifiedTime, @Nullable Instant creationTime) {
}
