package org.cryptomator.vfs.api;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * Optional file time updates.
 */
public record VfsTimes(@Nullable Instant lastAccessTime, @Nullable Instant lastModifiedTime) {
}
