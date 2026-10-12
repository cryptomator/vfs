package org.cryptomator.vfs.frontend.fskit;

/**
 * A named child entry returned while listing a directory across the binding boundary.
 */
public record FskitDirectoryEntry(String name, FskitNodeMetadata metadata) {}
