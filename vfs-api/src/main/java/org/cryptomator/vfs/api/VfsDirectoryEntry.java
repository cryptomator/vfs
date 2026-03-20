package org.cryptomator.vfs.api;

/**
 * A named child entry returned while listing a directory.
 */
public record VfsDirectoryEntry(String name, VfsNodeMetadata metadata) {}
