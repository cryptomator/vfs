package org.cryptomator.vfs.api;

import java.io.IOException;
import java.nio.file.AccessMode;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;

/**
 * Minimal shared VFS API for file and directory I/O.
 */
public interface VfsFileSystem {

	VfsNodeMetadata readNodeMetadata(String path) throws IOException;

	VfsMetadata readVfsMetadata(String path) throws IOException;

	void checkAccess(String path, Set<AccessMode> accessModes) throws IOException;

	List<VfsDirectoryEntry> listDirectory(String path) throws IOException;

	void createDirectory(String path, Set<PosixFilePermission> permissions) throws IOException;

	void deleteDirectory(String path) throws IOException;

	VfsFile openFile(String path, Set<StandardOpenOption> options) throws IOException;

	VfsFile createFile(String path, Set<StandardOpenOption> options, Set<PosixFilePermission> permissions) throws IOException;

	void truncate(String path, long size) throws IOException;

	void deleteFile(String path) throws IOException;

	void rename(String sourcePath, String targetPath) throws IOException;

	void setTimes(String path, VfsTimes times) throws IOException;
}
