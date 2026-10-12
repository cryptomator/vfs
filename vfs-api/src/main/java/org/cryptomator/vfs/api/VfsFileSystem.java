package org.cryptomator.vfs.api;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.AccessMode;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;

/**
 * Minimal shared VFS API for file and directory I/O, designed as the common denominator of FUSE, FSKit, WinFsp, SMB and WebDAV frontends.
 * <p>
 * All paths are absolute, {@code /}-separated and refer to nodes within this file system. The namespace is path-based; data operations on an open file go
 * through the {@link VfsFile} handle returned by {@link #openFile} or {@link #createFile}, and must keep working after the file has been renamed or deleted.
 * Optional capabilities (xattrs, symbolic links) are advertised via {@link #capabilities()}; their methods throw {@link UnsupportedOperationException}
 * when unsupported.
 */
public interface VfsFileSystem {

	/**
	 * Describes which optional features this file system supports.
	 *
	 * @return the static capabilities of this file system
	 */
	VfsCapabilities capabilities();

	/**
	 * Reads the metadata of the node at the given path without following a final symbolic link.
	 *
	 * @param path absolute path of the node
	 * @return metadata of the node
	 * @throws java.nio.file.NoSuchFileException if no node exists at {@code path}
	 * @throws IOException if the metadata cannot be read
	 */
	VfsNodeMetadata readNodeMetadata(String path) throws IOException;

	/**
	 * Reads space information of the volume that contains the given path.
	 *
	 * @param path absolute path of any node on the volume
	 * @return volume space information
	 * @throws IOException if the information cannot be read
	 */
	VfsMetadata readVfsMetadata(String path) throws IOException;

	/**
	 * Checks whether the given access modes are permitted on the node at the given path.
	 *
	 * @param path absolute path of the node
	 * @param accessModes the modes to check; an empty set only checks for existence
	 * @throws java.nio.file.NoSuchFileException if no node exists at {@code path}
	 * @throws java.nio.file.AccessDeniedException if any of the requested modes is denied
	 * @throws IOException if the check fails for other reasons
	 */
	void checkAccess(String path, Set<AccessMode> accessModes) throws IOException;

	/**
	 * Opens the directory at the given path for lazy, forward-only iteration over its entries, each carrying the child's metadata.
	 *
	 * @param path absolute path of the directory
	 * @return a stream over the entries (excluding {@code .} and {@code ..}) that must be closed by the caller
	 * @throws java.nio.file.NotDirectoryException if the node is not a directory
	 * @throws IOException if the directory cannot be opened
	 */
	VfsDirectoryStream openDirectory(String path) throws IOException;

	/**
	 * Creates a new, empty directory.
	 *
	 * @param path absolute path of the directory to create; its parent must exist
	 * @param permissions initial permissions
	 * @throws java.nio.file.FileAlreadyExistsException if a node already exists at {@code path}
	 * @throws IOException if the directory cannot be created
	 */
	void createDirectory(String path, Set<PosixFilePermission> permissions) throws IOException;

	/**
	 * Deletes an empty directory. This is never recursive; frontends with recursive delete semantics (e.g. WebDAV) must descend themselves.
	 *
	 * @param path absolute path of the directory
	 * @throws java.nio.file.DirectoryNotEmptyException if the directory still has entries
	 * @throws IOException if the directory cannot be deleted
	 */
	void deleteDirectory(String path) throws IOException;

	/**
	 * Opens an existing file.
	 *
	 * @param path absolute path of the file
	 * @param options open options; {@link StandardOpenOption#CREATE} and {@link StandardOpenOption#CREATE_NEW} are ignored, use {@link #createFile} instead
	 * @return an open handle that the caller must close
	 * @throws java.nio.file.NoSuchFileException if no file exists at {@code path}
	 * @throws IOException if the file cannot be opened
	 */
	VfsFile openFile(String path, Set<StandardOpenOption> options) throws IOException;

	/**
	 * Creates a new file and opens it.
	 *
	 * @param path absolute path of the file to create; its parent must exist
	 * @param options open options for the returned handle; {@link StandardOpenOption#CREATE_NEW} makes the call fail if the file already exists
	 * @param permissions initial permissions
	 * @return an open handle that the caller must close
	 * @throws java.nio.file.FileAlreadyExistsException if {@code CREATE_NEW} was requested and a node already exists at {@code path}
	 * @throws IOException if the file cannot be created
	 */
	VfsFile createFile(String path, Set<StandardOpenOption> options, Set<PosixFilePermission> permissions) throws IOException;

	/**
	 * Sets the size of a file, truncating or zero-extending it.
	 *
	 * @param path absolute path of the file
	 * @param size the new size in bytes
	 * @throws IOException if the size cannot be changed
	 * @see VfsFile#truncate(long)
	 */
	void truncate(String path, long size) throws IOException;

	/**
	 * Removes a file (or symbolic link) from the namespace. Open handles on the file remain usable until closed.
	 *
	 * @param path absolute path of the file
	 * @throws java.nio.file.NoSuchFileException if no node exists at {@code path}
	 * @throws IOException if the file cannot be deleted
	 */
	void deleteFile(String path) throws IOException;

	/**
	 * Atomically moves a node to a new path, optionally replacing an existing target.
	 * <p>
	 * A directory may only replace an empty directory, and a file may only replace a non-directory. Open handles on the moved node remain usable.
	 *
	 * @param sourcePath absolute path of the node to move
	 * @param targetPath absolute new path; its parent must exist
	 * @param replaceExisting whether an existing node at {@code targetPath} may be replaced
	 * @throws java.nio.file.FileAlreadyExistsException if {@code replaceExisting} is {@code false} and a node exists at {@code targetPath}
	 * @throws java.nio.file.DirectoryNotEmptyException if the target is a non-empty directory
	 * @throws IOException if the node cannot be moved
	 */
	void rename(String sourcePath, String targetPath, boolean replaceExisting) throws IOException;

	/**
	 * Updates the timestamps of a node; {@code null} fields of {@code times} are left unchanged.
	 *
	 * @param path absolute path of the node
	 * @param times the timestamps to set
	 * @throws IOException if the timestamps cannot be changed
	 */
	void setTimes(String path, VfsTimes times) throws IOException;

	/**
	 * Replaces the permissions of a node.
	 *
	 * @param path absolute path of the node
	 * @param permissions the new permissions
	 * @throws IOException if the permissions cannot be changed
	 */
	void setPermissions(String path, Set<PosixFilePermission> permissions) throws IOException;

	/**
	 * Reads the target of a symbolic link as stored, without resolving it.
	 *
	 * @param path absolute path of the symbolic link
	 * @return the link target
	 * @throws java.nio.file.NotLinkException if the node is not a symbolic link
	 * @throws IOException if the link cannot be read
	 * @throws UnsupportedOperationException if {@link VfsCapabilities#supportsSymbolicLinks()} is {@code false}
	 */
	default String readSymbolicLink(String path) throws IOException {
		throw new UnsupportedOperationException("symbolic links not supported");
	}

	/**
	 * Creates a symbolic link.
	 *
	 * @param path absolute path of the link to create; its parent must exist
	 * @param target the link target, stored verbatim
	 * @throws java.nio.file.FileAlreadyExistsException if a node already exists at {@code path}
	 * @throws IOException if the link cannot be created
	 * @throws UnsupportedOperationException if {@link VfsCapabilities#supportsSymbolicLinks()} is {@code false}
	 */
	default void createSymbolicLink(String path, String target) throws IOException {
		throw new UnsupportedOperationException("symbolic links not supported");
	}

	/**
	 * Lists the names of all extended attributes of a node.
	 *
	 * @param path absolute path of the node
	 * @return the attribute names, possibly empty
	 * @throws IOException if the attributes cannot be listed
	 * @throws UnsupportedOperationException if {@link VfsCapabilities#supportsXattrs()} is {@code false}
	 */
	default List<String> listXattrs(String path) throws IOException {
		throw new UnsupportedOperationException("extended attributes not supported");
	}

	/**
	 * Reads the value of an extended attribute.
	 *
	 * @param path absolute path of the node
	 * @param name name of the attribute
	 * @return a read-only buffer holding the value
	 * @throws java.nio.file.NoSuchFileException if the node has no attribute with the given name
	 * @throws IOException if the attribute cannot be read
	 * @throws UnsupportedOperationException if {@link VfsCapabilities#supportsXattrs()} is {@code false}
	 */
	default ByteBuffer getXattr(String path, String name) throws IOException {
		throw new UnsupportedOperationException("extended attributes not supported");
	}

	/**
	 * Writes the value of an extended attribute.
	 *
	 * @param path absolute path of the node
	 * @param name name of the attribute
	 * @param value the value; all remaining bytes are consumed
	 * @param policy whether the attribute must already exist, must not yet exist, or either
	 * @throws java.nio.file.FileAlreadyExistsException if {@code policy} is {@link VfsXattrPolicy#CREATE_ONLY} and the attribute exists
	 * @throws java.nio.file.NoSuchFileException if {@code policy} is {@link VfsXattrPolicy#REPLACE_ONLY} and the attribute does not exist
	 * @throws IOException if the attribute cannot be written
	 * @throws UnsupportedOperationException if {@link VfsCapabilities#supportsXattrs()} is {@code false}
	 */
	default void setXattr(String path, String name, ByteBuffer value, VfsXattrPolicy policy) throws IOException {
		throw new UnsupportedOperationException("extended attributes not supported");
	}

	/**
	 * Removes an extended attribute.
	 *
	 * @param path absolute path of the node
	 * @param name name of the attribute
	 * @throws java.nio.file.NoSuchFileException if the node has no attribute with the given name
	 * @throws IOException if the attribute cannot be removed
	 * @throws UnsupportedOperationException if {@link VfsCapabilities#supportsXattrs()} is {@code false}
	 */
	default void removeXattr(String path, String name) throws IOException {
		throw new UnsupportedOperationException("extended attributes not supported");
	}
}
