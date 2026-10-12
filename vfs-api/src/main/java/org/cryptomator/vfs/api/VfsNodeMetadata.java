package org.cryptomator.vfs.api;

import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.Set;

/**
 * Metadata of a single node as required by frontends such as FUSE, FSKit, WinFsp, SMB and WebDAV.
 *
 * @param type the node type
 * @param size the size in bytes (for symbolic links: the length of the target)
 * @param fileId a volume-unique, stable identifier of the node (inode number), or {@link #NO_FILE_ID} if the file system has none
 * @param permissions the POSIX permission bits
 * @param lastModifiedTime time of the last content change (mtime)
 * @param lastAccessTime time of the last access (atime)
 * @param changeTime time of the last metadata or content change (ctime)
 * @param creationTime time of creation (birth time)
 */
public record VfsNodeMetadata(
		VfsNodeType type,
		long size,
		long fileId,
		Set<PosixFilePermission> permissions,
		Instant lastModifiedTime,
		Instant lastAccessTime,
		Instant changeTime,
		Instant creationTime
) {

	/**
	 * Value of {@link #fileId()} for file systems that do not provide stable node identifiers.
	 */
	public static final long NO_FILE_ID = 0;

	public VfsNodeMetadata {
		permissions = Set.copyOf(permissions);
	}
}
