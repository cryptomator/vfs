package org.cryptomator.vfs.frontend.fskit;

import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Flat, binding-friendly facade over the shared VFS API for the FSKit extension.
 * <p>
 * Only primitives, {@code String}, {@code byte[]}, and carrier records cross the
 * binding boundary. Mutating operations return {@code 0} on success or a negative
 * POSIX error code (macOS values); object-returning operations return a carrier
 * holding {@code errorCode} plus the value. Open-file handles are strictly positive,
 * {@code 0} being the invalid-handle sentinel.
 * <p>
 * Native encodings: open flags and POSIX mode bits use macOS {@code O_*}/mode-bit
 * values, access masks use {@code R_OK}/{@code W_OK}/{@code X_OK}, and timestamps
 * are epoch seconds + nanos with {@link Long#MIN_VALUE} seconds meaning "not set".
 */
public final class FskitVfsAdapter {

	private static final Logger LOG = LoggerFactory.getLogger(FskitVfsAdapter.class);

	private static final int ENOENT = 2;
	private static final int EIO = 5;
	private static final int EBADF = 9;
	private static final int EACCES = 13;
	private static final int EEXIST = 17;
	private static final int ENOTDIR = 20;
	private static final int EISDIR = 21;
	private static final int EINVAL = 22;
	private static final int ENOTSUP = 45;
	private static final int ENOTEMPTY = 66;

	// macOS O_* bit values; mirrored by the Swift VfsItemTable's open-flag constants
	private static final int O_ACCMODE = 0x3;
	private static final int O_RDONLY = 0x0;
	private static final int O_WRONLY = 0x1;
	private static final int O_RDWR = 0x2;
	private static final int O_APPEND = 0x8;
	private static final int O_CREAT = 0x200;
	private static final int O_TRUNC = 0x400;
	private static final int O_EXCL = 0x800;

	private static final int R_OK = 0x4;
	private static final int W_OK = 0x2;
	private static final int X_OK = 0x1;

	private static final long TIME_NOT_SET = Long.MIN_VALUE;

	private final VfsFileSystem fileSystem;
	private final ConcurrentMap<Long, VfsFile> openFiles = new ConcurrentHashMap<>();
	private final AtomicLong nextFileHandle = new AtomicLong(1L);

	public FskitVfsAdapter(VfsFileSystem fileSystem) {
		this.fileSystem = fileSystem;
	}

	public int checkAccess(String path, int accessMask) {
		try {
			fileSystem.checkAccess(path, toAccessModes(accessMask));
			return 0;
		} catch (IOException e) {
			return toErrorCode(e);
		}
	}

	public FskitNodeMetadata readNodeMetadata(String path) {
		try {
			return toNodeMetadata(fileSystem.readNodeMetadata(path));
		} catch (IOException e) {
			return FskitNodeMetadata.failure(toErrorCode(e));
		}
	}

	public FskitVfsMetadata readVfsMetadata(String path) {
		try {
			var space = fileSystem.readVfsMetadata(path);
			return new FskitVfsMetadata(0, space.blockSize(), space.totalBlocks(), space.freeBlocks(), space.availableBlocks(), space.maxNameLength());
		} catch (IOException e) {
			return FskitVfsMetadata.failure(toErrorCode(e));
		}
	}

	public int createDirectory(String path, int posixMode) {
		try {
			fileSystem.createDirectory(path, toPermissions(posixMode));
			return 0;
		} catch (IOException e) {
			return toErrorCode(e);
		}
	}

	public FskitDirectoryListing listDirectory(String path) {
		try {
			var entries = fileSystem.listDirectory(path).stream()
					.map(entry -> new FskitDirectoryEntry(entry.name(), toNodeMetadata(entry.metadata())))
					.toArray(FskitDirectoryEntry[]::new);
			return new FskitDirectoryListing(0, entries);
		} catch (IOException e) {
			return FskitDirectoryListing.failure(toErrorCode(e));
		}
	}

	public FskitFileHandle createFile(String path, int openFlags, int posixMode) {
		try {
			var file = fileSystem.createFile(path, toOpenOptions(openFlags), toPermissions(posixMode));
			return new FskitFileHandle(0, registerOpenFile(file));
		} catch (IllegalArgumentException e) {
			// e.g. READ + APPEND, which FileChannel.open rejects
			return FskitFileHandle.failure(-EINVAL);
		} catch (IOException e) {
			return FskitFileHandle.failure(toErrorCode(e));
		}
	}

	public FskitFileHandle openFile(String path, int openFlags) {
		try {
			var file = fileSystem.openFile(path, toOpenOptions(openFlags));
			return new FskitFileHandle(0, registerOpenFile(file));
		} catch (IllegalArgumentException e) {
			// e.g. READ + APPEND, which FileChannel.open rejects
			return FskitFileHandle.failure(-EINVAL);
		} catch (IOException e) {
			return FskitFileHandle.failure(toErrorCode(e));
		}
	}

	public FskitReadResult read(long handle, long offset, int length) {
		if (length < 0) {
			return FskitReadResult.failure(-EINVAL);
		}
		var file = openFiles.get(handle);
		if (file == null) {
			return FskitReadResult.failure(-EBADF);
		}
		try {
			byte[] buffer = new byte[length];
			int read = file.read(ByteBuffer.wrap(buffer), offset);
			if (read <= 0) {
				return FskitReadResult.endOfFile();
			}
			return new FskitReadResult(0, read == length ? buffer : Arrays.copyOf(buffer, read));
		} catch (IOException e) {
			return FskitReadResult.failure(toErrorCode(e));
		}
	}

	public int write(long handle, long offset, byte[] buffer, int length) {
		if (length < 0 || length > buffer.length) {
			return -EINVAL;
		}
		var file = openFiles.get(handle);
		if (file == null) {
			return -EBADF;
		}
		try {
			return file.write(ByteBuffer.wrap(buffer, 0, length), offset);
		} catch (IOException e) {
			return toErrorCode(e);
		}
	}

	public int truncate(String path, long size) {
		try {
			fileSystem.truncate(path, size);
			return 0;
		} catch (IOException e) {
			return toErrorCode(e);
		}
	}

	public int force(long handle, boolean metadata) {
		var file = openFiles.get(handle);
		if (file == null) {
			return -EBADF;
		}
		try {
			file.force(metadata);
			return 0;
		} catch (IOException e) {
			return toErrorCode(e);
		}
	}

	public int close(long handle) {
		var file = openFiles.remove(handle);
		if (file == null) {
			return -EBADF;
		}
		try {
			file.close();
			return 0;
		} catch (IOException e) {
			return toErrorCode(e);
		}
	}

	public int deleteFile(String path) {
		try {
			if (fileSystem.readNodeMetadata(path).type() == VfsNodeType.DIRECTORY) {
				return -EISDIR;
			}
			fileSystem.deleteFile(path);
			return 0;
		} catch (IOException e) {
			return toErrorCode(e);
		}
	}

	public int deleteDirectory(String path) {
		try {
			if (fileSystem.readNodeMetadata(path).type() != VfsNodeType.DIRECTORY) {
				return -ENOTDIR;
			}
			fileSystem.deleteDirectory(path);
			return 0;
		} catch (IOException e) {
			return toErrorCode(e);
		}
	}

	public int rename(String sourcePath, String targetPath) {
		try {
			fileSystem.rename(sourcePath, targetPath);
			return 0;
		} catch (IOException e) {
			return toErrorCode(e);
		}
	}

	public int setTimes(String path, long accessedSeconds, int accessedNanos, long modifiedSeconds, int modifiedNanos) {
		try {
			fileSystem.setTimes(path, new VfsTimes(toInstant(accessedSeconds, accessedNanos), toInstant(modifiedSeconds, modifiedNanos)));
			return 0;
		} catch (UnsupportedOperationException e) {
			return -ENOTSUP;
		} catch (IOException e) {
			return toErrorCode(e);
		}
	}

	public void destroy() {
		openFiles.forEach((handle, file) -> {
			try {
				file.close();
			} catch (IOException e) {
				LOG.warn("Failed to close file handle {}", handle, e);
			}
		});
		openFiles.clear();
	}

	private long registerOpenFile(VfsFile file) {
		long fileHandle = nextFileHandle.incrementAndGet();
		openFiles.put(fileHandle, file);
		return fileHandle;
	}

	private static FskitNodeMetadata toNodeMetadata(VfsNodeMetadata metadata) {
		return new FskitNodeMetadata(0,
				toNodeType(metadata.type()),
				metadata.size(),
				toPosixMode(metadata.permissions()),
				metadata.lastModifiedTime().getEpochSecond(), metadata.lastModifiedTime().getNano(),
				metadata.lastAccessTime().getEpochSecond(), metadata.lastAccessTime().getNano(),
				metadata.creationTime().getEpochSecond(), metadata.creationTime().getNano());
	}

	private static int toNodeType(VfsNodeType type) {
		return switch (type) {
			case FILE -> FskitNodeMetadata.TYPE_FILE;
			case DIRECTORY -> FskitNodeMetadata.TYPE_DIRECTORY;
			case SYMBOLIC_LINK -> FskitNodeMetadata.TYPE_SYMBOLIC_LINK;
		};
	}

	private static Set<StandardOpenOption> toOpenOptions(int openFlags) {
		var options = EnumSet.noneOf(StandardOpenOption.class);
		// O_RDONLY is zero-valued, so the access mode must be decoded by value, not bit presence
		switch (openFlags & O_ACCMODE) {
			case O_RDONLY -> options.add(StandardOpenOption.READ);
			case O_WRONLY -> options.add(StandardOpenOption.WRITE);
			default -> {
				options.add(StandardOpenOption.READ);
				options.add(StandardOpenOption.WRITE);
			}
		}
		if ((openFlags & O_APPEND) != 0) {
			options.add(StandardOpenOption.APPEND);
		}
		if ((openFlags & O_TRUNC) != 0) {
			options.add(StandardOpenOption.TRUNCATE_EXISTING);
		}
		if ((openFlags & O_CREAT) != 0) {
			options.add((openFlags & O_EXCL) != 0 ? StandardOpenOption.CREATE_NEW : StandardOpenOption.CREATE);
		}
		return options;
	}

	private static Set<PosixFilePermission> toPermissions(int posixMode) {
		var permissions = EnumSet.noneOf(PosixFilePermission.class);
		for (var permission : PosixFilePermission.values()) {
			if ((posixMode & permissionBit(permission)) != 0) {
				permissions.add(permission);
			}
		}
		return permissions;
	}

	private static int toPosixMode(Set<PosixFilePermission> permissions) {
		int posixMode = 0;
		for (var permission : permissions) {
			posixMode |= permissionBit(permission);
		}
		return posixMode;
	}

	private static int permissionBit(PosixFilePermission permission) {
		// PosixFilePermission declares OWNER_READ..OTHERS_EXECUTE in descending bit order (0400..0001)
		return 0400 >> permission.ordinal();
	}

	private static Set<AccessMode> toAccessModes(int accessMask) {
		var accessModes = EnumSet.noneOf(AccessMode.class);
		if ((accessMask & X_OK) != 0) {
			accessModes.add(AccessMode.EXECUTE);
		}
		if ((accessMask & W_OK) != 0) {
			accessModes.add(AccessMode.WRITE);
		}
		if ((accessMask & R_OK) != 0) {
			accessModes.add(AccessMode.READ);
		}
		return accessModes;
	}

	private static @Nullable Instant toInstant(long seconds, int nanos) {
		if (seconds == TIME_NOT_SET) {
			return null;
		}
		return Instant.ofEpochSecond(seconds, nanos);
	}

	private static int toErrorCode(IOException e) {
		return switch (e) {
			case NoSuchFileException _ -> -ENOENT;
			case FileAlreadyExistsException _ -> -EEXIST;
			case AccessDeniedException _ -> -EACCES;
			case NotDirectoryException _ -> -ENOTDIR;
			case DirectoryNotEmptyException _ -> -ENOTEMPTY;
			case FileSystemException fse when "Is a directory".equalsIgnoreCase(fse.getReason()) -> -EISDIR;
			default -> -EIO;
		};
	}
}
