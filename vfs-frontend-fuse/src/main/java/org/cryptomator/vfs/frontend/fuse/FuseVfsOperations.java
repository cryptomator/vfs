package org.cryptomator.vfs.frontend.fuse;

import org.cryptomator.jfuse.api.DirFiller;
import org.cryptomator.jfuse.api.Errno;
import org.cryptomator.jfuse.api.FileInfo;
import org.cryptomator.jfuse.api.FileModes;
import org.cryptomator.jfuse.api.FuseConfig;
import org.cryptomator.jfuse.api.FuseConnInfo;
import org.cryptomator.jfuse.api.FuseOperations;
import org.cryptomator.jfuse.api.Stat;
import org.cryptomator.jfuse.api.Statvfs;
import org.cryptomator.jfuse.api.TimeSpec;
import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsMetadata;
import org.cryptomator.vfs.api.VfsNodeMetadata;
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
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thin adapter from the shared VFS API to jFUSE callbacks.
 */
public final class FuseVfsOperations implements FuseOperations {

	private static final Logger LOG = LoggerFactory.getLogger(FuseVfsOperations.class);

	private final VfsFileSystem fileSystem;
	private final Errno errno;
	private final ConcurrentMap<Long, VfsFile> openFiles = new ConcurrentHashMap<>();
	private final AtomicLong nextFileHandle = new AtomicLong(1L);

	public FuseVfsOperations(VfsFileSystem fileSystem, Errno errno) {
		this.fileSystem = fileSystem;
		this.errno = errno;
	}

	@Override
	public Errno errno() {
		return errno;
	}

	@Override
	public Set<Operation> supportedOperations() {
		return EnumSet.of(
				Operation.ACCESS,
				Operation.CREATE,
				Operation.DESTROY,
				Operation.FLUSH,
				Operation.FSYNC,
				Operation.GET_ATTR,
				Operation.MKDIR,
				Operation.OPEN,
				Operation.OPEN_DIR,
				Operation.READ,
				Operation.READ_DIR,
				Operation.RELEASE,
				Operation.RELEASE_DIR,
				Operation.RENAME,
				Operation.RMDIR,
				Operation.STATFS,
				Operation.TRUNCATE,
				Operation.UNLINK,
				Operation.UTIMENS,
				Operation.WRITE
		);
	}

	@Override
	public void init(FuseConnInfo conn, @Nullable FuseConfig cfg) {
		conn.setWant(conn.want() | (conn.capable() & FuseConnInfo.FUSE_CAP_BIG_WRITES));
		conn.setMaxBackground(16);
		conn.setCongestionThreshold(4);
	}

	@Override
	public int access(String path, int mask) {
		try {
			fileSystem.checkAccess(path, toAccessModes(mask));
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int getattr(String path, Stat stat, @Nullable FileInfo fi) {
		try {
			applyNodeMetadata(stat, fileSystem.readNodeMetadata(path));
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int statfs(String path, Statvfs statvfs) {
		try {
			VfsMetadata space = fileSystem.readVfsMetadata(path);
			statvfs.setBsize(space.blockSize());
			statvfs.setFrsize(space.blockSize());
			statvfs.setBlocks(space.totalBlocks());
			statvfs.setBfree(space.freeBlocks());
			statvfs.setBavail(space.availableBlocks());
			statvfs.setNameMax(space.maxNameLength());
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int mkdir(String path, int mode) {
		try {
			fileSystem.createDirectory(path, FileModes.toPermissions(mode));
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int opendir(String path, FileInfo fi) {
		try {
			if (fileSystem.readNodeMetadata(path).type() != VfsNodeType.DIRECTORY) {
				return -errno.enotdir();
			}
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int readdir(String path, DirFiller filler, long offset, FileInfo fi, int flags) {
		try {
			boolean fillPlus = (flags & FuseOperations.FUSE_READDIR_PLUS) != 0;
			fillEntry(filler, ".", fileSystem.readNodeMetadata(path), fillPlus);
			fillEntry(filler, "..", fileSystem.readNodeMetadata(parentPath(path)), fillPlus);
			for (var child : fileSystem.listDirectory(path)) {
				fillEntry(filler, child, fillPlus);
			}
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int releasedir(@Nullable String path, FileInfo fi) {
		return 0;
	}

	@Override
	public int create(String path, int mode, FileInfo fi) {
		try {
			var file = fileSystem.createFile(path, fi.getOpenFlags(), FileModes.toPermissions(mode));
			return registerOpenFile(file, fi);
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int open(String path, FileInfo fi) {
		try {
			var file = fileSystem.openFile(path, fi.getOpenFlags());
			return registerOpenFile(file, fi);
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int read(String path, ByteBuffer buf, long count, long offset, FileInfo fi) {
		var file = openFiles.get(fi.getFh());
		if (file == null) {
			return -errno.ebadf();
		}
		try {
			var window = limit(buf, count);
			int read = file.read(window, offset);
			if (read > 0) {
				buf.position(buf.position() + read);
			}
			return Math.max(read, 0);
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int write(String path, ByteBuffer buf, long count, long offset, FileInfo fi) {
		var file = openFiles.get(fi.getFh());
		if (file == null) {
			return -errno.ebadf();
		}
		try {
			var window = limit(buf, count);
			int written = file.write(window, offset);
			if (written > 0) {
				buf.position(buf.position() + written);
			}
			return written;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int truncate(String path, long size, @Nullable FileInfo fi) {
		try {
			fileSystem.truncate(path, size);
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int flush(String path, FileInfo fi) {
		return force(fi, false);
	}

	@Override
	public int fsync(String path, int datasync, FileInfo fi) {
		return force(fi, datasync == 0);
	}

	@Override
	public int release(String path, FileInfo fi) {
		var file = openFiles.remove(fi.getFh());
		if (file == null) {
			return -errno.ebadf();
		}
		try {
			file.close();
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int unlink(String path) {
		try {
			if (fileSystem.readNodeMetadata(path).type() == VfsNodeType.DIRECTORY) {
				return -errno.eisdir();
			}
			fileSystem.deleteFile(path);
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int rmdir(String path) {
		try {
			if (fileSystem.readNodeMetadata(path).type() != VfsNodeType.DIRECTORY) {
				return -errno.enotdir();
			}
			fileSystem.deleteDirectory(path);
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int rename(String oldpath, String newpath, int flags) {
		if (flags != 0) {
			return -errno.einval();
		}
		try {
			fileSystem.rename(oldpath, newpath);
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
	public int utimens(String path, TimeSpec atime, TimeSpec mtime, @Nullable FileInfo fi) {
		try {
			fileSystem.setTimes(path, new VfsTimes(atime.getOptional().orElse(null), mtime.getOptional().orElse(null)));
			return 0;
		} catch (UnsupportedOperationException e) {
			return -errno.enotsup();
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	@Override
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

	private int registerOpenFile(VfsFile file, FileInfo fi) {
		long fileHandle = nextFileHandle.incrementAndGet();
		fi.setFh(fileHandle);
		openFiles.put(fileHandle, file);
		return 0;
	}

	private int force(FileInfo fi, boolean metadata) {
		var file = openFiles.get(fi.getFh());
		if (file == null) {
			return -errno.ebadf();
		}
		try {
			file.force(metadata);
			return 0;
		} catch (IOException e) {
			return toErrno(e);
		}
	}

	private void fillEntry(DirFiller filler, VfsDirectoryEntry entry, boolean fillPlus) throws IOException {
		fillEntry(filler, entry.name(), entry.metadata(), fillPlus);
	}

	private void fillEntry(DirFiller filler, String name, VfsNodeMetadata metadata, boolean fillPlus) throws IOException {
		if (!fillPlus) {
			filler.fill(name);
			return;
		}
		int result = filler.fill(name, stat -> applyNodeMetadata(stat, metadata), 0L, DirFiller.FUSE_FILL_DIR_PLUS);
		if (result != 0) {
			throw new IOException("fuse_fill_dir_t unexpectedly returned " + result);
		}
	}

	private void applyNodeMetadata(Stat stat, VfsNodeMetadata metadata) {
		stat.setPermissions(metadata.permissions());
		stat.setSize(metadata.size());
		stat.setNLink((short) (metadata.type() == VfsNodeType.DIRECTORY ? 2 : 1));
		switch (metadata.type()) {
			case FILE -> stat.setModeBits(Stat.S_IFREG);
			case DIRECTORY -> stat.setModeBits(Stat.S_IFDIR);
			case SYMBOLIC_LINK -> stat.setModeBits(Stat.S_IFLNK);
		}
		stat.aTime().set(metadata.lastAccessTime());
		stat.mTime().set(metadata.lastModifiedTime());
		stat.cTime().set(metadata.lastModifiedTime());
		stat.birthTime().set(metadata.creationTime());
	}

	private String parentPath(String path) {
		if (path.isBlank() || "/".equals(path)) {
			return "/";
		}
		int lastSeparator = path.lastIndexOf('/');
		if (lastSeparator <= 0) {
			return "/";
		}
		return path.substring(0, lastSeparator);
	}

	private Set<AccessMode> toAccessModes(int mask) {
		var accessModes = EnumSet.noneOf(AccessMode.class);
		if ((mask & 0x01) != 0) {
			accessModes.add(AccessMode.EXECUTE);
		}
		if ((mask & 0x02) != 0) {
			accessModes.add(AccessMode.WRITE);
		}
		if ((mask & 0x04) != 0) {
			accessModes.add(AccessMode.READ);
		}
		return accessModes;
	}

	private ByteBuffer limit(ByteBuffer buffer, long count) {
		int max = Math.toIntExact(Math.min(count, buffer.remaining()));
		var window = buffer.slice();
		window.limit(max);
		return window;
	}

	private int toErrno(IOException e) {
		return switch (e) {
			case NoSuchFileException _ -> -errno.enoent();
			case FileAlreadyExistsException _ -> -errno.eexist();
			case AccessDeniedException _ -> -errno.eacces();
			case NotDirectoryException _ -> -errno.enotdir();
			case DirectoryNotEmptyException _ -> -errno.enotempty();
			case FileSystemException fse when "Is a directory".equalsIgnoreCase(fse.getReason()) -> -errno.eisdir();
			default -> -errno.eio();
		};
	}
}
