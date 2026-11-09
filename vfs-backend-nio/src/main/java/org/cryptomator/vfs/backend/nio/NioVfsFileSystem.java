package org.cryptomator.vfs.backend.nio;

import org.cryptomator.vfs.api.VfsCapabilities;
import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsDirectoryStream;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsMetadata;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;
import org.cryptomator.vfs.api.VfsXattrPolicy;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.time.Instant;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Simple mirrored filesystem backend backed by Java NIO.
 */
public final class NioVfsFileSystem implements VfsFileSystem {

	private static final long DEFAULT_BLOCK_SIZE = 4096L;
	private static final String UNIX_VIEW = "unix";
	private static final String USER_VIEW = "user";
	private static final XattrNames XATTR_NAMES = XattrNames.forCurrentPlatform();

	private final Path root; // real path: the root may be reached through symbolic links, nothing below it may be one
	private final FileStore fileStore;
	private final boolean posix;
	private final boolean unix;
	private final VfsCapabilities capabilities;
	private final Set<NioOpenFile> openFiles = ConcurrentHashMap.newKeySet(); // handles whose paths must follow a rename
	private final ReadWriteLock renameLock = new ReentrantReadWriteLock(); // read: open and register a handle, write: move and re-point handles

	/**
	 * Mirrors the given directory, probing the volume for case and normalization sensitivity.
	 *
	 * @param root the directory to expose as {@code /}
	 * @throws IOException if {@code root} is not a directory or its file store cannot be inspected
	 */
	public NioVfsFileSystem(Path root) throws IOException {
		this(root, probeCaseSensitivity(root.toAbsolutePath().normalize()), probeNormalizationSensitivity(root));
	}

	/**
	 * Mirrors the given directory with known case and normalization sensitivity.
	 *
	 * @param root the directory to expose as {@code /}
	 * @param caseSensitive whether the volume holding {@code root} distinguishes names by case
	 * @param normalizationSensitive whether the volume holding {@code root} distinguishes names that differ only in Unicode normalization form
	 * @throws IOException if {@code root} is not a directory or its file store cannot be inspected
	 */
	public NioVfsFileSystem(Path root, boolean caseSensitive, boolean normalizationSensitive) throws IOException {
		if (!Files.isDirectory(root)) {
			throw new NotDirectoryException(root.toString());
		}
		this.root = root.toRealPath();
		this.fileStore = Files.getFileStore(this.root);
		this.posix = fileStore.supportsFileAttributeView(PosixFileAttributeView.class);
		this.unix = fileStore.supportsFileAttributeView(UNIX_VIEW);
		this.capabilities = new VfsCapabilities(caseSensitive, normalizationSensitive, posix, fileStore.supportsFileAttributeView(USER_VIEW), VfsCapabilities.NO_LIMIT);
	}

	// NIO cannot ask the file store, so this checks whether the root is still reachable with the case of its letters swapped; a root without cased letters is assumed case-sensitive
	static boolean probeCaseSensitivity(Path root) throws IOException {
		var swapped = Path.of(swapCase(root.toString()));
		if (swapped.equals(root) || !Files.exists(swapped)) {
			return true;
		}
		return !Files.isSameFile(root, swapped);
	}

	// NIO cannot ask the file store either; APFS and HFS+ resolve every normalization form of a name to the same node, all other common file systems compare bytes
	static boolean probeNormalizationSensitivity(Path root) throws IOException {
		var type = Files.getFileStore(root).type().toLowerCase(Locale.ROOT);
		return !(type.equals("apfs") || type.startsWith("hfs"));
	}

	private static String swapCase(String s) {
		var sb = new StringBuilder(s.length());
		s.codePoints().forEach(cp -> sb.appendCodePoint(Character.isUpperCase(cp) ? Character.toLowerCase(cp) : Character.toUpperCase(cp)));
		return sb.toString();
	}

	@Override
	public VfsCapabilities capabilities() {
		return capabilities;
	}

	@Override
	public VfsNodeMetadata readNodeMetadata(String path) throws IOException {
		return readNodeMetadata(resolve(path));
	}

	@Override
	public VfsMetadata readVfsMetadata(String path) throws IOException {
		resolve(path);
		return new VfsMetadata(
				DEFAULT_BLOCK_SIZE,
				fileStore.getTotalSpace() / DEFAULT_BLOCK_SIZE,
				fileStore.getUnallocatedSpace() / DEFAULT_BLOCK_SIZE,
				fileStore.getUsableSpace() / DEFAULT_BLOCK_SIZE,
				255L
		);
	}

	@Override
	public void checkAccess(String path, Set<AccessMode> accessModes) throws IOException {
		var node = resolve(path);
		if (Files.isSymbolicLink(node)) {
			return; // access(2) would follow the link; the link itself exists and is always accessible
		}
		node.getFileSystem().provider().checkAccess(node, accessModes.toArray(AccessMode[]::new));
	}

	@Override
	public VfsDirectoryStream openDirectory(String path) throws IOException {
		var node = resolve(path);
		if (Files.isSymbolicLink(node)) {
			throw new NotDirectoryException(path); // newDirectoryStream would follow the link
		}
		return new NioDirectoryStream(Files.newDirectoryStream(node));
	}

	@Override
	public void createDirectory(String path, Set<PosixFilePermission> permissions) throws IOException {
		Files.createDirectory(resolve(path), posixAttributes(permissions));
	}

	@Override
	public void deleteDirectory(String path) throws IOException {
		var node = resolve(path);
		if (!Files.isDirectory(node, LinkOption.NOFOLLOW_LINKS)) {
			throw new NotDirectoryException(path);
		}
		Files.delete(node);
	}

	@Override
	public VfsFile openFile(String path, Set<StandardOpenOption> options) throws IOException {
		return open(resolve(path), normalizeOpenOptions(options));
	}

	@Override
	public VfsFile createFile(String path, Set<StandardOpenOption> options, Set<PosixFilePermission> permissions) throws IOException {
		var openOptions = normalizeOpenOptions(options);
		openOptions.add(StandardOpenOption.WRITE); // CREATE is ignored by NIO on read-only channels
		openOptions.add(options.contains(StandardOpenOption.CREATE_NEW) ? StandardOpenOption.CREATE_NEW : StandardOpenOption.CREATE);
		return open(resolve(path), openOptions, posixAttributes(permissions));
	}

	// opened and registered under the read lock, so a concurrent rename cannot slip in between and leave the handle with a stale path
	private NioOpenFile open(Path node, Set<StandardOpenOption> options, FileAttribute<?>... attrs) throws IOException {
		var openOptions = new HashSet<OpenOption>(options);
		openOptions.add(LinkOption.NOFOLLOW_LINKS); // O_NOFOLLOW, a symbolic link is never opened as a file
		renameLock.readLock().lock();
		try {
			var channel = FileChannel.open(node, openOptions, attrs);
			try {
				var file = new NioOpenFile(node, channel, readNodeMetadata(node));
				openFiles.add(file);
				return file;
			} catch (IOException e) {
				channel.close();
				throw e;
			}
		} finally {
			renameLock.readLock().unlock();
		}
	}

	@Override
	public void truncate(String path, long size) throws IOException {
		try (var channel = FileChannel.open(resolve(path), StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
			truncate(channel, size);
		}
	}

	@Override
	public void deleteFile(String path) throws IOException {
		var node = resolve(path);
		if (Files.isDirectory(node, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("Is a directory: " + path);
		}
		Files.delete(node);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @implNote Without {@code replaceExisting} this is not atomic: NIO offers no {@code RENAME_NOREPLACE}, so it is an existence check followed by
	 * {@code rename(2)}, and a node created at the target in between is overwritten. Open handles on the moved node and below it are re-pointed to
	 * their new paths, since NIO cannot stat a channel.
	 */
	@Override
	public void rename(String sourcePath, String targetPath, boolean replaceExisting) throws IOException {
		var source = resolve(sourcePath);
		var target = resolve(targetPath);
		if (source.equals(target)) {
			// rename(2) is a no-op for identical paths, but the pre-check below would reject a non-empty directory
			if (!Files.exists(source, LinkOption.NOFOLLOW_LINKS)) {
				throw new NoSuchFileException(sourcePath);
			}
			return;
		}
		renameLock.writeLock().lock();
		try {
			if (replaceExisting) {
				// rename(2) replaces atomically but reports ENOTEMPTY as a generic FileSystemException, hence the pre-check
				if (Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS) && !isEmptyDirectory(target)) {
					throw new DirectoryNotEmptyException(targetPath);
				}
				Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
			} else {
				// NIO has no RENAME_NOREPLACE; this is an existence check followed by rename(2)
				Files.move(source, target);
			}
			openFiles.forEach(file -> file.moved(source, target));
		} finally {
			renameLock.writeLock().unlock();
		}
	}

	private static boolean isEmptyDirectory(Path dir) throws IOException {
		try (var entries = Files.newDirectoryStream(dir)) {
			return !entries.iterator().hasNext();
		}
	}

	@Override
	public void setTimes(String path, VfsTimes times) throws IOException {
		setTimes(resolve(path), times);
	}

	@Override
	public void setPermissions(String path, Set<PosixFilePermission> permissions) throws IOException {
		var node = resolve(path);
		if (Files.isSymbolicLink(node)) {
			throw new FileSystemException(path, null, "cannot change permissions of a symbolic link"); // chmod(2) would follow the link
		}
		if (posix) {
			Files.setPosixFilePermissions(node, permissions);
		}
	}

	@Override
	public String readSymbolicLink(String path) throws IOException {
		requireSymbolicLinks();
		return Files.readSymbolicLink(resolve(path)).toString();
	}

	@Override
	public void createSymbolicLink(String path, String target) throws IOException {
		requireSymbolicLinks();
		Files.createSymbolicLink(resolve(path), Path.of(target));
	}

	@Override
	public List<String> listXattrs(String path) throws IOException {
		return xattrView(path).list().stream().map(XATTR_NAMES::toVfs).toList();
	}

	@Override
	public ByteBuffer getXattr(String path, String name) throws IOException {
		var view = xattrView(path);
		var viewName = XATTR_NAMES.toView(name);
		if (!view.list().contains(viewName)) {
			throw new NoSuchFileException(path, null, "no such xattr: " + name);
		}
		var buf = ByteBuffer.allocate(view.size(viewName));
		view.read(viewName, buf);
		return buf.flip().asReadOnlyBuffer();
	}

	@Override
	public void setXattr(String path, String name, ByteBuffer value, VfsXattrPolicy policy) throws IOException {
		var view = xattrView(path);
		var viewName = XATTR_NAMES.toView(name);
		if (policy != VfsXattrPolicy.CREATE_OR_REPLACE) {
			var exists = view.list().contains(viewName);
			if (exists && policy == VfsXattrPolicy.CREATE_ONLY) {
				throw new FileAlreadyExistsException(path, null, "xattr exists: " + name);
			}
			if (!exists && policy == VfsXattrPolicy.REPLACE_ONLY) {
				throw new NoSuchFileException(path, null, "no such xattr: " + name);
			}
		}
		view.write(viewName, value);
	}

	@Override
	public void removeXattr(String path, String name) throws IOException {
		var view = xattrView(path);
		var viewName = XATTR_NAMES.toView(name);
		if (!view.list().contains(viewName)) {
			throw new NoSuchFileException(path, null, "no such xattr: " + name);
		}
		view.delete(viewName);
	}

	// lexical confinement to the root, plus a check that no component below the root is a symbolic link: the parent's real path must be exactly the real root plus the relative path
	private Path resolve(String path) throws IOException {
		String relative = path;
		while (relative.startsWith("/")) {
			relative = relative.substring(1);
		}
		var resolved = relative.isEmpty() ? root : root.resolve(relative).normalize();
		if (!resolved.startsWith(root)) {
			throw new NoSuchFileException(path);
		}
		var parent = resolved.equals(root) ? root : resolved.getParent();
		if (!parent.equals(root) && !parent.toRealPath().equals(parent)) {
			throw new NoSuchFileException(path, null, "path contains a symbolic link");
		}
		return resolved;
	}

	private void requireSymbolicLinks() {
		if (!capabilities.supportsSymbolicLinks()) {
			throw new UnsupportedOperationException("symbolic links not supported");
		}
	}

	private UserDefinedFileAttributeView xattrView(String path) throws IOException {
		if (!capabilities.supportsXattrs()) {
			throw new UnsupportedOperationException("extended attributes not supported");
		}
		var node = resolve(path);
		if (!Files.exists(node, LinkOption.NOFOLLOW_LINKS)) {
			throw new NoSuchFileException(path);
		}
		return Files.getFileAttributeView(node, UserDefinedFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
	}

	// strips creation options and makes sure the channel is opened for reading or writing
	private static EnumSet<StandardOpenOption> normalizeOpenOptions(Set<StandardOpenOption> options) {
		var normalized = EnumSet.noneOf(StandardOpenOption.class);
		normalized.addAll(options);
		normalized.remove(StandardOpenOption.CREATE);
		normalized.remove(StandardOpenOption.CREATE_NEW);
		if (normalized.contains(StandardOpenOption.APPEND)) {
			normalized.add(StandardOpenOption.WRITE);
		}
		if (!normalized.contains(StandardOpenOption.WRITE)) {
			normalized.add(StandardOpenOption.READ);
		}
		return normalized;
	}

	private FileAttribute<?>[] posixAttributes(Set<PosixFilePermission> permissions) {
		if (!posix || permissions.isEmpty()) {
			return new FileAttribute<?>[0];
		}
		return new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(permissions)};
	}

	private static void truncate(FileChannel channel, long size) throws IOException {
		if (size < channel.size()) {
			channel.truncate(size);
		} else if (size > channel.size()) {
			channel.write(ByteBuffer.allocate(1), size - 1); // zero-extend (sparse where supported)
		}
	}

	private static void setTimes(Path node, VfsTimes times) throws IOException {
		var view = Files.getFileAttributeView(node, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
		view.setTimes(toFileTime(times.lastModifiedTime()), toFileTime(times.lastAccessTime()), toFileTime(times.creationTime()));
	}

	private static @Nullable FileTime toFileTime(@Nullable Instant instant) {
		return instant == null ? null : FileTime.from(instant);
	}

	private Set<PosixFilePermission> readPermissions(Path node, BasicFileAttributes attrs) throws IOException {
		if (posix) {
			return Files.readAttributes(node, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS).permissions();
		}
		var permissions = EnumSet.noneOf(PosixFilePermission.class);
		if (Files.isReadable(node)) {
			permissions.add(PosixFilePermission.OWNER_READ);
			permissions.add(PosixFilePermission.GROUP_READ);
			permissions.add(PosixFilePermission.OTHERS_READ);
		}
		if (Files.isWritable(node)) {
			permissions.add(PosixFilePermission.OWNER_WRITE);
			permissions.add(PosixFilePermission.GROUP_WRITE);
		}
		if (attrs.isDirectory() || Files.isExecutable(node)) {
			permissions.add(PosixFilePermission.OWNER_EXECUTE);
			permissions.add(PosixFilePermission.GROUP_EXECUTE);
			permissions.add(PosixFilePermission.OTHERS_EXECUTE);
		}
		return permissions;
	}

	private static VfsNodeType toNodeType(BasicFileAttributes attrs) {
		if (attrs.isDirectory()) {
			return VfsNodeType.DIRECTORY;
		}
		if (attrs.isSymbolicLink()) {
			return VfsNodeType.SYMBOLIC_LINK;
		}
		return VfsNodeType.FILE;
	}

	private VfsNodeMetadata readNodeMetadata(Path node) throws IOException {
		var attrs = Files.readAttributes(node, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
		long fileId = VfsNodeMetadata.NO_FILE_ID;
		Instant changeTime = attrs.lastModifiedTime().toInstant();
		if (unix) {
			var unixAttrs = Files.readAttributes(node, UNIX_VIEW + ":ino,ctime", LinkOption.NOFOLLOW_LINKS);
			fileId = (Long) unixAttrs.get("ino");
			changeTime = ((FileTime) unixAttrs.get("ctime")).toInstant();
		}
		return new VfsNodeMetadata(
				toNodeType(attrs),
				attrs.size(),
				fileId,
				readPermissions(node, attrs),
				attrs.lastModifiedTime().toInstant(),
				attrs.lastAccessTime().toInstant(),
				changeTime,
				attrs.creationTime().toInstant()
		);
	}

	private final class NioDirectoryStream implements VfsDirectoryStream {

		private final DirectoryStream<Path> delegate;
		private boolean iterated;

		NioDirectoryStream(DirectoryStream<Path> delegate) {
			this.delegate = delegate;
		}

		@Override
		public Iterator<VfsDirectoryEntry> iterator() {
			if (iterated) {
				throw new IllegalStateException("Iterator already obtained");
			}
			iterated = true;
			var paths = delegate.iterator();
			return new Iterator<>() {

				private @Nullable VfsDirectoryEntry next;

				@Override
				public boolean hasNext() {
					while (next == null && paths.hasNext()) {
						var child = paths.next();
						try {
							next = new VfsDirectoryEntry(child.getFileName().toString(), readNodeMetadata(child));
						} catch (NoSuchFileException _) {
							// entry vanished between listing and stat, skip it
						} catch (IOException e) {
							throw new UncheckedIOException(e);
						}
					}
					return next != null;
				}

				@Override
				public VfsDirectoryEntry next() {
					if (!hasNext()) {
						throw new NoSuchElementException();
					}
					var result = next;
					next = null;
					return result;
				}
			};
		}

		@Override
		public void close() throws IOException {
			delegate.close();
		}
	}

	private final class NioOpenFile implements VfsFile {

		private final FileChannel channel;
		private volatile Path node; // follows renames, see NioVfsFileSystem#rename
		private volatile VfsNodeMetadata lastKnown; // reported once the path is gone, with the live size from the channel

		NioOpenFile(Path node, FileChannel channel, VfsNodeMetadata metadata) {
			this.node = node;
			this.channel = channel;
			this.lastKnown = metadata;
		}

		void moved(Path from, Path to) {
			var current = node;
			if (current.equals(from)) {
				node = to;
			} else if (current.startsWith(from)) {
				node = to.resolve(from.relativize(current));
			}
		}

		@Override
		public int read(ByteBuffer dst, long offset) throws IOException {
			return channel.read(dst, offset);
		}

		@Override
		public int write(ByteBuffer src, long offset) throws IOException {
			return channel.write(src, offset);
		}

		@Override
		public VfsNodeMetadata readMetadata() throws IOException {
			// NIO cannot fstat a channel; after an unlink the inode is unreachable by path, so the last known metadata with the live size is the best available
			try {
				var metadata = readNodeMetadata(node);
				lastKnown = metadata;
				return metadata;
			} catch (NoSuchFileException _) {
				var stale = lastKnown;
				return new VfsNodeMetadata(stale.type(), channel.size(), stale.fileId(), stale.permissions(), stale.lastModifiedTime(), stale.lastAccessTime(), stale.changeTime(), stale.creationTime());
			}
		}

		@Override
		public void truncate(long size) throws IOException {
			NioVfsFileSystem.truncate(channel, size);
		}

		@Override
		public void setTimes(VfsTimes times) throws IOException {
			NioVfsFileSystem.setTimes(node, times);
		}

		@Override
		public void force(boolean metadata) throws IOException {
			channel.force(metadata);
		}

		@Override
		public void close() throws IOException {
			openFiles.remove(this);
			channel.close();
		}
	}
}
