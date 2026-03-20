package org.cryptomator.vfs.backend.nio;

import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsMetadata;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AccessMode;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
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
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Simple mirrored filesystem backend backed by Java NIO.
 */
public final class NioVfsFileSystem implements VfsFileSystem {

	private static final long DEFAULT_BLOCK_SIZE = 4096L;

	private final Path root;
	private final FileStore fileStore;
	private final boolean posix;

	public NioVfsFileSystem(Path root) throws IOException {
		this.root = root.toAbsolutePath().normalize();
		if (!Files.isDirectory(this.root)) {
			throw new NotDirectoryException(this.root.toString());
		}
		this.fileStore = Files.getFileStore(this.root);
		this.posix = fileStore.supportsFileAttributeView(PosixFileAttributeView.class);
	}

	@Override
	public VfsNodeMetadata readNodeMetadata(String path) throws IOException {
		var node = resolve(path);
		var attrs = Files.readAttributes(node, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
		return toNodeMetadata(node, attrs);
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
		node.getFileSystem().provider().checkAccess(node, accessModes.toArray(AccessMode[]::new));
	}

	@Override
	public List<VfsDirectoryEntry> listDirectory(String path) throws IOException {
		var node = resolve(path);
		var entries = new ArrayList<VfsDirectoryEntry>();
		try (var dir = Files.newDirectoryStream(node)) {
			for (var child : dir) {
				var attrs = Files.readAttributes(child, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
				entries.add(new VfsDirectoryEntry(child.getFileName().toString(), toNodeMetadata(child, attrs)));
			}
		}
		return List.copyOf(entries);
	}

	@Override
	public void createDirectory(String path, Set<PosixFilePermission> permissions) throws IOException {
		Files.createDirectory(resolve(path), posixAttributes(permissions));
	}

	@Override
	public void deleteDirectory(String path) throws IOException {
		Files.delete(resolve(path));
	}

	@Override
	public VfsFile openFile(String path, Set<StandardOpenOption> options) throws IOException {
		return new NioOpenFile(FileChannel.open(resolve(path), normalizeOpenOptions(options)));
	}

	@Override
	public VfsFile createFile(String path, Set<StandardOpenOption> options, Set<PosixFilePermission> permissions) throws IOException {
		var openOptions = EnumSet.copyOf(normalizeOpenOptions(options));
		openOptions.add(StandardOpenOption.CREATE_NEW);
		return new NioOpenFile(FileChannel.open(resolve(path), openOptions, posixAttributes(permissions)));
	}

	@Override
	public void truncate(String path, long size) throws IOException {
		try (var channel = FileChannel.open(resolve(path), StandardOpenOption.WRITE)) {
			channel.truncate(size);
		}
	}

	@Override
	public void deleteFile(String path) throws IOException {
		Files.delete(resolve(path));
	}

	@Override
	public void rename(String sourcePath, String targetPath) throws IOException {
		Files.move(resolve(sourcePath), resolve(targetPath), StandardCopyOption.REPLACE_EXISTING);
	}

	@Override
	public void setTimes(String path, VfsTimes times) throws IOException {
		var view = Files.getFileAttributeView(resolve(path), BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
		FileTime lastModifiedTime = times.lastModifiedTime() == null ? null : FileTime.from(times.lastModifiedTime());
		FileTime lastAccessTime = times.lastAccessTime() == null ? null : FileTime.from(times.lastAccessTime());
		view.setTimes(lastModifiedTime, lastAccessTime, null);
	}

	private Path resolve(String path) throws IOException {
		String relative = path;
		while (relative.startsWith("/")) {
			relative = relative.substring(1);
		}
		var resolved = relative.isEmpty() ? root : root.resolve(relative).normalize();
		if (!resolved.startsWith(root)) {
			throw new NoSuchFileException(path);
		}
		return resolved;
	}

	private Set<StandardOpenOption> normalizeOpenOptions(Set<StandardOpenOption> options) {
		if (options == null || options.isEmpty()) {
			return EnumSet.of(StandardOpenOption.READ);
		}
		if (options.size() == 1 && options.contains(StandardOpenOption.APPEND)) {
			return EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.APPEND);
		}
		return EnumSet.copyOf(options);
	}

	private FileAttribute<?>[] posixAttributes(Set<PosixFilePermission> permissions) {
		if (!posix || permissions == null || permissions.isEmpty()) {
			return new FileAttribute<?>[0];
		}
		return new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(permissions)};
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

	private VfsNodeType toNodeType(BasicFileAttributes attrs) {
		if (attrs.isDirectory()) {
			return VfsNodeType.DIRECTORY;
		}
		if (attrs.isSymbolicLink()) {
			return VfsNodeType.SYMBOLIC_LINK;
		}
		return VfsNodeType.FILE;
	}

	private VfsNodeMetadata toNodeMetadata(Path node, BasicFileAttributes attrs) throws IOException {
		return new VfsNodeMetadata(
				toNodeType(attrs),
				attrs.size(),
				readPermissions(node, attrs),
				attrs.lastModifiedTime().toInstant(),
				attrs.lastAccessTime().toInstant(),
				attrs.creationTime().toInstant()
		);
	}

	private record NioOpenFile(FileChannel channel) implements VfsFile {

		@Override
		public int read(ByteBuffer dst, long offset) throws IOException {
			return channel.read(dst, offset);
		}

		@Override
		public int write(ByteBuffer src, long offset) throws IOException {
			return channel.write(src, offset);
		}

		@Override
		public void force(boolean metadata) throws IOException {
			channel.force(metadata);
		}

		@Override
		public void close() throws IOException {
			channel.close();
		}
	}
}
