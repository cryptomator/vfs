package org.cryptomator.vfs.middleware.uvf;

import org.cryptomator.vfs.api.VfsCapabilities;
import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsDirectoryStream;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsMetadata;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Minimal in-memory {@link VfsFileSystem} for testing the middleware without a real backend.
 */
final class InMemoryVfsFileSystem implements VfsFileSystem {

	private static final class Node {
		final boolean directory;
		byte[] data = new byte[0];

		Node(boolean directory) {
			this.directory = directory;
		}
	}

	private final Map<String, Node> nodes = new TreeMap<>();

	InMemoryVfsFileSystem() {
		nodes.put("/", new Node(true));
	}

	/**
	 * @return all absolute paths currently stored, including the root
	 */
	Set<String> paths() {
		return Set.copyOf(nodes.keySet());
	}

	/**
	 * Writes a file, creating missing parent directories.
	 */
	void writeFile(String path, byte[] contents) throws IOException {
		var normalized = normalize(path);
		var parent = parentOf(normalized);
		if (!nodes.containsKey(parent)) {
			createDirectories(parent);
		}
		try (var file = createFile(normalized, Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING), Set.of())) {
			file.write(ByteBuffer.wrap(contents), 0);
		}
	}

	void createDirectories(String path) throws IOException {
		var normalized = normalize(path);
		if (nodes.containsKey(normalized)) {
			return;
		}
		createDirectories(parentOf(normalized));
		createDirectory(normalized, Set.of());
	}

	private static String normalize(String path) {
		var result = path;
		while (result.endsWith("/") && result.length() > 1) {
			result = result.substring(0, result.length() - 1);
		}
		return result.startsWith("/") ? result : "/" + result;
	}

	private static String parentOf(String path) {
		int separator = path.lastIndexOf('/');
		return separator <= 0 ? "/" : path.substring(0, separator);
	}

	private static String nameOf(String path) {
		return path.substring(path.lastIndexOf('/') + 1);
	}

	private Node require(String path) throws NoSuchFileException {
		var node = nodes.get(path);
		if (node == null) {
			throw new NoSuchFileException(path);
		}
		return node;
	}

	private void requireParentDirectory(String path) throws IOException {
		var parent = nodes.get(parentOf(path));
		if (parent == null) {
			throw new NoSuchFileException(parentOf(path));
		}
		if (!parent.directory) {
			throw new NotDirectoryException(parentOf(path));
		}
	}

	private List<String> childrenOf(String path) {
		var children = new ArrayList<String>();
		for (var key : nodes.keySet()) {
			if (!"/".equals(key) && parentOf(key).equals(path)) {
				children.add(key);
			}
		}
		return children;
	}

	private static VfsNodeMetadata metadata(Node node) {
		return new VfsNodeMetadata(node.directory ? VfsNodeType.DIRECTORY : VfsNodeType.FILE, node.directory ? 0 : node.data.length, VfsNodeMetadata.NO_FILE_ID, Set.of(), Instant.EPOCH, Instant.EPOCH, Instant.EPOCH, Instant.EPOCH);
	}

	@Override
	public VfsCapabilities capabilities() {
		return VfsCapabilities.MINIMAL;
	}

	@Override
	public VfsNodeMetadata readNodeMetadata(String path) throws IOException {
		return metadata(require(normalize(path)));
	}

	@Override
	public VfsMetadata readVfsMetadata(String path) throws IOException {
		require(normalize(path));
		return new VfsMetadata(4096, 1000, 500, 500, 255);
	}

	@Override
	public void checkAccess(String path, Set<AccessMode> accessModes) throws IOException {
		require(normalize(path));
	}

	@Override
	public VfsDirectoryStream openDirectory(String path) throws IOException {
		var normalized = normalize(path);
		if (!require(normalized).directory) {
			throw new NotDirectoryException(path);
		}
		var entries = new ArrayList<VfsDirectoryEntry>();
		for (var child : childrenOf(normalized)) {
			entries.add(new VfsDirectoryEntry(nameOf(child), metadata(nodes.get(child))));
		}
		return new VfsDirectoryStream() {
			@Override
			public Iterator<VfsDirectoryEntry> iterator() {
				return entries.iterator();
			}

			@Override
			public void close() {
			}
		};
	}

	@Override
	public void createDirectory(String path, Set<PosixFilePermission> permissions) throws IOException {
		var normalized = normalize(path);
		requireParentDirectory(normalized);
		if (nodes.containsKey(normalized)) {
			throw new FileAlreadyExistsException(path);
		}
		nodes.put(normalized, new Node(true));
	}

	@Override
	public void deleteDirectory(String path) throws IOException {
		var normalized = normalize(path);
		if (!require(normalized).directory) {
			throw new NotDirectoryException(path);
		}
		if (!childrenOf(normalized).isEmpty()) {
			throw new DirectoryNotEmptyException(path);
		}
		nodes.remove(normalized);
	}

	@Override
	public VfsFile openFile(String path, Set<StandardOpenOption> options) throws IOException {
		var node = require(normalize(path));
		if (node.directory) {
			throw new FileSystemException(path, null, "Is a directory");
		}
		if (options.contains(StandardOpenOption.TRUNCATE_EXISTING)) {
			node.data = new byte[0];
		}
		return new InMemoryFile(node);
	}

	@Override
	public VfsFile createFile(String path, Set<StandardOpenOption> options, Set<PosixFilePermission> permissions) throws IOException {
		var normalized = normalize(path);
		requireParentDirectory(normalized);
		var existing = nodes.get(normalized);
		if (existing != null) {
			if (options.contains(StandardOpenOption.CREATE_NEW)) {
				throw new FileAlreadyExistsException(path);
			}
			return openFile(normalized, options);
		}
		var node = new Node(false);
		nodes.put(normalized, node);
		return new InMemoryFile(node);
	}

	@Override
	public void truncate(String path, long size) throws IOException {
		var node = require(normalize(path));
		node.data = Arrays.copyOf(node.data, Math.toIntExact(size));
	}

	@Override
	public void deleteFile(String path) throws IOException {
		var normalized = normalize(path);
		if (require(normalized).directory) {
			throw new FileSystemException(path, null, "Is a directory");
		}
		nodes.remove(normalized);
	}

	@Override
	public void rename(String sourcePath, String targetPath, boolean replaceExisting) throws IOException {
		var source = normalize(sourcePath);
		var target = normalize(targetPath);
		var sourceNode = require(source);
		requireParentDirectory(target);
		var targetNode = nodes.get(target);
		if (targetNode != null) {
			if (!replaceExisting) {
				throw new FileAlreadyExistsException(targetPath);
			}
			if (targetNode.directory && !childrenOf(target).isEmpty()) {
				throw new DirectoryNotEmptyException(targetPath);
			}
			if (targetNode.directory != sourceNode.directory) {
				throw new FileSystemException(sourcePath, targetPath, targetNode.directory ? "Is a directory" : "Not a directory");
			}
			nodes.remove(target);
		}
		var moved = new TreeMap<String, Node>();
		for (var entry : nodes.entrySet()) {
			if (entry.getKey().equals(source) || entry.getKey().startsWith(source + "/")) {
				moved.put(target + entry.getKey().substring(source.length()), entry.getValue());
			}
		}
		moved.keySet().forEach(key -> nodes.remove(source + key.substring(target.length())));
		nodes.putAll(moved);
	}

	@Override
	public void setTimes(String path, VfsTimes times) throws IOException {
		require(normalize(path));
	}

	@Override
	public void setPermissions(String path, Set<PosixFilePermission> permissions) throws IOException {
		require(normalize(path));
	}

	private static final class InMemoryFile implements VfsFile {

		private final Node node;

		InMemoryFile(Node node) {
			this.node = node;
		}

		@Override
		public int read(ByteBuffer dst, long offset) {
			if (offset >= node.data.length) {
				return -1;
			}
			int available = (int) Math.min(dst.remaining(), node.data.length - offset);
			dst.put(node.data, (int) offset, available);
			return available;
		}

		@Override
		public int write(ByteBuffer src, long offset) {
			int length = src.remaining();
			int requiredSize = (int) offset + length;
			if (requiredSize > node.data.length) {
				node.data = Arrays.copyOf(node.data, requiredSize);
			}
			src.get(node.data, (int) offset, length);
			return length;
		}

		@Override
		public VfsNodeMetadata readMetadata() {
			return metadata(node);
		}

		@Override
		public void truncate(long size) {
			node.data = Arrays.copyOf(node.data, Math.toIntExact(size));
		}

		@Override
		public void setTimes(VfsTimes times) {
		}

		@Override
		public void force(boolean metadata) {
		}

		@Override
		public void close() {
		}
	}
}
