package org.cryptomator.vfs.middleware.shortening;

import org.cryptomator.vfs.api.VfsCapabilities;
import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsDirectoryStream;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsMetadata;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsTimes;
import org.cryptomator.vfs.api.VfsXattrPolicy;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.file.AccessMode;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A {@link VfsFileSystem} decorator that stores names longer than a threshold under a short, hash-derived name next to a sidecar file holding the original name.
 * <p>
 * The middleware involves no cryptography and operates on the names of the upper layer without understanding them.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/tree/develop/file-name-shortening">UVF File Name Shortening</a>
 */
public final class ShorteningFileSystem implements VfsFileSystem {

	/**
	 * The smallest permitted threshold, which is the length of a stored short name.
	 */
	public static final int MIN_THRESHOLD = NameShortener.HASH_LENGTH + NameShortener.NODE_SUFFIX.length();

	/**
	 * The recommended threshold, leaving headroom for suffixes added by sync services in case of conflicts.
	 */
	public static final int RECOMMENDED_THRESHOLD = 220;

	/**
	 * The maximum length in UTF-8 bytes of a name accepted from the upper layer, reported as {@link VfsMetadata#maxNameLength()}.
	 */
	public static final int MAX_NAME_LENGTH = 1024;

	private static final Logger LOG = LoggerFactory.getLogger(ShorteningFileSystem.class);
	private static final Set<PosixFilePermission> DEFAULT_PERMISSIONS = Set.of(); // let the delegate apply its defaults
	private static final int SIDECAR_CACHE_SIZE = 10_000;

	private final VfsFileSystem delegate;
	private final NameShortener shortener;
	// verified sidecar contents by hash; the hash determines the content, so entries never become wrong
	private final Map<String, String> sidecarCache = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
		@Override
		protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
			return size() > SIDECAR_CACHE_SIZE;
		}
	});
	// stored path of the parent joined with a reported conflict name -> stored path of the conflicting node, learned while listing directories
	private final ConcurrentMap<String, String> conflicts = new ConcurrentHashMap<>();

	/**
	 * Creates a shortening layer on top of the given delegate.
	 *
	 * @param delegate the underlying file system storing the shortened names
	 * @param threshold names longer than this many UTF-8 bytes get shortened, e.g. {@code nameShorteningThreshold} from {@code vault.uvf}
	 * @throws IllegalArgumentException if {@code threshold} is less than {@link #MIN_THRESHOLD}
	 */
	public ShorteningFileSystem(VfsFileSystem delegate, int threshold) {
		if (threshold < MIN_THRESHOLD) {
			throw new IllegalArgumentException("Threshold must be at least " + MIN_THRESHOLD + ", was " + threshold);
		}
		this.delegate = delegate;
		this.shortener = new NameShortener(threshold);
	}

	@Override
	public VfsCapabilities capabilities() {
		return delegate.capabilities();
	}

	@Override
	public VfsNodeMetadata readNodeMetadata(String path) throws IOException {
		return delegate.readNodeMetadata(storedPath(path));
	}

	@Override
	public VfsMetadata readVfsMetadata(String path) throws IOException {
		var stored = delegate.readVfsMetadata(storedPath(path));
		return new VfsMetadata(stored.blockSize(), stored.totalBlocks(), stored.freeBlocks(), stored.availableBlocks(), Math.max(stored.maxNameLength(), MAX_NAME_LENGTH));
	}

	@Override
	public void checkAccess(String path, Set<AccessMode> accessModes) throws IOException {
		delegate.checkAccess(storedPath(path), accessModes);
	}

	@Override
	public VfsDirectoryStream openDirectory(String path) throws IOException {
		var storedDir = storedPath(path);
		return new MappingDirectoryStream(delegate.openDirectory(storedDir), entry -> toUpperEntry(storedDir, entry));
	}

	// null for sidecars and for entries that cannot be mapped back to a valid name
	private @Nullable VfsDirectoryEntry toUpperEntry(String storedDir, VfsDirectoryEntry storedEntry) {
		var storedName = storedEntry.name();
		if (NameShortener.SIDECAR.matcher(storedName).matches()) {
			return null;
		}
		var matcher = NameShortener.SHORTENED_NODE.matcher(storedName);
		if (matcher.matches()) {
			var hash = matcher.group(1);
			var conflictSuffix = matcher.group(2);
			String name;
			try {
				name = readSidecar(storedDir, hash);
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
			if (name == null) {
				LOG.warn("Skipping {}, its sidecar is missing or invalid", join(storedDir, storedName));
				return null;
			}
			if (conflictSuffix.isEmpty()) {
				return new VfsDirectoryEntry(name, storedEntry.metadata());
			}
			var conflictName = NameShortener.conflictName(name, conflictSuffix);
			conflicts.put(join(storedDir, conflictName), join(storedDir, storedName));
			return new VfsDirectoryEntry(conflictName, storedEntry.metadata());
		}
		if (shortener.isLong(storedName)) {
			LOG.warn("Skipping {}, its name exceeds the shortening threshold", join(storedDir, storedName));
			return null;
		}
		return storedEntry;
	}

	@Override
	public void createDirectory(String path, Set<PosixFilePermission> permissions) throws IOException {
		var node = resolve(path);
		writeSidecar(node);
		delegate.createDirectory(node.path(), permissions);
	}

	@Override
	public void deleteDirectory(String path) throws IOException {
		var node = resolve(path);
		delegate.deleteDirectory(node.path());
		forgetConflicts(node);
		deleteSidecar(node);
	}

	@Override
	public VfsFile openFile(String path, Set<StandardOpenOption> options) throws IOException {
		return delegate.openFile(storedPath(path), options);
	}

	@Override
	public VfsFile createFile(String path, Set<StandardOpenOption> options, Set<PosixFilePermission> permissions) throws IOException {
		var node = resolve(path);
		writeSidecar(node);
		return delegate.createFile(node.path(), options, permissions);
	}

	@Override
	public void truncate(String path, long size) throws IOException {
		delegate.truncate(storedPath(path), size);
	}

	@Override
	public void deleteFile(String path) throws IOException {
		var node = resolve(path);
		delegate.deleteFile(node.path());
		forgetConflicts(node);
		deleteSidecar(node);
	}

	@Override
	public void rename(String sourcePath, String targetPath, boolean replaceExisting) throws IOException {
		var source = resolve(sourcePath);
		var target = resolve(targetPath);
		writeSidecar(target);
		delegate.rename(source.path(), target.path(), replaceExisting); // the node moves atomically
		forgetConflicts(source);
		boolean sharesSidecar = source.shortened() && target.shortened() && source.sidecarPath().equals(target.sidecarPath());
		if (!sharesSidecar) {
			deleteSidecar(source);
		}
	}

	@Override
	public void setTimes(String path, VfsTimes times) throws IOException {
		delegate.setTimes(storedPath(path), times);
	}

	@Override
	public void setPermissions(String path, Set<PosixFilePermission> permissions) throws IOException {
		delegate.setPermissions(storedPath(path), permissions);
	}

	@Override
	public String readSymbolicLink(String path) throws IOException {
		return delegate.readSymbolicLink(storedPath(path));
	}

	@Override
	public void createSymbolicLink(String path, String target) throws IOException {
		var node = resolve(path);
		writeSidecar(node);
		delegate.createSymbolicLink(node.path(), target);
	}

	@Override
	public List<String> listXattrs(String path) throws IOException {
		return delegate.listXattrs(storedPath(path));
	}

	@Override
	public ByteBuffer getXattr(String path, String name) throws IOException {
		return delegate.getXattr(storedPath(path), name);
	}

	@Override
	public void setXattr(String path, String name, ByteBuffer value, VfsXattrPolicy policy) throws IOException {
		delegate.setXattr(storedPath(path), name, value, policy);
	}

	@Override
	public void removeXattr(String path, String name) throws IOException {
		delegate.removeXattr(storedPath(path), name);
	}

	// --- path mapping ---

	private String storedPath(String path) throws IOException {
		var storedPath = "/";
		for (var name : path.split("/")) {
			if (!name.isEmpty()) {
				storedPath = join(storedPath, storedName(path, storedPath, name));
			}
		}
		return storedPath;
	}

	private StoredNode resolve(String path) throws IOException {
		int separator = path.lastIndexOf('/');
		var name = path.substring(separator + 1);
		if (name.isEmpty()) {
			throw new FileSystemException(path, null, "Not a valid node path");
		}
		var storedParent = storedPath(path.substring(0, separator));
		return new StoredNode(storedParent, name, storedName(path, storedParent, name));
	}

	private String storedName(String path, String storedParent, String name) throws IOException {
		var conflictingNode = conflicts.get(join(storedParent, name));
		if (conflictingNode != null) {
			return conflictingNode.substring(conflictingNode.lastIndexOf('/') + 1);
		}
		var utf8Name = NameShortener.utf8(name);
		if (utf8Name.length > MAX_NAME_LENGTH) {
			throw new FileSystemException(path, null, "File name too long");
		}
		if (shortener.isLong(utf8Name)) {
			return shortener.shortName(utf8Name) + NameShortener.NODE_SUFFIX;
		}
		if (NameShortener.isReserved(name)) {
			throw new FileSystemException(path, null, "Reserved file name");
		}
		return name;
	}

	private static String join(String parent, String name) {
		return "/".equals(parent) ? "/" + name : parent + "/" + name;
	}

	// a reported conflict name is only valid as long as the node it was learned from exists in place
	private void forgetConflicts(StoredNode node) {
		conflicts.remove(join(node.parentPath(), node.name()));
		var descendants = node.path() + "/";
		conflicts.keySet().removeIf(key -> key.startsWith(descendants));
	}

	// --- sidecar I/O ---

	// written before the node; an existing sidecar is left alone unless it is invalid, so an interruption never damages another node's sidecar
	private void writeSidecar(StoredNode node) throws IOException {
		if (!node.shortened()) {
			return;
		}
		try {
			writeAll(node.sidecarPath(), Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW), NameShortener.utf8(node.name()));
		} catch (FileAlreadyExistsException e) {
			if (readSidecar(node.parentPath(), node.hash()) == null) {
				writeAll(node.sidecarPath(), Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING), NameShortener.utf8(node.name()));
			}
		}
	}

	// deleted after the node; an orphaned sidecar is harmless, whereas deleting one that is still referenced by another node is not
	private void deleteSidecar(StoredNode node) throws IOException {
		if (!node.shortened() || node.conflicting() || isReferencedByConflictingNode(node)) {
			return;
		}
		try {
			delegate.deleteFile(node.sidecarPath());
		} catch (NoSuchFileException _) {
			// orphaned node, nothing to do
		}
	}

	private boolean isReferencedByConflictingNode(StoredNode node) {
		var nodePrefix = join(node.parentPath(), node.hash() + ".shortened");
		var nodePath = node.path();
		return conflicts.values().stream().anyMatch(conflictingNode -> conflictingNode.startsWith(nodePrefix) && !conflictingNode.equals(nodePath));
	}

	// the verified original name, or null if the sidecar is missing or invalid
	private @Nullable String readSidecar(String storedDir, String hash) throws IOException {
		var cached = sidecarCache.get(hash);
		if (cached != null) {
			return cached;
		}
		byte[] contents;
		try {
			contents = readAtMost(join(storedDir, hash + NameShortener.SIDECAR_SUFFIX), MAX_NAME_LENGTH + 1);
		} catch (NoSuchFileException _) {
			return null;
		}
		var name = contents.length > MAX_NAME_LENGTH ? null : shortener.verifySidecar(hash, contents);
		if (name != null) {
			sidecarCache.put(hash, name);
		}
		return name;
	}

	private byte[] readAtMost(String storedPath, int maxBytes) throws IOException {
		try (var file = delegate.openFile(storedPath, Set.of(StandardOpenOption.READ))) {
			var buf = ByteBuffer.allocate(maxBytes);
			while (buf.hasRemaining() && file.read(buf, buf.position()) >= 0) {
				// keep reading
			}
			return Arrays.copyOf(buf.array(), buf.position());
		}
	}

	private void writeAll(String storedPath, Set<StandardOpenOption> options, byte[] contents) throws IOException {
		try (var file = delegate.createFile(storedPath, options, DEFAULT_PERMISSIONS)) {
			var buf = ByteBuffer.wrap(contents);
			while (buf.hasRemaining()) {
				file.write(buf, buf.position());
			}
		}
	}

	// a node as stored on the delegate; storedName differs from name for long names and for conflicting copies
	private record StoredNode(String parentPath, String name, String storedName) {

		String path() {
			return join(parentPath, storedName);
		}

		boolean shortened() {
			return !name.equals(storedName);
		}

		// a conflicting copy shares its sidecar with the regular node of the same hash
		boolean conflicting() {
			return shortened() && !storedName.equals(hash() + NameShortener.NODE_SUFFIX);
		}

		String hash() {
			return storedName.substring(0, NameShortener.HASH_LENGTH);
		}

		String sidecarPath() {
			return join(parentPath, hash() + NameShortener.SIDECAR_SUFFIX);
		}
	}
}
