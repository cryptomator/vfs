package org.cryptomator.vfs.middleware.uvf.shortening;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.NameShortener;
import org.cryptomator.cryptolib.api.ShortenedVaultNode;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessMode;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

/**
 * A {@link VfsFileSystem} decorator that stores names longer than a threshold under a short, hash-derived name next to a sidecar file holding the original name.
 * <p>
 * The middleware involves no keys and operates on the names of the upper layer without understanding them. The name format is the one of the Unified Vault Format, provided by
 * cryptolib's {@link NameShortener#uvf(int)}; this class performs the I/O.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/tree/develop/file-name-shortening">UVF File Name Shortening</a>
 * @see <a href="https://github.com/cryptomator/vfs/blob/develop/docs/conflict-resolution.md">Sync conflict resolution</a>
 */
public final class ShorteningFileSystem implements VfsFileSystem {

	/**
	 * The recommended threshold, leaving headroom for suffixes added by sync services in case of conflicts.
	 */
	public static final int RECOMMENDED_THRESHOLD = 220;

	/**
	 * The maximum length in UTF-8 bytes of a name accepted from the upper layer, reported as {@link VfsMetadata#maxNameLength()} unless shortening is disabled.
	 */
	public static final int MAX_NAME_LENGTH = 1024;

	private static final Logger LOG = LoggerFactory.getLogger(ShorteningFileSystem.class);
	private static final Set<PosixFilePermission> DEFAULT_PERMISSIONS = Set.of(); // let the delegate apply its defaults
	private static final int SIDECAR_CACHE_SIZE = 10_000;

	private final VfsFileSystem delegate;
	private final NameShortener shortener;
	private final boolean resolveConflicts;
	private final VfsCapabilities capabilities;
	// verified full names by shortened name; the hash in the shortened name determines the sidecar's content, so entries never become wrong
	private final Map<String, String> sidecarCache = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
		@Override
		protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
			return size() > SIDECAR_CACHE_SIZE;
		}
	});

	/**
	 * Creates a shortening layer on top of the given delegate.
	 *
	 * @param delegate the underlying file system storing the shortened names
	 * @param threshold names longer than this many UTF-8 bytes get shortened: {@code nameShorteningThreshold} from {@code vault.uvf}, i.e. at least {@link NameShortener#MIN_UVF_THRESHOLD},
	 * or {@link NameShortener#DISABLED} to pass all names through unchanged
	 * @param resolveConflicts whether listings repair conflicting copies created by sync services, writing to the delegate; if {@code false}, conflicting copies of shortened nodes are
	 * not listed
	 * @throws IllegalArgumentException if {@code threshold} is invalid
	 */
	public ShorteningFileSystem(VfsFileSystem delegate, int threshold, boolean resolveConflicts) {
		this.delegate = delegate;
		this.shortener = NameShortener.uvf(threshold); // UVF only: CVF8 shortening changes the node type, which a per-component mapping cannot do
		this.resolveConflicts = resolveConflicts;
		// a long name is stored under the hash of its exact UTF-8 bytes, so names differing only in case or normalization never alias, whatever the delegate does.
		// Reporting the delegate's insensitivity would let frontends rewrite names and miss long-named nodes, so the strict variant is reported
		var delegateCapabilities = delegate.capabilities();
		this.capabilities = new VfsCapabilities(true, true, delegateCapabilities.supportsSymbolicLinks(), delegateCapabilities.supportsXattrs(), delegateCapabilities.maxXattrValueSize());
	}

	@Override
	public VfsCapabilities capabilities() {
		return capabilities;
	}

	@Override
	public VfsNodeMetadata readNodeMetadata(String path) throws IOException {
		return delegate.readNodeMetadata(storedPath(path));
	}

	@Override
	public VfsMetadata readVfsMetadata(String path) throws IOException {
		var stored = delegate.readVfsMetadata(storedPath(path));
		if (shortener.threshold() == NameShortener.DISABLED) {
			return stored; // names pass through unchanged, so the delegate's limit applies
		}
		return new VfsMetadata(stored.blockSize(), stored.totalBlocks(), stored.freeBlocks(), stored.availableBlocks(), Math.max(stored.maxNameLength(), MAX_NAME_LENGTH));
	}

	@Override
	public void checkAccess(String path, Set<AccessMode> accessModes) throws IOException {
		delegate.checkAccess(storedPath(path), accessModes);
	}

	@Override
	public VfsDirectoryStream openDirectory(String path) throws IOException {
		var storedDir = storedPath(path);
		var createdNodes = new HashSet<String>(); // nodes renamed into place by conflict resolution during this listing, which the delegate's listing may or may not show again
		return new MappingDirectoryStream(delegate, storedDir, entry -> createdNodes.contains(entry.name()) ? null : toUpperEntry(storedDir, entry, createdNodes));
	}

	// null for sidecars and for entries that cannot be mapped back to a valid name
	private @Nullable VfsDirectoryEntry toUpperEntry(String storedDir, VfsDirectoryEntry storedEntry, Set<String> createdNodes) {
		var storedName = storedEntry.name();
		// conflicting copies of sidecars are interchangeable or invalid, so they are hidden as well; valid ones are only used to restore a broken sidecar
		if (shortener.isSidecar(storedName) || ConflictName.parse(storedName, shortener::isSidecar) != null) {
			return null;
		}
		try {
			if (shortener.isShortened(storedName)) {
				var name = verifiedName(storedDir, storedName);
				return name == null ? null : new VfsDirectoryEntry(name, storedEntry.metadata());
			}
			var conflict = ConflictName.parse(storedName, shortener::isShortened);
			if (conflict != null) {
				var name = resolveConflictingNode(storedDir, storedName, conflict, createdNodes);
				return name == null ? null : new VfsDirectoryEntry(name, storedEntry.metadata());
			}
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
		if (!isCanonical(storedName)) {
			LOG.warn("Skipping {}, its name is reserved or exceeds the shortening threshold", join(storedDir, storedName));
			return null;
		}
		return storedEntry;
	}

	// every name has exactly one stored representation: a name that would have been shortened, or that is reserved, is invalid when found as is
	private boolean isCanonical(String storedName) {
		try {
			return shortener.shorten(storedName) == null;
		} catch (IllegalArgumentException _) {
			return false;
		}
	}

	// the full name of a shortened node, restoring its sidecar from a conflicting copy if necessary; null if the node cannot be mapped back
	private @Nullable String verifiedName(String storedDir, String shortenedName) throws IOException {
		var name = readSidecar(storedDir, shortenedName);
		if (name == null && resolveConflicts) {
			name = restoreSidecar(storedDir, shortenedName);
		}
		if (name == null) {
			LOG.warn("Skipping {}, its sidecar is missing or invalid", join(storedDir, shortenedName));
		}
		return name;
	}

	// --- conflict resolution ---

	/*
	 * Turns a conflicting copy "H.shortened (x).uvf" of a node with full name N into a regular shortened node: its full name N' is N with the conflict suffix inserted, so the upper
	 * layer sees an ordinary conflicting copy and resolves it with its own knowledge. The sidecar of N' is written first, then the copy is moved atomically; H.original.uvf is left
	 * alone, as it still belongs to H.shortened.uvf.
	 */
	private @Nullable String resolveConflictingNode(String storedDir, String storedName, ConflictName conflict, Set<String> createdNodes) throws IOException {
		var copyPath = join(storedDir, storedName);
		if (!resolveConflicts) {
			LOG.info("Skipping conflicting copy {}, conflict resolution is disabled", copyPath);
			return null;
		}
		// the new sidecar is derived from the stored one, never from the cache: a cached name says nothing about whether its sidecar still exists
		var originalName = loadSidecar(storedDir, conflict.canonicalName());
		if (originalName == null) {
			originalName = restoreSidecar(storedDir, conflict.canonicalName());
		}
		if (originalName == null) {
			LOG.warn("Skipping conflicting copy {}, the sidecar it shares with {} is missing or invalid", copyPath, join(storedDir, conflict.canonicalName()));
			return null;
		}
		var name = conflict.applyTo(originalName);
		if (name.getBytes(StandardCharsets.UTF_8).length > MAX_NAME_LENGTH) {
			LOG.warn("Skipping conflicting copy {}, its name would exceed {} bytes", copyPath, MAX_NAME_LENGTH);
			return null;
		}
		var node = new StoredNode(storedDir, name, shortener.shorten(name)); // longer than the original name, hence always shortened
		try {
			writeSidecar(node);
			delegate.rename(copyPath, node.path(), false);
		} catch (FileAlreadyExistsException _) {
			LOG.warn("Skipping conflicting copy {}, its resolved name is taken by {}", copyPath, node.path());
			return null;
		} catch (IOException | UnsupportedOperationException e) { // e.g. read-only storage
			LOG.warn("Skipping conflicting copy {}, it cannot be resolved: {}", copyPath, e.getMessage());
			return null;
		}
		LOG.info("Resolved conflicting copy {} as {}", copyPath, node.path());
		createdNodes.add(node.storedName());
		return name;
	}

	// replaces a missing or invalid sidecar by a valid conflicting copy of it, returning the full name, or null if there is none
	private @Nullable String restoreSidecar(String storedDir, String shortenedName) throws IOException {
		var sidecarName = shortener.sidecarFile(shortenedName);
		for (var copyName : conflictingCopies(storedDir, sidecarName::equals)) {
			var copyPath = join(storedDir, copyName);
			var name = verify(shortenedName, readAtMost(copyPath, MAX_NAME_LENGTH + 1));
			if (name != null) {
				try {
					delegate.rename(copyPath, join(storedDir, sidecarName), true);
					LOG.info("Restored sidecar {} from conflicting copy {}", join(storedDir, sidecarName), copyPath);
				} catch (IOException | UnsupportedOperationException e) { // e.g. read-only storage; the name is still known for this listing
					LOG.warn("Failed to restore sidecar {} from conflicting copy {}: {}", join(storedDir, sidecarName), copyPath, e.getMessage());
				}
				sidecarCache.put(shortenedName, name);
				return name;
			}
		}
		return null;
	}

	// names of the entries in a stored directory that are conflicting copies of a name accepted by isCanonical
	private List<String> conflictingCopies(String storedDir, Predicate<String> isCanonical) throws IOException {
		try (var entries = delegate.openDirectory(storedDir)) {
			var copies = new ArrayList<String>();
			for (var entry : entries) {
				if (ConflictName.parse(entry.name(), isCanonical) != null) {
					copies.add(entry.name());
				}
			}
			return copies;
		} catch (UncheckedIOException e) {
			throw e.getCause();
		}
	}

	// --- node operations ---

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
		deleteSidecar(node);
	}

	@Override
	public void rename(String sourcePath, String targetPath, boolean replaceExisting) throws IOException {
		var source = resolve(sourcePath);
		var target = resolve(targetPath);
		writeSidecar(target);
		delegate.rename(source.path(), target.path(), replaceExisting); // the node moves atomically
		boolean sharesSidecar = source.shortened() != null && target.shortened() != null && source.sidecarPath().equals(target.sidecarPath());
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
				storedPath = join(storedPath, storedNode(path, storedPath, name).storedName());
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
		return storedNode(path, storedPath(path.substring(0, separator)), name);
	}

	private StoredNode storedNode(String path, String storedParent, String name) throws IOException {
		if (name.getBytes(StandardCharsets.UTF_8).length > MAX_NAME_LENGTH) {
			throw new FileSystemException(path, null, "File name too long");
		}
		try {
			return new StoredNode(storedParent, name, shortener.shorten(name));
		} catch (IllegalArgumentException _) {
			throw new FileSystemException(path, null, "Reserved file name");
		}
	}

	private static String join(String parent, String name) {
		return "/".equals(parent) ? "/" + name : parent + "/" + name;
	}

	// --- sidecar I/O ---

	// written before the node; an existing sidecar is left alone unless it is invalid, so an interruption never damages another node's sidecar
	private void writeSidecar(StoredNode node) throws IOException {
		var shortened = node.shortened();
		if (shortened == null) {
			return;
		}
		try {
			writeAll(node.sidecarPath(), Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW), shortened.sidecarContents());
		} catch (FileAlreadyExistsException _) {
			if (loadSidecar(node.parentPath(), shortened.shortenedName()) == null) {
				writeAll(node.sidecarPath(), Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING), shortened.sidecarContents());
			}
		}
	}

	// deleted after the node; conflicting copies sharing the sidecar are resolved by the listing that precedes every delete or rename, so it belongs to this node alone
	private void deleteSidecar(StoredNode node) throws IOException {
		if (node.shortened() == null) {
			return;
		}
		try {
			delegate.deleteFile(node.sidecarPath());
		} catch (NoSuchFileException _) {
			// orphaned node, nothing to do
		}
	}

	// the verified full name, preferably from the cache, or null if the sidecar is missing or invalid; reading the cache never causes writes
	private @Nullable String readSidecar(String storedDir, String shortenedName) throws IOException {
		var cached = sidecarCache.get(shortenedName);
		return cached != null ? cached : loadSidecar(storedDir, shortenedName);
	}

	// the verified full name as currently stored, bypassing the cache; every decision that writes to the delegate relies on this
	private @Nullable String loadSidecar(String storedDir, String shortenedName) throws IOException {
		byte[] contents;
		try {
			contents = readAtMost(join(storedDir, shortener.sidecarFile(shortenedName)), MAX_NAME_LENGTH + 1);
		} catch (NoSuchFileException _) {
			return null;
		}
		var name = verify(shortenedName, contents);
		if (name != null) {
			sidecarCache.put(shortenedName, name);
		}
		return name;
	}

	private @Nullable String verify(String shortenedName, byte[] sidecarContents) {
		if (sidecarContents.length > MAX_NAME_LENGTH) {
			return null;
		}
		try {
			return shortener.unshorten(shortenedName, sidecarContents);
		} catch (AuthenticationFailedException e) {
			LOG.debug("Invalid sidecar contents for {}: {}", shortenedName, e.getMessage());
			return null;
		}
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

	// a node as stored on the delegate; shortened is null if the name is stored as is
	private record StoredNode(String parentPath, String name, @Nullable ShortenedVaultNode shortened) {

		String storedName() {
			return shortened == null ? name : shortened.shortenedName();
		}

		String path() {
			return join(parentPath, storedName());
		}

		String sidecarPath() {
			if (shortened == null) {
				throw new IllegalStateException("Not shortened: " + path());
			}
			return join(parentPath, shortened.sidecarFile());
		}
	}
}
