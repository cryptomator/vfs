package org.cryptomator.vfs.middleware.uvf;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.LockedVault;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultReader;
import org.cryptomator.cryptolib.api.VaultWriter;
import org.cryptomator.vfs.api.VfsCapabilities;
import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsDirectoryStream;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsMetadata;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;
import org.cryptomator.vfs.middleware.uvf.content.UvfVfsFile;
import org.cryptomator.vfs.middleware.uvf.dir.DirectoryPathResolver;
import org.cryptomator.vfs.middleware.uvf.dir.DirectoryPathResolver.ResolvedPath;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotLinkException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * A {@link VfsFileSystem} decorator that encrypts writes and decrypts reads according to the Universal Vault Format specification.
 * <p>
 * cryptolib does all cryptography and knows the vault layout; this class maps VFS operations onto it and performs the I/O on the delegate.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format">UVF Spec</a>
 */
public final class UvfFileSystem implements VfsFileSystem, AutoCloseable {

	private static final String VAULT_CONFIG_PATH = "/vault.uvf";
	private static final Set<PosixFilePermission> DEFAULT_PERMISSIONS = Set.of(); // let the delegate apply its defaults

	private final VfsFileSystem delegate;
	private final UvfUnlockedVault vault;
	private final DirectoryPathResolver pathResolver;
	private final VaultReader reader;
	private final VfsCapabilities capabilities;

	UvfFileSystem(VfsFileSystem delegate, UvfUnlockedVault vault) {
		this.delegate = delegate;
		this.vault = vault;
		this.reader = relPath -> readAll(delegate, "/" + relPath);
		this.pathResolver = new DirectoryPathResolver(vault, reader);
		// encrypted names are compared exactly; xattrs are not yet part of this middleware
		this.capabilities = new VfsCapabilities(true, true, false, 0);
	}

	/**
	 * Opens an existing vault stored on the delegate filesystem.
	 *
	 * @param delegate the underlying filesystem storing the ciphertext, with {@code vault.uvf} in its root
	 * @param unlocker callback that unlocks the parsed {@code vault.uvf}
	 * @return a ready-to-use UVF filesystem that must be closed to destroy its key material
	 * @throws IOException if the vault configuration cannot be read or parsed, or the vault structure is broken
	 * @throws org.cryptomator.cryptolib.api.VaultKeyInvalidException if the unlocker's secret is wrong
	 */
	public static UvfFileSystem create(VfsFileSystem delegate, VaultUnlocker unlocker) throws IOException {
		LockedVault lockedVault;
		try {
			lockedVault = LockedVault.parse(readAll(delegate, VAULT_CONFIG_PATH));
		} catch (VaultConfigLoadException e) {
			throw new IOException("Invalid vault configuration " + VAULT_CONFIG_PATH, e);
		}
		if (!(lockedVault instanceof UvfLockedVault uvfLockedVault)) {
			throw new IOException("Not a UVF vault, found " + lockedVault.configFileName());
		}
		var fileSystem = new UvfFileSystem(delegate, unlocker.unlock(uvfLockedVault));
		var rootContentDir = DirectoryPathResolver.contentDirPath(fileSystem.vault.rootDirectory());
		try {
			delegate.checkAccess(rootContentDir, Set.of(AccessMode.READ));
		} catch (IOException e) {
			fileSystem.close();
			throw new IOException("Vault structure is broken: ciphertext root directory not found at " + rootContentDir, e);
		}
		return fileSystem;
	}

	/**
	 * Creates a new vault on the delegate filesystem: writes {@code vault.uvf} and the root content directory, then opens the vault.
	 * <p>
	 * The vault must be fully configured, i.e. {@link UvfUnlockedVault#setPassword(CharSequence)} or {@link UvfUnlockedVault#setMemberKey(javax.crypto.SecretKey)}
	 * and {@link UvfUnlockedVault#setRecoveryKey(java.security.interfaces.ECPublicKey)} must have been called. Ownership of {@code vault} passes to the returned
	 * filesystem, which destroys it on {@link #close()}, also if initialization fails.
	 *
	 * @param delegate the underlying filesystem that will store the ciphertext
	 * @param vault a freshly created, configured vault, e.g. from {@link UvfUnlockedVault#create(java.security.SecureRandom)}
	 * @return a ready-to-use UVF filesystem that must be closed to destroy its key material
	 * @throws java.nio.file.FileAlreadyExistsException if the delegate already holds a {@code vault.uvf}
	 * @throws IOException if the vault files cannot be written
	 */
	public static UvfFileSystem initialize(VfsFileSystem delegate, UvfUnlockedVault vault) throws IOException {
		var fileSystem = new UvfFileSystem(delegate, vault);
		try {
			try (var configFile = delegate.createFile(VAULT_CONFIG_PATH, Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW), DEFAULT_PERMISSIONS)) {
				var buf = ByteBuffer.wrap(vault.serializeConfig());
				while (buf.hasRemaining()) {
					configFile.write(buf, buf.position());
				}
			}
			vault.rootDirectory().writeMetadataBackup(fileSystem.writer(DEFAULT_PERMISSIONS));
			return fileSystem;
		} catch (IOException e) {
			fileSystem.close();
			throw e;
		}
	}

	@Override
	public VfsCapabilities capabilities() {
		return capabilities;
	}

	@Override
	public VfsNodeMetadata readNodeMetadata(String path) throws IOException {
		if (DirectoryPathResolver.isRoot(path)) {
			return delegate.readNodeMetadata(DirectoryPathResolver.contentDirPath(vault.rootDirectory()));
		}
		var resolved = pathResolver.resolve(path);
		return toCleartextMetadata(resolved, delegate.readNodeMetadata(resolved.entryPath()));
	}

	@Override
	public VfsMetadata readVfsMetadata(String path) throws IOException {
		var ciphertextMetadata = delegate.readVfsMetadata("/");
		return new VfsMetadata(
				ciphertextMetadata.blockSize(),
				ciphertextMetadata.totalBlocks(),
				ciphertextMetadata.freeBlocks(),
				ciphertextMetadata.availableBlocks(),
				vault.maxCleartextNameLength(Math.toIntExact(ciphertextMetadata.maxNameLength()))
		);
	}

	@Override
	public void checkAccess(String path, Set<AccessMode> accessModes) throws IOException {
		delegate.checkAccess(entryOrRootPath(path), accessModes);
	}

	@Override
	public VfsDirectoryStream openDirectory(String path) throws IOException {
		var directory = pathResolver.resolveDirectory(path);
		var ciphertextStream = delegate.openDirectory(DirectoryPathResolver.contentDirPath(directory));
		return new VfsDirectoryStream() {

			@Override
			public Iterator<VfsDirectoryEntry> iterator() {
				var ciphertextEntries = ciphertextStream.iterator();
				return new Iterator<>() {

					private @Nullable VfsDirectoryEntry next;

					@Override
					public boolean hasNext() {
						while (next == null && ciphertextEntries.hasNext()) {
							next = toCleartextEntry(directory, ciphertextEntries.next());
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
				ciphertextStream.close();
			}
		};
	}

	// null for entries that are not vault nodes (e.g. the dir.uvf backup) or cannot be decrypted
	private @Nullable VfsDirectoryEntry toCleartextEntry(VaultDirectory directory, VfsDirectoryEntry ciphertextEntry) {
		try {
			var cleartextName = directory.decryptName(ciphertextEntry.name(), reader);
			var resolved = new ResolvedPath(directory, directory.encryptName(cleartextName));
			return new VfsDirectoryEntry(cleartextName, toCleartextMetadata(resolved, ciphertextEntry.metadata()));
		} catch (IllegalArgumentException | AuthenticationFailedException e) {
			return null;
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	@Override
	public void createDirectory(String path, Set<PosixFilePermission> permissions) throws IOException {
		var resolved = pathResolver.resolve(path);
		var child = vault.newDirectory();

		// create the content directory (d/XX/YYYYYY...) with its metadata backup first, an orphaned content dir is harmless whereas a dangling entry is not
		var backupPath = "/" + child.backupFilePath();
		writeAll(backupPath, child.encryptedMetadataBackup(), permissions);

		// then the encrypted directory entry in the parent's content dir and its dir.uvf
		try {
			delegate.createDirectory(resolved.entryPath(), permissions);
			writeAll(resolved.dirFilePath(), child.encryptedMetadata(), permissions);
		} catch (IOException e) {
			deleteQuietly(e, () -> delegate.deleteDirectory(resolved.entryPath()));
			deleteQuietly(e, () -> delegate.deleteFile(backupPath));
			deleteQuietly(e, () -> delegate.deleteDirectory(DirectoryPathResolver.contentDirPath(child)));
			throw e;
		} finally {
			pathResolver.invalidate(resolved.dirFilePath()); // a lookup racing with a previous delete of the same name must not win
		}
	}

	@Override
	public void deleteDirectory(String path) throws IOException {
		var resolved = pathResolver.resolve(path);
		var directory = directoryOf(resolved);
		var contentDir = DirectoryPathResolver.contentDirPath(directory);
		var backupPath = "/" + directory.backupFilePath();
		var backupName = backupPath.substring(backupPath.lastIndexOf('/') + 1);

		// the content directory only ever holds the metadata backup when the cleartext directory is empty
		try (var entries = delegate.openDirectory(contentDir)) {
			for (var entry : entries) {
				if (!backupName.equals(entry.name())) {
					throw new DirectoryNotEmptyException(path);
				}
			}
		} catch (UncheckedIOException e) {
			throw e.getCause();
		}

		deleteFileIfExists(backupPath);
		delegate.deleteDirectory(contentDir);
		try {
			delegate.deleteFile(resolved.dirFilePath());
		} finally {
			pathResolver.invalidate(resolved.dirFilePath());
		}
		delegate.deleteDirectory(resolved.entryPath());
	}

	@Override
	public VfsFile openFile(String path, Set<StandardOpenOption> options) throws IOException {
		var resolved = pathResolver.resolve(path);
		var ciphertextFile = delegate.openFile(resolved.contentsPath(), ciphertextOptions(options));
		return wrap(ciphertextFile, options);
	}

	@Override
	public VfsFile createFile(String path, Set<StandardOpenOption> options, Set<PosixFilePermission> permissions) throws IOException {
		var resolved = pathResolver.resolve(path);
		var ciphertextFile = delegate.createFile(resolved.contentsPath(), ciphertextOptions(options), permissions);
		return wrap(ciphertextFile, options);
	}

	private VfsFile wrap(VfsFile ciphertextFile, Set<StandardOpenOption> options) throws IOException {
		try {
			if (options.contains(StandardOpenOption.TRUNCATE_EXISTING)) {
				return new UvfVfsFile(ciphertextFile, vault, vault.createFile()); // the delegate truncated the ciphertext, the new header is written on first write
			} else {
				return UvfVfsFile.open(ciphertextFile, vault);
			}
		} catch (IOException e) {
			deleteQuietly(e, ciphertextFile::close);
			throw e;
		}
	}

	// encrypted I/O always needs READ access (header, read-modify-write of partial chunks) and is strictly positional, so APPEND must not leak through
	private static EnumSet<StandardOpenOption> ciphertextOptions(Set<StandardOpenOption> options) {
		var result = EnumSet.noneOf(StandardOpenOption.class);
		result.addAll(options);
		result.add(StandardOpenOption.READ);
		if (result.remove(StandardOpenOption.APPEND)) {
			result.add(StandardOpenOption.WRITE);
		}
		return result;
	}

	@Override
	public void truncate(String path, long size) throws IOException {
		try (var file = openFile(path, Set.of(StandardOpenOption.WRITE))) {
			file.truncate(size);
		}
	}

	@Override
	public void deleteFile(String path) throws IOException {
		var resolved = pathResolver.resolve(path);
		switch (nodeType(resolved, delegate.readNodeMetadata(resolved.entryPath()))) {
			case FILE -> delegate.deleteFile(resolved.contentsPath());
			case SYMBOLIC_LINK -> deleteSymbolicLink(resolved);
			case DIRECTORY -> throw new FileSystemException(path, null, "Is a directory");
		}
	}

	private void deleteSymbolicLink(ResolvedPath resolved) throws IOException {
		delegate.deleteFile(resolved.symlinkFilePath());
		delegate.deleteDirectory(resolved.entryPath());
	}

	@Override
	public void rename(String sourcePath, String targetPath, boolean replaceExisting) throws IOException {
		var source = pathResolver.resolve(sourcePath);
		var target = pathResolver.resolve(targetPath);
		var targetMetadata = replaceExisting ? metadataOrNull(target.entryPath()) : null;
		if (targetMetadata != null && targetMetadata.type() == VfsNodeType.DIRECTORY) {
			// directory and symlink entries are ciphertext directories with content, which the delegate can never replace; remove them first
			switch (nodeType(target, targetMetadata)) {
				case DIRECTORY -> {
					if (nodeType(source, delegate.readNodeMetadata(source.entryPath())) != VfsNodeType.DIRECTORY) {
						throw new FileSystemException(sourcePath, targetPath, "Is a directory");
					}
					deleteDirectory(targetPath);
				}
				case SYMBOLIC_LINK -> deleteSymbolicLink(target);
				case FILE -> throw new AssertionError();
			}
		}
		try {
			delegate.rename(source.entryPath(), target.entryPath(), replaceExisting);
		} finally {
			// a moved directory's dir.uvf lives under the entry and changes its path; its descendants live in content dirs and are unaffected
			pathResolver.invalidate(source.dirFilePath());
		}
	}

	@Override
	public void setTimes(String path, VfsTimes times) throws IOException {
		delegate.setTimes(entryOrRootPath(path), times);
	}

	@Override
	public void setPermissions(String path, Set<PosixFilePermission> permissions) throws IOException {
		delegate.setPermissions(entryOrRootPath(path), permissions);
	}

	@Override
	public String readSymbolicLink(String path) throws IOException {
		var resolved = pathResolver.resolve(path);
		if (nodeType(resolved, delegate.readNodeMetadata(resolved.entryPath())) != VfsNodeType.SYMBOLIC_LINK) {
			throw new NotLinkException(path);
		}
		return symlinkTarget(resolved);
	}

	@Override
	public void createSymbolicLink(String path, String target) throws IOException {
		var resolved = pathResolver.resolve(path);
		if (metadataOrNull(resolved.entryPath()) != null) {
			throw new FileAlreadyExistsException(path);
		}
		resolved.node().createSymlink(target, writer(DEFAULT_PERMISSIONS));
	}

	@Override
	public void close() {
		vault.destroy();
	}

	// --- node type and metadata translation ---

	private String entryOrRootPath(String path) throws IOException {
		if (DirectoryPathResolver.isRoot(path)) {
			return DirectoryPathResolver.contentDirPath(vault.rootDirectory());
		}
		return pathResolver.resolve(path).entryPath();
	}

	// directories and symlinks are both ciphertext directories, the symlink file tells them apart
	private VfsNodeType nodeType(ResolvedPath resolved, VfsNodeMetadata entryMetadata) throws IOException {
		if (entryMetadata.type() != VfsNodeType.DIRECTORY) {
			return VfsNodeType.FILE;
		}
		return metadataOrNull(resolved.symlinkFilePath()) != null ? VfsNodeType.SYMBOLIC_LINK : VfsNodeType.DIRECTORY;
	}

	private VfsNodeMetadata toCleartextMetadata(ResolvedPath resolved, VfsNodeMetadata entryMetadata) throws IOException {
		var type = nodeType(resolved, entryMetadata);
		long size = switch (type) {
			case FILE -> cleartextSize(entryMetadata.size());
			case DIRECTORY -> entryMetadata.size();
			case SYMBOLIC_LINK -> symlinkTarget(resolved).getBytes(StandardCharsets.UTF_8).length;
		};
		return new VfsNodeMetadata(
				type,
				size,
				entryMetadata.fileId(),
				entryMetadata.permissions(),
				entryMetadata.lastModifiedTime(),
				entryMetadata.lastAccessTime(),
				entryMetadata.changeTime(),
				entryMetadata.creationTime()
		);
	}

	private long cleartextSize(long ciphertextSize) throws IOException {
		if (ciphertextSize == 0) {
			return 0; // created but never written, the header is written on the first write
		}
		try {
			return vault.cleartextSize(ciphertextSize);
		} catch (IllegalArgumentException e) {
			throw new IOException("Invalid ciphertext file size " + ciphertextSize, e);
		}
	}

	private VaultDirectory directoryOf(ResolvedPath resolved) throws IOException {
		try {
			return resolved.node().directory(reader);
		} catch (AuthenticationFailedException e) {
			throw new IOException("Unauthentic directory metadata", e);
		}
	}

	private String symlinkTarget(ResolvedPath resolved) throws IOException {
		try {
			return resolved.node().symlinkTarget(reader);
		} catch (AuthenticationFailedException e) {
			throw new IOException("Unauthentic symbolic link", e);
		}
	}

	// --- metadata file I/O on the delegate ---

	private @Nullable VfsNodeMetadata metadataOrNull(String ciphertextPath) throws IOException {
		try {
			return delegate.readNodeMetadata(ciphertextPath);
		} catch (NoSuchFileException e) {
			return null;
		}
	}

	private void deleteFileIfExists(String ciphertextPath) throws IOException {
		try {
			delegate.deleteFile(ciphertextPath);
		} catch (NoSuchFileException e) {
			// nothing to do
		}
	}

	private static byte[] readAll(VfsFileSystem delegate, String ciphertextPath) throws IOException {
		try (var file = delegate.openFile(ciphertextPath, Set.of(StandardOpenOption.READ))) {
			var buf = ByteBuffer.allocate(Math.toIntExact(file.readMetadata().size()));
			while (buf.hasRemaining() && file.read(buf, buf.position()) >= 0) {
				// keep reading
			}
			return Arrays.copyOf(buf.array(), buf.position());
		}
	}

	private VaultWriter writer(Set<PosixFilePermission> directoryPermissions) {
		return (relPath, contents) -> writeAll("/" + relPath, contents, directoryPermissions);
	}

	// creates missing parent directories, as required of a VaultWriter
	private void writeAll(String ciphertextPath, byte[] contents, Set<PosixFilePermission> directoryPermissions) throws IOException {
		createParents(ciphertextPath, directoryPermissions);
		try (var file = delegate.createFile(ciphertextPath, Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING), DEFAULT_PERMISSIONS)) {
			var buf = ByteBuffer.wrap(contents);
			while (buf.hasRemaining()) {
				file.write(buf, buf.position());
			}
		}
	}

	private void createParents(String ciphertextPath, Set<PosixFilePermission> permissions) throws IOException {
		int separator = ciphertextPath.indexOf('/', 1);
		while (separator > 0) {
			var parent = ciphertextPath.substring(0, separator);
			try {
				delegate.createDirectory(parent, permissions);
			} catch (FileAlreadyExistsException e) {
				// exists already
			}
			separator = ciphertextPath.indexOf('/', separator + 1);
		}
	}

	@FunctionalInterface
	private interface IoAction {
		void run() throws IOException;
	}

	private static void deleteQuietly(IOException cause, IoAction action) {
		try {
			action.run();
		} catch (IOException e) {
			cause.addSuppressed(e);
		}
	}
}
