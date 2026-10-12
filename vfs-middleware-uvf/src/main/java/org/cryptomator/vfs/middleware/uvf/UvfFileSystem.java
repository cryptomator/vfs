package org.cryptomator.vfs.middleware.uvf;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.DirectoryMetadata;
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
import org.cryptomator.vfs.middleware.uvf.vault.VaultConfig;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.file.AccessMode;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * A {@link VfsFileSystem} decorator that encrypts writes and decrypts reads
 * according to the Universal Vault Format specification.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format">UVF Spec</a>
 */
public final class UvfFileSystem implements VfsFileSystem {

	private static final String DIR_METADATA_FILE = "dir.uvf";

	private final VfsFileSystem delegate;
	private final Cryptor cryptor;
	private final DirectoryPathResolver pathResolver;
	private final VfsCapabilities capabilities;

	private UvfFileSystem(VfsFileSystem delegate, Cryptor cryptor, DirectoryPathResolver pathResolver) {
		this.delegate = delegate;
		this.cryptor = cryptor;
		this.pathResolver = pathResolver;
		// encrypted names are compared exactly, symlinks and xattrs are not yet part of this middleware
		this.capabilities = new VfsCapabilities(true, false, false, 0);
	}

	/**
	 * Creates a new UVF middleware filesystem.
	 * <p>
	 * Reads and decrypts {@code vault.uvf}, initializes the cryptor, and verifies
	 * that the ciphertext root directory exists on the delegate filesystem.
	 *
	 * @param delegate              the underlying filesystem storing ciphertext
	 * @param vaultConfigDecryptor  callback to decrypt the vault.uvf JWE
	 * @param csprng                secure random for cryptographic operations
	 * @return a ready-to-use UVF filesystem
	 * @throws IOException if the vault configuration cannot be read, decrypted, or the vault structure is broken
	 */
	public static UvfFileSystem create(VfsFileSystem delegate, VaultConfigDecryptor vaultConfigDecryptor, SecureRandom csprng) throws IOException {
		var vaultConfig = new VaultConfig(delegate, vaultConfigDecryptor, csprng);
		var cryptor = vaultConfig.cryptor();
		var pathResolver = new DirectoryPathResolver(delegate, cryptor.directoryContentCryptor());

		// verify ciphertext root directory exists
		String rootContentDir = pathResolver.resolveContentDir("/");
		try {
			delegate.checkAccess(rootContentDir, Set.of(AccessMode.READ));
		} catch (IOException e) {
			throw new IOException("Vault structure is broken: ciphertext root directory not found at " + rootContentDir, e);
		}

		return new UvfFileSystem(delegate, cryptor, pathResolver);
	}

	@Override
	public VfsCapabilities capabilities() {
		return capabilities;
	}

	@Override
	public VfsNodeMetadata readNodeMetadata(String path) throws IOException {
		var resolved = pathResolver.resolve(path);
		return toCleartextMetadata(delegate.readNodeMetadata(resolved.ciphertextPath()));
	}

	@Override
	public VfsMetadata readVfsMetadata(String path) throws IOException {
		var resolved = pathResolver.resolve(path);
		return delegate.readVfsMetadata(resolved.ciphertextPath());
	}

	@Override
	public void checkAccess(String path, Set<AccessMode> accessModes) throws IOException {
		var resolved = pathResolver.resolve(path);
		delegate.checkAccess(resolved.ciphertextPath(), accessModes);
	}

	@Override
	public VfsDirectoryStream openDirectory(String path) throws IOException {
		String ciphertextContentDir = pathResolver.resolveContentDir(path);
		DirectoryMetadata dirMetadata = pathResolver.resolveDirectoryMetadata(path);
		var decryptor = pathResolver.dirCryptor().fileNameDecryptor(dirMetadata);
		var ciphertextStream = delegate.openDirectory(ciphertextContentDir);
		return new VfsDirectoryStream() {

			@Override
			public Iterator<VfsDirectoryEntry> iterator() {
				var ciphertextEntries = ciphertextStream.iterator();
				return new Iterator<>() {

					private @Nullable VfsDirectoryEntry next;

					@Override
					public boolean hasNext() {
						while (next == null && ciphertextEntries.hasNext()) {
							var ciphertextEntry = ciphertextEntries.next();
							if (DIR_METADATA_FILE.equals(ciphertextEntry.name())) {
								continue; // skip dir.uvf metadata files
							}
							try {
								String cleartextName = decryptor.decrypt(ciphertextEntry.name());
								next = new VfsDirectoryEntry(cleartextName, toCleartextMetadata(ciphertextEntry.metadata()));
							} catch (IllegalArgumentException e) {
								// skip entries that can't be decrypted (e.g., non-.uvf files)
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
				ciphertextStream.close();
			}
		};
	}

	@Override
	public void createDirectory(String path, Set<PosixFilePermission> permissions) throws IOException {
		var resolved = pathResolver.resolve(path);
		DirectoryMetadata newMetadata = pathResolver.newDirectoryMetadata();

		// create the content directory (d/XX/YYYYYY...) first, an orphaned content dir is harmless whereas a dangling entry is not
		String ciphertextContentDir = "/" + pathResolver.dirCryptor().dirPath(newMetadata);
		createDirectoryIfMissing(parentOf(ciphertextContentDir), permissions);
		delegate.createDirectory(ciphertextContentDir, permissions);

		// create the encrypted directory entry in the parent's content dir and write dir.uvf into it
		try {
			delegate.createDirectory(resolved.ciphertextPath(), permissions);
			pathResolver.writeDirectoryMetadata(resolved.ciphertextPath(), newMetadata);
		} catch (IOException e) {
			try {
				delegate.deleteDirectory(ciphertextContentDir);
			} catch (IOException suppressed) {
				e.addSuppressed(suppressed);
			}
			throw e;
		}
	}

	private void createDirectoryIfMissing(String ciphertextPath, Set<PosixFilePermission> permissions) throws IOException {
		try {
			delegate.createDirectory(ciphertextPath, permissions);
		} catch (FileAlreadyExistsException e) {
			// shard directory exists, nothing to do
		}
	}

	private static String parentOf(String path) {
		int lastSeparator = path.lastIndexOf('/');
		return lastSeparator <= 0 ? "/" : path.substring(0, lastSeparator);
	}

	@Override
	public void deleteDirectory(String path) throws IOException {
		// first delete the content directory, this fails if the cleartext directory is not empty
		String ciphertextContentDir = pathResolver.resolveContentDir(path);
		delegate.deleteDirectory(ciphertextContentDir);

		// then delete the directory entry (including dir.uvf)
		var resolved = pathResolver.resolve(path);
		delegate.deleteFile(resolved.ciphertextPath() + "/" + DIR_METADATA_FILE);
		delegate.deleteDirectory(resolved.ciphertextPath());
	}

	@Override
	public VfsFile openFile(String path, Set<StandardOpenOption> options) throws IOException {
		var resolved = pathResolver.resolve(path);
		var ciphertextFile = delegate.openFile(resolved.ciphertextPath(), ciphertextOptions(options));
		if (options.contains(StandardOpenOption.TRUNCATE_EXISTING)) {
			return UvfVfsFile.createNew(ciphertextFile, cryptor.fileHeaderCryptor(), cryptor.fileContentCryptor());
		} else {
			return UvfVfsFile.openExisting(ciphertextFile, cryptor.fileHeaderCryptor(), cryptor.fileContentCryptor());
		}
	}

	@Override
	public VfsFile createFile(String path, Set<StandardOpenOption> options, Set<PosixFilePermission> permissions) throws IOException {
		var resolved = pathResolver.resolve(path);
		boolean existed = exists(resolved.ciphertextPath());
		var ciphertextFile = delegate.createFile(resolved.ciphertextPath(), ciphertextOptions(options), permissions);
		if (!existed || options.contains(StandardOpenOption.TRUNCATE_EXISTING)) {
			return UvfVfsFile.createNew(ciphertextFile, cryptor.fileHeaderCryptor(), cryptor.fileContentCryptor());
		} else {
			return UvfVfsFile.openExisting(ciphertextFile, cryptor.fileHeaderCryptor(), cryptor.fileContentCryptor());
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

	private boolean exists(String ciphertextPath) throws IOException {
		try {
			delegate.checkAccess(ciphertextPath, Set.of());
			return true;
		} catch (NoSuchFileException e) {
			return false;
		}
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
		delegate.deleteFile(resolved.ciphertextPath());
	}

	@Override
	public void rename(String sourcePath, String targetPath, boolean replaceExisting) throws IOException {
		var resolvedSource = pathResolver.resolve(sourcePath);
		var resolvedTarget = pathResolver.resolve(targetPath);
		if (replaceExisting && isDirectory(resolvedTarget.ciphertextPath())) {
			// a ciphertext directory entry always contains dir.uvf, so the delegate can never replace it; remove the (empty) cleartext directory first
			if (!isDirectory(resolvedSource.ciphertextPath())) {
				throw new FileSystemException(sourcePath, targetPath, "Is a directory");
			}
			deleteDirectory(targetPath);
		}
		delegate.rename(resolvedSource.ciphertextPath(), resolvedTarget.ciphertextPath(), replaceExisting);
	}

	private boolean isDirectory(String ciphertextPath) throws IOException {
		try {
			return delegate.readNodeMetadata(ciphertextPath).type() == VfsNodeType.DIRECTORY;
		} catch (NoSuchFileException e) {
			return false;
		}
	}

	@Override
	public void setTimes(String path, VfsTimes times) throws IOException {
		var resolved = pathResolver.resolve(path);
		delegate.setTimes(resolved.ciphertextPath(), times);
	}

	@Override
	public void setPermissions(String path, Set<PosixFilePermission> permissions) throws IOException {
		var resolved = pathResolver.resolve(path);
		delegate.setPermissions(resolved.ciphertextPath(), permissions);
	}

	private VfsNodeMetadata toCleartextMetadata(VfsNodeMetadata ciphertextMetadata) {
		return UvfVfsFile.toCleartextMetadata(ciphertextMetadata, cryptor.fileHeaderCryptor().headerSize(), cryptor.fileContentCryptor());
	}
}
