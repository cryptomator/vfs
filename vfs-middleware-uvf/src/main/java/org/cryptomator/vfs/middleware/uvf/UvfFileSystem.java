package org.cryptomator.vfs.middleware.uvf;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.DirectoryMetadata;
import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsMetadata;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;
import org.cryptomator.vfs.middleware.uvf.content.UvfVfsFile;
import org.cryptomator.vfs.middleware.uvf.dir.DirectoryPathResolver;
import org.cryptomator.vfs.middleware.uvf.vault.VaultConfig;

import java.io.IOException;
import java.nio.file.AccessMode;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
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

	private UvfFileSystem(VfsFileSystem delegate, Cryptor cryptor, DirectoryPathResolver pathResolver) {
		this.delegate = delegate;
		this.cryptor = cryptor;
		this.pathResolver = pathResolver;
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
	public VfsNodeMetadata readNodeMetadata(String path) throws IOException {
		var resolved = pathResolver.resolve(path);
		var ciphertextMetadata = delegate.readNodeMetadata(resolved.ciphertextPath());
		if (ciphertextMetadata.type() == VfsNodeType.FILE) {
			long ciphertextPayloadSize = ciphertextMetadata.size() - cryptor.fileHeaderCryptor().headerSize();
			long cleartextSize = ciphertextPayloadSize > 0 ? cryptor.fileContentCryptor().cleartextSize(ciphertextPayloadSize) : 0;
			return new VfsNodeMetadata(ciphertextMetadata.type(), cleartextSize, ciphertextMetadata.permissions(), ciphertextMetadata.lastModifiedTime(), ciphertextMetadata.lastAccessTime(), ciphertextMetadata.creationTime());
		}
		return ciphertextMetadata;
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
	public List<VfsDirectoryEntry> listDirectory(String path) throws IOException {
		String ciphertextContentDir = pathResolver.resolveContentDir(path);
		DirectoryMetadata dirMetadata = pathResolver.resolveDirectoryMetadata(path);
		var decryptor = pathResolver.dirCryptor().fileNameDecryptor(dirMetadata);

		List<VfsDirectoryEntry> result = new ArrayList<>();
		for (var ciphertextEntry : delegate.listDirectory(ciphertextContentDir)) {
			if (DIR_METADATA_FILE.equals(ciphertextEntry.name())) {
				continue; // skip dir.uvf metadata files
			}
			try {
				String cleartextName = decryptor.decrypt(ciphertextEntry.name());
				result.add(new VfsDirectoryEntry(cleartextName, ciphertextEntry.metadata()));
			} catch (IllegalArgumentException e) {
				// skip entries that can't be decrypted (e.g., non-.uvf files)
			}
		}
		return List.copyOf(result);
	}

	@Override
	public void createDirectory(String path, Set<PosixFilePermission> permissions) throws IOException {
		var resolved = pathResolver.resolve(path);

		// create the encrypted directory entry in the parent's content dir
		delegate.createDirectory(resolved.ciphertextPath(), permissions);

		// create new directory metadata and write dir.uvf
		DirectoryMetadata newMetadata = pathResolver.newDirectoryMetadata();
		pathResolver.writeDirectoryMetadata(resolved.ciphertextPath(), newMetadata);

		// create the content directory (d/XX/YYYYYY...)
		String ciphertextContentDir = "/" + pathResolver.dirCryptor().dirPath(newMetadata);
		delegate.createDirectory(ciphertextContentDir, permissions);
	}

	@Override
	public void deleteDirectory(String path) throws IOException {
		// first delete the content directory
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
		var ciphertextOptions = ensureReadable(options);

		boolean fileExists = fileExists(resolved.ciphertextPath());
		var ciphertextFile = delegate.openFile(resolved.ciphertextPath(), ciphertextOptions);
		if (!fileExists && options.contains(StandardOpenOption.CREATE)) {
			return UvfVfsFile.createNew(ciphertextFile, cryptor.fileHeaderCryptor(), cryptor.fileContentCryptor());
		} else {
			return UvfVfsFile.openExisting(ciphertextFile, cryptor.fileHeaderCryptor(), cryptor.fileContentCryptor());
		}
	}

	@Override
	public VfsFile createFile(String path, Set<StandardOpenOption> options, Set<PosixFilePermission> permissions) throws IOException {
		var resolved = pathResolver.resolve(path);
		var ciphertextFile = delegate.createFile(resolved.ciphertextPath(), ensureReadable(options), permissions);
		return UvfVfsFile.createNew(ciphertextFile, cryptor.fileHeaderCryptor(), cryptor.fileContentCryptor());
	}

	/**
	 * Encrypted I/O always needs READ access (to read the header and for read-modify-write on partial chunks).
	 */
	private static EnumSet<StandardOpenOption> ensureReadable(Set<StandardOpenOption> options) {
		var result = EnumSet.copyOf(options);
		result.add(StandardOpenOption.READ);
		return result;
	}

	private boolean fileExists(String ciphertextPath) {
		try {
			delegate.checkAccess(ciphertextPath, Set.of());
			return true;
		} catch (IOException e) {
			return false;
		}
	}

	@Override
	public void truncate(String path, long size) throws IOException {
		var resolved = pathResolver.resolve(path);
		long ciphertextSize = size == 0 ? cryptor.fileHeaderCryptor().headerSize() : cryptor.fileHeaderCryptor().headerSize() + cryptor.fileContentCryptor().ciphertextSize(size);
		delegate.truncate(resolved.ciphertextPath(), ciphertextSize);
	}

	@Override
	public void deleteFile(String path) throws IOException {
		var resolved = pathResolver.resolve(path);
		delegate.deleteFile(resolved.ciphertextPath());
	}

	@Override
	public void rename(String sourcePath, String targetPath) throws IOException {
		var resolvedSource = pathResolver.resolve(sourcePath);
		var resolvedTarget = pathResolver.resolve(targetPath);
		delegate.rename(resolvedSource.ciphertextPath(), resolvedTarget.ciphertextPath());
	}

	@Override
	public void setTimes(String path, VfsTimes times) throws IOException {
		var resolved = pathResolver.resolve(path);
		delegate.setTimes(resolved.ciphertextPath(), times);
	}
}
