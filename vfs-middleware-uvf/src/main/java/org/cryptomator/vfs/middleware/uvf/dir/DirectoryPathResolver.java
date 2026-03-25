package org.cryptomator.vfs.middleware.uvf.dir;

import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.DirectoryMetadata;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Set;

import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;

/**
 * Resolves cleartext VFS paths to ciphertext paths on the delegate filesystem.
 * <p>
 * Each cleartext directory maps to a flat {@code d/XX/YYYYYY...} path on the delegate,
 * determined by hashing its {@link DirectoryMetadata}. File and directory names are
 * encrypted using the parent directory's metadata as context.
 */
public final class DirectoryPathResolver {

	private static final String DIR_METADATA_FILE = "dir.uvf";

	private final VfsFileSystem delegate;
	private final DirectoryContentCryptor dirCryptor;
	private final DirectoryMetadata rootMetadata;

	public DirectoryPathResolver(VfsFileSystem delegate, DirectoryContentCryptor dirCryptor) {
		this.delegate = delegate;
		this.dirCryptor = dirCryptor;
		this.rootMetadata = dirCryptor.rootDirectoryMetadata();
	}

	/**
	 * Result of resolving a cleartext path.
	 *
	 * @param ciphertextPath the full ciphertext path on the delegate filesystem
	 * @param parentMetadata the directory metadata of the parent directory (used for name encryption)
	 */
	public record ResolvedPath(String ciphertextPath, DirectoryMetadata parentMetadata) {}

	/**
	 * Resolves a cleartext path to its ciphertext equivalent on the delegate filesystem.
	 * <p>
	 * For a path like {@code /foo/bar/baz.txt}, this:
	 * <ol>
	 *   <li>Gets the root directory's ciphertext path via {@code dirPath(rootMetadata)}</li>
	 *   <li>Encrypts "foo" using the root metadata, reads foo's {@code dir.uvf} to get its metadata</li>
	 *   <li>Encrypts "bar" using foo's metadata, reads bar's {@code dir.uvf}</li>
	 *   <li>Encrypts "baz.txt" using bar's metadata</li>
	 * </ol>
	 *
	 * @param cleartextPath absolute cleartext path (e.g., {@code /foo/bar/baz.txt})
	 * @return the resolved ciphertext path and parent metadata
	 * @throws IOException if reading directory metadata fails
	 */
	public ResolvedPath resolve(String cleartextPath) throws IOException {
		String[] components = splitPath(cleartextPath);
		if (components.length == 0) {
			// root directory
			String ciphertextDirPath = "/" + dirCryptor.dirPath(rootMetadata);
			return new ResolvedPath(ciphertextDirPath, rootMetadata);
		}

		DirectoryMetadata currentMetadata = rootMetadata;
		String currentCiphertextDir = "/" + dirCryptor.dirPath(rootMetadata);

		// resolve all components except the last one as directories
		for (int i = 0; i < components.length - 1; i++) {
			String encryptedName = dirCryptor.fileNameEncryptor(currentMetadata).encrypt(components[i]);
			String childCiphertextPath = currentCiphertextDir + "/" + encryptedName;
			currentMetadata = readDirectoryMetadata(childCiphertextPath);
			currentCiphertextDir = "/" + dirCryptor.dirPath(currentMetadata);
		}

		// resolve the last component (may be file or directory)
		String lastComponent = components[components.length - 1];
		String encryptedName = dirCryptor.fileNameEncryptor(currentMetadata).encrypt(lastComponent);
		String ciphertextPath = currentCiphertextDir + "/" + encryptedName;
		return new ResolvedPath(ciphertextPath, currentMetadata);
	}

	/**
	 * Resolves a cleartext directory path and returns its directory metadata.
	 *
	 * @param cleartextPath absolute cleartext directory path
	 * @return the directory metadata for the given path
	 * @throws IOException if reading directory metadata fails
	 */
	public DirectoryMetadata resolveDirectoryMetadata(String cleartextPath) throws IOException {
		String[] components = splitPath(cleartextPath);
		if (components.length == 0) {
			return rootMetadata;
		}

		DirectoryMetadata currentMetadata = rootMetadata;
		String currentCiphertextDir = "/" + dirCryptor.dirPath(rootMetadata);

		for (String component : components) {
			String encryptedName = dirCryptor.fileNameEncryptor(currentMetadata).encrypt(component);
			String childCiphertextPath = currentCiphertextDir + "/" + encryptedName;
			currentMetadata = readDirectoryMetadata(childCiphertextPath);
			currentCiphertextDir = "/" + dirCryptor.dirPath(currentMetadata);
		}

		return currentMetadata;
	}

	/**
	 * Resolves a cleartext directory path to its ciphertext content directory
	 * (the {@code d/XX/YYYYYY...} path where the directory's children are stored).
	 *
	 * @param cleartextPath absolute cleartext directory path
	 * @return the ciphertext content directory path on the delegate
	 * @throws IOException if reading directory metadata fails
	 */
	public String resolveContentDir(String cleartextPath) throws IOException {
		DirectoryMetadata metadata = resolveDirectoryMetadata(cleartextPath);
		return "/" + dirCryptor.dirPath(metadata);
	}

	/**
	 * Writes encrypted directory metadata ({@code dir.uvf}) for a new directory.
	 *
	 * @param ciphertextDirEntryPath the ciphertext path of the directory entry (the encrypted name in the parent)
	 * @param metadata               the new directory's metadata to encrypt and write
	 * @throws IOException if writing fails
	 */
	public void writeDirectoryMetadata(String ciphertextDirEntryPath, DirectoryMetadata metadata) throws IOException {
		byte[] encrypted = dirCryptor.encryptDirectoryMetadata(metadata);
		String dirUvfPath = ciphertextDirEntryPath + "/" + DIR_METADATA_FILE;
		try (VfsFile file = delegate.createFile(dirUvfPath, Set.of(WRITE, CREATE_NEW), Set.of())) {
			file.write(ByteBuffer.wrap(encrypted), 0);
		}
	}

	/**
	 * Creates a new {@link DirectoryMetadata} for a new directory.
	 */
	public DirectoryMetadata newDirectoryMetadata() {
		return dirCryptor.newDirectoryMetadata();
	}

	/**
	 * Returns the {@link DirectoryContentCryptor} for name encryption/decryption.
	 */
	public DirectoryContentCryptor dirCryptor() {
		return dirCryptor;
	}

	private DirectoryMetadata readDirectoryMetadata(String ciphertextDirEntryPath) throws IOException {
		String dirUvfPath = ciphertextDirEntryPath + "/" + DIR_METADATA_FILE;
		try (VfsFile file = delegate.openFile(dirUvfPath, Set.of(READ))) {
			// dir.uvf is always 128 bytes
			ByteBuffer buf = ByteBuffer.allocate(128);
			int totalRead = 0;
			int read;
			while (buf.hasRemaining() && (read = file.read(buf, totalRead)) > 0) {
				totalRead += read;
			}
			buf.flip();
			byte[] ciphertext = new byte[buf.remaining()];
			buf.get(ciphertext);
			return dirCryptor.decryptDirectoryMetadata(ciphertext);
		}
	}

	private static String[] splitPath(String path) {
		if (path.isEmpty() || "/".equals(path)) {
			return new String[0];
		}
		String normalized = path;
		if (normalized.startsWith("/")) {
			normalized = normalized.substring(1);
		}
		if (normalized.endsWith("/")) {
			normalized = normalized.substring(0, normalized.length() - 1);
		}
		if (normalized.isEmpty()) {
			return new String[0];
		}
		return normalized.split("/");
	}
}
