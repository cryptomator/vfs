package org.cryptomator.vfs.middleware.uvf.vault;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.middleware.uvf.VaultConfigDecryptor;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Set;

import static java.nio.file.StandardOpenOption.READ;

/**
 * Reads the {@code vault.uvf} file from the delegate filesystem and initializes a {@link Cryptor}.
 */
public final class VaultConfig {

	private static final String VAULT_FILE_PATH = "/vault.uvf";

	private final Cryptor cryptor;

	/**
	 * Loads the vault configuration from the delegate filesystem.
	 *
	 * @param delegate       the underlying filesystem containing the encrypted vault
	 * @param jweDecryptor   callback that decrypts the JWE content of vault.uvf and returns the decrypted JSON payload
	 * @param csprng         secure random for cryptographic operations
	 * @throws IOException if reading vault.uvf fails
	 */
	@SuppressWarnings("deprecation") // UVF_DRAFT until cryptolib stabilizes the scheme
	public VaultConfig(VfsFileSystem delegate, VaultConfigDecryptor jweDecryptor, SecureRandom csprng) throws IOException {
		byte[] jweBytes = readVaultFile(delegate);
		String decryptedPayload = jweDecryptor.decrypt(jweBytes);
		UVFMasterkey masterkey = UVFMasterkey.fromDecryptedPayload(decryptedPayload);
		this.cryptor = CryptorProvider.forScheme(CryptorProvider.Scheme.UVF_DRAFT).provide(masterkey, csprng);
	}

	public Cryptor cryptor() {
		return cryptor;
	}

	private static byte[] readVaultFile(VfsFileSystem delegate) throws IOException {
		try (VfsFile file = delegate.openFile(VAULT_FILE_PATH, Set.of(READ))) {
			// vault.uvf is a small JSON file, 64 KB is more than enough
			ByteBuffer buf = ByteBuffer.allocate(64 * 1024);
			int totalRead = 0;
			int read;
			while ((read = file.read(buf, totalRead)) > 0) {
				totalRead += read;
			}
			buf.flip();
			byte[] result = new byte[buf.remaining()];
			buf.get(result);
			return result;
		}
	}
}
