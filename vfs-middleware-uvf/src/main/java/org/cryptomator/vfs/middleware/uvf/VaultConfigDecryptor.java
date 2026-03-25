package org.cryptomator.vfs.middleware.uvf;

import java.io.IOException;

/**
 * Callback to decrypt the JWE content of vault.uvf.
 */
@FunctionalInterface
public interface VaultConfigDecryptor {

	/**
	 * Decrypts the raw JWE bytes and returns the decrypted JSON payload.
	 *
	 * @param jweData the raw bytes of the vault.uvf file
	 * @return the decrypted JSON payload string
	 * @throws IOException if decryption fails
	 */
	String decrypt(byte[] jweData) throws IOException;
}
