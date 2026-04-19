package org.cryptomator.vfs.middleware.uvf;

import java.io.IOException;

/**
 * Callback to encrypt a vault configuration payload into a JWE for vault.uvf.
 */
@FunctionalInterface
public interface VaultConfigEncryptor {

	/**
	 * Encrypts the JSON payload and returns the raw JWE bytes.
	 *
	 * @param payload the JSON payload string to encrypt
	 * @return the JWE bytes (JSON serialization)
	 * @throws IOException if encryption fails
	 */
	byte[] encrypt(String payload) throws IOException;
}
