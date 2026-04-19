package org.cryptomator.vfs.middleware.uvf.vault;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.UnprotectedHeader;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import com.nimbusds.jose.crypto.PasswordBasedEncrypter;
import org.cryptomator.vfs.middleware.uvf.VaultConfigDecryptor;
import org.cryptomator.vfs.middleware.uvf.VaultConfigEncryptor;

import java.io.IOException;
import java.text.ParseException;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Encrypts and decrypts a {@code vault.uvf} JWE using a password via PBES2-HS512+A256KW.
 * <p>
 * This is intended for testing purposes only and is package-private.
 */
final class VaultConfigWithPbes2 implements VaultConfigDecryptor, VaultConfigEncryptor {

	static final String KID = "org.cryptomator.password.pbes2";
	private static final int SALT_LENGTH = 16;
	private static final int ITERATION_COUNT = 310_000;
	private static final Set<String> DEFERRED_CRITICAL_PARAMS = Set.of("uvf.spec.version");

	private final byte[] password;

	VaultConfigWithPbes2(String password) {
		this.password = password.getBytes(UTF_8);
	}

	@Override
	public String decrypt(byte[] jweData) throws IOException {
		try {
			var jweJson = JWEObjectJSON.parse(new String(jweData, UTF_8));
			var recipient = JweHelper.findRecipient(jweJson, KID);
			return JweHelper.decryptRecipient(jweJson, recipient, new PasswordBasedDecrypter(password, DEFERRED_CRITICAL_PARAMS));
		} catch (ParseException e) {
			throw new IOException("Failed to parse vault.uvf JWE", e);
		} catch (JOSEException e) {
			throw new IOException("Failed to decrypt vault.uvf", e);
		}
	}

	@Override
	public byte[] encrypt(String payload) throws IOException {
		try {
			var recipientHeader = new UnprotectedHeader.Builder()
					.param("kid", KID)
					.build();
			return JweHelper.encryptPayload(JWEAlgorithm.PBES2_HS512_A256KW, payload, new PasswordBasedEncrypter(password, SALT_LENGTH, ITERATION_COUNT), recipientHeader);
		} catch (JOSEException e) {
			throw new IOException("Failed to encrypt vault.uvf", e);
		}
	}
}
