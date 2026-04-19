package org.cryptomator.vfs.middleware.uvf.vault;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.UnprotectedHeader;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.AESEncrypter;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.cryptomator.vfs.middleware.uvf.VaultConfigDecryptor;
import org.cryptomator.vfs.middleware.uvf.VaultConfigEncryptor;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Encrypts and decrypts a {@code vault.uvf} JWE using Argon2-derived A256KW key wrapping.
 * <p>
 * The Argon2 parameters are stored in the recipient's unprotected header:
 * <ul>
 *   <li>{@code argon2.salt} — base64url-encoded salt</li>
 *   <li>{@code argon2.iterations} — time cost (number of iterations)</li>
 *   <li>{@code argon2.memoryKB} — memory cost in KiB</li>
 *   <li>{@code argon2.parallelism} — parallelism (lanes)</li>
 * </ul>
 * The derived key is 32 bytes (256 bits) using Argon2id.
 */
public final class VaultConfigWithArgon2 implements VaultConfigDecryptor, VaultConfigEncryptor {

	static final String KID = "org.cryptomator.password.argon2";
	private static final int KEY_LENGTH = 32;
	private static final int DEFAULT_SALT_LENGTH = 16;
	private static final int DEFAULT_ITERATIONS = 3;
	private static final int DEFAULT_MEMORY_KB = 64 * 1024;
	private static final int DEFAULT_PARALLELISM = 1;
	private static final Set<String> DEFERRED_CRITICAL_PARAMS = Set.of("uvf.spec.version");

	private final byte[] password;

	/**
	 * @param password the password to derive the AES-256 key from
	 */
	public VaultConfigWithArgon2(String password) {
		this.password = password.getBytes(UTF_8);
	}

	@Override
	public String decrypt(byte[] jweData) throws IOException {
		try {
			var jweJson = JWEObjectJSON.parse(new String(jweData, UTF_8));
			var recipient = JweHelper.findRecipient(jweJson, KID);

			var recipientHeader = recipient.getUnprotectedHeader();
			var sharedHeader = jweJson.getUnprotectedHeader();
			byte[] derivedKey = deriveKey(recipientHeader, sharedHeader);
			return JweHelper.decryptRecipient(jweJson, recipient, new AESDecrypter(new SecretKeySpec(derivedKey, "AES"), DEFERRED_CRITICAL_PARAMS));
		} catch (ParseException e) {
			throw new IOException("Failed to parse vault.uvf JWE", e);
		} catch (JOSEException e) {
			throw new IOException("Failed to decrypt vault.uvf with Argon2-derived key", e);
		}
	}

	@Override
	public byte[] encrypt(String payload) throws IOException {
		try {
			byte[] salt = new byte[DEFAULT_SALT_LENGTH];
			SecureRandom.getInstanceStrong().nextBytes(salt);

			byte[] derivedKey = deriveKey(password, salt, DEFAULT_ITERATIONS, DEFAULT_MEMORY_KB, DEFAULT_PARALLELISM);
			String saltB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(salt);

			var recipientHeader = new UnprotectedHeader.Builder()
					.param("kid", KID)
					.param("argon2.salt", saltB64)
					.param("argon2.iterations", DEFAULT_ITERATIONS)
					.param("argon2.memoryKB", DEFAULT_MEMORY_KB)
					.param("argon2.parallelism", DEFAULT_PARALLELISM)
					.build();
			return JweHelper.encryptPayload(JWEAlgorithm.A256KW, payload, new AESEncrypter(derivedKey), recipientHeader);
		} catch (JOSEException e) {
			throw new IOException("Failed to encrypt vault.uvf with Argon2-derived key", e);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new IOException("Strong SecureRandom not available", e);
		}
	}

	private byte[] deriveKey(com.nimbusds.jose.UnprotectedHeader recipientHeader, com.nimbusds.jose.UnprotectedHeader sharedHeader) throws IOException {
		Object saltParam = getParam("argon2.salt", recipientHeader, sharedHeader);
		Object iterationsParam = getParam("argon2.iterations", recipientHeader, sharedHeader);
		Object memoryParam = getParam("argon2.memoryKB", recipientHeader, sharedHeader);
		Object parallelismParam = getParam("argon2.parallelism", recipientHeader, sharedHeader);

		if (!(saltParam instanceof String saltB64)) {
			throw new IOException("Missing or invalid argon2.salt in recipient header");
		}
		if (!(iterationsParam instanceof Number iterations)) {
			throw new IOException("Missing or invalid argon2.iterations in recipient header");
		}
		if (!(memoryParam instanceof Number memoryKB)) {
			throw new IOException("Missing or invalid argon2.memoryKB in recipient header");
		}
		if (!(parallelismParam instanceof Number parallelism)) {
			throw new IOException("Missing or invalid argon2.parallelism in recipient header");
		}

		byte[] salt = Base64.getUrlDecoder().decode(saltB64);
		return deriveKey(password, salt, iterations.intValue(), memoryKB.intValue(), parallelism.intValue());
	}

	private static byte[] deriveKey(byte[] password, byte[] salt, int iterations, int memoryKB, int parallelism) {
		var params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
				.withVersion(Argon2Parameters.ARGON2_VERSION_13)
				.withSalt(salt)
				.withIterations(iterations)
				.withMemoryAsKB(memoryKB)
				.withParallelism(parallelism)
				.build();

		var generator = new Argon2BytesGenerator();
		generator.init(params);
		byte[] derivedKey = new byte[KEY_LENGTH];
		generator.generateBytes(password, derivedKey);
		return derivedKey;
	}

	private static Object getParam(String name, com.nimbusds.jose.UnprotectedHeader recipientHeader, com.nimbusds.jose.UnprotectedHeader sharedHeader) {
		if (recipientHeader != null) {
			Object val = recipientHeader.getParam(name);
			if (val != null) return val;
		}
		if (sharedHeader != null) {
			return sharedHeader.getParam(name);
		}
		return null;
	}
}
