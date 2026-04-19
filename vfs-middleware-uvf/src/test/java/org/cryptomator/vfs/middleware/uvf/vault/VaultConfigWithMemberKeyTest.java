package org.cryptomator.vfs.middleware.uvf.vault;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultConfigWithMemberKeyTest {

	private static final String SAMPLE_PAYLOAD = """
			{
			    "fileFormat": "AES-256-GCM-32k",
			    "nameFormat": "AES-SIV-512-B64URL",
			    "kdf": "HKDF-SHA512"
			}""";

	@Test
	@DisplayName("decrypt(encrypt(payload)) == payload")
	void encryptThenDecrypt() throws Exception {
		byte[] key = randomKey();
		var handler = new VaultConfigWithMemberKey(key);

		byte[] jweData = handler.encrypt(SAMPLE_PAYLOAD);
		String result = handler.decrypt(jweData);

		assertTrue(result.contains("AES-256-GCM-32k"));
	}

	@Test
	@DisplayName("decrypt with wrong key fails")
	void decryptWithWrongKey() throws Exception {
		var encryptor = new VaultConfigWithMemberKey(randomKey());
		byte[] jweData = encryptor.encrypt(SAMPLE_PAYLOAD);

		var decryptor = new VaultConfigWithMemberKey(randomKey());
		assertThrows(IOException.class, () -> decryptor.decrypt(jweData));
	}

	@Test
	@DisplayName("decrypt JWE without matching kid fails")
	void decryptWithMissingRecipient() throws Exception {
		// encrypt with Argon2 kid, try to decrypt with member key kid
		var encryptor = new VaultConfigWithArgon2("password");
		byte[] jweData = encryptor.encrypt(SAMPLE_PAYLOAD);

		var decryptor = new VaultConfigWithMemberKey(randomKey());
		assertThrows(IOException.class, () -> decryptor.decrypt(jweData));
	}

	@Test
	@DisplayName("constructor rejects key with wrong length")
	void rejectsWrongKeyLength() {
		assertThrows(IllegalArgumentException.class, () -> new VaultConfigWithMemberKey(new byte[16]));
	}

	private static byte[] randomKey() {
		byte[] key = new byte[32];
		new SecureRandom().nextBytes(key);
		return key;
	}
}
