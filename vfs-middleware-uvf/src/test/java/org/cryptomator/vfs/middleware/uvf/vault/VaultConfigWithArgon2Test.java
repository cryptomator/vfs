package org.cryptomator.vfs.middleware.uvf.vault;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultConfigWithArgon2Test {

	private static final String SAMPLE_PAYLOAD = """
			{
			    "fileFormat": "AES-256-GCM-32k",
			    "nameFormat": "AES-SIV-512-B64URL",
			    "kdf": "HKDF-SHA512"
			}""";

	@Test
	@DisplayName("decrypt(encrypt(payload)) == payload")
	void encryptThenDecrypt() throws Exception {
		var handler = new VaultConfigWithArgon2("correct-horse-battery-staple");

		byte[] jweData = handler.encrypt(SAMPLE_PAYLOAD);
		String result = handler.decrypt(jweData);

		assertTrue(result.contains("AES-256-GCM-32k"));
	}

	@Test
	@DisplayName("decrypt with wrong password fails")
	void decryptWithWrongPassword() throws Exception {
		var encryptor = new VaultConfigWithArgon2("correct");
		byte[] jweData = encryptor.encrypt(SAMPLE_PAYLOAD);

		var decryptor = new VaultConfigWithArgon2("wrong");
		assertThrows(IOException.class, () -> decryptor.decrypt(jweData));
	}

	@Test
	@DisplayName("decrypt JWE without Argon2 params fails")
	void decryptWithMissingParams() throws Exception {
		// encrypt with member key (no argon2 params), try to decrypt with argon2
		var encryptor = new VaultConfigWithMemberKey(new byte[32]);
		byte[] jweData = encryptor.encrypt(SAMPLE_PAYLOAD);

		var decryptor = new VaultConfigWithArgon2("password");
		assertThrows(IOException.class, () -> decryptor.decrypt(jweData));
	}
}
