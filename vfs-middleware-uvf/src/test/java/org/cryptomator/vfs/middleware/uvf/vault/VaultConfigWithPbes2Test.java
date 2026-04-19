package org.cryptomator.vfs.middleware.uvf.vault;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultConfigWithPbes2Test {

	private static final String SAMPLE_PAYLOAD = """
			{
			    "fileFormat": "AES-256-GCM-32k",
			    "nameFormat": "AES-SIV-512-B64URL",
			    "seeds": {
			        "HDm38g": "ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs"
			    },
			    "initialSeed": "HDm38i",
			    "latestSeed": "HDm38i",
			    "kdf": "HKDF-SHA512",
			    "kdfSalt": "NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8"
			}""";

	@Test
	@DisplayName("decrypt(encrypt(payload)) == payload")
	void encryptThenDecrypt() throws Exception {
		String password = "test-password";
		var handler = new VaultConfigWithPbes2(password);

		byte[] jweData = handler.encrypt(SAMPLE_PAYLOAD);
		String result = handler.decrypt(jweData);

		assertTrue(result.contains("AES-256-GCM-32k"));
		assertTrue(result.contains("AES-SIV-512-B64URL"));
		assertTrue(result.contains("HKDF-SHA512"));
	}

	@Test
	@DisplayName("decrypt with wrong password fails")
	void decryptWithWrongPassword() throws Exception {
		var encryptor = new VaultConfigWithPbes2("correct-password");
		byte[] jweData = encryptor.encrypt(SAMPLE_PAYLOAD);

		var decryptor = new VaultConfigWithPbes2("wrong-password");
		assertThrows(IOException.class, () -> decryptor.decrypt(jweData));
	}

	@Test
	@DisplayName("decrypt malformed JWE fails")
	void decryptMalformedJwe() {
		var decryptor = new VaultConfigWithPbes2("password");
		assertThrows(IOException.class, () -> decryptor.decrypt("not-a-jwe".getBytes(UTF_8)));
	}
}
