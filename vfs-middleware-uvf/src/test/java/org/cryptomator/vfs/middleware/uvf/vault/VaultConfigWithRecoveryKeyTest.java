package org.cryptomator.vfs.middleware.uvf.vault;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultConfigWithRecoveryKeyTest {

	private static final String SAMPLE_PAYLOAD = """
			{
			    "fileFormat": "AES-256-GCM-32k",
			    "nameFormat": "AES-SIV-512-B64URL",
			    "kdf": "HKDF-SHA512"
			}""";

	@Test
	@DisplayName("decrypt(encrypt(payload)) == payload")
	void encryptThenDecrypt() throws Exception {
		var ecKey = new ECKeyGenerator(Curve.P_384).generate();
		String kid = "org.cryptomator.hub.recoverykey." + ecKey.computeThumbprint().toString();
		var handler = new VaultConfigWithRecoveryKey(ecKey.toECPrivateKey(), ecKey.toECPublicKey(), kid);

		byte[] jweData = handler.encrypt(SAMPLE_PAYLOAD);
		String result = handler.decrypt(jweData);

		assertTrue(result.contains("AES-256-GCM-32k"));
	}

	@Test
	@DisplayName("decrypt with wrong EC key fails")
	void decryptWithWrongKey() throws Exception {
		var correctKey = new ECKeyGenerator(Curve.P_384).generate();
		var wrongKey = new ECKeyGenerator(Curve.P_384).generate();
		String kid = "org.cryptomator.hub.recoverykey." + correctKey.computeThumbprint().toString();

		var encryptor = new VaultConfigWithRecoveryKey(correctKey.toECPrivateKey(), correctKey.toECPublicKey(), kid);
		byte[] jweData = encryptor.encrypt(SAMPLE_PAYLOAD);

		var decryptor = new VaultConfigWithRecoveryKey(wrongKey.toECPrivateKey(), kid);
		assertThrows(IOException.class, () -> decryptor.decrypt(jweData));
	}

	@Test
	@DisplayName("constructor rejects invalid kid prefix")
	void rejectsInvalidKidPrefix() throws Exception {
		var ecKey = new ECKeyGenerator(Curve.P_384).generate();
		assertThrows(IllegalArgumentException.class,
				() -> new VaultConfigWithRecoveryKey(ecKey.toECPrivateKey(), "invalid.kid"));
	}
}
