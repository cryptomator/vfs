package org.cryptomator.vfs.middleware.uvf.vault;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.UnprotectedHeader;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import org.cryptomator.vfs.middleware.uvf.VaultConfigDecryptor;
import org.cryptomator.vfs.middleware.uvf.VaultConfigEncryptor;

import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Encrypts and decrypts a {@code vault.uvf} JWE using an EC key pair via ECDH-ES+A256KW.
 * <p>
 * Selects the recipient with kid matching {@code org.cryptomator.hub.recoverykey.{thumbprint}}.
 */
public final class VaultConfigWithRecoveryKey implements VaultConfigDecryptor, VaultConfigEncryptor {

	private static final String KID_PREFIX = "org.cryptomator.hub.recoverykey.";
	private static final Set<String> DEFERRED_CRITICAL_PARAMS = Set.of("uvf.spec.version");

	private final ECPrivateKey privateKey;
	private final ECPublicKey publicKey;
	private final String kid;

	/**
	 * @param privateKey the EC private key for ECDH key agreement (decryption)
	 * @param publicKey  the EC public key for ECDH key agreement (encryption)
	 * @param kid        the full kid value including thumbprint (e.g., {@code org.cryptomator.hub.recoverykey.abc123})
	 */
	public VaultConfigWithRecoveryKey(ECPrivateKey privateKey, ECPublicKey publicKey, String kid) {
		if (!kid.startsWith(KID_PREFIX)) {
			throw new IllegalArgumentException("kid must start with " + KID_PREFIX);
		}
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.kid = kid;
	}

	/**
	 * Decryption-only constructor (cannot encrypt).
	 *
	 * @param privateKey the EC private key for ECDH key agreement
	 * @param kid        the full kid value including thumbprint
	 */
	public VaultConfigWithRecoveryKey(ECPrivateKey privateKey, String kid) {
		this(privateKey, null, kid);
	}

	@Override
	public String decrypt(byte[] jweData) throws IOException {
		try {
			var jweJson = JWEObjectJSON.parse(new String(jweData, UTF_8));
			var recipient = JweHelper.findRecipient(jweJson, kid);
			return JweHelper.decryptRecipient(jweJson, recipient, new ECDHDecrypter(privateKey, DEFERRED_CRITICAL_PARAMS));
		} catch (ParseException e) {
			throw new IOException("Failed to parse vault.uvf JWE", e);
		} catch (JOSEException e) {
			throw new IOException("Failed to decrypt vault.uvf with recovery key", e);
		}
	}

	@Override
	public byte[] encrypt(String payload) throws IOException {
		if (publicKey == null) {
			throw new IOException("No public key available for encryption");
		}
		try {
			var recipientHeader = new UnprotectedHeader.Builder()
					.param("kid", kid)
					.build();
			return JweHelper.encryptPayload(JWEAlgorithm.ECDH_ES_A256KW, payload, new ECDHEncrypter(publicKey), recipientHeader);
		} catch (JOSEException e) {
			throw new IOException("Failed to encrypt vault.uvf with recovery key", e);
		}
	}
}
