package org.cryptomator.vfs.middleware.uvf.vault;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.UnprotectedHeader;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.AESEncrypter;
import org.cryptomator.vfs.middleware.uvf.VaultConfigDecryptor;
import org.cryptomator.vfs.middleware.uvf.VaultConfigEncryptor;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.text.ParseException;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Encrypts and decrypts a {@code vault.uvf} JWE using a 256-bit member key via A256KW.
 * <p>
 * Selects the recipient with kid {@code org.cryptomator.hub.memberkey}.
 */
public final class VaultConfigWithMemberKey implements VaultConfigDecryptor, VaultConfigEncryptor {

	static final String KID = "org.cryptomator.hub.memberkey";
	private static final Set<String> DEFERRED_CRITICAL_PARAMS = Set.of("uvf.spec.version");

	private final byte[] memberKey;

	/**
	 * @param memberKey 32-byte AES-256 key
	 */
	public VaultConfigWithMemberKey(byte[] memberKey) {
		if (memberKey.length != 32) {
			throw new IllegalArgumentException("Member key must be 32 bytes (256 bits)");
		}
		this.memberKey = memberKey.clone();
	}

	@Override
	public String decrypt(byte[] jweData) throws IOException {
		try {
			var jweJson = JWEObjectJSON.parse(new String(jweData, UTF_8));
			var recipient = JweHelper.findRecipient(jweJson, KID);
			return JweHelper.decryptRecipient(jweJson, recipient, new AESDecrypter(new SecretKeySpec(memberKey, "AES"), DEFERRED_CRITICAL_PARAMS));
		} catch (ParseException e) {
			throw new IOException("Failed to parse vault.uvf JWE", e);
		} catch (JOSEException e) {
			throw new IOException("Failed to decrypt vault.uvf with member key", e);
		}
	}

	@Override
	public byte[] encrypt(String payload) throws IOException {
		try {
			var recipientHeader = new UnprotectedHeader.Builder()
					.param("kid", KID)
					.build();
			return JweHelper.encryptPayload(JWEAlgorithm.A256KW, payload, new AESEncrypter(memberKey), recipientHeader);
		} catch (JOSEException e) {
			throw new IOException("Failed to encrypt vault.uvf with member key", e);
		}
	}
}
