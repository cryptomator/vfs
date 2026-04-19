package org.cryptomator.vfs.middleware.uvf.vault;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.UnprotectedHeader;

import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Shared utilities for encrypting and decrypting JWE JSON serialization objects with multiple recipients.
 */
final class JweHelper {

	private JweHelper() {}

	/**
	 * Finds a recipient by kid. Checks per-recipient unprotected headers first,
	 * then falls back to the shared unprotected header for single-recipient JWEs.
	 */
	static JWEObjectJSON.Recipient findRecipient(JWEObjectJSON jweJson, String kid) throws IOException {
		for (var recipient : jweJson.getRecipients()) {
			var header = recipient.getUnprotectedHeader();
			if (header != null && kid.equals(header.getParam("kid"))) {
				return recipient;
			}
		}
		var sharedHeader = jweJson.getUnprotectedHeader();
		if (sharedHeader != null && kid.equals(sharedHeader.getParam("kid"))) {
			var recipients = jweJson.getRecipients();
			if (recipients.size() == 1) {
				return recipients.getFirst();
			}
		}
		throw new IOException("No recipient found with kid: " + kid);
	}

	/**
	 * Decrypts a specific recipient of a JWE JSON object.
	 * <p>
	 * Merges the protected, shared unprotected, and per-recipient unprotected headers
	 * to form the complete header for the decrypter (needed for algorithm-specific params
	 * like {@code p2s}, {@code p2c}, {@code epk}, etc.). Uses the original protected header
	 * for AAD computation to match what was used during encryption.
	 */
	static String decryptRecipient(JWEObjectJSON jweJson, JWEObjectJSON.Recipient recipient, JWEDecrypter decrypter) throws JOSEException, ParseException {
		// Merge protected + per-recipient headers for the decrypter (it needs algorithm-specific
		// params like p2s, p2c, epk). Excludes the shared unprotected header (kid etc.)
		// which is not needed for decryption.
		var mergedParams = new HashMap<>(jweJson.getHeader().toJSONObject());
		if (recipient.getUnprotectedHeader() != null) {
			mergedParams.putAll(recipient.getUnprotectedHeader().toJSONObject());
		}
		var mergedHeader = JWEHeader.parse(mergedParams);

		// Use the original protected header's base64url as AAD.
		// We cannot rely on mergedHeader.toBase64URL() because JWEHeader re-serialization
		// may produce a different JSON key order than the original encryption-time header.
		byte[] aad = jweJson.getHeader().toBase64URL().toString().getBytes(UTF_8);
		byte[] cleartext = decrypter.decrypt(mergedHeader, recipient.getEncryptedKey(), jweJson.getIV(), jweJson.getCipherText(), jweJson.getAuthTag(), aad);
		return new String(cleartext, UTF_8);
	}

	/**
	 * Encrypts a payload into a JWE JSON serialization with the UVF protected header.
	 *
	 * @param alg              the key management algorithm
	 * @param payload          the JSON payload to encrypt
	 * @param encrypter        the JWE encrypter
	 * @param recipientHeader  per-recipient unprotected header (kid, algorithm-specific params)
	 * @return the serialized JWE bytes
	 */
	static byte[] encryptPayload(JWEAlgorithm alg, String payload, JWEEncrypter encrypter, UnprotectedHeader recipientHeader) throws JOSEException {
		var protectedHeader = new JWEHeader.Builder(alg, EncryptionMethod.A256GCM)
				.contentType("json")
				.criticalParams(Set.of("uvf.spec.version"))
				.customParams(Map.of("uvf.spec.version", 1))
				.build();
		var jwe = new JWEObjectJSON(protectedHeader, new Payload(payload), recipientHeader, null);
		jwe.encrypt(encrypter);
		return jwe.serializeGeneral().getBytes(UTF_8);
	}
}
