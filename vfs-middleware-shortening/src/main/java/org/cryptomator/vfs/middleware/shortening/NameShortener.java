package org.cryptomator.vfs.middleware.shortening;

import org.jspecify.annotations.Nullable;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * The name mapping functions of the UVF file name shortening spec for a given threshold, free of any I/O.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/tree/develop/file-name-shortening">UVF File Name Shortening</a>
 */
final class NameShortener {

	static final String NODE_SUFFIX = ".shortened.uvf";
	static final String SIDECAR_SUFFIX = ".original.uvf";
	static final int HASH_LENGTH = 32; // 160 bits in base32

	// group 1: hash, group 2: suffix inserted by sync services in case of conflicts, empty for regular nodes
	static final Pattern SHORTENED_NODE = Pattern.compile("([A-Z2-7]{32})\\.shortened(.*)\\.uvf");
	// conflicting copies of sidecars are interchangeable, so they are hidden as well
	static final Pattern SIDECAR = Pattern.compile("[A-Z2-7]{32}\\.original.*\\.uvf");

	private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	private static final int TRUNCATED_HASH_BYTES = 20;

	private final int threshold;

	NameShortener(int threshold) {
		this.threshold = threshold;
	}

	boolean isLong(String name) {
		return isLong(utf8(name));
	}

	boolean isLong(byte[] utf8Name) {
		return utf8Name.length > threshold;
	}

	/**
	 * Tells whether a name that the upper layer passes in would be mistaken for a node or sidecar created by this middleware.
	 *
	 * @param name a path component of the upper layer
	 * @return {@code true} if the name must not be stored as-is
	 */
	static boolean isReserved(String name) {
		return SHORTENED_NODE.matcher(name).matches() || SIDECAR.matcher(name).matches();
	}

	String shortName(String name) {
		return shortName(utf8(name));
	}

	String shortName(byte[] utf8Name) {
		try {
			var hash = MessageDigest.getInstance("SHA-256").digest(utf8Name);
			return base32(Arrays.copyOf(hash, TRUNCATED_HASH_BYTES));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Every JVM must support SHA-256", e);
		}
	}

	/**
	 * Decodes and verifies the contents of a sidecar file.
	 *
	 * @param hash the hash taken from the name of the shortened node
	 * @param contents the raw contents of the sidecar file
	 * @return the original name, or {@code null} if the sidecar is invalid, i.e. not UTF-8, not long, or not matching {@code hash}
	 */
	@Nullable String verifySidecar(String hash, byte[] contents) {
		if (!isLong(contents) || !shortName(contents).equals(hash)) {
			return null;
		}
		try {
			return StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(contents))
					.toString();
		} catch (CharacterCodingException _) {
			return null;
		}
	}

	/**
	 * Builds the name reported for a conflicting copy of a shortened node, inserting the conflict suffix before the last extension.
	 *
	 * @param originalName the verified name of the shortened node
	 * @param conflictSuffix the suffix found between {@code .shortened} and {@code .uvf}, e.g. {@code " (conflicted copy)"}
	 * @return e.g. {@code "abc (conflicted copy).uvf"} for {@code "abc.uvf"}
	 */
	static String conflictName(String originalName, String conflictSuffix) {
		int dot = originalName.lastIndexOf('.');
		if (dot <= 0) {
			return originalName + conflictSuffix;
		}
		return originalName.substring(0, dot) + conflictSuffix + originalName.substring(dot);
	}

	static byte[] utf8(String name) {
		return name.getBytes(StandardCharsets.UTF_8);
	}

	// RFC 4648 base32, uppercase alphabet, no padding
	static String base32(byte[] bytes) {
		var result = new StringBuilder((bytes.length * 8 + 4) / 5);
		int buffer = 0;
		int bits = 0;
		for (byte b : bytes) {
			buffer = (buffer << 8) | (b & 0xFF);
			bits += 8;
			while (bits >= 5) {
				result.append(BASE32_ALPHABET.charAt((buffer >>> (bits - 5)) & 0x1F));
				bits -= 5;
			}
		}
		if (bits > 0) {
			result.append(BASE32_ALPHABET.charAt((buffer << (5 - bits)) & 0x1F));
		}
		return result.toString();
	}
}
