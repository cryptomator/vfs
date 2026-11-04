package org.cryptomator.vfs.middleware.shortening;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NameShortenerTest {

	// the example from the spec
	static final String SPEC_NAME = "cAp6_KasM-0d74bYyP1eOpweCA4NGgwjVfDGc6heAlXbLIVq2tMWskWpw-DGgyoC63Tjjs3weXCL3hjGfQlP_uJDocVs7kxvIKDEsnHk2GYEnbLGJgCsYcIahvxW9PLxkIXowBkEcaedqWWZNmW0Cv0e9-EaPHmiveg-uvH7Hdp0vxEbxqxRioJBDN1jmVVfV-rE8fCa6ijyBJXYem0IvMLYl4wNgi0G.uvf";
	static final String SPEC_HASH = "WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4";

	private final NameShortener shortener = new NameShortener(220);

	@Test
	@DisplayName("shortName() matches the example from the spec")
	void testSpecExample() {
		assertEquals(228, SPEC_NAME.length());
		assertTrue(shortener.isLong(SPEC_NAME));
		assertEquals(SPEC_HASH, shortener.shortName(SPEC_NAME));
	}

	@ParameterizedTest(name = "base32({0}) = {1}")
	@DisplayName("base32() matches the RFC 4648 test vectors without padding")
	@CsvSource({"'',''", "f,MY", "fo,MZXQ", "foo,MZXW6", "foob,MZXW6YQ", "fooba,MZXW6YTB", "foobar,MZXW6YTBOI"})
	void testBase32(String input, String expected) {
		assertEquals(expected, NameShortener.base32(input.getBytes(StandardCharsets.US_ASCII)));
	}

	@Test
	@DisplayName("isLong() counts UTF-8 bytes, not characters")
	void testIsLongCountsBytes() {
		assertFalse(shortener.isLong("a".repeat(220)));
		assertTrue(shortener.isLong("a".repeat(221)));
		assertTrue(shortener.isLong("ä".repeat(111))); // 222 bytes, 111 chars
	}

	@ParameterizedTest
	@DisplayName("isReserved() matches stored node and sidecar names, including conflicting copies")
	@ValueSource(strings = {"WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4.shortened.uvf", "WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4.original.uvf", "WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4.shortened (1).uvf", "WQ6QCEQX5BTXEPNQZNJLHDN52MADIVA4.original (1).uvf"})
	void testIsReserved(String name) {
		assertTrue(NameShortener.isReserved(name));
	}

	@ParameterizedTest
	@DisplayName("isReserved() does not match ordinary names")
	@ValueSource(strings = {"5TyvCyF255sRtfrIv83ucADQ.uvf", "dir.uvf", "foo.shortened.uvf", "wq6qceqx5btxepnqznjlhdn52madiva4.shortened.uvf"})
	void testIsNotReserved(String name) {
		assertFalse(NameShortener.isReserved(name));
	}

	@Test
	@DisplayName("verifySidecar() accepts a sidecar matching the hash")
	void testVerifyValidSidecar() {
		assertEquals(SPEC_NAME, shortener.verifySidecar(SPEC_HASH, SPEC_NAME.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	@DisplayName("verifySidecar() rejects a sidecar of a different name")
	void testVerifyWrongHash() {
		var other = "b".repeat(300);
		assertNull(shortener.verifySidecar(SPEC_HASH, other.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	@DisplayName("verifySidecar() rejects a name that would not have been shortened")
	void testVerifyShortName() {
		var shortName = "a".repeat(220);
		assertNull(shortener.verifySidecar(shortener.shortName(shortName), shortName.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	@DisplayName("verifySidecar() rejects malformed UTF-8 even if the hash matches")
	void testVerifyMalformedUtf8() {
		var contents = new byte[300];
		Arrays.fill(contents, (byte) 0xFF);
		assertNull(shortener.verifySidecar(shortener.shortName(contents), contents));
	}

	@ParameterizedTest(name = "conflictName({0}, {1}) = {2}")
	@DisplayName("conflictName() inserts the suffix before the last extension")
	@CsvSource({"abc.uvf, ' (1)', abc (1).uvf", "a.b.uvf, ' (1)', a.b (1).uvf", "abc, ' (1)', abc (1)", ".uvf, ' (1)', .uvf (1)"})
	void testConflictName(String name, String suffix, String expected) {
		assertEquals(expected, NameShortener.conflictName(name, suffix));
	}
}
