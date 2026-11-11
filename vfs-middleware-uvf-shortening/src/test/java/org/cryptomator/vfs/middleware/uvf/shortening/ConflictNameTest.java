package org.cryptomator.vfs.middleware.uvf.shortening;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ConflictNameTest {

	@ParameterizedTest(name = "{0} -> {1} + \"{2}\"")
	@DisplayName("parse() finds the canonical name for the suffixes of common sync services")
	@CsvSource(delimiter = '|', value = {
			"abc (Alice's conflicted copy 2026-11-11).uvf | abc.uvf | ' (Alice''s conflicted copy 2026-11-11)'",
			"abc (conflicted copy 2026-11-11 104009).uvf | abc.uvf | ' (conflicted copy 2026-11-11 104009)'",
			"abc (1).uvf | abc.uvf | ' (1)'",
			"abc 2.uvf | abc.uvf | ' 2'",
			"abc-HOST-NAME.uvf | abc.uvf | -HOST-NAME",
			"abc.sync-conflict-20261111-104009-ABCDEFG.uvf | abc.uvf | .sync-conflict-20261111-104009-ABCDEFG",
			"a.b (1).uvf | a.b.uvf | ' (1)'"
	})
	void testParse(String name, String canonicalName, String suffix) {
		var conflict = ConflictName.parse(name, Set.of(canonicalName)::contains);

		assertEquals(new ConflictName(canonicalName, suffix), conflict);
	}

	@Test
	@DisplayName("parse() returns null if no candidate is canonical")
	void testParseNoMatch() {
		assertNull(ConflictName.parse("abc (1).uvf", _ -> false));
		assertNull(ConflictName.parse("abc (1)", _ -> true)); // no extension
	}

	@Test
	@DisplayName("parse() never proposes the name itself or an empty stem")
	void testParseCandidates() {
		var candidates = new ArrayList<String>();
		ConflictName.parse("-a-b.uvf", candidate -> {
			candidates.add(candidate);
			return false;
		});

		assertEquals(List.of("-a.uvf"), candidates);
	}

	@ParameterizedTest(name = "\"{1}\" into {0} = {2}")
	@DisplayName("applyTo() inserts the suffix before the last extension")
	@CsvSource({"abc.uvf, ' (1)', abc (1).uvf", "a.b.uvf, ' (1)', a.b (1).uvf", "abc, ' (1)', abc (1)", ".uvf, ' (1)', .uvf (1)"})
	void testApplyTo(String name, String suffix, String expected) {
		assertEquals(expected, new ConflictName("irrelevant", suffix).applyTo(name));
	}
}
