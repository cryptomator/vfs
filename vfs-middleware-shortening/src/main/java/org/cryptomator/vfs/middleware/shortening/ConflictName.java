package org.cryptomator.vfs.middleware.shortening;

import org.jspecify.annotations.Nullable;

import java.util.function.Predicate;

/**
 * A name as produced by sync services for a conflicting copy: the canonical name with a suffix inserted before its last extension, e.g. {@code name (1).ext}.
 * <p>
 * This only reflects how sync services name copies and is independent of any name format; the caller decides which candidates are canonical.
 *
 * @param canonicalName the name of the original, e.g. {@code name.ext}
 * @param suffix the inserted suffix, e.g. {@code " (1)"}
 */
record ConflictName(String canonicalName, String suffix) {

	/**
	 * Splits a name into canonical name and conflict suffix, assuming the suffix starts with a character other than an ASCII letter or digit (a space, {@code (}, {@code -}, {@code .}, ...).
	 *
	 * @param name a name found in a directory
	 * @param isCanonical tells whether a candidate is a canonical name
	 * @return the split name, or {@code null} if no candidate is canonical
	 */
	static @Nullable ConflictName parse(String name, Predicate<String> isCanonical) {
		int extensionStart = name.lastIndexOf('.');
		if (extensionStart <= 0) {
			return null;
		}
		var stem = name.substring(0, extensionStart);
		var extension = name.substring(extensionStart);
		for (int cut = stem.length() - 1; cut > 0; cut--) {
			if (isSeparator(stem.charAt(cut))) {
				var candidate = stem.substring(0, cut) + extension;
				if (isCanonical.test(candidate)) {
					return new ConflictName(candidate, stem.substring(cut));
				}
			}
		}
		return null;
	}

	private static boolean isSeparator(char c) {
		return !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9');
	}

	/**
	 * Inserts this conflict's suffix into another name in the same way, i.e. before its last extension.
	 *
	 * @param name e.g. {@code abc.uvf}
	 * @return e.g. {@code abc (1).uvf}
	 */
	String applyTo(String name) {
		int extensionStart = name.lastIndexOf('.');
		if (extensionStart <= 0) {
			return name + suffix;
		}
		return name.substring(0, extensionStart) + suffix + name.substring(extensionStart);
	}
}
