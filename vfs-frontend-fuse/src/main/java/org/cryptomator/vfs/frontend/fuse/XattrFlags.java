package org.cryptomator.vfs.frontend.fuse;

import org.cryptomator.vfs.api.VfsXattrPolicy;
import org.jspecify.annotations.Nullable;

import java.util.Locale;

/**
 * The platform's {@code setxattr(2)} flag values, which jFUSE forwards unchanged.
 *
 * @param create the {@code XATTR_CREATE} bit
 * @param replace the {@code XATTR_REPLACE} bit
 */
record XattrFlags(int create, int replace) {

	static final XattrFlags LINUX = new XattrFlags(1, 2);
	static final XattrFlags MACOS = new XattrFlags(2, 4); // sys/xattr.h; bit 1 is XATTR_NOFOLLOW

	static XattrFlags forCurrentPlatform() {
		var osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
		return osName.contains("mac") || osName.contains("darwin") ? MACOS : LINUX;
	}

	// the policy encoded in the flags, or null if both bits are set; other bits are ignored
	@Nullable VfsXattrPolicy policy(int flags) {
		var masked = flags & (create | replace);
		if (masked == 0) {
			return VfsXattrPolicy.CREATE_OR_REPLACE;
		} else if (masked == create) {
			return VfsXattrPolicy.CREATE_ONLY;
		} else if (masked == replace) {
			return VfsXattrPolicy.REPLACE_ONLY;
		} else {
			return null;
		}
	}
}
