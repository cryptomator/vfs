package org.cryptomator.vfs.backend.nio;

import java.util.Locale;

/**
 * Maps the fully qualified extended attribute names of the VFS API to the names understood by NIO's {@link java.nio.file.attribute.UserDefinedFileAttributeView}.
 * <p>
 * On Linux the view works implicitly in the {@code user.} namespace and strips or prepends that prefix itself, whereas frontends pass names the way
 * {@code getxattr(2)} sees them. On macOS and other platforms the view uses names verbatim.
 *
 * @param prefix the namespace prefix the view implies, empty if names are used verbatim
 */
record XattrNames(String prefix) {

	static final XattrNames LINUX = new XattrNames("user.");
	static final XattrNames VERBATIM = new XattrNames("");

	static XattrNames forCurrentPlatform() {
		var osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
		return osName.contains("linux") ? LINUX : VERBATIM;
	}

	/**
	 * Converts a VFS attribute name to the name expected by the view.
	 *
	 * @param vfsName fully qualified attribute name
	 * @return the name without the implied namespace prefix
	 * @throws UnsupportedOperationException if the name lies outside the namespace the view can address
	 */
	String toView(String vfsName) {
		if (!vfsName.startsWith(prefix)) {
			throw new UnsupportedOperationException("Only the " + prefix + " namespace is supported, not " + vfsName);
		}
		return vfsName.substring(prefix.length());
	}

	/**
	 * Converts a name listed by the view to the fully qualified VFS attribute name.
	 *
	 * @param viewName name as listed by the view
	 * @return the fully qualified name
	 */
	String toVfs(String viewName) {
		return prefix + viewName;
	}
}
