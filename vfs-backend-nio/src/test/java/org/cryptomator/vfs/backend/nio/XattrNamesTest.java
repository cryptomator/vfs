package org.cryptomator.vfs.backend.nio;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class XattrNamesTest {

	@Test
	@DisplayName("linux strips and prepends the user namespace")
	void linux() {
		Assertions.assertEquals("test", XattrNames.LINUX.toView("user.test"));
		Assertions.assertEquals("user.test", XattrNames.LINUX.toVfs("test"));
	}

	@Test
	@DisplayName("linux rejects other namespaces and unqualified names")
	void linuxRejectsOtherNamespaces() {
		Assertions.assertThrows(UnsupportedOperationException.class, () -> XattrNames.LINUX.toView("security.selinux"));
		Assertions.assertThrows(UnsupportedOperationException.class, () -> XattrNames.LINUX.toView("test"));
	}

	@Test
	@DisplayName("verbatim mapping is the identity")
	void verbatim() {
		Assertions.assertEquals("com.apple.quarantine", XattrNames.VERBATIM.toView("com.apple.quarantine"));
		Assertions.assertEquals("com.apple.quarantine", XattrNames.VERBATIM.toVfs("com.apple.quarantine"));
	}
}
