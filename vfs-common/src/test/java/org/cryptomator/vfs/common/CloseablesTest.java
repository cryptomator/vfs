package org.cryptomator.vfs.common;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CloseablesTest {

	@Test
	@DisplayName("a failing close is attached to the exception in flight instead of replacing it")
	void failingCloseIsSuppressed() {
		var inFlight = new IOException("original");
		var closeFailure = new IllegalStateException("close failed");
		AutoCloseable resource = () -> {
			throw closeFailure;
		};

		Closeables.suppressWhileClosing(resource, inFlight);

		assertArrayEquals(new Throwable[]{closeFailure}, inFlight.getSuppressed());
	}

	@Test
	@DisplayName("a successful close leaves the exception in flight untouched")
	void successfulClose() {
		var inFlight = new IOException("original");
		var closed = new boolean[1];

		Closeables.suppressWhileClosing(() -> closed[0] = true, inFlight);

		assertTrue(closed[0]);
		assertEquals(0, inFlight.getSuppressed().length);
	}
}
