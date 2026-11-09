package org.cryptomator.vfs.common;

import org.jspecify.annotations.Nullable;

/**
 * Helpers for releasing resources on failure paths.
 */
public final class Closeables {

	private Closeables() {
	}

	/**
	 * Closes a resource while an exception is already in flight, so that a failing close cannot replace the original exception.
	 *
	 * @param toClose the resource to close
	 * @param suppressor the exception in flight; whatever closing throws is added to it as a suppressed exception
	 */
	public static void suppressWhileClosing(@Nullable AutoCloseable toClose, Throwable suppressor) {
		if (toClose == null) {
			return;
		}
		try {
			toClose.close();
		} catch (Exception e) {
			suppressor.addSuppressed(e);
		}
	}
}
