package org.cryptomator.vfs.api;

import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Iterator;

/**
 * A lazily populated, forward-only, single-use iteration over the entries of a directory that must be closed when done.
 * <p>
 * Frontends that need resumable listings (directory cookies, markers) keep this stream open across calls or buffer the entries themselves.
 */
public interface VfsDirectoryStream extends Iterable<VfsDirectoryEntry>, Closeable {

	/**
	 * Returns the single iterator over this stream's entries. Entries never include {@code .} or {@code ..}.
	 *
	 * @return the iterator
	 * @throws IllegalStateException if called more than once or after the stream was closed
	 * @throws UncheckedIOException from {@link Iterator#hasNext()} or {@link Iterator#next()} if reading the directory fails
	 */
	@Override
	Iterator<VfsDirectoryEntry> iterator();

	@Override
	void close() throws IOException;
}
