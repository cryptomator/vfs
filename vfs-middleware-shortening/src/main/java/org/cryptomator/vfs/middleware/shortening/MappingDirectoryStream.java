package org.cryptomator.vfs.middleware.shortening;

import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsDirectoryStream;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.function.Function;

/**
 * A view of a stored directory listing that maps each entry through a function and skips entries that map to {@code null}.
 */
final class MappingDirectoryStream implements VfsDirectoryStream {

	private final VfsDirectoryStream storedStream;
	private final Function<VfsDirectoryEntry, @Nullable VfsDirectoryEntry> mapping;

	/**
	 * @param storedStream the listing of the delegate, owned and closed by this stream
	 * @param mapping maps a stored entry to the entry reported to the upper layer, or to {@code null} to hide it
	 */
	MappingDirectoryStream(VfsDirectoryStream storedStream, Function<VfsDirectoryEntry, @Nullable VfsDirectoryEntry> mapping) {
		this.storedStream = storedStream;
		this.mapping = mapping;
	}

	@Override
	public Iterator<VfsDirectoryEntry> iterator() {
		var storedEntries = storedStream.iterator();
		return new Iterator<>() {

			private @Nullable VfsDirectoryEntry next;

			@Override
			public boolean hasNext() {
				while (next == null && storedEntries.hasNext()) {
					next = mapping.apply(storedEntries.next());
				}
				return next != null;
			}

			@Override
			public VfsDirectoryEntry next() {
				if (!hasNext()) {
					throw new NoSuchElementException();
				}
				var result = next;
				next = null;
				return result;
			}
		};
	}

	@Override
	public void close() throws IOException {
		storedStream.close();
	}
}
