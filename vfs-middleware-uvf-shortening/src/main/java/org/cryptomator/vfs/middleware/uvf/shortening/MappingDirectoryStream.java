package org.cryptomator.vfs.middleware.uvf.shortening;

import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsDirectoryStream;
import org.cryptomator.vfs.api.VfsFileSystem;
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
	 * Opens the stored directory on the delegate. The returned stream owns the underlying listing and closes it in {@link #close()}.
	 *
	 * @param delegate the file system holding the stored names
	 * @param storedDirPath the absolute path of the directory on the delegate
	 * @param mapping maps a stored entry to the entry reported to the upper layer, or to {@code null} to hide it
	 * @throws IOException if the stored directory cannot be opened
	 */
	MappingDirectoryStream(VfsFileSystem delegate, String storedDirPath, Function<VfsDirectoryEntry, @Nullable VfsDirectoryEntry> mapping) throws IOException {
		this.storedStream = delegate.openDirectory(storedDirPath);
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
