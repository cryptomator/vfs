package org.cryptomator.vfs.middleware.uvf.dir;

import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsDirectoryStream;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.function.Function;

/**
 * A cleartext view of a ciphertext directory listing, mapping each entry through a decryption function and skipping entries that map to {@code null}.
 */
public final class UvfDirectoryStream implements VfsDirectoryStream {

	private final VfsDirectoryStream ciphertextStream;
	private final Function<VfsDirectoryEntry, @Nullable VfsDirectoryEntry> toCleartextEntry;

	/**
	 * Opens the ciphertext directory on the delegate. The returned stream owns the underlying listing and closes it in {@link #close()}.
	 *
	 * @param delegate the ciphertext filesystem
	 * @param ciphertextDirPath the absolute path of the content directory on the delegate
	 * @param toCleartextEntry maps a ciphertext entry to its cleartext counterpart or to {@code null} if the entry is not a vault node
	 * @throws IOException if the ciphertext directory cannot be opened
	 */
	public UvfDirectoryStream(VfsFileSystem delegate, String ciphertextDirPath, Function<VfsDirectoryEntry, @Nullable VfsDirectoryEntry> toCleartextEntry) throws IOException {
		this.ciphertextStream = delegate.openDirectory(ciphertextDirPath);
		this.toCleartextEntry = toCleartextEntry;
	}

	@Override
	public Iterator<VfsDirectoryEntry> iterator() {
		var ciphertextEntries = ciphertextStream.iterator();
		return new Iterator<>() {

			private @Nullable VfsDirectoryEntry next;

			@Override
			public boolean hasNext() {
				while (next == null && ciphertextEntries.hasNext()) {
					next = toCleartextEntry.apply(ciphertextEntries.next());
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
		ciphertextStream.close();
	}
}
