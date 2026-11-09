package org.cryptomator.vfs.middleware.uvf.content;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.UnlockedVault;
import org.cryptomator.cryptolib.api.VaultFile;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;
import org.cryptomator.vfs.common.Closeables;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.locks.Lock;

/**
 * A {@link VfsFile} decorator that transparently encrypts writes and decrypts reads using the vault's chunked file format.
 * <p>
 * All chunk arithmetic, read-modify-write of partial chunks and header handling is done by cryptolib's {@link VaultFile}; this class only connects it to the
 * ciphertext {@link VfsFile} on the delegate.
 *
 * @implNote Handles share nothing. The ciphertext on the delegate is the single source of truth: a writable handle persists the header as soon as it is
 * opened on an empty ciphertext, and every write, truncate and metadata read first compares the ciphertext size against the size its {@link VaultFile} was
 * derived from, re-reading header and size when another handle changed them in between (reads do so lazily, see {@link #read}). Concurrent writes from
 * different handles into the same chunk may still lose data, just as unsynchronised writers do on any file system.
 */
public final class UvfVfsFile implements VfsFile {

	/**
	 * Opens the ciphertext file on the delegate file system.
	 */
	@FunctionalInterface
	public interface Opener {

		/**
		 * Opens the ciphertext file.
		 *
		 * @return the open ciphertext file, owned by the {@link UvfVfsFile} from now on
		 * @throws IOException if the file cannot be opened
		 */
		VfsFile open() throws IOException;
	}

	private final UnlockedVault vault;
	private final VfsFile delegate;
	private VaultFile vaultFile; // header, file key and cleartext size, valid for a ciphertext of ciphertextSize bytes
	private long ciphertextSize; // 0 while the fresh header of an empty file has not been persisted

	/**
	 * Opens a ciphertext file, reading and authenticating its header. Everything acquired here is released by {@link #close()}, also if this constructor fails.
	 * <p>
	 * An empty ciphertext file is an empty cleartext file. A writable handle immediately writes a fresh header to it, so that all later opens share that header; a
	 * read-only handle keeps a fresh header in memory until the ciphertext is written by someone else. {@code TRUNCATE_EXISTING} is applied to the cleartext of
	 * a writable handle after opening, so the header survives; like NIO, it is ignored on read-only handles.
	 *
	 * @param vault the unlocked vault
	 * @param creationLock serialises writable opens of an empty ciphertext across all handles of a file system, so only one header is ever persisted
	 * @param opener opens the ciphertext file on the delegate
	 * @param writable whether the delegate is opened for writing
	 * @param truncate whether the caller asked for {@code TRUNCATE_EXISTING}
	 * @throws IOException if the ciphertext cannot be opened, or its header cannot be read or written, is unauthentic, or the ciphertext size is invalid
	 */
	public UvfVfsFile(UnlockedVault vault, Lock creationLock, Opener opener, boolean writable, boolean truncate) throws IOException {
		var opened = Opened.open(vault, opener);
		this.vault = vault;
		this.delegate = opened.delegate();
		this.vaultFile = opened.vaultFile();
		this.ciphertextSize = opened.ciphertextSize();
		if (!writable) {
			return;
		}
		try { // every field is set, so from here on close() releases everything
			persistHeaderIfEmpty(creationLock);
			if (truncate) {
				truncate(0);
			}
		} catch (IOException | RuntimeException e) {
			Closeables.suppressWhileClosing(this, e);
			throw e;
		}
	}

	// the resources a handle needs, acquired together: on failure nothing half-open escapes
	private record Opened(VfsFile delegate, VaultFile vaultFile, long ciphertextSize) {

		static Opened open(UnlockedVault vault, Opener opener) throws IOException {
			var delegate = opener.open();
			try {
				long ciphertextSize = delegate.readMetadata().size();
				return new Opened(delegate, load(delegate, vault, ciphertextSize), ciphertextSize);
			} catch (IOException | RuntimeException e) {
				Closeables.suppressWhileClosing(delegate, e);
				throw e;
			}
		}
	}

	// a writable handle on an empty ciphertext writes its header right away, so every later open shares it; the lock keeps two such handles from racing
	private void persistHeaderIfEmpty(Lock creationLock) throws IOException {
		if (ciphertextSize != 0) {
			return;
		}
		creationLock.lock();
		try {
			if (sync().size() == 0) { // if another handle persisted its header while we waited, sync() has adopted it instead
				writeUnsynced(ByteBuffer.allocate(0), 0); // persists the header and, depending on the layout, the EOF chunk
			}
		} finally {
			creationLock.unlock();
		}
	}

	// derives the vault file for a ciphertext of the given size, reading the header from the delegate unless the ciphertext is empty
	private static VaultFile load(VfsFile delegate, UnlockedVault vault, long ciphertextSize) throws IOException {
		if (ciphertextSize == 0) {
			return vault.createFile();
		}
		var header = ByteBuffer.allocate(vault.headerSize());
		while (header.hasRemaining()) {
			if (delegate.read(header, header.position()) < 0) {
				throw new IOException("Unexpected end of file while reading header");
			}
		}
		header.flip();
		try {
			return vault.openFile(header, ciphertextSize);
		} catch (AuthenticationFailedException | IllegalArgumentException e) {
			throw new IOException("Invalid file header or size", e);
		}
	}

	// picks up size and header changes made through other handles since this one last looked, returns the current ciphertext metadata
	private VfsNodeMetadata sync() throws IOException {
		var metadata = delegate.readMetadata();
		long current = metadata.size();
		if (current == ciphertextSize) {
			return metadata;
		}
		if (ciphertextSize == 0 || current == 0) {
			// this handle's header was never persisted, so the one on disk is somebody else's; or the file was emptied behind our back
			var previous = vaultFile;
			vaultFile = load(delegate, vault, current);
			previous.close();
		} else {
			try {
				vaultFile.adoptCiphertextSize(current); // the header is written once and never changes, only the size is stale
			} catch (IllegalArgumentException e) {
				throw new IOException("Invalid ciphertext size " + current, e);
			}
		}
		ciphertextSize = current;
		return metadata;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @implNote Reads are optimistic: the ciphertext size is only re-checked when reading at or beyond the known size, or after a chunk failed to read. As every
	 * chunk is authenticated, a stale size cannot yield wrong bytes; it shows as a false end of file (another handle extended the file), a short chunk (another
	 * handle truncated it) or a failed authentication (another handle truncated and rewrote it), and the read is retried once with the current size.
	 */
	@Override
	public synchronized int read(ByteBuffer dst, long offset) throws IOException {
		if (offset >= vaultFile.size()) {
			sync();
		}
		long knownSize = ciphertextSize;
		int start = dst.position();
		try {
			return vaultFile.read(offset, dst, delegate::read);
		} catch (EOFException | AuthenticationFailedException e) {
			dst.position(start);
			if (sync().size() != knownSize) {
				return readSynced(dst, offset);
			}
			if (e instanceof EOFException eof) {
				throw eof;
			}
			throw new IOException("Unauthentic file content", e);
		}
	}

	private int readSynced(ByteBuffer dst, long offset) throws IOException {
		try {
			return vaultFile.read(offset, dst, delegate::read);
		} catch (AuthenticationFailedException e) {
			throw new IOException("Unauthentic file content", e);
		}
	}

	@Override
	public synchronized int write(ByteBuffer src, long offset) throws IOException {
		sync();
		return writeUnsynced(src, offset);
	}

	private int writeUnsynced(ByteBuffer src, long offset) throws IOException {
		try {
			int written = vaultFile.write(offset, src, delegate::read, delegate::write);
			ciphertextSize = vault.ciphertextSize(vaultFile.size());
			return written;
		} catch (AuthenticationFailedException e) {
			throw new IOException("Unauthentic file content", e);
		}
	}

	@Override
	public synchronized VfsNodeMetadata readMetadata() throws IOException {
		var ciphertextMetadata = sync();
		return new VfsNodeMetadata(
				VfsNodeType.FILE,
				vaultFile.size(),
				ciphertextMetadata.fileId(),
				ciphertextMetadata.permissions(),
				ciphertextMetadata.lastModifiedTime(),
				ciphertextMetadata.lastAccessTime(),
				ciphertextMetadata.changeTime(),
				ciphertextMetadata.creationTime()
		);
	}

	@Override
	public synchronized void truncate(long size) throws IOException {
		if (size < 0) {
			throw new IllegalArgumentException("Negative size");
		}
		sync();
		long currentSize = vaultFile.size();
		if (size < currentSize) {
			try {
				vaultFile.truncate(size, delegate::read, delegate::write);
			} catch (AuthenticationFailedException e) {
				throw new IOException("Unauthentic file content", e);
			}
			ciphertextSize = vault.ciphertextSize(size);
			delegate.truncate(ciphertextSize); // the header stays, so an emptied file never looks like a never-written one
		} else if (size > currentSize) {
			writeUnsynced(ByteBuffer.allocate(1), size - 1); // zero-fills the gap and the last byte
		}
	}

	@Override
	public void setTimes(VfsTimes times) throws IOException {
		delegate.setTimes(times);
	}

	@Override
	public void force(boolean metadata) throws IOException {
		delegate.force(metadata);
	}

	@Override
	public synchronized void close() throws IOException {
		var file = vaultFile; // a local copy, as try-with-resources needs an effectively final variable
		try (file) {
			delegate.close();
		}
	}
}
