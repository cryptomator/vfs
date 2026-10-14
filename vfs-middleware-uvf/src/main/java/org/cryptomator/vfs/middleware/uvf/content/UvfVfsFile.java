package org.cryptomator.vfs.middleware.uvf.content;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.UnlockedVault;
import org.cryptomator.cryptolib.api.VaultFile;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * A {@link VfsFile} decorator that transparently encrypts writes and decrypts reads using the vault's chunked file format.
 * <p>
 * All chunk arithmetic, read-modify-write of partial chunks and header handling is done by cryptolib's {@link VaultFile}; this class only connects it to the
 * ciphertext {@link VfsFile} on the delegate.
 */
public final class UvfVfsFile implements VfsFile {

	private final VfsFile delegate;
	private final UnlockedVault vault;
	private final VaultFile file;

	/**
	 * Wraps an open ciphertext file.
	 *
	 * @param delegate the ciphertext file on the delegate filesystem
	 * @param vault the unlocked vault
	 * @param file the vault file holding header and file key, either fresh from {@link UnlockedVault#createFile()} or opened from an existing header
	 */
	public UvfVfsFile(VfsFile delegate, UnlockedVault vault, VaultFile file) {
		this.delegate = delegate;
		this.vault = vault;
		this.file = file;
	}

	/**
	 * Opens a ciphertext file, reading and authenticating its header. An empty ciphertext file (created but never written) gets a fresh header that is persisted on the first write.
	 *
	 * @param delegate the ciphertext file on the delegate filesystem
	 * @param vault the unlocked vault
	 * @return an encrypted file handle
	 * @throws IOException if the header cannot be read, is unauthentic, or the ciphertext size is invalid
	 */
	public static UvfVfsFile open(VfsFile delegate, UnlockedVault vault) throws IOException {
		long ciphertextSize = delegate.readMetadata().size();
		if (ciphertextSize == 0) {
			return new UvfVfsFile(delegate, vault, vault.createFile());
		}
		var header = ByteBuffer.allocate(vault.headerSize());
		while (header.hasRemaining()) {
			if (delegate.read(header, header.position()) < 0) {
				throw new IOException("Unexpected end of file while reading header");
			}
		}
		header.flip();
		try {
			return new UvfVfsFile(delegate, vault, vault.openFile(header, ciphertextSize));
		} catch (AuthenticationFailedException | IllegalArgumentException e) {
			throw new IOException("Invalid file header or size", e);
		}
	}

	@Override
	public int read(ByteBuffer dst, long offset) throws IOException {
		try {
			return file.read(offset, dst, delegate::read);
		} catch (AuthenticationFailedException e) {
			throw new IOException("Unauthentic file content", e);
		}
	}

	@Override
	public int write(ByteBuffer src, long offset) throws IOException {
		try {
			return file.write(offset, src, delegate::read, delegate::write);
		} catch (AuthenticationFailedException e) {
			throw new IOException("Unauthentic file content", e);
		}
	}

	@Override
	public VfsNodeMetadata readMetadata() throws IOException {
		var ciphertextMetadata = delegate.readMetadata();
		return new VfsNodeMetadata(
				VfsNodeType.FILE,
				file.size(),
				ciphertextMetadata.fileId(),
				ciphertextMetadata.permissions(),
				ciphertextMetadata.lastModifiedTime(),
				ciphertextMetadata.lastAccessTime(),
				ciphertextMetadata.changeTime(),
				ciphertextMetadata.creationTime()
		);
	}

	@Override
	public void truncate(long size) throws IOException {
		if (size < 0) {
			throw new IllegalArgumentException("Negative size");
		}
		long currentSize = file.size();
		if (size < currentSize) {
			try {
				file.truncate(size, delegate::read, delegate::write);
			} catch (AuthenticationFailedException e) {
				throw new IOException("Unauthentic file content", e);
			}
			delegate.truncate(vault.ciphertextSize(size));
		} else if (size > currentSize) {
			write(ByteBuffer.allocate(1), size - 1); // zero-fills the gap and the last byte
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
	public void close() throws IOException {
		try (file) {
			delegate.close();
		}
	}
}
