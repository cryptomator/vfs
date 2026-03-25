package org.cryptomator.vfs.middleware.uvf.content;

import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.vfs.api.VfsFile;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * A {@link VfsFile} decorator that transparently encrypts writes and decrypts reads
 * using the UVF chunked file format.
 * <p>
 * File layout on the delegate:
 * <pre>
 * [header (68 bytes)] [chunk 0 (32812 bytes)] [chunk 1] ... [chunk N]
 * </pre>
 * Each cleartext chunk is up to {@code cleartextChunkSize} bytes. Each ciphertext chunk
 * is {@code ciphertextChunkSize} bytes (nonce + encrypted payload + GCM tag).
 */
public final class UvfVfsFile implements VfsFile {

	private final VfsFile delegate;
	private final FileHeader header;
	private final FileContentCryptor contentCryptor;
	private final int headerSize;
	private final int cleartextChunkSize;
	private final int ciphertextChunkSize;

	private UvfVfsFile(VfsFile delegate, FileHeader header, FileContentCryptor contentCryptor, int headerSize) {
		this.delegate = delegate;
		this.header = header;
		this.contentCryptor = contentCryptor;
		this.headerSize = headerSize;
		this.cleartextChunkSize = contentCryptor.cleartextChunkSize();
		this.ciphertextChunkSize = contentCryptor.ciphertextChunkSize();
	}

	/**
	 * Opens an existing encrypted file, reading and decrypting its header.
	 *
	 * @param delegate       the ciphertext file on the delegate filesystem
	 * @param headerCryptor  cryptor for file headers
	 * @param contentCryptor cryptor for file content chunks
	 * @return an encrypted file handle
	 * @throws IOException if reading or decrypting the header fails
	 */
	public static UvfVfsFile openExisting(VfsFile delegate, FileHeaderCryptor headerCryptor, FileContentCryptor contentCryptor) throws IOException {
		int headerSize = headerCryptor.headerSize();
		ByteBuffer headerBuf = ByteBuffer.allocate(headerSize);
		int totalRead = 0;
		while (headerBuf.hasRemaining()) {
			int read = delegate.read(headerBuf, totalRead);
			if (read == -1) {
				throw new IOException("Unexpected end of file while reading header");
			}
			totalRead += read;
		}
		headerBuf.flip();
		FileHeader header = headerCryptor.decryptHeader(headerBuf);
		return new UvfVfsFile(delegate, header, contentCryptor, headerSize);
	}

	/**
	 * Creates a new encrypted file, generating and writing a fresh header.
	 *
	 * @param delegate       the ciphertext file on the delegate filesystem
	 * @param headerCryptor  cryptor for file headers
	 * @param contentCryptor cryptor for file content chunks
	 * @return an encrypted file handle
	 * @throws IOException if writing the header fails
	 */
	public static UvfVfsFile createNew(VfsFile delegate, FileHeaderCryptor headerCryptor, FileContentCryptor contentCryptor) throws IOException {
		int headerSize = headerCryptor.headerSize();
		FileHeader header = headerCryptor.create();
		ByteBuffer headerBuf = headerCryptor.encryptHeader(header);
		delegate.write(headerBuf, 0);
		return new UvfVfsFile(delegate, header, contentCryptor, headerSize);
	}

	@Override
	public int read(ByteBuffer dst, long offset) throws IOException {
		if (offset < 0) {
			throw new IllegalArgumentException("Negative offset");
		}

		int totalRead = 0;
		while (dst.hasRemaining()) {
			long currentOffset = offset + totalRead;
			long chunkNumber = currentOffset / cleartextChunkSize;
			int offsetInChunk = (int) (currentOffset % cleartextChunkSize);

			// read the ciphertext chunk from delegate
			long ciphertextOffset = headerSize + chunkNumber * ciphertextChunkSize;
			ByteBuffer ciphertextChunk = ByteBuffer.allocate(ciphertextChunkSize);
			int chunkBytesRead = readFully(ciphertextChunk, ciphertextOffset);
			if (chunkBytesRead == 0) {
				break; // EOF
			}
			ciphertextChunk.flip();

			// decrypt
			ByteBuffer cleartextChunk = contentCryptor.decryptChunk(ciphertextChunk, chunkNumber, header, true);

			// skip to offset within chunk and copy to dst
			if (offsetInChunk >= cleartextChunk.remaining()) {
				break; // offset beyond available data in this chunk
			}
			cleartextChunk.position(cleartextChunk.position() + offsetInChunk);
			int bytesToCopy = Math.min(cleartextChunk.remaining(), dst.remaining());
			int oldLimit = cleartextChunk.limit();
			cleartextChunk.limit(cleartextChunk.position() + bytesToCopy);
			dst.put(cleartextChunk);
			cleartextChunk.limit(oldLimit);
			totalRead += bytesToCopy;
		}

		return totalRead == 0 ? -1 : totalRead;
	}

	@Override
	public int write(ByteBuffer src, long offset) throws IOException {
		if (offset < 0) {
			throw new IllegalArgumentException("Negative offset");
		}

		int totalWritten = 0;
		while (src.hasRemaining()) {
			long currentOffset = offset + totalWritten;
			long chunkNumber = currentOffset / cleartextChunkSize;
			int offsetInChunk = (int) (currentOffset % cleartextChunkSize);

			// if writing to the middle of a chunk, read-decrypt-modify-encrypt
			ByteBuffer cleartextChunk;
			if (offsetInChunk > 0 || src.remaining() < cleartextChunkSize) {
				cleartextChunk = readExistingChunkOrAllocate(chunkNumber);
			} else {
				cleartextChunk = ByteBuffer.allocate(cleartextChunkSize);
			}

			// write src data into the cleartext chunk at the correct position
			cleartextChunk.position(offsetInChunk);
			int bytesToWrite = Math.min(src.remaining(), cleartextChunk.remaining());
			int oldLimit = src.limit();
			src.limit(src.position() + bytesToWrite);
			cleartextChunk.put(src);
			src.limit(oldLimit);

			// adjust limit to actual data end (max of old data and new data)
			int newDataEnd = offsetInChunk + bytesToWrite;
			if (newDataEnd > cleartextChunk.limit()) {
				cleartextChunk.limit(newDataEnd);
			}
			cleartextChunk.flip();

			// encrypt and write
			ByteBuffer ciphertextChunk = contentCryptor.encryptChunk(cleartextChunk, chunkNumber, header);
			long ciphertextOffset = headerSize + chunkNumber * ciphertextChunkSize;
			delegate.write(ciphertextChunk, ciphertextOffset);

			totalWritten += bytesToWrite;
		}

		return totalWritten;
	}

	@Override
	public void force(boolean metadata) throws IOException {
		delegate.force(metadata);
	}

	@Override
	public void close() throws IOException {
		delegate.close();
	}

	/**
	 * Reads an existing ciphertext chunk and decrypts it, or allocates a new empty buffer
	 * if the chunk doesn't exist yet (i.e., writing beyond current file size).
	 */
	private ByteBuffer readExistingChunkOrAllocate(long chunkNumber) throws IOException {
		long ciphertextOffset = headerSize + chunkNumber * ciphertextChunkSize;
		ByteBuffer ciphertextChunk = ByteBuffer.allocate(ciphertextChunkSize);
		int bytesRead = readFully(ciphertextChunk, ciphertextOffset);
		if (bytesRead == 0) {
			// chunk doesn't exist yet — return empty buffer
			return ByteBuffer.allocate(cleartextChunkSize);
		}
		ciphertextChunk.flip();
		return contentCryptor.decryptChunk(ciphertextChunk, chunkNumber, header, true);
	}

	/**
	 * Reads as many bytes as possible into {@code buf} from the delegate at the given offset.
	 *
	 * @return the number of bytes actually read (0 if EOF immediately)
	 */
	private int readFully(ByteBuffer buf, long offset) throws IOException {
		int totalRead = 0;
		while (buf.hasRemaining()) {
			int read = delegate.read(buf, offset + totalRead);
			if (read == -1) {
				break;
			}
			totalRead += read;
		}
		return totalRead;
	}
}
