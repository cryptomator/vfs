package org.cryptomator.vfs.api;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Open file handle abstraction used across VFS layers; stays valid after the file has been renamed or deleted, until closed.
 */
public interface VfsFile extends AutoCloseable {

	/**
	 * Reads bytes starting at the given file offset into the buffer.
	 *
	 * @param dst destination buffer; bytes are written from its position up to its limit
	 * @param offset absolute file offset to start reading at
	 * @return the number of bytes read, or {@code -1} if {@code offset} is at or beyond the end of the file
	 * @throws IOException if the read fails
	 */
	int read(ByteBuffer dst, long offset) throws IOException;

	/**
	 * Writes the remaining bytes of the buffer starting at the given file offset, extending the file if necessary.
	 *
	 * @param src source buffer; bytes are read from its position up to its limit
	 * @param offset absolute file offset to start writing at
	 * @return the number of bytes written
	 * @throws IOException if the write fails
	 */
	int write(ByteBuffer src, long offset) throws IOException;

	/**
	 * Reads the current metadata of this file.
	 *
	 * @return metadata of the open file
	 * @throws IOException if the metadata cannot be read
	 */
	VfsNodeMetadata readMetadata() throws IOException;

	/**
	 * Sets the size of this file, truncating or zero-extending it.
	 *
	 * @param size the new size in bytes
	 * @throws IOException if the size cannot be changed
	 */
	void truncate(long size) throws IOException;

	/**
	 * Updates the timestamps of this file; {@code null} fields of {@code times} are left unchanged.
	 *
	 * @param times the timestamps to set
	 * @throws IOException if the timestamps cannot be changed
	 */
	void setTimes(VfsTimes times) throws IOException;

	/**
	 * Forces pending updates to the underlying storage.
	 *
	 * @param metadata whether metadata updates must be forced as well
	 * @throws IOException if the sync fails
	 */
	void force(boolean metadata) throws IOException;

	@Override
	void close() throws IOException;
}
