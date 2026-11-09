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

	// TODO decide whether a cheaper size query is worth an API extension. The UVF middleware calls readMetadata() before every write, truncate and end-of-file read
	//  only to learn the ciphertext size, which on the NIO backend is a path-based stat, whereas FileChannel.size() is an fstat on the open descriptor. Measure
	//  first: a JMH benchmark on vfs-backend-nio comparing readMetadata() with FileChannel.size() on a local volume and on a network mount, and an
	//  async-profiler run of a sequential-write and an append-heavy workload through the UVF middleware to see whether the stat shows up at all. Only if it does,
	//  uncomment this method and implement it in every backend:
	//
	// /**
	//  * Reads the current size of this file, which is cheaper than {@link #readMetadata()} on backends that can query the open handle instead of the path.
	//  *
	//  * @return the current size in bytes
	//  * @throws IOException if the size cannot be read
	//  */
	// long size() throws IOException;

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
