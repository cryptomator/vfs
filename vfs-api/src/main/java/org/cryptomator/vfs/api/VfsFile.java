package org.cryptomator.vfs.api;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Open file handle abstraction used across VFS layers.
 */
public interface VfsFile extends AutoCloseable {

	int read(ByteBuffer dst, long offset) throws IOException;

	int write(ByteBuffer src, long offset) throws IOException;

	void force(boolean metadata) throws IOException;

	@Override
	void close() throws IOException;
}
