package org.cryptomator.vfs.middleware.uvf.content;

import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UvfVfsFileTest {

	private UvfUnlockedVault vault;

	@BeforeEach
	void setUp() {
		vault = UvfUnlockedVault.create(new SecureRandom());
	}

	@AfterEach
	void tearDown() {
		vault.destroy();
	}

	private UvfVfsFile createNew(VfsFile backing) {
		return new UvfVfsFile(backing, vault, vault.createFile());
	}

	private UvfVfsFile openExisting(VfsFile backing) throws IOException {
		return UvfVfsFile.open(backing, vault);
	}

	private static byte[] readAll(VfsFile file, int size) throws IOException {
		var buf = ByteBuffer.allocate(size);
		while (buf.hasRemaining() && file.read(buf, buf.position()) >= 0) {
			// keep reading
		}
		return Arrays.copyOf(buf.array(), buf.position());
	}

	@Test
	@DisplayName("write then read small content")
	void writeAndReadSmallContent() throws IOException {
		var backing = new InMemoryVfsFile();
		byte[] cleartext = "Hello, World!".getBytes(StandardCharsets.UTF_8);

		try (var file = createNew(backing)) {
			assertEquals(cleartext.length, file.write(ByteBuffer.wrap(cleartext), 0));
		}

		assertTrue(backing.size() > cleartext.length);
		try (var file = openExisting(backing)) {
			assertArrayEquals(cleartext, readAll(file, 100));
		}
	}

	@Test
	@DisplayName("write then read content spanning multiple chunks")
	void writeAndReadMultiChunk() throws IOException {
		var backing = new InMemoryVfsFile();
		byte[] cleartext = new byte[vault.cleartextChunkSize() * 3 + 17];
		new SecureRandom().nextBytes(cleartext);

		try (var file = createNew(backing)) {
			file.write(ByteBuffer.wrap(cleartext), 0);
		}

		try (var file = openExisting(backing)) {
			assertArrayEquals(cleartext, readAll(file, cleartext.length + 10));
		}
	}

	@Test
	@DisplayName("read with offset into middle of chunk")
	void readWithOffset() throws IOException {
		var backing = new InMemoryVfsFile();
		byte[] cleartext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

		try (var file = createNew(backing)) {
			file.write(ByteBuffer.wrap(cleartext), 0);
		}

		try (var file = openExisting(backing)) {
			ByteBuffer dst = ByteBuffer.allocate(10);
			assertEquals(10, file.read(dst, 5));
			assertEquals("FGHIJKLMNO", new String(dst.array(), StandardCharsets.UTF_8));
		}
	}

	@Test
	@DisplayName("read beyond end of file returns -1")
	void readBeyondEof() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var file = createNew(backing)) {
			file.write(ByteBuffer.wrap("short".getBytes(StandardCharsets.UTF_8)), 0);
		}

		try (var file = openExisting(backing)) {
			assertEquals(-1, file.read(ByteBuffer.allocate(10), 1000));
			assertEquals(-1, file.read(ByteBuffer.allocate(10), 5));
		}
	}

	@Test
	@DisplayName("sequential small writes append within a chunk, gaps are zero-filled")
	void sequentialSmallWrites() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var file = createNew(backing)) {
			assertEquals(2, file.write(ByteBuffer.wrap("hi".getBytes(StandardCharsets.UTF_8)), 0));
			assertEquals(1, file.write(ByteBuffer.wrap("!".getBytes(StandardCharsets.UTF_8)), 2));
			assertEquals(1, file.write(ByteBuffer.wrap("?".getBytes(StandardCharsets.UTF_8)), 5));
		}

		try (var file = openExisting(backing)) {
			assertArrayEquals(new byte[]{'h', 'i', '!', 0, 0, '?'}, readAll(file, 10));
		}
	}

	@Test
	@DisplayName("readMetadata reports cleartext size")
	void readMetadataReportsCleartextSize() throws IOException {
		var backing = new InMemoryVfsFile();
		byte[] cleartext = new byte[vault.cleartextChunkSize() + 7];

		try (var file = createNew(backing)) {
			assertEquals(0, file.readMetadata().size());
			assertEquals(VfsNodeType.FILE, file.readMetadata().type());
			file.write(ByteBuffer.wrap(cleartext), 0);
			assertEquals(cleartext.length, file.readMetadata().size());
		}
		try (var file = openExisting(backing)) {
			assertEquals(cleartext.length, file.readMetadata().size());
		}
	}

	@Test
	@DisplayName("truncate mid-chunk keeps the remaining data readable")
	void truncateMidChunk() throws IOException {
		var backing = new InMemoryVfsFile();
		byte[] cleartext = new byte[vault.cleartextChunkSize() * 2 + 100];
		new SecureRandom().nextBytes(cleartext);
		int newSize = vault.cleartextChunkSize() + 50;

		try (var file = createNew(backing)) {
			file.write(ByteBuffer.wrap(cleartext), 0);
			file.truncate(newSize);
			assertEquals(newSize, file.readMetadata().size());
		}

		assertEquals(vault.ciphertextSize(newSize), backing.size());
		try (var file = openExisting(backing)) {
			assertEquals(newSize, file.readMetadata().size());
			assertArrayEquals(Arrays.copyOf(cleartext, newSize), readAll(file, newSize + 10));
		}
	}

	@Test
	@DisplayName("truncate to zero leaves a valid empty file")
	void truncateToZero() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var file = createNew(backing)) {
			file.write(ByteBuffer.wrap("hello".getBytes(StandardCharsets.UTF_8)), 0);
			file.truncate(0);
			assertEquals(0, file.readMetadata().size());
		}

		assertEquals(vault.ciphertextSize(0), backing.size());
		try (var file = openExisting(backing)) {
			assertEquals(0, file.readMetadata().size());
			assertEquals(-1, file.read(ByteBuffer.allocate(1), 0));
		}
	}

	@Test
	@DisplayName("truncate beyond end zero-extends")
	void truncateExtends() throws IOException {
		var backing = new InMemoryVfsFile();
		int newSize = vault.cleartextChunkSize() + 3;

		try (var file = createNew(backing)) {
			file.write(ByteBuffer.wrap("hi".getBytes(StandardCharsets.UTF_8)), 0);
			file.truncate(newSize);
			assertEquals(newSize, file.readMetadata().size());

			byte[] expected = new byte[newSize];
			expected[0] = 'h';
			expected[1] = 'i';
			assertArrayEquals(expected, readAll(file, newSize));
		}
	}

	@Test
	@DisplayName("header is written on first write and starts with the UVF magic bytes")
	void headerContainsMagicBytes() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var file = createNew(backing)) {
			assertEquals(0, backing.size());
			file.write(ByteBuffer.wrap("x".getBytes(StandardCharsets.UTF_8)), 0);
		}

		assertTrue(backing.size() >= vault.headerSize());
		ByteBuffer header = ByteBuffer.allocate(4);
		backing.read(header, 0);
		assertArrayEquals(new byte[]{'u', 'v', 'f', 0x00}, header.array());
	}

	@Test
	@DisplayName("open of an empty backing file yields a fresh empty file")
	void openEmptyBacking() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var file = openExisting(backing)) {
			assertEquals(0, file.readMetadata().size());
		}
	}

	@Test
	@DisplayName("open fails on garbage")
	void openFailsOnGarbage() throws IOException {
		var backing = new InMemoryVfsFile();
		byte[] garbage = new byte[vault.headerSize() + 10];
		new SecureRandom().nextBytes(garbage);
		backing.write(ByteBuffer.wrap(garbage), 0);

		assertThrows(IOException.class, () -> openExisting(backing));
	}

	@Test
	@DisplayName("size calculations are consistent")
	void sizeCalculation() {
		for (long size : new long[]{0, 1, vault.cleartextChunkSize() - 1, vault.cleartextChunkSize(), vault.cleartextChunkSize() + 1, 12345L}) {
			assertEquals(size, vault.cleartextSize(vault.ciphertextSize(size)));
		}
	}

	/**
	 * Simple in-memory VfsFile implementation for testing.
	 */
	static class InMemoryVfsFile implements VfsFile {

		private byte[] data = new byte[0];

		@Override
		public int read(ByteBuffer dst, long offset) {
			if (offset >= data.length) {
				return -1;
			}
			int available = (int) Math.min(dst.remaining(), data.length - offset);
			dst.put(data, (int) offset, available);
			return available;
		}

		@Override
		public int write(ByteBuffer src, long offset) {
			int length = src.remaining();
			int requiredSize = (int) offset + length;
			if (requiredSize > data.length) {
				data = Arrays.copyOf(data, requiredSize);
			}
			src.get(data, (int) offset, length);
			return length;
		}

		@Override
		public VfsNodeMetadata readMetadata() {
			return new VfsNodeMetadata(VfsNodeType.FILE, data.length, VfsNodeMetadata.NO_FILE_ID, Set.of(), Instant.EPOCH, Instant.EPOCH, Instant.EPOCH, Instant.EPOCH);
		}

		@Override
		public void truncate(long size) {
			data = Arrays.copyOf(data, (int) size);
		}

		@Override
		public void setTimes(VfsTimes times) {
		}

		@Override
		public void force(boolean metadata) {
		}

		@Override
		public void close() {
		}

		int size() {
			return data.length;
		}
	}
}
