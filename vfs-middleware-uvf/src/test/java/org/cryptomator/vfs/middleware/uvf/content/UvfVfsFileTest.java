package org.cryptomator.vfs.middleware.uvf.content;

import org.cryptomator.cryptolib.api.UvfKeyEncryptionKey;
import org.cryptomator.cryptolib.api.UvfRecoveryKey;
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
		var csprng = new SecureRandom();
		vault = UvfUnlockedVault.create(csprng, UvfKeyEncryptionKey.password("pw"), UvfRecoveryKey.generate(csprng));
	}

	@AfterEach
	void tearDown() {
		vault.destroy();
	}

	private UvfVfsFile createNew(VfsFile backing) throws IOException {
		return UvfVfsFile.open(backing, vault, true);
	}

	private UvfVfsFile openExisting(VfsFile backing) throws IOException {
		return UvfVfsFile.open(backing, vault, false);
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
	@DisplayName("header is written on open and starts with the UVF magic bytes")
	void headerContainsMagicBytes() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var file = createNew(backing)) {
			assertTrue(backing.size() >= vault.headerSize());
			file.write(ByteBuffer.wrap("x".getBytes(StandardCharsets.UTF_8)), 0);
		}

		assertTrue(backing.size() >= vault.headerSize());
		ByteBuffer header = ByteBuffer.allocate(3); // followed by the format version byte, which the spec may bump
		backing.read(header, 0);
		assertArrayEquals(new byte[]{'u', 'v', 'f'}, header.array());
	}

	@Test
	@DisplayName("read-only open of an empty backing file yields an empty file and writes nothing")
	void openEmptyBacking() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var file = openExisting(backing)) {
			assertEquals(0, file.readMetadata().size());
		}

		assertEquals(0, backing.size());
	}

	@Test
	@DisplayName("writable open of an empty backing file persists the header right away")
	void writableOpenPersistsHeader() throws IOException {
		var backing = new InMemoryVfsFile();

		createNew(backing).close();

		assertEquals(vault.ciphertextSize(0), backing.size());
		try (var file = openExisting(backing)) {
			assertEquals(0, file.readMetadata().size());
			assertEquals(-1, file.read(ByteBuffer.allocate(1), 0));
		}
	}

	@Test
	@DisplayName("two writable handles share one header and see each other's writes")
	void twoWritersShareHeader() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var first = createNew(backing); var second = createNew(backing)) {
			first.write(ByteBuffer.wrap("hello".getBytes(StandardCharsets.UTF_8)), 0);
			assertEquals(5, second.readMetadata().size());
			assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), readAll(second, 100));

			second.write(ByteBuffer.wrap(" world".getBytes(StandardCharsets.UTF_8)), 5);
			assertArrayEquals("hello world".getBytes(StandardCharsets.UTF_8), readAll(first, 100));

			second.truncate(4);
			assertEquals(4, first.readMetadata().size());
			assertArrayEquals("hell".getBytes(StandardCharsets.UTF_8), readAll(first, 100));
		}
	}

	@Test
	@DisplayName("a read-only handle opened on an empty backing file adopts the header of a later writer")
	void readerAdoptsLaterHeader() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var reader = openExisting(backing)) {
			assertEquals(-1, reader.read(ByteBuffer.allocate(1), 0));
			try (var writer = createNew(backing)) {
				writer.write(ByteBuffer.wrap("late".getBytes(StandardCharsets.UTF_8)), 0);
			}
			assertEquals(4, reader.readMetadata().size());
			assertArrayEquals("late".getBytes(StandardCharsets.UTF_8), readAll(reader, 100));
		}
	}

	@Test
	@DisplayName("reads within the known size do not consult the delegate's metadata")
	void readWithinKnownSizeIsOptimistic() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var file = createNew(backing)) {
			file.write(ByteBuffer.wrap("hello".getBytes(StandardCharsets.UTF_8)), 0);
			backing.metadataReads = 0;

			assertEquals(5, file.read(ByteBuffer.allocate(5), 0));
			assertEquals(0, backing.metadataReads);
			assertEquals(-1, file.read(ByteBuffer.allocate(5), 5));
			assertEquals(1, backing.metadataReads);
		}
	}

	@Test
	@DisplayName("a read recovers from a truncation, an extension and a rewrite made through another handle")
	void readRecoversFromChangesByOtherHandle() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var first = createNew(backing); var second = createNew(backing)) {
			first.write(ByteBuffer.wrap("hello world".getBytes(StandardCharsets.UTF_8)), 0);

			second.truncate(4); // shorter chunk than first expects
			assertArrayEquals("hell".getBytes(StandardCharsets.UTF_8), readAll(first, 100));

			second.write(ByteBuffer.wrap("o again".getBytes(StandardCharsets.UTF_8)), 4); // extended beyond what first expects
			assertArrayEquals("hello again".getBytes(StandardCharsets.UTF_8), readAll(first, 100));

			second.truncate(0); // rewritten at a larger size, so the chunk first expects no longer authenticates
			second.write(ByteBuffer.wrap("something else entirely".getBytes(StandardCharsets.UTF_8)), 0);
			assertArrayEquals("something else entirely".getBytes(StandardCharsets.UTF_8), readAll(first, 100));
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

		int metadataReads;

		@Override
		public VfsNodeMetadata readMetadata() {
			metadataReads++;
			return new VfsNodeMetadata(VfsNodeType.FILE, data.length, VfsNodeMetadata.NO_FILE_ID, Set.of(), Instant.EPOCH, Instant.EPOCH, Instant.EPOCH, Instant.EPOCH);
		}

		@Override
		public void truncate(long size) {
			data = Arrays.copyOf(data, (int) size);
		}

		@Override
		public void setTimes(VfsTimes times) {
			// times are not tracked by this fake
		}

		@Override
		public void force(boolean metadata) {
			// nothing to flush, the content lives in memory
		}

		@Override
		public void close() {
			// nothing to release, the content lives in memory
		}

		int size() {
			return data.length;
		}
	}
}
