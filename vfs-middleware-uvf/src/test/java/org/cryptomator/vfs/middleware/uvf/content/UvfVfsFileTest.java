package org.cryptomator.vfs.middleware.uvf.content;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.cryptomator.vfs.api.VfsFile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("deprecation")
class UvfVfsFileTest {

	private static final String SAMPLE_PAYLOAD = """
			{
			    "fileFormat": "AES-256-GCM-32k",
			    "nameFormat": "AES-SIV-512-B64URL",
			    "seeds": {
			        "HDm38g": "ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs",
			        "gBryKw": "PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0",
			        "QBsJFg": "Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y"
			    },
			    "initialSeed": "HDm38i",
			    "latestSeed": "QBsJFo",
			    "kdf": "HKDF-SHA512",
			    "kdfSalt": "NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8"
			}""";

	private Cryptor cryptor;
	private FileHeaderCryptor headerCryptor;
	private FileContentCryptor contentCryptor;

	@BeforeEach
	void setUp() {
		var masterkey = UVFMasterkey.fromDecryptedPayload(SAMPLE_PAYLOAD);
		cryptor = CryptorProvider.forScheme(CryptorProvider.Scheme.UVF_DRAFT).provide(masterkey, new SecureRandom());
		headerCryptor = cryptor.fileHeaderCryptor();
		contentCryptor = cryptor.fileContentCryptor();
	}

	@Test
	@DisplayName("write then read small content")
	void writeAndReadSmallContent() throws IOException {
		var backing = new InMemoryVfsFile();
		byte[] cleartext = "Hello, World!".getBytes(StandardCharsets.UTF_8);

		try (var file = UvfVfsFile.createNew(backing, headerCryptor, contentCryptor)) {
			file.write(ByteBuffer.wrap(cleartext), 0);
		}

		// ciphertext should be larger than cleartext (header + chunk overhead)
		assertTrue(backing.size() > cleartext.length);

		try (var file = UvfVfsFile.openExisting(backing, headerCryptor, contentCryptor)) {
			ByteBuffer dst = ByteBuffer.allocate(cleartext.length);
			int read = file.read(dst, 0);
			assertEquals(cleartext.length, read);
			assertArrayEquals(cleartext, dst.array());
		}
	}

	@Test
	@DisplayName("write then read content spanning multiple chunks")
	void writeAndReadMultiChunkContent() throws IOException {
		var backing = new InMemoryVfsFile();
		// write 2.5 chunks worth of data
		int dataSize = contentCryptor.cleartextChunkSize() * 2 + contentCryptor.cleartextChunkSize() / 2;
		byte[] cleartext = new byte[dataSize];
		Arrays.fill(cleartext, (byte) 0x42);

		try (var file = UvfVfsFile.createNew(backing, headerCryptor, contentCryptor)) {
			file.write(ByteBuffer.wrap(cleartext), 0);
		}

		try (var file = UvfVfsFile.openExisting(backing, headerCryptor, contentCryptor)) {
			ByteBuffer dst = ByteBuffer.allocate(dataSize);
			int totalRead = 0;
			while (dst.hasRemaining()) {
				int read = file.read(dst, totalRead);
				if (read == -1) break;
				totalRead += read;
			}
			assertEquals(dataSize, totalRead);
			assertArrayEquals(cleartext, dst.array());
		}
	}

	@Test
	@DisplayName("read with offset into middle of chunk")
	void readWithOffset() throws IOException {
		var backing = new InMemoryVfsFile();
		byte[] cleartext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);

		try (var file = UvfVfsFile.createNew(backing, headerCryptor, contentCryptor)) {
			file.write(ByteBuffer.wrap(cleartext), 0);
		}

		try (var file = UvfVfsFile.openExisting(backing, headerCryptor, contentCryptor)) {
			ByteBuffer dst = ByteBuffer.allocate(10);
			int read = file.read(dst, 5); // read "FGHIJKLMNO"
			assertEquals(10, read);
			assertEquals("FGHIJKLMNO", new String(dst.array(), StandardCharsets.UTF_8));
		}
	}

	@Test
	@DisplayName("read beyond end of file returns -1")
	void readBeyondEof() throws IOException {
		var backing = new InMemoryVfsFile();
		byte[] cleartext = "short".getBytes(StandardCharsets.UTF_8);

		try (var file = UvfVfsFile.createNew(backing, headerCryptor, contentCryptor)) {
			file.write(ByteBuffer.wrap(cleartext), 0);
		}

		try (var file = UvfVfsFile.openExisting(backing, headerCryptor, contentCryptor)) {
			ByteBuffer dst = ByteBuffer.allocate(10);
			int read = file.read(dst, 1000);
			assertEquals(-1, read);
		}
	}

	@Test
	@DisplayName("createNew writes header with UVF magic bytes")
	void headerContainsMagicBytes() throws IOException {
		var backing = new InMemoryVfsFile();

		try (var ignored = UvfVfsFile.createNew(backing, headerCryptor, contentCryptor)) {
			// just create the file
		}

		assertTrue(backing.size() >= 4);
		ByteBuffer header = ByteBuffer.allocate(4);
		backing.read(header, 0);
		assertArrayEquals(new byte[]{'u', 'v', 'f', 0x00}, header.array());
	}

	@Test
	@DisplayName("openExisting fails on empty file")
	void openExistingFailsOnEmptyFile() {
		var backing = new InMemoryVfsFile();
		assertThrows(IOException.class, () -> UvfVfsFile.openExisting(backing, headerCryptor, contentCryptor));
	}

	@Test
	@DisplayName("cleartext size calculations are consistent")
	void cleartextSizeCalculation() {
		int headerSize = headerCryptor.headerSize();
		int cleartextChunkSize = contentCryptor.cleartextChunkSize();
		int ciphertextChunkSize = contentCryptor.ciphertextChunkSize();

		// one full chunk
		long ciphertextPayload = ciphertextChunkSize;
		long cleartext = contentCryptor.cleartextSize(ciphertextPayload);
		assertEquals(cleartextChunkSize, cleartext);

		// round-trip: cleartext -> ciphertext -> cleartext
		long originalSize = 12345L;
		long cipherSize = contentCryptor.ciphertextSize(originalSize);
		long roundTripped = contentCryptor.cleartextSize(cipherSize);
		assertEquals(originalSize, roundTripped);
	}

	/**
	 * Simple in-memory VfsFile implementation for testing.
	 */
	static class InMemoryVfsFile implements VfsFile {

		private byte[] data = new byte[0];

		@Override
		public int read(ByteBuffer dst, long offset) throws IOException {
			if (offset >= data.length) {
				return -1;
			}
			int available = (int) Math.min(dst.remaining(), data.length - offset);
			dst.put(data, (int) offset, available);
			return available;
		}

		@Override
		public int write(ByteBuffer src, long offset) throws IOException {
			int length = src.remaining();
			int requiredSize = (int) offset + length;
			if (requiredSize > data.length) {
				data = Arrays.copyOf(data, requiredSize);
			}
			src.get(data, (int) offset, length);
			return length;
		}

		@Override
		public void force(boolean metadata) {}

		@Override
		public void close() {}

		int size() {
			return data.length;
		}
	}
}
