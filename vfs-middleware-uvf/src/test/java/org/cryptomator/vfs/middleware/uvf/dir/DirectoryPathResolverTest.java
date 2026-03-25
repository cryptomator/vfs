package org.cryptomator.vfs.middleware.uvf.dir;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.DirectoryMetadata;
import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;

import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class DirectoryPathResolverTest {

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

	private DirectoryContentCryptor dirCryptor;
	private VfsFileSystem delegate;
	private DirectoryPathResolver resolver;

	@BeforeEach
	void setUp() {
		var masterkey = UVFMasterkey.fromDecryptedPayload(SAMPLE_PAYLOAD);
		var cryptor = CryptorProvider.forScheme(CryptorProvider.Scheme.UVF_DRAFT).provide(masterkey, new SecureRandom());
		dirCryptor = cryptor.directoryContentCryptor();
		delegate = mock(VfsFileSystem.class);
		resolver = new DirectoryPathResolver(delegate, dirCryptor);
	}

	@Test
	void resolveRootPath() throws IOException {
		var resolved = resolver.resolve("/");

		assertNotNull(resolved.ciphertextPath());
		assertTrue(resolved.ciphertextPath().startsWith("/d/"));
	}

	@Test
	void resolveRootReturnsConsistentPath() throws IOException {
		var first = resolver.resolve("/");
		var second = resolver.resolve("/");

		assertEquals(first.ciphertextPath(), second.ciphertextPath());
	}

	@Test
	void resolveFileInRoot() throws IOException {
		var resolved = resolver.resolve("/test.txt");

		assertNotNull(resolved.ciphertextPath());
		assertTrue(resolved.ciphertextPath().endsWith(".uvf"));
		assertTrue(resolved.ciphertextPath().startsWith("/d/"));
	}

	@Test
	void resolveFileInRootIsDeterministic() throws IOException {
		var first = resolver.resolve("/test.txt");
		var second = resolver.resolve("/test.txt");

		assertEquals(first.ciphertextPath(), second.ciphertextPath());
	}

	@Test
	void resolveSubdirectoryFile() throws IOException {
		// create directory metadata for "subdir"
		DirectoryMetadata subdirMetadata = dirCryptor.newDirectoryMetadata();
		byte[] encryptedMetadata = dirCryptor.encryptDirectoryMetadata(subdirMetadata);

		// mock reading dir.uvf for the encrypted "subdir" entry
		var dirUvfFile = mock(VfsFile.class);
		// the encrypted name of "subdir" under root
		var rootMetadata = dirCryptor.rootDirectoryMetadata();
		String encryptedSubdirName = dirCryptor.fileNameEncryptor(rootMetadata).encrypt("subdir");
		String rootContentDir = "/" + dirCryptor.dirPath(rootMetadata);
		String dirUvfPath = rootContentDir + "/" + encryptedSubdirName + "/dir.uvf";

		Mockito.doReturn(dirUvfFile).when(delegate).openFile(eq(dirUvfPath), eq(Set.of(READ)));
		Mockito.doAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			buf.put(encryptedMetadata);
			return encryptedMetadata.length;
		}).when(dirUvfFile).read(any(ByteBuffer.class), anyLong());

		var resolved = resolver.resolve("/subdir/file.txt");

		assertNotNull(resolved.ciphertextPath());
		assertTrue(resolved.ciphertextPath().endsWith(".uvf"));
		// the file should be in subdir's content directory, not root's
		String subdirContentDir = "/" + dirCryptor.dirPath(subdirMetadata);
		assertTrue(resolved.ciphertextPath().startsWith(subdirContentDir));
	}

	@Test
	void writeDirectoryMetadata() throws IOException {
		DirectoryMetadata metadata = dirCryptor.newDirectoryMetadata();
		var dirUvfFile = mock(VfsFile.class);
		Mockito.doReturn(dirUvfFile).when(delegate).createFile(
				eq("/d/AB/somepath/dir.uvf"), eq(Set.of(WRITE, CREATE_NEW)), eq(Set.of()));
		Mockito.doReturn(0).when(dirUvfFile).write(any(ByteBuffer.class), eq(0L));

		resolver.writeDirectoryMetadata("/d/AB/somepath", metadata);

		verify(delegate).createFile(eq("/d/AB/somepath/dir.uvf"), eq(Set.of(WRITE, CREATE_NEW)), eq(Set.of()));
	}

	@Nested
	@DisplayName("Name encryption round-trip")
	class NameEncryptionRoundTrip {

		@Test
		@DisplayName("decrypt(encrypt(name)) == name for file in root")
		void roundTripFileInRoot() {
			var rootMetadata = dirCryptor.rootDirectoryMetadata();
			var encryptor = dirCryptor.fileNameEncryptor(rootMetadata);
			var decryptor = dirCryptor.fileNameDecryptor(rootMetadata);

			String cleartext = "hello.txt";
			String ciphertext = encryptor.encrypt(cleartext);
			String decrypted = decryptor.decrypt(ciphertext);

			assertEquals(cleartext, decrypted);
		}

		@Test
		@DisplayName("decrypt(encrypt(name)) == name for file in nested directory")
		void roundTripFileInNestedDir() {
			var childMetadata = dirCryptor.newDirectoryMetadata();
			var encryptor = dirCryptor.fileNameEncryptor(childMetadata);
			var decryptor = dirCryptor.fileNameDecryptor(childMetadata);

			String cleartext = "deep-nested-file.md";
			String ciphertext = encryptor.encrypt(cleartext);
			String decrypted = decryptor.decrypt(ciphertext);

			assertEquals(cleartext, decrypted);
		}

		@Test
		@DisplayName("same name encrypted in different directories produces different ciphertext")
		void sameNameDifferentDirsDifferentCiphertext() {
			var dir1 = dirCryptor.newDirectoryMetadata();
			var dir2 = dirCryptor.newDirectoryMetadata();

			String ciphertext1 = dirCryptor.fileNameEncryptor(dir1).encrypt("file.txt");
			String ciphertext2 = dirCryptor.fileNameEncryptor(dir2).encrypt("file.txt");

			assertNotEquals(ciphertext1, ciphertext2);
		}
	}

	@Nested
	@DisplayName("Path resolution round-trip")
	class PathResolutionRoundTrip {

		@Test
		@DisplayName("resolve('/a/b.txt') encrypts each component and produces a valid ciphertext path")
		void resolveTwoLevelPath() throws IOException {
			// set up "a" as a directory with its own metadata
			DirectoryMetadata dirAMetadata = dirCryptor.newDirectoryMetadata();
			byte[] encryptedDirAMetadata = dirCryptor.encryptDirectoryMetadata(dirAMetadata);
			mockDirUvfRead("a", dirCryptor.rootDirectoryMetadata(), encryptedDirAMetadata);

			var resolved = resolver.resolve("/a/b.txt");

			// b.txt should be encrypted using dirA's metadata and live in dirA's content dir
			String expectedContentDir = "/" + dirCryptor.dirPath(dirAMetadata);
			String expectedEncryptedName = dirCryptor.fileNameEncryptor(dirAMetadata).encrypt("b.txt");
			assertEquals(expectedContentDir + "/" + expectedEncryptedName, resolved.ciphertextPath());
		}

		@Test
		@DisplayName("resolve('/x/y/z.bin') walks three levels")
		void resolveThreeLevelPath() throws IOException {
			DirectoryMetadata dirXMetadata = dirCryptor.newDirectoryMetadata();
			byte[] encryptedDirXMetadata = dirCryptor.encryptDirectoryMetadata(dirXMetadata);
			mockDirUvfRead("x", dirCryptor.rootDirectoryMetadata(), encryptedDirXMetadata);

			DirectoryMetadata dirYMetadata = dirCryptor.newDirectoryMetadata();
			byte[] encryptedDirYMetadata = dirCryptor.encryptDirectoryMetadata(dirYMetadata);
			mockDirUvfRead("y", dirXMetadata, encryptedDirYMetadata);

			var resolved = resolver.resolve("/x/y/z.bin");

			String expectedContentDir = "/" + dirCryptor.dirPath(dirYMetadata);
			String expectedEncryptedName = dirCryptor.fileNameEncryptor(dirYMetadata).encrypt("z.bin");
			assertEquals(expectedContentDir + "/" + expectedEncryptedName, resolved.ciphertextPath());
		}

		@Test
		@DisplayName("resolving same path twice gives identical result")
		void resolveIsDeterministic() throws IOException {
			DirectoryMetadata dirMetadata = dirCryptor.newDirectoryMetadata();
			byte[] encrypted = dirCryptor.encryptDirectoryMetadata(dirMetadata);
			mockDirUvfRead("docs", dirCryptor.rootDirectoryMetadata(), encrypted);

			var first = resolver.resolve("/docs/readme.md");
			var second = resolver.resolve("/docs/readme.md");

			assertEquals(first.ciphertextPath(), second.ciphertextPath());
		}

		private void mockDirUvfRead(String cleartextDirName, DirectoryMetadata parentMetadata, byte[] encryptedMetadata) throws IOException {
			String encryptedName = dirCryptor.fileNameEncryptor(parentMetadata).encrypt(cleartextDirName);
			String parentContentDir = "/" + dirCryptor.dirPath(parentMetadata);
			String dirUvfPath = parentContentDir + "/" + encryptedName + "/dir.uvf";

			var dirUvfFile = mock(VfsFile.class);
			Mockito.doReturn(dirUvfFile).when(delegate).openFile(eq(dirUvfPath), eq(Set.of(READ)));
			Mockito.doAnswer(invocation -> {
				ByteBuffer buf = invocation.getArgument(0);
				buf.put(encryptedMetadata);
				return encryptedMetadata.length;
			}).when(dirUvfFile).read(any(ByteBuffer.class), anyLong());
		}
	}

	@Nested
	@DisplayName("Seed rotation in directory metadata")
	class SeedRotation {

		private static final byte[] INITIAL_SEED_ID = Base64.getUrlDecoder().decode("HDm38i");
		private static final byte[] LATEST_SEED_ID = Base64.getUrlDecoder().decode("QBsJFo");

		@Test
		@DisplayName("root directory metadata uses initial seed")
		void rootUsesInitialSeed() {
			DirectoryMetadata rootMetadata = dirCryptor.rootDirectoryMetadata();
			byte[] encrypted = dirCryptor.encryptDirectoryMetadata(rootMetadata);

			// seed ID is at bytes 4-8 in the encrypted header (after 'uvf\0' magic bytes)
			byte[] seedIdBytes = Arrays.copyOfRange(encrypted, 4, 8);
			assertArrayEquals(INITIAL_SEED_ID, seedIdBytes, "root dir metadata should use initial seed");
		}

		@Test
		@DisplayName("newly created directory metadata uses latest seed")
		void newDirUsesLatestSeed() {
			DirectoryMetadata newMetadata = dirCryptor.newDirectoryMetadata();
			byte[] encrypted = dirCryptor.encryptDirectoryMetadata(newMetadata);

			byte[] seedIdBytes = Arrays.copyOfRange(encrypted, 4, 8);
			assertArrayEquals(LATEST_SEED_ID, seedIdBytes, "new dir metadata should use latest seed");
		}

		@Test
		@DisplayName("initial seed and latest seed are different")
		void initialAndLatestSeedDiffer() {
			DirectoryMetadata rootMetadata = dirCryptor.rootDirectoryMetadata();
			DirectoryMetadata newMetadata = dirCryptor.newDirectoryMetadata();

			byte[] rootEncrypted = dirCryptor.encryptDirectoryMetadata(rootMetadata);
			byte[] newEncrypted = dirCryptor.encryptDirectoryMetadata(newMetadata);

			byte[] rootSeedId = Arrays.copyOfRange(rootEncrypted, 4, 8);
			byte[] newSeedId = Arrays.copyOfRange(newEncrypted, 4, 8);

			assertNotEquals(Arrays.hashCode(rootSeedId), Arrays.hashCode(newSeedId),
					"root (initial seed) and new directory (latest seed) should use different seeds");
		}

		@Test
		@DisplayName("multiple new directories all use the latest seed")
		void multipleNewDirsUseLatestSeed() {
			DirectoryMetadata dir1 = dirCryptor.newDirectoryMetadata();
			DirectoryMetadata dir2 = dirCryptor.newDirectoryMetadata();
			DirectoryMetadata dir3 = dirCryptor.newDirectoryMetadata();

			byte[] seed1 = Arrays.copyOfRange(dirCryptor.encryptDirectoryMetadata(dir1), 4, 8);
			byte[] seed2 = Arrays.copyOfRange(dirCryptor.encryptDirectoryMetadata(dir2), 4, 8);
			byte[] seed3 = Arrays.copyOfRange(dirCryptor.encryptDirectoryMetadata(dir3), 4, 8);

			assertArrayEquals(LATEST_SEED_ID, seed1);
			assertArrayEquals(LATEST_SEED_ID, seed2);
			assertArrayEquals(LATEST_SEED_ID, seed3);
		}

		@Test
		@DisplayName("encrypt then decrypt preserves metadata regardless of seed")
		void encryptDecryptRoundTripWithDifferentSeeds() {
			DirectoryMetadata rootMetadata = dirCryptor.rootDirectoryMetadata();
			DirectoryMetadata newMetadata = dirCryptor.newDirectoryMetadata();

			// round-trip root metadata (initial seed)
			byte[] rootEncrypted = dirCryptor.encryptDirectoryMetadata(rootMetadata);
			DirectoryMetadata rootDecrypted = dirCryptor.decryptDirectoryMetadata(rootEncrypted);
			byte[] rootReEncrypted = dirCryptor.encryptDirectoryMetadata(rootDecrypted);
			DirectoryMetadata rootReDecrypted = dirCryptor.decryptDirectoryMetadata(rootReEncrypted);

			// root dir path should be stable across encrypt/decrypt cycles
			assertEquals(dirCryptor.dirPath(rootMetadata), dirCryptor.dirPath(rootDecrypted));
			assertEquals(dirCryptor.dirPath(rootMetadata), dirCryptor.dirPath(rootReDecrypted));

			// round-trip new metadata (latest seed)
			byte[] newEncrypted = dirCryptor.encryptDirectoryMetadata(newMetadata);
			DirectoryMetadata newDecrypted = dirCryptor.decryptDirectoryMetadata(newEncrypted);

			assertEquals(dirCryptor.dirPath(newMetadata), dirCryptor.dirPath(newDecrypted));
		}
	}
}
