package org.cryptomator.vfs.middleware.uvf;

import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;
import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsNodeType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotLinkException;
import java.nio.file.StandardOpenOption;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UvfFileSystemTest {

	private static final Set<StandardOpenOption> WRITE = Set.of(StandardOpenOption.WRITE);
	private static final Set<StandardOpenOption> READ = Set.of(StandardOpenOption.READ);

	private SecureRandom csprng;
	private UvfUnlockedVault vault;
	private InMemoryVfsFileSystem ciphertext;
	private UvfFileSystem fs;

	@BeforeEach
	void setUp() throws IOException {
		csprng = new SecureRandom();
		vault = UvfUnlockedVault.create(csprng);
		ciphertext = new InMemoryVfsFileSystem();
		vault.rootDirectory().writeMetadataBackup(ciphertext::writeFile);
		fs = new UvfFileSystem(ciphertext, vault);
	}

	@AfterEach
	void tearDown() {
		fs.close();
	}

	private void writeFile(String path, String content) throws IOException {
		try (var file = fs.createFile(path, WRITE, Set.of())) {
			file.write(ByteBuffer.wrap(content.getBytes(StandardCharsets.UTF_8)), 0);
		}
	}

	private String readFile(String path) throws IOException {
		try (var file = fs.openFile(path, READ)) {
			var buf = ByteBuffer.allocate((int) file.readMetadata().size());
			while (buf.hasRemaining() && file.read(buf, buf.position()) >= 0) {
				// keep reading
			}
			return new String(buf.array(), 0, buf.position(), StandardCharsets.UTF_8);
		}
	}

	private Map<String, VfsDirectoryEntry> list(String path) throws IOException {
		var entries = new ArrayList<VfsDirectoryEntry>();
		try (var stream = fs.openDirectory(path)) {
			stream.forEach(entries::add);
		}
		return entries.stream().collect(Collectors.toMap(VfsDirectoryEntry::name, e -> e));
	}

	@Test
	@DisplayName("fresh vault has an empty root directory")
	void emptyRoot() throws IOException {
		assertEquals(VfsNodeType.DIRECTORY, fs.readNodeMetadata("/").type());
		assertTrue(list("/").isEmpty());
	}

	@Test
	@DisplayName("ciphertext never contains cleartext names")
	void noCleartextNamesOnDisk() throws IOException {
		fs.createDirectory("/secretdir", Set.of());
		writeFile("/secretdir/secretfile.txt", "top secret");

		for (var path : ciphertext.paths()) {
			assertFalse(path.contains("secret"), path);
		}
		assertTrue(ciphertext.paths().stream().noneMatch(p -> p.contains("top secret")));
	}

	@Nested
	@DisplayName("directories")
	class Directories {

		@Test
		@DisplayName("create, list and stat")
		void createAndList() throws IOException {
			fs.createDirectory("/a", Set.of());
			fs.createDirectory("/a/b", Set.of());

			assertEquals(VfsNodeType.DIRECTORY, fs.readNodeMetadata("/a").type());
			assertEquals(VfsNodeType.DIRECTORY, fs.readNodeMetadata("/a/b").type());
			assertEquals(Set.of("a"), list("/").keySet());
			assertEquals(Set.of("b"), list("/a").keySet());
			assertTrue(list("/a/b").isEmpty());
		}

		@Test
		@DisplayName("delete refuses non-empty directories")
		void deleteNonEmpty() throws IOException {
			fs.createDirectory("/a", Set.of());
			writeFile("/a/f", "x");

			assertThrows(DirectoryNotEmptyException.class, () -> fs.deleteDirectory("/a"));
		}

		@Test
		@DisplayName("delete removes entry and content directory")
		void deleteEmpty() throws IOException {
			fs.createDirectory("/a", Set.of());
			int pathsBefore = ciphertext.paths().size();
			writeFile("/a/f", "x");
			fs.deleteFile("/a/f");

			fs.deleteDirectory("/a");

			assertThrows(NoSuchFileException.class, () -> fs.readNodeMetadata("/a"));
			assertTrue(ciphertext.paths().size() < pathsBefore);
			assertTrue(list("/").isEmpty());
		}

		@Test
		@DisplayName("recreating a deleted directory yields a fresh, empty directory")
		void deleteAndRecreate() throws IOException {
			fs.createDirectory("/a", Set.of());
			writeFile("/a/f", "x");
			assertEquals(Set.of("f"), list("/a").keySet());
			fs.deleteFile("/a/f");
			fs.deleteDirectory("/a");

			fs.createDirectory("/a", Set.of());

			assertTrue(list("/a").isEmpty());
			writeFile("/a/g", "y");
			assertEquals("y", readFile("/a/g"));
		}

		@Test
		@DisplayName("renamed directory is resolvable under its new name only")
		void renameInvalidates() throws IOException {
			fs.createDirectory("/a", Set.of());
			writeFile("/a/f", "x");
			assertEquals("x", readFile("/a/f"));

			fs.rename("/a", "/b", false);

			assertEquals("x", readFile("/b/f"));
			assertThrows(NoSuchFileException.class, () -> fs.readNodeMetadata("/a/f"));
			fs.createDirectory("/a", Set.of());
			assertTrue(list("/a").isEmpty());
		}

		@Test
		@DisplayName("deleteFile refuses directories")
		void deleteFileOnDirectory() throws IOException {
			fs.createDirectory("/a", Set.of());

			assertThrows(FileSystemException.class, () -> fs.deleteFile("/a"));
			assertEquals(VfsNodeType.DIRECTORY, fs.readNodeMetadata("/a").type());
		}

		@Test
		@DisplayName("missing intermediate directory yields NoSuchFileException")
		void missingParent() {
			assertThrows(NoSuchFileException.class, () -> fs.readNodeMetadata("/missing/file"));
			assertThrows(NoSuchFileException.class, () -> fs.createDirectory("/missing/dir", Set.of()));
		}
	}

	@Nested
	@DisplayName("files")
	class Files {

		@Test
		@DisplayName("round-trip content and report cleartext sizes")
		void roundTrip() throws IOException {
			writeFile("/f.txt", "hello world");

			assertEquals("hello world", readFile("/f.txt"));
			assertEquals(11, fs.readNodeMetadata("/f.txt").size());
			var entry = list("/").get("f.txt");
			assertEquals(VfsNodeType.FILE, entry.metadata().type());
			assertEquals(11, entry.metadata().size());
		}

		@Test
		@DisplayName("created but unwritten file has size zero and can be reopened")
		void emptyFile() throws IOException {
			fs.createFile("/empty", WRITE, Set.of()).close();

			assertEquals(0, fs.readNodeMetadata("/empty").size());
			try (var file = fs.openFile("/empty", READ)) {
				assertEquals(-1, file.read(ByteBuffer.allocate(1), 0));
			}
		}

		@Test
		@DisplayName("CREATE_NEW fails on existing file")
		void createNew() throws IOException {
			writeFile("/f", "x");

			assertThrows(FileAlreadyExistsException.class, () -> fs.createFile("/f", Set.of(StandardOpenOption.CREATE_NEW), Set.of()));
			assertEquals("x", readFile("/f"));
		}

		@Test
		@DisplayName("TRUNCATE_EXISTING starts a fresh file")
		void truncateExisting() throws IOException {
			writeFile("/f", "long content here");

			try (var file = fs.openFile("/f", Set.of(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING))) {
				assertEquals(0, file.readMetadata().size());
				file.write(ByteBuffer.wrap("new".getBytes(StandardCharsets.UTF_8)), 0);
			}

			assertEquals("new", readFile("/f"));
		}

		@Test
		@DisplayName("path-based truncate")
		void truncate() throws IOException {
			writeFile("/f", "hello world");

			fs.truncate("/f", 5);

			assertEquals("hello", readFile("/f"));
			assertEquals(5, fs.readNodeMetadata("/f").size());
		}

		@Test
		@DisplayName("delete")
		void delete() throws IOException {
			writeFile("/f", "x");

			fs.deleteFile("/f");

			assertThrows(NoSuchFileException.class, () -> fs.readNodeMetadata("/f"));
			assertTrue(list("/").isEmpty());
		}

		@Test
		@DisplayName("a file with an invalid ciphertext size is listed as empty and does not break the listing")
		void invalidCiphertextSize() throws IOException {
			writeFile("/good", "fine");
			writeFile("/bad", "will be damaged");
			var badCiphertextPath = ciphertext.paths().stream().filter(p -> p.endsWith(".uvf") && !p.endsWith("dir.uvf")).filter(p -> {
				try {
					return ciphertext.readNodeMetadata(p).size() > vault.ciphertextSize(4);
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			}).findFirst().orElseThrow();
			ciphertext.truncate(badCiphertextPath, vault.headerSize() + 3); // a torn chunk

			var entries = list("/");

			assertEquals(Set.of("good", "bad"), entries.keySet());
			assertEquals(4, entries.get("good").metadata().size());
			assertEquals(0, entries.get("bad").metadata().size());
			assertEquals(0, fs.readNodeMetadata("/bad").size());
			assertThrows(IOException.class, () -> fs.openFile("/bad", READ));
		}

		@Test
		@DisplayName("maximum name length is reduced for encryption overhead")
		void maxNameLength() throws IOException {
			assertTrue(fs.readVfsMetadata("/").maxNameLength() < 255);
		}
	}

	@Nested
	@DisplayName("rename")
	class Rename {

		@Test
		@DisplayName("moves a file between directories")
		void moveFile() throws IOException {
			fs.createDirectory("/dir", Set.of());
			writeFile("/f", "content");

			fs.rename("/f", "/dir/g", false);

			assertThrows(NoSuchFileException.class, () -> fs.readNodeMetadata("/f"));
			assertEquals("content", readFile("/dir/g"));
		}

		@Test
		@DisplayName("refuses to replace without flag")
		void noReplace() throws IOException {
			writeFile("/a", "a");
			writeFile("/b", "b");

			assertThrows(FileAlreadyExistsException.class, () -> fs.rename("/a", "/b", false));
			assertEquals("b", readFile("/b"));
		}

		@Test
		@DisplayName("replaces an existing file")
		void replaceFile() throws IOException {
			writeFile("/a", "a");
			writeFile("/b", "b");

			fs.rename("/a", "/b", true);

			assertEquals("a", readFile("/b"));
		}

		@Test
		@DisplayName("replaces an empty directory and keeps the moved directory's content")
		void replaceDirectory() throws IOException {
			fs.createDirectory("/src", Set.of());
			writeFile("/src/f", "x");
			fs.createDirectory("/dst", Set.of());

			fs.rename("/src", "/dst", true);

			assertEquals(Set.of("dst"), list("/").keySet());
			assertEquals("x", readFile("/dst/f"));
		}

		@Test
		@DisplayName("refuses to replace a non-empty directory")
		void replaceNonEmptyDirectory() throws IOException {
			fs.createDirectory("/src", Set.of());
			fs.createDirectory("/dst", Set.of());
			writeFile("/dst/f", "x");

			assertThrows(DirectoryNotEmptyException.class, () -> fs.rename("/src", "/dst", true));
		}

		@Test
		@DisplayName("refuses to replace a directory with a file")
		void fileOverDirectory() throws IOException {
			writeFile("/f", "x");
			fs.createDirectory("/dst", Set.of());

			assertThrows(FileSystemException.class, () -> fs.rename("/f", "/dst", true));
			assertEquals(VfsNodeType.DIRECTORY, fs.readNodeMetadata("/dst").type());
		}
	}

	@Nested
	@DisplayName("symbolic links")
	class Symlinks {

		@Test
		@DisplayName("create, read, list and delete")
		void roundTrip() throws IOException {
			assertTrue(fs.capabilities().supportsSymbolicLinks());

			fs.createSymbolicLink("/link", "../target");

			assertEquals("../target", fs.readSymbolicLink("/link"));
			var metadata = fs.readNodeMetadata("/link");
			assertEquals(VfsNodeType.SYMBOLIC_LINK, metadata.type());
			assertEquals(9, metadata.size());
			assertEquals(VfsNodeType.SYMBOLIC_LINK, list("/").get("link").metadata().type());

			fs.deleteFile("/link");

			assertThrows(NoSuchFileException.class, () -> fs.readNodeMetadata("/link"));
		}

		@Test
		@DisplayName("readSymbolicLink on a file fails")
		void notALink() throws IOException {
			writeFile("/f", "x");

			assertThrows(NotLinkException.class, () -> fs.readSymbolicLink("/f"));
		}

		@Test
		@DisplayName("creating over an existing node fails")
		void existing() throws IOException {
			writeFile("/f", "x");

			assertThrows(FileAlreadyExistsException.class, () -> fs.createSymbolicLink("/f", "target"));
		}
	}

	@Nested
	@DisplayName("create from vault.uvf")
	class Create {

		@BeforeEach
		void persistConfig() throws Exception {
			var keyGen = KeyPairGenerator.getInstance("EC");
			keyGen.initialize(new ECGenParameterSpec("secp256r1"));
			vault.setPassword("correct horse");
			vault.setRecoveryKey((ECPublicKey) keyGen.generateKeyPair().getPublic());
			ciphertext.writeFile("/vault.uvf", vault.serializeConfig());
			fs.createDirectory("/existing", Set.of());
		}

		@Test
		@DisplayName("unlocks with the right password and sees existing content")
		void unlock() throws IOException {
			try (var unlocked = UvfFileSystem.create(ciphertext, VaultUnlocker.withPassword("correct horse", csprng))) {
				assertEquals(VfsNodeType.DIRECTORY, unlocked.readNodeMetadata("/existing").type());
			}
		}

		@Test
		@DisplayName("rejects a wrong password")
		void wrongPassword() {
			assertThrows(VaultKeyInvalidException.class, () -> UvfFileSystem.create(ciphertext, VaultUnlocker.withPassword("wrong", csprng)));
		}

		@Test
		@DisplayName("rejects a malformed configuration")
		void malformedConfig() throws IOException {
			ciphertext.writeFile("/vault.uvf", "garbage".getBytes(StandardCharsets.UTF_8));

			assertThrows(IOException.class, () -> UvfFileSystem.create(ciphertext, VaultUnlocker.withPassword("correct horse", csprng)));
		}

		@Test
		@DisplayName("rejects a vault without root directory")
		void missingRoot() throws IOException {
			var empty = new InMemoryVfsFileSystem();
			empty.writeFile("/vault.uvf", vault.serializeConfig());

			var e = assertThrows(IOException.class, () -> UvfFileSystem.create(empty, VaultUnlocker.withPassword("correct horse", csprng)));
			assertTrue(e.getMessage().contains("broken"));
		}
	}

	@Nested
	@DisplayName("initialize")
	class Initialize {

		private UvfUnlockedVault configuredVault() throws Exception {
			var keyGen = KeyPairGenerator.getInstance("EC");
			keyGen.initialize(new ECGenParameterSpec("secp256r1"));
			var newVault = UvfUnlockedVault.create(csprng);
			newVault.setPassword("pw");
			newVault.setRecoveryKey((ECPublicKey) keyGen.generateKeyPair().getPublic());
			return newVault;
		}

		@Test
		@DisplayName("writes vault.uvf and the root directory, reopenable with the password")
		void initializeEmptyDelegate() throws Exception {
			var empty = new InMemoryVfsFileSystem();

			try (var initialized = UvfFileSystem.initialize(empty, configuredVault())) {
				initialized.createDirectory("/dir", Set.of());
			}

			assertTrue(empty.paths().contains("/vault.uvf"));
			try (var reopened = UvfFileSystem.create(empty, VaultUnlocker.withPassword("pw", csprng)); var entries = reopened.openDirectory("/")) {
				var names = new ArrayList<String>();
				entries.forEach(e -> names.add(e.name()));
				assertEquals(List.of("dir"), names);
			}
		}

		@Test
		@DisplayName("refuses to overwrite an existing vault.uvf")
		void refusesExisting() throws Exception {
			var existing = new InMemoryVfsFileSystem();
			existing.writeFile("/vault.uvf", "old".getBytes(StandardCharsets.UTF_8));
			var newVault = configuredVault();

			assertThrows(FileAlreadyExistsException.class, () -> UvfFileSystem.initialize(existing, newVault));

			assertArrayEquals("old".getBytes(StandardCharsets.UTF_8), readCiphertext(existing, "/vault.uvf"));
			assertEquals(Set.of("/", "/vault.uvf"), existing.paths());
		}

		private byte[] readCiphertext(InMemoryVfsFileSystem fs, String path) throws IOException {
			try (var file = fs.openFile(path, READ)) {
				var buf = ByteBuffer.allocate((int) file.readMetadata().size());
				file.read(buf, 0);
				return buf.array();
			}
		}
	}

	@Test
	@DisplayName("large file spans multiple chunks")
	void multiChunk() throws IOException {
		var content = new byte[vault.cleartextChunkSize() * 2 + 123];
		csprng.nextBytes(content);
		try (var file = fs.createFile("/big", WRITE, Set.of())) {
			file.write(ByteBuffer.wrap(content), 0);
		}

		assertEquals(content.length, fs.readNodeMetadata("/big").size());
		try (var file = fs.openFile("/big", READ)) {
			var buf = ByteBuffer.allocate(content.length);
			while (buf.hasRemaining() && file.read(buf, buf.position()) >= 0) {
				// keep reading
			}
			assertArrayEquals(content, buf.array());
		}
		List<String> ciphertextFiles = ciphertext.paths().stream().filter(p -> p.endsWith(".uvf")).toList();
		assertFalse(ciphertextFiles.isEmpty());
	}
}
