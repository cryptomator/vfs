package org.cryptomator.vfs.test;

import org.cryptomator.cryptolib.api.UvfKeyEncryptionKey;
import org.cryptomator.cryptolib.api.UvfRecoveryKey;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.backend.nio.NioVfsFileSystem;
import org.cryptomator.vfs.middleware.uvf.shortening.ShorteningFileSystem;
import org.cryptomator.vfs.middleware.uvf.encryption.UvfFileSystem;
import org.cryptomator.vfs.middleware.uvf.encryption.VaultUnlocker;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Walks through the lifecycle of a vault on the real stack UVF → file name shortening → NIO, one step per test method, each building on the state left by the previous one.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class UvfShorteningStackIT {

	private static final int THRESHOLD = ShorteningFileSystem.RECOMMENDED_THRESHOLD;
	private static final String PASSWORD = "correct horse battery staple";
	private static final String CONFLICT_SUFFIX = " (conflicted copy)";
	// 200 cleartext bytes encrypt to well over 220 ciphertext bytes, so these names are always shortened
	private static final String LONG_DIR = longName("dir-");
	private static final String LONG_DIR_RENAMED = longName("dir-renamed-");
	private static final String LONG_FILE = longName("file-");
	private static final String LONG_FILE_RENAMED = longName("file-renamed-");
	private static final String LONG_LINK = longName("link-");

	private final SecureRandom csprng = new SecureRandom();

	@TempDir
	static Path vaultDir; // static: one directory for all steps, an instance field gets a new one per test method
	@Nullable UvfFileSystem uvf;

	private static String longName(String prefix) {
		return prefix + "x".repeat(196 - prefix.length()) + ".txt";
	}

	private VfsFileSystem shorteningOverNio() throws IOException {
		return new ShorteningFileSystem(new NioVfsFileSystem(vaultDir), THRESHOLD, true);
	}

	private UvfFileSystem uvf() {
		assertTrue(uvf != null, "vault not open, an earlier step failed");
		return uvf;
	}

	@AfterAll
	void closeVault() {
		if (uvf != null) {
			uvf.close();
		}
	}

	@Test
	@Order(1)
	@DisplayName("create a vault whose configuration enables shortening")
	void initializeVault() throws IOException {
		var vault = UvfUnlockedVault.create(csprng, UvfKeyEncryptionKey.password(PASSWORD), UvfRecoveryKey.generate(csprng), THRESHOLD);
		uvf = UvfFileSystem.initialize(shorteningOverNio(), vault);

		assertTrue(Files.isRegularFile(vaultDir.resolve("vault.uvf")));
		assertEquals(List.of(), list("/"));
	}

	@Test
	@Order(2)
	@DisplayName("create a long-named directory, file and symbolic link next to a short-named file")
	void createNodes() throws IOException {
		uvf().createDirectory("/" + LONG_DIR, Set.of());
		write("/" + LONG_DIR + "/" + LONG_FILE, "long file");
		uvf().createSymbolicLink("/" + LONG_LINK, "/" + LONG_DIR);
		write("/short.txt", "short file");

		assertEquals(sorted(LONG_DIR, LONG_LINK, "short.txt"), list("/"));
		assertEquals(List.of(LONG_FILE), list("/" + LONG_DIR));
		assertEquals("long file", read("/" + LONG_DIR + "/" + LONG_FILE));
		assertEquals("/" + LONG_DIR, uvf().readSymbolicLink("/" + LONG_LINK));
		assertEquals(VfsNodeType.DIRECTORY, uvf().readNodeMetadata("/" + LONG_DIR).type());
		assertEquals(VfsNodeType.SYMBOLIC_LINK, uvf().readNodeMetadata("/" + LONG_LINK).type());
	}

	@Test
	@Order(3)
	@DisplayName("no stored name exceeds the threshold, and every shortened node has exactly one sidecar")
	void storedNamesAreShort() throws IOException {
		var names = storedNames();

		assertTrue(names.stream().allMatch(name -> name.getBytes(StandardCharsets.UTF_8).length <= THRESHOLD), () -> "too long: " + names);
		assertEquals(3, count(names, ".shortened.uvf"));
		assertEquals(3, count(names, ".original.uvf"));
	}

	@Test
	@Order(4)
	@DisplayName("rename short → long, long → short across directories and a long-named directory with its children")
	void renameNodes() throws IOException {
		uvf().rename("/short.txt", "/" + LONG_FILE_RENAMED, false);
		uvf().rename("/" + LONG_DIR + "/" + LONG_FILE, "/renamed.txt", false);
		uvf().rename("/" + LONG_DIR, "/" + LONG_DIR_RENAMED, false);

		assertEquals(sorted(LONG_DIR_RENAMED, LONG_FILE_RENAMED, LONG_LINK, "renamed.txt"), list("/"));
		assertEquals(List.of(), list("/" + LONG_DIR_RENAMED));
		assertEquals("short file", read("/" + LONG_FILE_RENAMED));
		assertEquals("long file", read("/renamed.txt"));
		var names = storedNames();
		assertEquals(3, count(names, ".shortened.uvf"));
		assertEquals(3, count(names, ".original.uvf")); // no orphaned sidecars
	}

	@Test
	@Order(5)
	@DisplayName("a reopened vault shows the same names and contents, so nothing depends on in-memory state")
	void reopenVault() throws IOException {
		uvf().close();
		uvf = null;

		uvf = UvfFileSystem.create(shorteningOverNio(), VaultUnlocker.withPassword(PASSWORD, csprng));

		assertEquals(sorted(LONG_DIR_RENAMED, LONG_FILE_RENAMED, LONG_LINK, "renamed.txt"), list("/"));
		assertEquals("short file", read("/" + LONG_FILE_RENAMED));
		assertEquals("/" + LONG_DIR, uvf().readSymbolicLink("/" + LONG_LINK));
	}

	@Test
	@Order(6)
	@DisplayName("a sync conflict copy of a shortened file is normalized by the shortening layer and, lacking conflict detection in UVF, not listed in cleartext")
	void syncConflictOfShortenedFile() throws IOException {
		var shortenedFile = onlyShortenedRegularFile();
		var conflictCopy = shortenedFile.resolveSibling(shortenedFile.getFileName().toString().replace(".shortened.uvf", ".shortened" + CONFLICT_SUFFIX + ".uvf"));
		Files.copy(shortenedFile, conflictCopy);

		// UVF cannot decrypt "<ciphertext> (conflicted copy).uvf" yet and skips it, see docs/conflict-resolution.md
		assertEquals(sorted(LONG_DIR_RENAMED, LONG_FILE_RENAMED, LONG_LINK, "renamed.txt"), list("/"));

		var names = storedNames();
		assertTrue(names.stream().noneMatch(name -> name.contains(CONFLICT_SUFFIX)), () -> "unresolved: " + names);
		assertEquals(4, count(names, ".shortened.uvf"));
		assertEquals(4, count(names, ".original.uvf"));
		var sidecars = sidecarContents();
		assertEquals(1, sidecars.stream().filter(name -> name.endsWith(CONFLICT_SUFFIX + ".uvf")).count(), () -> "sidecars: " + sidecars);
	}

	@Test
	@Order(7)
	@DisplayName("deleting all nodes leaves only the vault structure and the conflict copy invisible to UVF")
	void deleteNodes() throws IOException {
		uvf().deleteFile("/" + LONG_FILE_RENAMED);
		uvf().deleteFile("/renamed.txt");
		uvf().deleteFile("/" + LONG_LINK);
		uvf().deleteDirectory("/" + LONG_DIR_RENAMED);

		assertEquals(List.of(), list("/"));
		var names = storedNames();
		assertEquals(1, count(names, ".shortened.uvf"));
		assertEquals(1, count(names, ".original.uvf"));
		assertTrue(sidecarContents().getFirst().endsWith(CONFLICT_SUFFIX + ".uvf"));
	}

	// --- helpers ---

	private List<String> list(String path) throws IOException {
		var names = new ArrayList<String>();
		try (var entries = uvf().openDirectory(path)) {
			entries.forEach(entry -> names.add(entry.name()));
		}
		return names.stream().sorted().toList();
	}

	private static List<String> sorted(String... names) {
		return Stream.of(names).sorted().toList();
	}

	private void write(String path, String contents) throws IOException {
		try (var file = uvf().createFile(path, Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW), Set.of())) {
			var buf = ByteBuffer.wrap(contents.getBytes(StandardCharsets.UTF_8));
			while (buf.hasRemaining()) {
				file.write(buf, buf.position());
			}
		}
	}

	private String read(String path) throws IOException {
		try (var file = uvf().openFile(path, Set.of(StandardOpenOption.READ))) {
			var buf = ByteBuffer.allocate(1024);
			while (buf.hasRemaining() && file.read(buf, buf.position()) >= 0) {
				// keep reading
			}
			return new String(buf.array(), 0, buf.position(), StandardCharsets.UTF_8);
		}
	}

	// names of all files and directories stored by the backend
	private List<String> storedNames() throws IOException {
		try (var paths = Files.walk(vaultDir)) {
			return paths.filter(path -> !path.equals(vaultDir)).map(path -> path.getFileName().toString()).toList();
		}
	}

	private static long count(List<String> names, String suffix) {
		return names.stream().filter(name -> name.endsWith(suffix)).count();
	}

	private List<String> sidecarContents() throws IOException {
		try (var paths = Files.walk(vaultDir)) {
			var sidecars = paths.filter(path -> path.getFileName().toString().endsWith(".original.uvf")).toList();
			var contents = new ArrayList<String>();
			for (var sidecar : sidecars) {
				contents.add(Files.readString(sidecar));
			}
			return contents;
		}
	}

	// the stored node of the only long-named regular file; long-named directories and symbolic links are stored as directories
	private Path onlyShortenedRegularFile() throws IOException {
		try (var paths = Files.walk(vaultDir)) {
			var files = paths.filter(path -> path.getFileName().toString().endsWith(".shortened.uvf") && Files.isRegularFile(path)).toList();
			assertEquals(1, files.size(), () -> "shortened files: " + files);
			return files.getFirst();
		}
	}
}
