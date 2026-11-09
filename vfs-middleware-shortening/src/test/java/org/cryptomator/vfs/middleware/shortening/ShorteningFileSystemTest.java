package org.cryptomator.vfs.middleware.shortening;

import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.backend.nio.NioVfsFileSystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ShorteningFileSystemTest {

	private static final int THRESHOLD = ShorteningFileSystem.RECOMMENDED_THRESHOLD;
	private static final String LONG_NAME = NameShortenerTest.SPEC_NAME;
	private static final String LONG_HASH = NameShortenerTest.SPEC_HASH;
	private static final String LONG_NODE = LONG_HASH + ".shortened.uvf";
	private static final String LONG_SIDECAR = LONG_HASH + ".original.uvf";
	private static final String OTHER_LONG_NAME = "b".repeat(THRESHOLD) + ".uvf";

	private final NameShortener shortener = new NameShortener(THRESHOLD);

	@TempDir
	Path root;
	ShorteningFileSystem fs;

	@BeforeEach
	void setup() throws IOException {
		fs = new ShorteningFileSystem(new NioVfsFileSystem(root), THRESHOLD);
	}

	private String storedNode(String name) {
		return shortener.shortName(name) + ".shortened.uvf";
	}

	private String storedSidecar(String name) {
		return shortener.shortName(name) + ".original.uvf";
	}

	private static List<String> sorted(String... names) {
		return Stream.of(names).sorted().toList();
	}

	private List<String> storedNames(Path dir) throws IOException {
		try (Stream<Path> children = Files.list(dir)) {
			return children.map(p -> p.getFileName().toString()).sorted().toList();
		}
	}

	private List<String> list(String path) throws IOException {
		var names = new ArrayList<String>();
		try (var entries = fs.openDirectory(path)) {
			for (VfsDirectoryEntry entry : entries) {
				names.add(entry.name());
			}
		}
		return names.stream().sorted().toList();
	}

	private void createFile(String path, String contents) throws IOException {
		try (var file = fs.createFile(path, Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW), Set.of())) {
			file.write(ByteBuffer.wrap(contents.getBytes(StandardCharsets.UTF_8)), 0);
		}
	}

	private String readFile(String path) throws IOException {
		try (var file = fs.openFile(path, Set.of(StandardOpenOption.READ))) {
			var buf = ByteBuffer.allocate(100);
			file.read(buf, 0);
			return new String(buf.array(), 0, buf.position(), StandardCharsets.UTF_8);
		}
	}

	@ParameterizedTest
	@DisplayName("constructor rejects thresholds below the length of a stored short name")
	@ValueSource(ints = {-1, 0, 45})
	void testInvalidThreshold(int threshold) throws IOException {
		var delegate = new NioVfsFileSystem(root);
		assertThrows(IllegalArgumentException.class, () -> new ShorteningFileSystem(delegate, threshold));
	}

	@Test
	@DisplayName("capabilities are case- and normalization-sensitive, optional features come from the delegate")
	void testCapabilities() throws IOException {
		var delegateCapabilities = new NioVfsFileSystem(root).capabilities();
		var capabilities = fs.capabilities();

		assertTrue(capabilities.caseSensitive());
		assertTrue(capabilities.normalizationSensitive());
		assertEquals(delegateCapabilities.supportsSymbolicLinks(), capabilities.supportsSymbolicLinks());
		assertEquals(delegateCapabilities.supportsXattrs(), capabilities.supportsXattrs());
		assertEquals(delegateCapabilities.maxXattrValueSize(), capabilities.maxXattrValueSize());
	}

	@Test
	@DisplayName("short names are stored as-is")
	void testShortNamePassThrough() throws IOException {
		var name = "a".repeat(THRESHOLD);
		createFile("/" + name, "hello");

		assertEquals(List.of(name), storedNames(root));
		assertEquals(List.of(name), list("/"));
		assertEquals("hello", readFile("/" + name));
	}

	@Test
	@DisplayName("a long file name is stored under its hash next to a sidecar holding the name")
	void testCreateLongFile() throws IOException {
		createFile("/" + LONG_NAME, "hello");

		assertEquals(List.of(LONG_SIDECAR, LONG_NODE), storedNames(root));
		assertEquals(LONG_NAME, Files.readString(root.resolve(LONG_SIDECAR)));
		assertEquals("hello", Files.readString(root.resolve(LONG_NODE)));
		assertEquals(List.of(LONG_NAME), list("/"));
		assertEquals("hello", readFile("/" + LONG_NAME));
		assertEquals(VfsNodeType.FILE, fs.readNodeMetadata("/" + LONG_NAME).type());
	}

	@Test
	@DisplayName("a long directory name keeps the node type, its children are mapped recursively")
	void testLongDirectory() throws IOException {
		fs.createDirectory("/" + LONG_NAME, Set.of());
		fs.createDirectory("/" + LONG_NAME + "/" + OTHER_LONG_NAME, Set.of());
		createFile("/" + LONG_NAME + "/" + OTHER_LONG_NAME + "/dir.uvf", "x");

		assertTrue(Files.isDirectory(root.resolve(LONG_NODE)));
		assertTrue(Files.isRegularFile(root.resolve(LONG_SIDECAR)));
		assertTrue(Files.isRegularFile(root.resolve(LONG_NODE).resolve(storedNode(OTHER_LONG_NAME)).resolve("dir.uvf")));
		assertEquals(List.of(OTHER_LONG_NAME), list("/" + LONG_NAME));
		assertEquals(VfsNodeType.DIRECTORY, fs.readNodeMetadata("/" + LONG_NAME + "/" + OTHER_LONG_NAME).type());
	}

	@Test
	@DisplayName("deleting a long file removes the node and its sidecar")
	void testDeleteLongFile() throws IOException {
		createFile("/" + LONG_NAME, "hello");

		fs.deleteFile("/" + LONG_NAME);

		assertEquals(List.of(), storedNames(root));
	}

	@Test
	@DisplayName("deleting a long directory removes the node and its sidecar")
	void testDeleteLongDirectory() throws IOException {
		fs.createDirectory("/" + LONG_NAME, Set.of());

		fs.deleteDirectory("/" + LONG_NAME);

		assertEquals(List.of(), storedNames(root));
	}

	@Test
	@DisplayName("an existing node keeps its sidecar if creation fails")
	void testCreateExistingKeepsSidecar() throws IOException {
		createFile("/" + LONG_NAME, "hello");

		assertThrows(FileAlreadyExistsException.class, () -> createFile("/" + LONG_NAME, "other"));

		assertEquals(List.of(LONG_SIDECAR, LONG_NODE), storedNames(root));
		assertEquals("hello", readFile("/" + LONG_NAME));
	}

	@Test
	@DisplayName("an invalid sidecar in the way of a new node is replaced")
	void testCreateReplacesInvalidSidecar() throws IOException {
		Files.writeString(root.resolve(LONG_SIDECAR), "garbage");

		createFile("/" + LONG_NAME, "hello");

		assertEquals(LONG_NAME, Files.readString(root.resolve(LONG_SIDECAR)));
		assertEquals(List.of(LONG_NAME), list("/"));
	}

	@Test
	@DisplayName("short and long names cannot exceed the advertised maximum")
	void testMaxNameLength() throws IOException {
		assertEquals(ShorteningFileSystem.MAX_NAME_LENGTH, fs.readVfsMetadata("/").maxNameLength());
		var tooLong = "/" + "a".repeat(ShorteningFileSystem.MAX_NAME_LENGTH + 1);
		assertThrows(FileSystemException.class, () -> createFile(tooLong, "x"));
	}

	@Test
	@DisplayName("short names that look like stored names are rejected")
	void testReservedName() {
		assertThrows(FileSystemException.class, () -> createFile("/" + LONG_NODE, "x"));
		assertThrows(FileSystemException.class, () -> createFile("/" + LONG_SIDECAR, "x"));
	}

	@Nested
	@DisplayName("rename")
	class Rename {

		@BeforeEach
		void setup() throws IOException {
			fs.createDirectory("/dir", Set.of());
		}

		@Test
		@DisplayName("short → long writes the target sidecar")
		void testShortToLong() throws IOException {
			createFile("/short.uvf", "hello");

			fs.rename("/short.uvf", "/dir/" + LONG_NAME, false);

			assertEquals(List.of("dir"), storedNames(root));
			assertEquals(List.of(LONG_SIDECAR, LONG_NODE), storedNames(root.resolve("dir")));
			assertEquals("hello", readFile("/dir/" + LONG_NAME));
		}

		@Test
		@DisplayName("long → short deletes the source sidecar")
		void testLongToShort() throws IOException {
			createFile("/" + LONG_NAME, "hello");

			fs.rename("/" + LONG_NAME, "/dir/short.uvf", false);

			assertEquals(List.of("dir"), storedNames(root));
			assertEquals(List.of("short.uvf"), storedNames(root.resolve("dir")));
		}

		@Test
		@DisplayName("long → long moves node and sidecar")
		void testLongToLong() throws IOException {
			createFile("/" + LONG_NAME, "hello");

			fs.rename("/" + LONG_NAME, "/dir/" + OTHER_LONG_NAME, false);

			assertEquals(List.of("dir"), storedNames(root));
			assertEquals(List.of(storedSidecar(OTHER_LONG_NAME), storedNode(OTHER_LONG_NAME)), storedNames(root.resolve("dir")));
			assertEquals(List.of(OTHER_LONG_NAME), list("/dir"));
		}

		@Test
		@DisplayName("long → same long name keeps the sidecar")
		void testLongToSelf() throws IOException {
			createFile("/" + LONG_NAME, "hello");

			fs.rename("/" + LONG_NAME, "/" + LONG_NAME, true);

			assertEquals(List.of(LONG_SIDECAR, LONG_NODE, "dir"), storedNames(root));
		}

		@Test
		@DisplayName("long → existing long name replaces the target and keeps its sidecar")
		void testLongReplacingLong() throws IOException {
			createFile("/dir/" + LONG_NAME, "target");
			createFile("/" + OTHER_LONG_NAME, "source");

			fs.rename("/" + OTHER_LONG_NAME, "/dir/" + LONG_NAME, true);

			assertEquals(List.of("dir"), storedNames(root));
			assertEquals(List.of(LONG_NAME), list("/dir"));
			assertEquals("source", readFile("/dir/" + LONG_NAME));
		}

		@Test
		@DisplayName("a failed rename leaves the source untouched")
		void testFailedRename() throws IOException {
			createFile("/" + LONG_NAME, "hello");
			createFile("/" + OTHER_LONG_NAME, "other");

			assertThrows(FileAlreadyExistsException.class, () -> fs.rename("/" + LONG_NAME, "/" + OTHER_LONG_NAME, false));

			assertEquals(sorted(LONG_NAME, OTHER_LONG_NAME, "dir"), list("/"));
			assertEquals("hello", readFile("/" + LONG_NAME));
		}
	}

	@Nested
	@DisplayName("listing")
	class Listing {

		@Test
		@DisplayName("orphaned sidecars are hidden")
		void testOrphanedSidecar() throws IOException {
			Files.writeString(root.resolve(LONG_SIDECAR), LONG_NAME);
			Files.writeString(root.resolve(LONG_HASH + ".original (conflicted copy).uvf"), LONG_NAME);

			assertEquals(List.of(), list("/"));
		}

		@Test
		@DisplayName("a shortened node without sidecar is skipped")
		void testMissingSidecar() throws IOException {
			Files.writeString(root.resolve(LONG_NODE), "x");

			assertEquals(List.of(), list("/"));
		}

		@Test
		@DisplayName("a shortened node with a sidecar of another name is skipped")
		void testSwappedSidecar() throws IOException {
			Files.writeString(root.resolve(LONG_NODE), "x");
			Files.writeString(root.resolve(LONG_SIDECAR), OTHER_LONG_NAME);

			assertEquals(List.of(), list("/"));
		}

		@Test
		@DisplayName("a stored name exceeding the threshold is skipped")
		void testNonCanonicalName() throws IOException {
			Files.writeString(root.resolve(OTHER_LONG_NAME), "x");

			assertEquals(List.of(), list("/"));
		}
	}

	@Nested
	@DisplayName("sync conflicts")
	class Conflicts {

		private static final String CONFLICT_NODE = LONG_HASH + ".shortened (conflicted copy).uvf";
		private static final String CONFLICT_NAME = LONG_NAME.substring(0, LONG_NAME.length() - 4) + " (conflicted copy).uvf";

		@BeforeEach
		void setup() throws IOException {
			createFile("/" + LONG_NAME, "original");
			Files.writeString(root.resolve(CONFLICT_NODE), "conflict");
		}

		@Test
		@DisplayName("a conflicting copy is reported with the suffix inserted before the extension")
		void testListConflict() throws IOException {
			assertEquals(sorted(CONFLICT_NAME, LONG_NAME), list("/"));
			assertEquals("conflict", readFile("/" + CONFLICT_NAME));
		}

		@Test
		@DisplayName("renaming a conflicting copy converts it into regular shortened form and keeps the shared sidecar")
		void testResolveConflict() throws IOException {
			list("/");

			fs.rename("/" + CONFLICT_NAME, "/" + OTHER_LONG_NAME, false);

			assertEquals(sorted(LONG_SIDECAR, LONG_NODE, storedSidecar(OTHER_LONG_NAME), storedNode(OTHER_LONG_NAME)), storedNames(root));
			assertEquals(sorted(LONG_NAME, OTHER_LONG_NAME), list("/"));
			assertEquals("conflict", readFile("/" + OTHER_LONG_NAME));
			assertThrows(NoSuchFileException.class, () -> fs.readNodeMetadata("/" + CONFLICT_NAME));
		}

		@Test
		@DisplayName("deleting the regular node keeps the sidecar while a conflicting copy is known")
		void testDeleteRegularNodeKeepsSidecarOfConflict() throws IOException {
			list("/");

			fs.deleteFile("/" + LONG_NAME);

			assertEquals(List.of(CONFLICT_NAME), list("/"));
		}

		@Test
		@DisplayName("deleting a conflicting copy keeps the sidecar of the regular node")
		void testDeleteConflict() throws IOException {
			list("/");

			fs.deleteFile("/" + CONFLICT_NAME);

			assertEquals(List.of(LONG_SIDECAR, LONG_NODE), storedNames(root));
			assertFalse(list("/").contains(CONFLICT_NAME));
		}
	}
}
