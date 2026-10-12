package org.cryptomator.vfs.backend.nio;

import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;
import org.cryptomator.vfs.api.VfsXattrPolicy;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NioVfsFileSystemTest {

	private static final Set<PosixFilePermission> RW = Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
	private static final Set<PosixFilePermission> RWX = Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);

	@TempDir
	Path root;

	NioVfsFileSystem fs;

	@BeforeEach
	void setUp() throws IOException {
		fs = new NioVfsFileSystem(root);
	}

	private void writeFile(String path, String content) throws IOException {
		try (var file = fs.createFile(path, Set.of(StandardOpenOption.WRITE), RW)) {
			file.write(ByteBuffer.wrap(content.getBytes(StandardCharsets.UTF_8)), 0);
		}
	}

	private String readFile(String path) throws IOException {
		try (var file = fs.openFile(path, Set.of(StandardOpenOption.READ))) {
			var size = (int) file.readMetadata().size();
			var buf = ByteBuffer.allocate(size);
			while (buf.hasRemaining() && file.read(buf, buf.position()) >= 0) {
				// keep reading
			}
			return new String(buf.array(), 0, buf.position(), StandardCharsets.UTF_8);
		}
	}

	@Nested
	@DisplayName("openDirectory")
	class OpenDirectory {

		@Test
		@DisplayName("lists entries with metadata")
		void listsEntriesWithMetadata() throws IOException {
			fs.createDirectory("/sub", RWX);
			writeFile("/a.txt", "hello");

			var entries = new ArrayList<VfsDirectoryEntry>();
			try (var stream = fs.openDirectory("/")) {
				stream.forEach(entries::add);
			}

			assertEquals(2, entries.size());
			var byName = entries.stream().collect(java.util.stream.Collectors.toMap(VfsDirectoryEntry::name, VfsDirectoryEntry::metadata));
			assertEquals(VfsNodeType.DIRECTORY, byName.get("sub").type());
			assertEquals(VfsNodeType.FILE, byName.get("a.txt").type());
			assertEquals(5, byName.get("a.txt").size());
		}

		@Test
		@DisplayName("only one iterator per stream")
		void singleUse() throws IOException {
			try (var stream = fs.openDirectory("/")) {
				stream.iterator();
				assertThrows(IllegalStateException.class, stream::iterator);
			}
		}
	}

	@Nested
	@DisplayName("rename")
	class Rename {

		@Test
		@DisplayName("fails without replaceExisting if target exists")
		void noReplace() throws IOException {
			writeFile("/a", "a");
			writeFile("/b", "b");

			assertThrows(FileAlreadyExistsException.class, () -> fs.rename("/a", "/b", false));
			assertEquals("b", readFile("/b"));
		}

		@Test
		@DisplayName("replaces existing target with replaceExisting")
		void replace() throws IOException {
			writeFile("/a", "a");
			writeFile("/b", "b");

			fs.rename("/a", "/b", true);

			assertEquals("a", readFile("/b"));
			assertThrows(NoSuchFileException.class, () -> fs.readNodeMetadata("/a"));
		}

		@Test
		@DisplayName("refuses to replace a non-empty directory")
		void nonEmptyDirectoryTarget() throws IOException {
			fs.createDirectory("/src", RWX);
			fs.createDirectory("/dst", RWX);
			writeFile("/dst/child", "x");

			assertThrows(DirectoryNotEmptyException.class, () -> fs.rename("/src", "/dst", true));
		}
	}

	@Nested
	@DisplayName("VfsFile")
	class OpenFile {

		@Test
		@DisplayName("truncate extends with zeros and shrinks")
		void truncate() throws IOException {
			writeFile("/f", "hello");
			try (var file = fs.openFile("/f", Set.of(StandardOpenOption.WRITE, StandardOpenOption.READ))) {
				file.truncate(8);
				assertEquals(8, file.readMetadata().size());
				var buf = ByteBuffer.allocate(3);
				file.read(buf, 5);
				assertArrayEquals(new byte[3], buf.array());

				file.truncate(2);
				assertEquals(2, file.readMetadata().size());
			}
			assertEquals("he", readFile("/f"));
		}

		@Test
		@DisplayName("handle survives delete")
		void surviveDelete() throws IOException {
			writeFile("/f", "hello");
			try (var file = fs.openFile("/f", Set.of(StandardOpenOption.READ))) {
				fs.deleteFile("/f");
				var buf = ByteBuffer.allocate(5);
				assertEquals(5, file.read(buf, 0));
				assertEquals("hello", new String(buf.array(), StandardCharsets.UTF_8));
			}
		}

		@Test
		@DisplayName("setTimes updates mtime")
		void setTimes() throws IOException {
			writeFile("/f", "hello");
			var mtime = Instant.parse("2020-01-02T03:04:05Z");
			try (var file = fs.openFile("/f", Set.of(StandardOpenOption.WRITE))) {
				file.setTimes(new VfsTimes(null, mtime, null));
			}
			assertEquals(mtime, fs.readNodeMetadata("/f").lastModifiedTime());
		}

		@Test
		@DisplayName("createFile without CREATE_NEW opens existing file")
		void createExisting() throws IOException {
			writeFile("/f", "hello");
			try (var file = fs.createFile("/f", Set.of(StandardOpenOption.WRITE), RW)) {
				assertEquals(5, file.readMetadata().size());
			}
			assertThrows(FileAlreadyExistsException.class, () -> fs.createFile("/f", Set.of(StandardOpenOption.CREATE_NEW), RW));
		}
	}

	@Nested
	@DisplayName("metadata")
	class Metadata {

		@Test
		@DisplayName("reports stable file ids and change time on unix")
		void fileId() throws IOException {
			writeFile("/a", "a");
			writeFile("/b", "b");
			var a = fs.readNodeMetadata("/a");
			var b = fs.readNodeMetadata("/b");

			if (root.getFileSystem().supportedFileAttributeViews().contains("unix")) {
				assertNotEquals(VfsNodeMetadata.NO_FILE_ID, a.fileId());
				assertNotEquals(a.fileId(), b.fileId());
			} else {
				assertEquals(VfsNodeMetadata.NO_FILE_ID, a.fileId());
			}
			assertFalse(a.changeTime().isBefore(a.creationTime()));
		}

		@Test
		@DisplayName("setPermissions replaces permissions on posix")
		void setPermissions() throws IOException {
			Assumptions.assumeTrue(root.getFileSystem().supportedFileAttributeViews().contains("posix"));
			writeFile("/f", "x");

			fs.setPermissions("/f", Set.of(PosixFilePermission.OWNER_READ));

			assertEquals(Set.of(PosixFilePermission.OWNER_READ), fs.readNodeMetadata("/f").permissions());
		}
	}

	@Nested
	@DisplayName("optional features")
	class OptionalFeatures {

		@Test
		@DisplayName("symbolic links round-trip")
		void symlinks() throws IOException {
			Assumptions.assumeTrue(fs.capabilities().supportsSymbolicLinks());

			fs.createSymbolicLink("/link", "target/file");

			assertEquals("target/file", fs.readSymbolicLink("/link"));
			assertEquals(VfsNodeType.SYMBOLIC_LINK, fs.readNodeMetadata("/link").type());
		}

		@Test
		@DisplayName("xattrs honour policies")
		void xattrs() throws IOException {
			Assumptions.assumeTrue(fs.capabilities().supportsXattrs());
			writeFile("/f", "x");
			var value = ByteBuffer.wrap("v1".getBytes(StandardCharsets.UTF_8));

			assertThrows(NoSuchFileException.class, () -> fs.setXattr("/f", "user.test", value.duplicate(), VfsXattrPolicy.REPLACE_ONLY));
			fs.setXattr("/f", "user.test", value.duplicate(), VfsXattrPolicy.CREATE_ONLY);
			assertThrows(FileAlreadyExistsException.class, () -> fs.setXattr("/f", "user.test", value.duplicate(), VfsXattrPolicy.CREATE_ONLY));
			fs.setXattr("/f", "user.test", ByteBuffer.wrap("v2".getBytes(StandardCharsets.UTF_8)), VfsXattrPolicy.CREATE_OR_REPLACE);

			assertEquals(List.of("user.test"), fs.listXattrs("/f"));
			var read = fs.getXattr("/f", "user.test");
			assertEquals("v2", StandardCharsets.UTF_8.decode(read).toString());

			fs.removeXattr("/f", "user.test");
			assertTrue(fs.listXattrs("/f").isEmpty());
			assertThrows(NoSuchFileException.class, () -> fs.getXattr("/f", "user.test"));
		}
	}

	@Test
	@DisplayName("deleteDirectory is not recursive")
	void deleteDirectoryNotRecursive() throws IOException {
		fs.createDirectory("/d", RWX);
		writeFile("/d/f", "x");

		assertThrows(DirectoryNotEmptyException.class, () -> fs.deleteDirectory("/d"));
		assertTrue(Files.exists(root.resolve("d/f")));
	}
}
