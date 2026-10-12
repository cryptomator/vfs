package org.cryptomator.vfs.frontend.fuse;

import org.cryptomator.jfuse.api.DirFiller;
import org.cryptomator.jfuse.api.Errno;
import org.cryptomator.jfuse.api.FileInfo;
import org.cryptomator.jfuse.api.FuseOperations;
import org.cryptomator.jfuse.api.Stat;
import org.cryptomator.jfuse.api.TimeSpec;
import org.cryptomator.vfs.api.VfsCapabilities;
import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsDirectoryStream;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;
import org.cryptomator.vfs.api.VfsXattrPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FuseVfsOperationsTest {

	private static final int ENOENT = 2;
	private static final int EEXIST = 17;
	private static final int EINVAL = 22;
	private static final int ERANGE = 34;
	private static final int ENOATTR = 93;

	private VfsFileSystem fs;
	private Errno errno;
	private FuseVfsOperations ops;

	@BeforeEach
	void setUp() {
		fs = Mockito.mock(VfsFileSystem.class);
		errno = Mockito.mock(Errno.class);
		Mockito.doReturn(ENOENT).when(errno).enoent();
		Mockito.doReturn(EEXIST).when(errno).eexist();
		Mockito.doReturn(EINVAL).when(errno).einval();
		Mockito.doReturn(ERANGE).when(errno).erange();
		Mockito.doReturn(ENOATTR).when(errno).enoattr();
		Mockito.doReturn(VfsCapabilities.MINIMAL).when(fs).capabilities();
		ops = new FuseVfsOperations(fs, errno);
	}

	private static VfsNodeMetadata metadata(VfsNodeType type, long size) {
		return new VfsNodeMetadata(type, size, VfsNodeMetadata.NO_FILE_ID, Set.of(), Instant.EPOCH, Instant.EPOCH, Instant.EPOCH, Instant.EPOCH);
	}

	private static VfsDirectoryStream stream(List<VfsDirectoryEntry> entries) {
		return new VfsDirectoryStream() {
			@Override
			public Iterator<VfsDirectoryEntry> iterator() {
				return entries.iterator();
			}

			@Override
			public void close() {
			}
		};
	}

	@Nested
	@DisplayName("supportedOperations")
	class SupportedOperations {

		@Test
		@DisplayName("omits optional operations for a minimal file system")
		void minimal() {
			var supported = ops.supportedOperations();

			assertTrue(supported.contains(FuseOperations.Operation.INIT));
			assertTrue(supported.contains(FuseOperations.Operation.CHMOD));
			assertFalse(supported.contains(FuseOperations.Operation.READLINK));
			assertFalse(supported.contains(FuseOperations.Operation.GET_XATTR));
		}

		@Test
		@DisplayName("adds symlink and xattr operations when supported")
		void full() {
			Mockito.doReturn(new VfsCapabilities(true, true, true, VfsCapabilities.NO_LIMIT)).when(fs).capabilities();

			var supported = ops.supportedOperations();

			assertTrue(supported.containsAll(Set.of(FuseOperations.Operation.READLINK, FuseOperations.Operation.SYMLINK, FuseOperations.Operation.GET_XATTR, FuseOperations.Operation.SET_XATTR, FuseOperations.Operation.LIST_XATTR, FuseOperations.Operation.REMOVE_XATTR)));
		}
	}

	@Nested
	@DisplayName("rename")
	class Rename {

		@Test
		@DisplayName("without flags replaces existing")
		void replace() throws IOException {
			assertEquals(0, ops.rename("/a", "/b", 0));
			Mockito.verify(fs).rename("/a", "/b", true);
		}

		@Test
		@DisplayName("RENAME_NOREPLACE maps to replaceExisting=false")
		void noReplace() throws IOException {
			Mockito.doThrow(new FileAlreadyExistsException("/b")).when(fs).rename("/a", "/b", false);

			assertEquals(-EEXIST, ops.rename("/a", "/b", 1));
		}

		@Test
		@DisplayName("RENAME_EXCHANGE is rejected")
		void exchange() throws IOException {
			assertEquals(-EINVAL, ops.rename("/a", "/b", 2));
			Mockito.verify(fs, Mockito.never()).rename(Mockito.anyString(), Mockito.anyString(), Mockito.anyBoolean());
		}
	}

	@Nested
	@DisplayName("readdir")
	class Readdir {

		@Test
		@DisplayName("fills dot entries and children with attributes")
		void readdirPlus() throws IOException {
			Mockito.doReturn(metadata(VfsNodeType.DIRECTORY, 0)).when(fs).readNodeMetadata("/d");
			Mockito.doReturn(metadata(VfsNodeType.DIRECTORY, 0)).when(fs).readNodeMetadata("/");
			var child = new VfsDirectoryEntry("f.txt", metadata(VfsNodeType.FILE, 42));
			Mockito.doReturn(stream(List.of(child))).when(fs).openDirectory("/d");
			var names = new ArrayList<String>();
			var sizes = new ArrayList<Long>();
			DirFiller filler = (name, statFiller, offset, flags) -> {
				var stat = Mockito.mock(Stat.class);
				Mockito.doReturn(Mockito.mock(TimeSpec.class)).when(stat).aTime();
				Mockito.doReturn(Mockito.mock(TimeSpec.class)).when(stat).mTime();
				Mockito.doReturn(Mockito.mock(TimeSpec.class)).when(stat).cTime();
				Mockito.doReturn(Mockito.mock(TimeSpec.class)).when(stat).birthTime();
				statFiller.accept(stat);
				names.add(name);
				var size = Mockito.mockingDetails(stat).getInvocations().stream().filter(i -> i.getMethod().getName().equals("setSize")).map(i -> (Long) i.getArgument(0)).findFirst().orElse(-1L);
				sizes.add(size);
				return 0;
			};

			assertEquals(0, ops.readdir("/d", filler, 0, Mockito.mock(FileInfo.class), FuseOperations.FUSE_READDIR_PLUS));

			assertEquals(List.of(".", "..", "f.txt"), names);
			assertEquals(42L, sizes.get(2));
		}

		@Test
		@DisplayName("reports missing directory as ENOENT")
		void missing() throws IOException {
			Mockito.doThrow(new NoSuchFileException("/d")).when(fs).readNodeMetadata("/d");

			assertEquals(-ENOENT, ops.readdir("/d", Mockito.mock(DirFiller.class), 0, Mockito.mock(FileInfo.class), 0));
		}
	}

	@Nested
	@DisplayName("open file handles")
	class OpenFiles {

		private VfsFile file;
		private FileInfo fi;

		@BeforeEach
		void open() throws IOException {
			file = Mockito.mock(VfsFile.class);
			fi = Mockito.mock(FileInfo.class);
			Mockito.doReturn(Set.of()).when(fi).getOpenFlags();
			Mockito.doReturn(file).when(fs).openFile(Mockito.eq("/f"), Mockito.any());
			assertEquals(0, ops.open("/f", fi));
			var handle = Mockito.mockingDetails(fi).getInvocations().stream().filter(i -> i.getMethod().getName().equals("setFh")).map(i -> (Long) i.getArgument(0)).findFirst().orElseThrow();
			Mockito.doReturn(handle).when(fi).getFh();
		}

		@Test
		@DisplayName("truncate with FileInfo goes through the handle")
		void truncateViaHandle() throws IOException {
			assertEquals(0, ops.truncate("/f", 7, fi));

			Mockito.verify(file).truncate(7);
			Mockito.verify(fs, Mockito.never()).truncate(Mockito.anyString(), Mockito.anyLong());
		}

		@Test
		@DisplayName("truncate without FileInfo goes through the path")
		void truncateViaPath() throws IOException {
			assertEquals(0, ops.truncate("/f", 7, null));

			Mockito.verify(fs).truncate("/f", 7);
		}

		@Test
		@DisplayName("utimens with FileInfo goes through the handle")
		void utimensViaHandle() throws IOException {
			var atime = Mockito.mock(TimeSpec.class);
			var mtime = Mockito.mock(TimeSpec.class);
			Mockito.doReturn(Optional.empty()).when(atime).getOptional();
			Mockito.doReturn(Optional.of(Instant.EPOCH)).when(mtime).getOptional();

			assertEquals(0, ops.utimens("/f", atime, mtime, fi));

			Mockito.verify(file).setTimes(new VfsTimes(null, Instant.EPOCH, null));
		}

		@Test
		@DisplayName("getattr with FileInfo reads metadata from the handle")
		void getattrViaHandle() throws IOException {
			Mockito.doReturn(metadata(VfsNodeType.FILE, 5)).when(file).readMetadata();
			var stat = Mockito.mock(Stat.class);
			Mockito.doReturn(Mockito.mock(TimeSpec.class)).when(stat).aTime();
			Mockito.doReturn(Mockito.mock(TimeSpec.class)).when(stat).mTime();
			Mockito.doReturn(Mockito.mock(TimeSpec.class)).when(stat).cTime();
			Mockito.doReturn(Mockito.mock(TimeSpec.class)).when(stat).birthTime();

			assertEquals(0, ops.getattr("/f", stat, fi));

			Mockito.verify(stat).setSize(5);
			Mockito.verify(fs, Mockito.never()).readNodeMetadata(Mockito.anyString());
		}
	}

	@Nested
	@DisplayName("symlinks")
	class Symlinks {

		@Test
		@DisplayName("symlink passes target content and link path in the right order")
		void symlink() throws IOException {
			assertEquals(0, ops.symlink("target/file", "/link"));

			Mockito.verify(fs).createSymbolicLink("/link", "target/file");
		}

		@Test
		@DisplayName("readlink writes a NUL-terminated, possibly truncated target")
		void readlink() throws IOException {
			Mockito.doReturn("abcdef").when(fs).readSymbolicLink("/link");
			var buf = ByteBuffer.allocate(4);

			assertEquals(0, ops.readlink("/link", buf, 4));

			assertArrayEquals(new byte[]{'a', 'b', 'c', 0}, buf.array());
		}
	}

	@Nested
	@DisplayName("xattrs")
	class Xattrs {

		@Test
		@DisplayName("getxattr with empty buffer returns the size")
		void getxattrSize() throws IOException {
			Mockito.doReturn(ByteBuffer.wrap("value".getBytes(StandardCharsets.UTF_8))).when(fs).getXattr("/f", "user.a");

			assertEquals(5, ops.getxattr("/f", "user.a", ByteBuffer.allocate(0)));
		}

		@Test
		@DisplayName("getxattr with too small buffer returns ERANGE")
		void getxattrRange() throws IOException {
			Mockito.doReturn(ByteBuffer.wrap("value".getBytes(StandardCharsets.UTF_8))).when(fs).getXattr("/f", "user.a");

			assertEquals(-ERANGE, ops.getxattr("/f", "user.a", ByteBuffer.allocate(3)));
		}

		@Test
		@DisplayName("getxattr copies the value")
		void getxattrCopy() throws IOException {
			Mockito.doReturn(ByteBuffer.wrap("value".getBytes(StandardCharsets.UTF_8))).when(fs).getXattr("/f", "user.a");
			var buf = ByteBuffer.allocate(8);

			assertEquals(5, ops.getxattr("/f", "user.a", buf));

			assertEquals("value", new String(buf.array(), 0, 5, StandardCharsets.UTF_8));
		}

		@Test
		@DisplayName("missing attribute maps to ENOATTR, not ENOENT")
		void getxattrMissing() throws IOException {
			Mockito.doThrow(new NoSuchFileException("/f")).when(fs).getXattr("/f", "user.a");

			assertEquals(-ENOATTR, ops.getxattr("/f", "user.a", ByteBuffer.allocate(0)));
		}

		@Test
		@DisplayName("setxattr maps flags to policies")
		void setxattrFlags() throws IOException {
			var value = ByteBuffer.allocate(1);

			assertEquals(0, ops.setxattr("/f", "user.a", value, 0));
			assertEquals(0, ops.setxattr("/f", "user.a", value, 1));
			assertEquals(0, ops.setxattr("/f", "user.a", value, 2));
			assertEquals(-EINVAL, ops.setxattr("/f", "user.a", value, 3));

			Mockito.verify(fs).setXattr("/f", "user.a", value, VfsXattrPolicy.CREATE_OR_REPLACE);
			Mockito.verify(fs).setXattr("/f", "user.a", value, VfsXattrPolicy.CREATE_ONLY);
			Mockito.verify(fs).setXattr("/f", "user.a", value, VfsXattrPolicy.REPLACE_ONLY);
		}

		@Test
		@DisplayName("listxattr packs NUL-separated names")
		void listxattr() throws IOException {
			Mockito.doReturn(List.of("user.a", "user.bb")).when(fs).listXattrs("/f");

			assertEquals(15, ops.listxattr("/f", ByteBuffer.allocate(0)));
			assertEquals(-ERANGE, ops.listxattr("/f", ByteBuffer.allocate(10)));
			var buf = ByteBuffer.allocate(15);
			assertEquals(15, ops.listxattr("/f", buf));
			assertArrayEquals("user.a\0user.bb\0".getBytes(StandardCharsets.UTF_8), buf.array());
		}
	}
}
