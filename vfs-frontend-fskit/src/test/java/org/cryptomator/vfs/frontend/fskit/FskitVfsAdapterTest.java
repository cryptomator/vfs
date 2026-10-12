package org.cryptomator.vfs.frontend.fskit;

import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsMetadata;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.cryptomator.vfs.api.VfsTimes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class FskitVfsAdapterTest {

	private static final Instant MODIFIED = Instant.ofEpochSecond(1_700_000_000L, 111_000_001L);
	private static final Instant ACCESSED = Instant.ofEpochSecond(1_700_000_100L, 222_000_002L);
	private static final Instant CREATED = Instant.ofEpochSecond(1_700_000_200L, 333_000_003L);

	private final VfsFileSystem fileSystem = mock(VfsFileSystem.class);
	private final FskitVfsAdapter adapter = new FskitVfsAdapter(fileSystem);
	private final Map<VfsFile, Long> openHandles = new HashMap<>();

	@Test
	void openIssuesStrictlyPositiveHandles() throws IOException {
		Mockito.doReturn(mock(VfsFile.class)).when(fileSystem).openFile(anyString(), anySet());

		var first = adapter.openFile("/file.txt", 0x0);
		var second = adapter.openFile("/file.txt", 0x0);

		assertEquals(0, first.errorCode());
		assertEquals(0, second.errorCode());
		assertTrue(first.handle() > 0);
		assertTrue(second.handle() > first.handle());
	}

	@ParameterizedTest
	@MethodSource("openFlagEncodings")
	void openFlagsDecodeToOpenOptions(int openFlags, Set<StandardOpenOption> expected) throws IOException {
		Mockito.doReturn(mock(VfsFile.class)).when(fileSystem).openFile(anyString(), anySet());

		adapter.openFile("/file.txt", openFlags);

		@SuppressWarnings("unchecked")
		ArgumentCaptor<Set<StandardOpenOption>> options = ArgumentCaptor.forClass(Set.class);
		verify(fileSystem).openFile(eq("/file.txt"), options.capture());
		assertEquals(expected, options.getValue());
	}

	static Stream<Arguments> openFlagEncodings() {
		return Stream.of(
				Arguments.of(0x0, Set.of(READ)), // plain O_RDONLY
				Arguments.of(0x1, Set.of(WRITE)),
				Arguments.of(0x2, Set.of(READ, WRITE)),
				Arguments.of(0x1 | 0x8, Set.of(WRITE, APPEND)),
				Arguments.of(0x1 | 0x200, Set.of(WRITE, CREATE)),
				Arguments.of(0x1 | 0x200 | 0x800, Set.of(WRITE, CREATE_NEW)),
				Arguments.of(0x1 | 0x400, Set.of(WRITE, TRUNCATE_EXISTING)),
				Arguments.of(0x2 | 0x200 | 0x400, Set.of(READ, WRITE, CREATE, TRUNCATE_EXISTING))
		);
	}

	@Test
	void createFileDecodesPermissions() throws IOException {
		Mockito.doReturn(mock(VfsFile.class)).when(fileSystem).createFile(anyString(), anySet(), anySet());

		var result = adapter.createFile("/file.txt", 0x1 | 0x200, 0750);

		assertEquals(0, result.errorCode());
		@SuppressWarnings("unchecked")
		ArgumentCaptor<Set<PosixFilePermission>> permissions = ArgumentCaptor.forClass(Set.class);
		verify(fileSystem).createFile(eq("/file.txt"), eq(Set.of(WRITE, CREATE)), permissions.capture());
		assertEquals(Set.of(
				PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE,
				PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_EXECUTE
		), permissions.getValue());
	}

	@Test
	void createDirectoryDecodesPermissions() throws IOException {
		assertEquals(0, adapter.createDirectory("/dir", 0644));

		@SuppressWarnings("unchecked")
		ArgumentCaptor<Set<PosixFilePermission>> permissions = ArgumentCaptor.forClass(Set.class);
		verify(fileSystem).createDirectory(eq("/dir"), permissions.capture());
		assertEquals(Set.of(
				PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
				PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ
		), permissions.getValue());
	}

	@ParameterizedTest
	@MethodSource("accessMaskEncodings")
	void accessMasksDecodeToAccessModes(int accessMask, Set<AccessMode> expected) throws IOException {
		assertEquals(0, adapter.checkAccess("/file.txt", accessMask));

		@SuppressWarnings("unchecked")
		ArgumentCaptor<Set<AccessMode>> accessModes = ArgumentCaptor.forClass(Set.class);
		verify(fileSystem).checkAccess(eq("/file.txt"), accessModes.capture());
		assertEquals(expected, accessModes.getValue());
	}

	static Stream<Arguments> accessMaskEncodings() {
		return Stream.of(
				Arguments.of(0x0, Set.of()),
				Arguments.of(0x1, Set.of(AccessMode.EXECUTE)),
				Arguments.of(0x2, Set.of(AccessMode.WRITE)),
				Arguments.of(0x4, Set.of(AccessMode.READ)),
				Arguments.of(0x7, Set.of(AccessMode.READ, AccessMode.WRITE, AccessMode.EXECUTE))
		);
	}

	@Test
	void readNodeMetadataProjectsAllFields() throws IOException {
		Mockito.doReturn(new VfsNodeMetadata(VfsNodeType.FILE, 42L, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ), MODIFIED, ACCESSED, CREATED))
				.when(fileSystem).readNodeMetadata("/file.txt");

		var metadata = adapter.readNodeMetadata("/file.txt");

		assertEquals(0, metadata.errorCode());
		assertEquals(FskitNodeMetadata.TYPE_FILE, metadata.type());
		assertEquals(42L, metadata.size());
		assertEquals(0644, metadata.posixMode());
		assertEquals(MODIFIED.getEpochSecond(), metadata.modifiedSeconds());
		assertEquals(MODIFIED.getNano(), metadata.modifiedNanos());
		assertEquals(ACCESSED.getEpochSecond(), metadata.accessedSeconds());
		assertEquals(ACCESSED.getNano(), metadata.accessedNanos());
		assertEquals(CREATED.getEpochSecond(), metadata.createdSeconds());
		assertEquals(CREATED.getNano(), metadata.createdNanos());
	}

	@Test
	void readNodeMetadataProjectsDirectoryType() throws IOException {
		Mockito.doReturn(nodeMetadata(VfsNodeType.DIRECTORY)).when(fileSystem).readNodeMetadata("/dir");

		assertEquals(FskitNodeMetadata.TYPE_DIRECTORY, adapter.readNodeMetadata("/dir").type());
	}

	@Test
	void readVfsMetadataProjectsAllFields() throws IOException {
		Mockito.doReturn(new VfsMetadata(4096L, 1000L, 500L, 400L, 255L)).when(fileSystem).readVfsMetadata("/");

		var metadata = adapter.readVfsMetadata("/");

		assertEquals(0, metadata.errorCode());
		assertEquals(4096L, metadata.blockSize());
		assertEquals(1000L, metadata.totalBlocks());
		assertEquals(500L, metadata.freeBlocks());
		assertEquals(400L, metadata.availableBlocks());
		assertEquals(255L, metadata.maxNameLength());
	}

	@Test
	void listDirectoryProjectsEntries() throws IOException {
		Mockito.doReturn(List.of(new VfsDirectoryEntry("file.txt", nodeMetadata(VfsNodeType.FILE)), new VfsDirectoryEntry("subdir", nodeMetadata(VfsNodeType.DIRECTORY))))
				.when(fileSystem).listDirectory("/dir");

		var listing = adapter.listDirectory("/dir");

		assertEquals(0, listing.errorCode());
		assertEquals(2, listing.entries().length);
		assertEquals("file.txt", listing.entries()[0].name());
		assertEquals(FskitNodeMetadata.TYPE_FILE, listing.entries()[0].metadata().type());
		assertEquals("subdir", listing.entries()[1].name());
		assertEquals(FskitNodeMetadata.TYPE_DIRECTORY, listing.entries()[1].metadata().type());
	}

	@Test
	void readReturnsPartiallyFilledData() throws IOException {
		var file = openFileWithHandle();
		byte[] content = "hello".getBytes(StandardCharsets.UTF_8);
		Mockito.doAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			buf.put(content);
			return content.length;
		}).when(file).read(any(ByteBuffer.class), eq(3L));

		var result = adapter.read(handleOf(file), 3L, 8);

		assertEquals(0, result.errorCode());
		assertArrayEquals(content, result.data());
	}

	@Test
	void readRequestsExactlyTheGivenLength() throws IOException {
		var file = openFileWithHandle();
		Mockito.doAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			int remaining = buf.remaining();
			buf.position(buf.limit());
			return remaining;
		}).when(file).read(any(ByteBuffer.class), anyLong());

		var result = adapter.read(handleOf(file), 0L, 4);

		assertEquals(0, result.errorCode());
		assertEquals(4, result.data().length);
	}

	@Test
	void readClampsEofToEmptyData() throws IOException {
		var file = openFileWithHandle();
		Mockito.doReturn(-1).when(file).read(any(ByteBuffer.class), anyLong());

		var result = adapter.read(handleOf(file), 0L, 8);

		assertEquals(0, result.errorCode());
		assertEquals(0, result.data().length);
	}

	@Test
	void readClampsZeroToEmptyData() throws IOException {
		var file = openFileWithHandle();
		Mockito.doReturn(0).when(file).read(any(ByteBuffer.class), anyLong());

		var result = adapter.read(handleOf(file), 0L, 8);

		assertEquals(0, result.errorCode());
		assertEquals(0, result.data().length);
	}

	@Test
	void readRejectsNegativeLength() throws IOException {
		var file = openFileWithHandle();

		assertEquals(-22, adapter.read(handleOf(file), 0L, -1).errorCode());
	}

	@Test
	void writeWindowsBufferToLength() throws IOException {
		var file = openFileWithHandle();
		Mockito.doAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			int remaining = buf.remaining();
			buf.position(buf.limit());
			return remaining;
		}).when(file).write(any(ByteBuffer.class), eq(7L));

		assertEquals(4, adapter.write(handleOf(file), 7L, new byte[10], 4));
	}

	@Test
	void operationsOnUnknownHandleReturnEbadf() {
		assertEquals(-9, adapter.read(0L, 0L, 1).errorCode());
		assertEquals(-9, adapter.write(0L, 0L, new byte[1], 1));
		assertEquals(-9, adapter.force(0L, true));
		assertEquals(-9, adapter.close(0L));
	}

	@Test
	void closeReleasesHandle() throws IOException {
		var file = openFileWithHandle();
		long handle = handleOf(file);

		assertEquals(0, adapter.close(handle));
		verify(file).close();
		assertEquals(-9, adapter.close(handle));
	}

	@Test
	void forceDelegatesToFile() throws IOException {
		var file = openFileWithHandle();

		assertEquals(0, adapter.force(handleOf(file), true));
		verify(file).force(true);
	}

	@Test
	void destroyClosesAllHandles() throws IOException {
		var first = openFileWithHandle();
		var second = openFileWithHandle();

		adapter.destroy();

		verify(first).close();
		verify(second).close();
		assertEquals(-9, adapter.read(handleOf(first), 0L, 1).errorCode());
	}

	@Test
	void destroyClosesRemainingHandlesWhenOneCloseFails() throws IOException {
		var failing = openFileWithHandle();
		var healthy = openFileWithHandle();
		Mockito.doThrow(new IOException("boom")).when(failing).close();

		adapter.destroy();

		verify(healthy).close();
		assertEquals(-9, adapter.force(handleOf(failing), false));
		assertEquals(-9, adapter.force(handleOf(healthy), false));
	}

	@Test
	void readMapsIoExceptionToErrorCode() throws IOException {
		var file = openFileWithHandle();
		Mockito.doThrow(new IOException("boom")).when(file).read(any(ByteBuffer.class), anyLong());

		assertEquals(-5, adapter.read(handleOf(file), 0L, 8).errorCode());
	}

	@Test
	void writeMapsIoExceptionToErrorCode() throws IOException {
		var file = openFileWithHandle();
		Mockito.doThrow(new IOException("boom")).when(file).write(any(ByteBuffer.class), anyLong());

		assertEquals(-5, adapter.write(handleOf(file), 0L, new byte[4], 4));
	}

	@Test
	void forceMapsIoExceptionToErrorCode() throws IOException {
		var file = openFileWithHandle();
		Mockito.doThrow(new IOException("boom")).when(file).force(anyBoolean());

		assertEquals(-5, adapter.force(handleOf(file), false));
	}

	@Test
	void closeMapsIoExceptionToErrorCode() throws IOException {
		var file = openFileWithHandle();
		Mockito.doThrow(new IOException("boom")).when(file).close();

		assertEquals(-5, adapter.close(handleOf(file)));
	}

	@Test
	void deleteFileOnDirectoryReturnsEisdir() throws IOException {
		Mockito.doReturn(nodeMetadata(VfsNodeType.DIRECTORY)).when(fileSystem).readNodeMetadata("/dir");

		assertEquals(-21, adapter.deleteFile("/dir"));
	}

	@Test
	void deleteFileMapsMissingPathToEnoent() throws IOException {
		Mockito.doThrow(new NoSuchFileException("/missing")).when(fileSystem).readNodeMetadata("/missing");

		assertEquals(-2, adapter.deleteFile("/missing"));
	}

	@Test
	void openFileMapsInvalidOptionCombinationToEinval() throws IOException {
		Mockito.doThrow(new IllegalArgumentException("READ + APPEND not allowed")).when(fileSystem).openFile(anyString(), anySet());

		assertEquals(-22, adapter.openFile("/file.txt", 0x0 | 0x8).errorCode());
	}

	@Test
	void createFileMapsInvalidOptionCombinationToEinval() throws IOException {
		Mockito.doThrow(new IllegalArgumentException("READ + APPEND not allowed")).when(fileSystem).createFile(anyString(), anySet(), anySet());

		assertEquals(-22, adapter.createFile("/file.txt", 0x0 | 0x8, 0644).errorCode());
	}

	@Test
	void createFileMapsIoExceptionToErrorCode() throws IOException {
		Mockito.doThrow(new FileAlreadyExistsException("/file.txt")).when(fileSystem).createFile(anyString(), anySet(), anySet());

		var result = adapter.createFile("/file.txt", 0x200 | 0x800, 0644);

		assertEquals(-17, result.errorCode());
		assertEquals(0L, result.handle());
	}

	@Test
	void writeRejectsInvalidLengths() throws IOException {
		var file = openFileWithHandle();

		assertEquals(-22, adapter.write(handleOf(file), 0L, new byte[4], -1));
		assertEquals(-22, adapter.write(handleOf(file), 0L, new byte[4], 5));
	}

	@Test
	void deleteFileDelegatesForFiles() throws IOException {
		Mockito.doReturn(nodeMetadata(VfsNodeType.FILE)).when(fileSystem).readNodeMetadata("/file.txt");

		assertEquals(0, adapter.deleteFile("/file.txt"));
		verify(fileSystem).deleteFile("/file.txt");
	}

	@Test
	void deleteDirectoryOnFileReturnsEnotdir() throws IOException {
		Mockito.doReturn(nodeMetadata(VfsNodeType.FILE)).when(fileSystem).readNodeMetadata("/file.txt");

		assertEquals(-20, adapter.deleteDirectory("/file.txt"));
	}

	@Test
	void deleteDirectoryDelegatesForDirectories() throws IOException {
		Mockito.doReturn(nodeMetadata(VfsNodeType.DIRECTORY)).when(fileSystem).readNodeMetadata("/dir");

		assertEquals(0, adapter.deleteDirectory("/dir"));
		verify(fileSystem).deleteDirectory("/dir");
	}

	@Test
	void renameDelegates() throws IOException {
		assertEquals(0, adapter.rename("/old.txt", "/new.txt"));
		verify(fileSystem).rename("/old.txt", "/new.txt");
	}

	@Test
	void truncateDelegates() throws IOException {
		assertEquals(0, adapter.truncate("/file.txt", 123L));
		verify(fileSystem).truncate("/file.txt", 123L);
	}

	@Test
	void setTimesDecodesInstants() throws IOException {
		assertEquals(0, adapter.setTimes("/file.txt", ACCESSED.getEpochSecond(), ACCESSED.getNano(), MODIFIED.getEpochSecond(), MODIFIED.getNano()));

		verify(fileSystem).setTimes("/file.txt", new VfsTimes(ACCESSED, MODIFIED));
	}

	@Test
	void setTimesDecodesNotSetSentinel() throws IOException {
		assertEquals(0, adapter.setTimes("/file.txt", Long.MIN_VALUE, 0, MODIFIED.getEpochSecond(), MODIFIED.getNano()));

		verify(fileSystem).setTimes("/file.txt", new VfsTimes(null, MODIFIED));
	}

	@Test
	void setTimesMapsUnsupportedOperationToEnotsup() throws IOException {
		Mockito.doThrow(new UnsupportedOperationException()).when(fileSystem).setTimes(anyString(), any(VfsTimes.class));

		assertEquals(-45, adapter.setTimes("/file.txt", 0L, 0, 0L, 0));
	}

	@ParameterizedTest
	@MethodSource("errorCodeMappings")
	void ioExceptionsMapToPosixErrorCodes(IOException exception, int expectedErrorCode) throws IOException {
		Mockito.doThrow(exception).when(fileSystem).readNodeMetadata("/file.txt");

		assertEquals(expectedErrorCode, adapter.readNodeMetadata("/file.txt").errorCode());
	}

	static Stream<Arguments> errorCodeMappings() {
		return Stream.of(
				Arguments.of(new NoSuchFileException("/file.txt"), -2),
				Arguments.of(new FileAlreadyExistsException("/file.txt"), -17),
				Arguments.of(new AccessDeniedException("/file.txt"), -13),
				Arguments.of(new NotDirectoryException("/file.txt"), -20),
				Arguments.of(new DirectoryNotEmptyException("/file.txt"), -66),
				Arguments.of(new FileSystemException("/file.txt", null, "Is a directory"), -21),
				Arguments.of(new IOException("boom"), -5)
		);
	}

	@Test
	void errorCarriersReportFailures() throws IOException {
		Mockito.doThrow(new NoSuchFileException("/missing")).when(fileSystem).readVfsMetadata("/missing");
		Mockito.doThrow(new NoSuchFileException("/missing")).when(fileSystem).listDirectory("/missing");
		Mockito.doThrow(new NoSuchFileException("/missing")).when(fileSystem).openFile(eq("/missing"), anySet());

		assertEquals(-2, adapter.readVfsMetadata("/missing").errorCode());
		assertEquals(-2, adapter.listDirectory("/missing").errorCode());
		var result = adapter.openFile("/missing", 0x0);
		assertEquals(-2, result.errorCode());
		assertEquals(0L, result.handle());
	}

	private VfsFile openFileWithHandle() throws IOException {
		var file = mock(VfsFile.class);
		Mockito.doReturn(file).when(fileSystem).openFile(anyString(), anySet());
		long handle = adapter.openFile("/file.txt", 0x2).handle();
		openHandles.put(file, handle);
		return file;
	}

	private long handleOf(VfsFile file) {
		return openHandles.get(file);
	}

	private static VfsNodeMetadata nodeMetadata(VfsNodeType type) {
		return new VfsNodeMetadata(type, 42L, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), MODIFIED, ACCESSED, CREATED);
	}
}
