package org.cryptomator.vfs.middleware.uvf.dir;

import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsDirectoryStream;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsNodeType;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

class UvfDirectoryStreamTest {

	private static final VfsNodeMetadata METADATA = new VfsNodeMetadata(VfsNodeType.FILE, 0, VfsNodeMetadata.NO_FILE_ID, Set.of(), null, null, null, null);

	private final VfsFileSystem delegate = Mockito.mock(VfsFileSystem.class);
	private final VfsDirectoryStream ciphertextStream = Mockito.mock(VfsDirectoryStream.class);

	@BeforeEach
	void setUp() throws IOException {
		Mockito.doReturn(ciphertextStream).when(delegate).openDirectory("/d/AB/CDEF");
	}

	@Test
	void opensCiphertextDirectoryOnConstruction() throws IOException {
		try (var _ = new UvfDirectoryStream(delegate, "/d/AB/CDEF", entry -> entry)) {
			Mockito.verify(delegate).openDirectory("/d/AB/CDEF");
		}
	}

	@Test
	void skipsEntriesMappedToNull() throws IOException {
		var entries = List.of(entry("a.uvf"), entry("dir.uvf"), entry("b.uvf"));
		Mockito.doReturn(entries.iterator()).when(ciphertextStream).iterator();

		try (var stream = new UvfDirectoryStream(delegate, "/d/AB/CDEF", UvfDirectoryStreamTest::decrypt)) {
			var it = stream.iterator();
			Assertions.assertEquals("a", it.next().name());
			Assertions.assertEquals("b", it.next().name());
			Assertions.assertFalse(it.hasNext());
			Assertions.assertThrows(NoSuchElementException.class, it::next);
		}
	}

	@Test
	void closePropagatesToCiphertextStream() throws IOException {
		new UvfDirectoryStream(delegate, "/d/AB/CDEF", entry -> entry).close();

		Mockito.verify(ciphertextStream).close();
	}

	private static VfsDirectoryEntry entry(String name) {
		return new VfsDirectoryEntry(name, METADATA);
	}

	// strips the .uvf suffix, treats the dir.uvf backup as a non-node
	private static @Nullable VfsDirectoryEntry decrypt(VfsDirectoryEntry ciphertextEntry) {
		var name = ciphertextEntry.name();
		if (name.equals("dir.uvf")) {
			return null;
		}
		return new VfsDirectoryEntry(name.substring(0, name.length() - ".uvf".length()), ciphertextEntry.metadata());
	}
}
