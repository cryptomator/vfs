package org.cryptomator.vfs.test;

import org.cryptomator.vfs.frontend.fskit.FskitDirectoryEntry;
import org.cryptomator.vfs.frontend.fskit.FskitDirectoryListing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FskitVfsBootstrapTest {

	private static final int O_RDONLY = 0x0;
	private static final int O_RDWR = 0x2;
	private static final int O_CREAT = 0x200;

	@TempDir
	Path rootDir;

	@Test
	void createFailsForMissingRootDir() {
		assertThrows(IOException.class, () -> FskitVfsBootstrap.create(rootDir.resolve("missing").toString()));
	}

	@Test
	void facadeRoundTrip() throws IOException {
		var adapter = FskitVfsBootstrap.create(rootDir.toString());

		assertEquals(0, adapter.createDirectory("/dir", 0755));

		var created = adapter.createFile("/dir/file.txt", O_RDWR | O_CREAT, 0644);
		assertEquals(0, created.errorCode());
		byte[] content = "hello fskit".getBytes(StandardCharsets.UTF_8);
		assertEquals(content.length, adapter.write(created.handle(), 0L, content, content.length));
		assertEquals(0, adapter.close(created.handle()));

		var opened = adapter.openFile("/dir/file.txt", O_RDONLY);
		assertEquals(0, opened.errorCode());
		var read = adapter.read(opened.handle(), 0L, 64);
		assertEquals(0, read.errorCode());
		assertArrayEquals(content, read.data());
		assertEquals(0, adapter.close(opened.handle()));

		assertEquals(List.of("dir"), entryNames(adapter.listDirectory("/")));
		assertEquals(List.of("file.txt"), entryNames(adapter.listDirectory("/dir")));
	}

	private static List<String> entryNames(FskitDirectoryListing listing) {
		assertEquals(0, listing.errorCode());
		return Arrays.stream(listing.entries()).map(FskitDirectoryEntry::name).toList();
	}
}
