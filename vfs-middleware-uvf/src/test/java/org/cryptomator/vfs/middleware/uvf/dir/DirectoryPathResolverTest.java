package org.cryptomator.vfs.middleware.uvf.dir;

import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultReader;
import org.cryptomator.cryptolib.api.VaultWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DirectoryPathResolverTest {

	private final Map<String, byte[]> files = new HashMap<>();
	private final VaultReader reader = relPath -> {
		var contents = files.get(relPath);
		if (contents == null) {
			throw new NoSuchFileException(relPath);
		}
		return contents;
	};
	private final VaultWriter writer = files::put;

	private UvfUnlockedVault vault;
	private DirectoryPathResolver resolver;

	@BeforeEach
	void setUp() {
		vault = UvfUnlockedVault.create(new SecureRandom());
		resolver = new DirectoryPathResolver(vault, reader);
	}

	@AfterEach
	void tearDown() {
		vault.destroy();
	}

	private VaultDirectory createDirectory(VaultDirectory parent, String name) throws IOException {
		var child = vault.newDirectory();
		parent.encryptName(name).createDirectory(child, writer);
		return child;
	}

	@Test
	@DisplayName("isRoot recognizes all spellings of the root")
	void isRoot() {
		assertTrue(DirectoryPathResolver.isRoot("/"));
		assertTrue(DirectoryPathResolver.isRoot(""));
		assertTrue(DirectoryPathResolver.isRoot("//"));
		assertFalse(DirectoryPathResolver.isRoot("/a"));
	}

	@Test
	@DisplayName("root resolves to the vault's root directory")
	void resolveRoot() throws IOException {
		assertEquals(vault.rootDirectory(), resolver.resolveDirectory("/"));
		assertEquals("/" + vault.rootDirectory().dirPath(), DirectoryPathResolver.contentDirPath(vault.rootDirectory()));
		assertThrows(FileSystemException.class, () -> resolver.resolve("/"));
	}

	@Test
	@DisplayName("file in root resolves deterministically below the root content dir")
	void resolveFileInRoot() throws IOException {
		var first = resolver.resolve("/test.txt");
		var second = resolver.resolve("/test.txt");

		assertEquals(vault.rootDirectory(), first.parent());
		assertEquals(first.entryPath(), second.entryPath());
		assertTrue(first.entryPath().startsWith("/d/"));
		assertTrue(first.entryPath().endsWith(".uvf"));
		assertEquals(first.entryPath(), first.contentsPath());
		assertTrue(first.dirFilePath().endsWith("/dir.uvf"));
		assertTrue(first.symlinkFilePath().endsWith("/symlink.uvf"));
		assertTrue(first.dirFilePath().startsWith(first.entryPath() + "/"));
	}

	@Test
	@DisplayName("different names and parents yield different entries")
	void distinctEntries() throws IOException {
		var sub = createDirectory(vault.rootDirectory(), "sub");

		var a = resolver.resolve("/a.txt");
		var b = resolver.resolve("/b.txt");
		var subA = resolver.resolve("/sub/a.txt");

		assertFalse(a.entryPath().equals(b.entryPath()));
		assertFalse(a.node().name().equals(subA.node().name()));
		assertEquals(sub, subA.parent());
	}

	@Test
	@DisplayName("descends through subdirectories by reading dir.uvf")
	void resolveNested() throws IOException {
		var sub = createDirectory(vault.rootDirectory(), "sub");
		var subSub = createDirectory(sub, "subsub");

		assertEquals(sub, resolver.resolveDirectory("/sub"));
		assertEquals(subSub, resolver.resolveDirectory("/sub/subsub/"));
		assertEquals(subSub, resolver.resolve("/sub/subsub/file").parent());
		assertEquals("/" + subSub.dirPath(), DirectoryPathResolver.contentDirPath(subSub));
	}

	@Test
	@DisplayName("missing intermediate directory fails")
	void missingDirectory() {
		assertThrows(NoSuchFileException.class, () -> resolver.resolveDirectory("/missing"));
		assertThrows(NoSuchFileException.class, () -> resolver.resolve("/missing/file"));
	}

	@Nested
	@DisplayName("cache")
	class Caching {

		private int reads;

		@BeforeEach
		void countReads() {
			VaultReader counting = relPath -> {
				reads++;
				return reader.read(relPath);
			};
			resolver = new DirectoryPathResolver(vault, counting);
		}

		@Test
		@DisplayName("reads each dir.uvf once")
		void readsOnce() throws IOException {
			var sub = createDirectory(vault.rootDirectory(), "sub");
			createDirectory(sub, "subsub");

			resolver.resolveDirectory("/sub/subsub");
			resolver.resolve("/sub/subsub/file");
			resolver.resolveDirectory("/sub");

			assertEquals(2, reads);
		}

		@Test
		@DisplayName("does not cache misses or failures")
		void noNegativeCaching() throws IOException {
			assertThrows(NoSuchFileException.class, () -> resolver.resolveDirectory("/later"));
			var later = createDirectory(vault.rootDirectory(), "later");

			assertEquals(later, resolver.resolveDirectory("/later"));
		}

		@Test
		@DisplayName("serves a replaced directory from cache until invalidated")
		void invalidate() throws IOException {
			var first = createDirectory(vault.rootDirectory(), "sub");
			assertEquals(first, resolver.resolveDirectory("/sub"));
			var second = createDirectory(vault.rootDirectory(), "sub"); // overwrites dir.uvf, as delete + create would

			assertEquals(first, resolver.resolveDirectory("/sub"));
			resolver.invalidate("/" + vault.rootDirectory().dirPath() + "/" + vault.rootDirectory().encryptName("sub").dirFile());
			assertEquals(second, resolver.resolveDirectory("/sub"));
		}

		@Test
		@DisplayName("expires entries after the time to live")
		void timeToLive() throws Exception {
			resolver = new DirectoryPathResolver(vault, reader, new DirectoryPathResolver.CacheSettings(100, Duration.ofMillis(1)));
			var first = createDirectory(vault.rootDirectory(), "sub");
			assertEquals(first, resolver.resolveDirectory("/sub"));
			var second = createDirectory(vault.rootDirectory(), "sub");

			Thread.sleep(20);

			assertEquals(second, resolver.resolveDirectory("/sub"));
		}

		@Test
		@DisplayName("disabled cache reads every time")
		void disabled() throws IOException {
			var counting = new DirectoryPathResolver(vault, relPath -> {
				reads++;
				return reader.read(relPath);
			}, DirectoryPathResolver.CacheSettings.DISABLED);
			createDirectory(vault.rootDirectory(), "sub");

			counting.resolveDirectory("/sub");
			counting.resolveDirectory("/sub");

			assertEquals(2, reads);
		}
	}

	@Test
	@DisplayName("tampered dir.uvf fails")
	void tamperedMetadata() throws IOException {
		createDirectory(vault.rootDirectory(), "sub");
		var dirFile = vault.rootDirectory().dirPath() + "/" + vault.rootDirectory().encryptName("sub").dirFile();
		var contents = files.get(dirFile);
		contents[contents.length - 1] ^= 0x01;

		assertThrows(IOException.class, () -> resolver.resolveDirectory("/sub"));
	}
}
