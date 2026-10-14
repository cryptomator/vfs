package org.cryptomator.vfs.middleware.uvf.dir;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.UnlockedVault;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultNode;
import org.cryptomator.cryptolib.api.VaultReader;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystemException;
import java.time.Duration;

/**
 * Resolves cleartext VFS paths to their {@link VaultDirectory} and {@link VaultNode} on the ciphertext side.
 * <p>
 * Each cleartext directory maps to a flat {@code d/XX/YYYYYY...} content directory on the delegate. File and directory names are encrypted per parent directory,
 * so resolving a path descends from the root, reading each intermediate directory's {@code dir.uvf} through the {@link VaultReader}. Resolved directories are
 * cached by the ciphertext path of their {@code dir.uvf}; callers that delete, move or recreate a directory must {@link #invalidate(String) invalidate} that path.
 */
public final class DirectoryPathResolver {

	/**
	 * Bounds of the directory cache.
	 *
	 * @param maximumSize maximum number of cached directories
	 * @param timeToLive how long a cached directory is trusted; bounds staleness caused by changes made to the ciphertext behind this file system's back
	 */
	public record CacheSettings(long maximumSize, Duration timeToLive) {

		public static final CacheSettings DEFAULT = new CacheSettings(10_000, Duration.ofSeconds(5));

		/**
		 * Settings that cache nothing, for tests and diagnostics.
		 */
		public static final CacheSettings DISABLED = new CacheSettings(0, Duration.ZERO);
	}

	private final UnlockedVault vault;
	private final VaultReader reader;
	private final Cache<String, VaultDirectory> directories; // key: absolute ciphertext path of the directory's dir.uvf

	public DirectoryPathResolver(UnlockedVault vault, VaultReader reader) {
		this(vault, reader, CacheSettings.DEFAULT);
	}

	public DirectoryPathResolver(UnlockedVault vault, VaultReader reader, CacheSettings cacheSettings) {
		this.vault = vault;
		this.reader = reader;
		this.directories = Caffeine.newBuilder().maximumSize(cacheSettings.maximumSize()).expireAfterWrite(cacheSettings.timeToLive()).build();
	}

	/**
	 * A non-root cleartext path resolved to its parent directory and the node within it; all paths are absolute ciphertext paths on the delegate.
	 *
	 * @param parent the directory containing the node
	 * @param node the node, i.e. the encrypted name and the layout of its well-known files
	 */
	public record ResolvedPath(VaultDirectory parent, VaultNode node) {

		/**
		 * @return the ciphertext path of the entry as listed in the parent's content directory (a file for regular files, a directory for directories and symlinks)
		 */
		public String entryPath() {
			return contentDirPath(parent) + "/" + node.name();
		}

		/**
		 * @return the ciphertext path of the file holding the content, if the node is a regular file
		 */
		public String contentsPath() {
			return contentDirPath(parent) + "/" + node.contentsFile();
		}

		/**
		 * @return the ciphertext path of the {@code dir.uvf} file, if the node is a directory
		 */
		public String dirFilePath() {
			return contentDirPath(parent) + "/" + node.dirFile();
		}

		/**
		 * @return the ciphertext path of the {@code symlink.uvf} file, if the node is a symbolic link
		 */
		public String symlinkFilePath() {
			return contentDirPath(parent) + "/" + node.symlinkFile();
		}
	}

	/**
	 * Tests whether a cleartext path denotes the root directory.
	 *
	 * @param cleartextPath absolute cleartext path
	 * @return {@code true} for {@code /} and equivalent spellings
	 */
	public static boolean isRoot(String cleartextPath) {
		return splitPath(cleartextPath).length == 0;
	}

	/**
	 * Computes the absolute ciphertext path of a directory's content directory.
	 *
	 * @param directory the directory
	 * @return the {@code /d/XX/YYYYYY...} path on the delegate
	 */
	public static String contentDirPath(VaultDirectory directory) {
		return "/" + directory.dirPath();
	}

	/**
	 * Resolves a cleartext directory path.
	 *
	 * @param cleartextPath absolute cleartext path of a directory (the root is allowed)
	 * @return the directory
	 * @throws IOException if an intermediate directory does not exist or its metadata cannot be read or authenticated
	 */
	public VaultDirectory resolveDirectory(String cleartextPath) throws IOException {
		var directory = vault.rootDirectory();
		for (var component : splitPath(cleartextPath)) {
			directory = descend(directory, component);
		}
		return directory;
	}

	/**
	 * Resolves a non-root cleartext path to the node within its parent directory. The node itself need not exist.
	 *
	 * @param cleartextPath absolute cleartext path (e.g. {@code /foo/bar/baz.txt})
	 * @return the parent directory and the node
	 * @throws IOException if the path is the root or an intermediate directory cannot be resolved
	 */
	public ResolvedPath resolve(String cleartextPath) throws IOException {
		var components = splitPath(cleartextPath);
		if (components.length == 0) {
			throw new FileSystemException(cleartextPath, null, "Is the root directory");
		}
		var parent = vault.rootDirectory();
		for (int i = 0; i < components.length - 1; i++) {
			parent = descend(parent, components[i]);
		}
		return new ResolvedPath(parent, parent.encryptName(components[components.length - 1]));
	}

	/**
	 * Drops a cached directory after its {@code dir.uvf} was deleted, moved or replaced.
	 *
	 * @param dirFilePath the absolute ciphertext path of the {@code dir.uvf} file, see {@link ResolvedPath#dirFilePath()}
	 */
	public void invalidate(String dirFilePath) {
		directories.invalidate(dirFilePath);
	}

	/**
	 * Drops all cached directories.
	 */
	public void invalidateAll() {
		directories.invalidateAll();
	}

	// the cache computes atomically per key: a concurrent invalidate() waits for a running load and then discards its result, so a lookup that
	// started before a delete can never leave a stale entry behind
	private VaultDirectory descend(VaultDirectory parent, String cleartextName) throws IOException {
		var node = parent.encryptName(cleartextName);
		var dirFilePath = contentDirPath(parent) + "/" + node.dirFile();
		try {
			return directories.get(dirFilePath, key -> load(node, cleartextName));
		} catch (UncheckedIOException e) {
			throw e.getCause();
		}
	}

	private VaultDirectory load(VaultNode node, String cleartextName) {
		try {
			return node.directory(reader);
		} catch (AuthenticationFailedException e) {
			throw new UncheckedIOException(new IOException("Directory metadata of " + cleartextName + " is unauthentic", e));
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private static String[] splitPath(String path) {
		var normalized = path;
		while (normalized.startsWith("/")) {
			normalized = normalized.substring(1);
		}
		while (normalized.endsWith("/")) {
			normalized = normalized.substring(0, normalized.length() - 1);
		}
		return normalized.isEmpty() ? new String[0] : normalized.split("/");
	}
}
