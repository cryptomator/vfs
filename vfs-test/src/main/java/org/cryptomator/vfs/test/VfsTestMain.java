package org.cryptomator.vfs.test;

import org.cryptomator.jfuse.api.Fuse;
import org.cryptomator.jfuse.api.FuseMountFailedException;
import org.cryptomator.vfs.backend.nio.NioVfsFileSystem;
import org.cryptomator.vfs.frontend.fuse.FuseVfsOperations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeoutException;

/**
 * Mounts a physical directory through the NIO backend and the FUSE frontend.
 */
public final class VfsTestMain {

	private static final Logger LOG = LoggerFactory.getLogger(VfsTestMain.class);

	public static void main(String[] args) throws Exception {
		if (args.length < 2 || args.length > 3) {
			printUsage();
			return;
		}

		var sourceDir = Path.of(args[0]).toAbsolutePath().normalize();
		var mountPoint = Path.of(args[1]).toAbsolutePath().normalize();
		var libraryPath = args.length == 3 ? args[2] : null;

		if (!Files.isDirectory(sourceDir)) {
			throw new IllegalArgumentException("Source directory does not exist: " + sourceDir);
		}
		if (!Files.isDirectory(mountPoint)) {
			throw new IllegalArgumentException("Mount point does not exist: " + mountPoint);
		}

		var backend = new NioVfsFileSystem(sourceDir);
		var builder = Fuse.builder();
		if (libraryPath != null && !libraryPath.isBlank()) {
			builder.setLibraryPath(libraryPath);
		}

		var operations = new FuseVfsOperations(backend, builder.errno());
		try (var fuse = builder.build(operations)) {
			Runtime.getRuntime().addShutdownHook(new Thread(() -> closeQuietly(fuse), "vfs-test-shutdown"));
			LOG.info("Mounting{} at {}", sourceDir, mountPoint);
			fuse.mount("vfs-test", mountPoint, "-s");
			LOG.info("Enter anything to unmount...");
			System.in.read();
		} catch (FuseMountFailedException | TimeoutException e) {
			LOG.error("Un/Mounting failed. ", e);
			System.exit(1);
		} catch (IOException e) {
			LOG.error("Failed to create mirror", e);
			System.exit(1);
		}
	}

	private static void printUsage() {
		System.out.println("Usage: VfsTestMain <sourceDir> <mountPoint> [fuseLibraryPath]");
	}

	private static void closeQuietly(Fuse fuse) {
		try {
			fuse.close();
		} catch (Exception e) {
			System.err.println("Failed to close FUSE mount: " + e.getMessage());
		}
	}
}
