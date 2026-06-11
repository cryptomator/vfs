package org.cryptomator.vfs.test;

import org.cryptomator.vfs.backend.nio.NioVfsFileSystem;
import org.cryptomator.vfs.frontend.fskit.FskitVfsAdapter;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Mirrors a directory through the NIO backend into the FSKit facade. Single
 * entry point called by the Swift FSKit extension.
 */
public final class FskitVfsBootstrap {

	private FskitVfsBootstrap() {
	}

	public static FskitVfsAdapter create(String rootDir) throws IOException {
		var backend = new NioVfsFileSystem(Path.of(rootDir));
		return new FskitVfsAdapter(new LoggingVfsFileSystem("mirror", backend));
	}
}
