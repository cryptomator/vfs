package org.cryptomator.vfs.test;

import org.cryptomator.vfs.api.VfsDirectoryEntry;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsMetadata;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsTimes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import java.io.IOException;
import java.nio.file.AccessMode;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;

/**
 * A {@link VfsFileSystem} decorator that logs every method call via SLF4J at DEBUG level.
 */
final class LoggingVfsFileSystem implements VfsFileSystem {

	private final VfsFileSystem delegate;
	private final Logger log;

	LoggingVfsFileSystem(String label, VfsFileSystem delegate) {
		this.delegate = delegate;
		this.log = LoggerFactory.getLogger(LoggingVfsFileSystem.class.getName() + "." + label);
	}

	@Override
	public VfsNodeMetadata readNodeMetadata(String path) throws IOException {
		log.debug("readNodeMetadata({})", path);
		return delegate.readNodeMetadata(path);
	}

	@Override
	public VfsMetadata readVfsMetadata(String path) throws IOException {
		log.debug("readVfsMetadata({})", path);
		return delegate.readVfsMetadata(path);
	}

	@Override
	public void checkAccess(String path, Set<AccessMode> accessModes) throws IOException {
		log.debug("checkAccess({}, {})", path, accessModes);
		delegate.checkAccess(path, accessModes);
	}

	@Override
	public List<VfsDirectoryEntry> listDirectory(String path) throws IOException {
		log.debug("listDirectory({})", path);
		return delegate.listDirectory(path);
	}

	@Override
	public void createDirectory(String path, Set<PosixFilePermission> permissions) throws IOException {
		log.debug("createDirectory({})", path);
		delegate.createDirectory(path, permissions);
	}

	@Override
	public void deleteDirectory(String path) throws IOException {
		log.debug("deleteDirectory({})", path);
		delegate.deleteDirectory(path);
	}

	@Override
	public VfsFile openFile(String path, Set<StandardOpenOption> options) throws IOException {
		log.debug("openFile({}, {})", path, options);
		return delegate.openFile(path, options);
	}

	@Override
	public VfsFile createFile(String path, Set<StandardOpenOption> options, Set<PosixFilePermission> permissions) throws IOException {
		log.debug("createFile({})", path);
		return delegate.createFile(path, options, permissions);
	}

	@Override
	public void truncate(String path, long size) throws IOException {
		log.debug("truncate({}, {})", path, size);
		delegate.truncate(path, size);
	}

	@Override
	public void deleteFile(String path) throws IOException {
		log.debug("deleteFile({})", path);
		delegate.deleteFile(path);
	}

	@Override
	public void rename(String sourcePath, String targetPath) throws IOException {
		log.debug("rename({}, {})", sourcePath, targetPath);
		delegate.rename(sourcePath, targetPath);
	}

	@Override
	public void setTimes(String path, VfsTimes times) throws IOException {
		log.debug("setTimes({})", path);
		delegate.setTimes(path, times);
	}
}
