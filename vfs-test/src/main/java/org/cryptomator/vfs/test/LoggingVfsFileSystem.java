package org.cryptomator.vfs.test;

import org.cryptomator.vfs.api.VfsCapabilities;
import org.cryptomator.vfs.api.VfsDirectoryStream;
import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.api.VfsMetadata;
import org.cryptomator.vfs.api.VfsNodeMetadata;
import org.cryptomator.vfs.api.VfsTimes;
import org.cryptomator.vfs.api.VfsXattrPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
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
	public VfsCapabilities capabilities() {
		log.debug("capabilities()");
		return delegate.capabilities();
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
	public VfsDirectoryStream openDirectory(String path) throws IOException {
		log.debug("openDirectory({})", path);
		return delegate.openDirectory(path);
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
		log.debug("createFile({}, {})", path, options);
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
	public void rename(String sourcePath, String targetPath, boolean replaceExisting) throws IOException {
		log.debug("rename({}, {}, replaceExisting={})", sourcePath, targetPath, replaceExisting);
		delegate.rename(sourcePath, targetPath, replaceExisting);
	}

	@Override
	public void setTimes(String path, VfsTimes times) throws IOException {
		log.debug("setTimes({}, {})", path, times);
		delegate.setTimes(path, times);
	}

	@Override
	public void setPermissions(String path, Set<PosixFilePermission> permissions) throws IOException {
		log.debug("setPermissions({}, {})", path, permissions);
		delegate.setPermissions(path, permissions);
	}

	@Override
	public String readSymbolicLink(String path) throws IOException {
		log.debug("readSymbolicLink({})", path);
		return delegate.readSymbolicLink(path);
	}

	@Override
	public void createSymbolicLink(String path, String target) throws IOException {
		log.debug("createSymbolicLink({}, {})", path, target);
		delegate.createSymbolicLink(path, target);
	}

	@Override
	public List<String> listXattrs(String path) throws IOException {
		log.debug("listXattrs({})", path);
		return delegate.listXattrs(path);
	}

	@Override
	public ByteBuffer getXattr(String path, String name) throws IOException {
		log.debug("getXattr({}, {})", path, name);
		return delegate.getXattr(path, name);
	}

	@Override
	public void setXattr(String path, String name, ByteBuffer value, VfsXattrPolicy policy) throws IOException {
		log.debug("setXattr({}, {}, {} bytes, {})", path, name, value.remaining(), policy);
		delegate.setXattr(path, name, value, policy);
	}

	@Override
	public void removeXattr(String path, String name) throws IOException {
		log.debug("removeXattr({}, {})", path, name);
		delegate.removeXattr(path, name);
	}
}
