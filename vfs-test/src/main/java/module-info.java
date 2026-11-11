import org.jspecify.annotations.NullMarked;

@NullMarked
module org.cryptomator.vfs.test {
	requires org.cryptomator.jfuse;
	requires org.cryptomator.vfs.api;
	requires org.cryptomator.vfs.frontend.fuse;
	requires org.cryptomator.vfs.backend.nio;
	requires org.cryptomator.vfs.middleware.uvf.shortening;
	requires org.cryptomator.vfs.middleware.uvf.encryption;
	requires org.slf4j.simple;
	requires static org.jspecify;
	requires org.slf4j;

	exports org.cryptomator.vfs.test;
}
