import org.jspecify.annotations.NullMarked;

@NullMarked
module org.cryptomator.vfs.backend.nio {
	requires org.cryptomator.vfs.api;
	requires org.cryptomator.vfs.common;
	requires static org.jspecify;

	exports org.cryptomator.vfs.backend.nio;
}
