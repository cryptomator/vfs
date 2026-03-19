import org.jspecify.annotations.NullMarked;

@NullMarked
module org.cryptomator.vfs.frontend.fuse {
	requires org.cryptomator.jfuse.api;
	requires org.cryptomator.vfs.api;
	requires org.slf4j;
	requires static org.jspecify;

	exports org.cryptomator.vfs.frontend.fuse;
}
