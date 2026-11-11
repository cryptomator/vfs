import org.jspecify.annotations.NullMarked;

@NullMarked
module org.cryptomator.vfs.middleware.shortening {
	requires org.cryptomator.vfs.api;
	requires org.cryptomator.cryptolib;
	requires org.slf4j;
	requires static org.jspecify;

	exports org.cryptomator.vfs.middleware.shortening;
}
