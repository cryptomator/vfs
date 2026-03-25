import org.jspecify.annotations.NullMarked;

@NullMarked
module org.cryptomator.vfs.middleware.uvf {
	requires org.cryptomator.cryptolib;
	requires org.cryptomator.vfs.api;
	requires static org.jspecify;

	exports org.cryptomator.vfs.middleware.uvf;
}
