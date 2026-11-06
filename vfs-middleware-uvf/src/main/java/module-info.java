import org.jspecify.annotations.NullMarked;

@NullMarked
module org.cryptomator.vfs.middleware.uvf {
	requires transitive org.cryptomator.cryptolib;
	requires org.cryptomator.vfs.api;
	requires com.github.benmanes.caffeine;
	requires org.slf4j;
	requires static org.jspecify;

	exports org.cryptomator.vfs.middleware.uvf;
}
