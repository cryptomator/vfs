import org.jspecify.annotations.NullMarked;

@NullMarked
module org.cryptomator.vfs.middleware.crypto {
	requires static org.jspecify;

	exports org.cryptomator.vfs.middleware.crypto;
}
