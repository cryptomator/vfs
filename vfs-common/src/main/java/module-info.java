import org.jspecify.annotations.NullMarked;

@NullMarked
module org.cryptomator.vfs.common {
	requires static org.jspecify;

	exports org.cryptomator.vfs.common;
}
