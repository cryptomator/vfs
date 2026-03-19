import org.jspecify.annotations.NullMarked;

@NullMarked
module org.cryptomator.vfs.frontend.webdav {
	requires static org.jspecify;

	exports org.cryptomator.vfs.frontend.webdav;
}
