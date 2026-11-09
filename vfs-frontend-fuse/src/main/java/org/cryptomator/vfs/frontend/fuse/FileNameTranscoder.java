package org.cryptomator.vfs.frontend.fuse;

import org.cryptomator.vfs.api.VfsCapabilities;
import org.jspecify.annotations.Nullable;

import java.text.Normalizer;
import java.util.Locale;

/**
 * Translates names between the Unicode normalization form the FUSE host uses and the form the VFS expects, or passes them through unchanged.
 * <p>
 * macOS hands names to FUSE in decomposed form (NFD) and keys its kernel nodes by the exact name bytes, so a name listed in NFC and looked up in NFD would
 * become two different nodes. Returning NFD to macOS and normalizing everything to NFC towards the VFS keeps one node per file. This is only permissible
 * for file systems that resolve every normalization form of a name to the same node; on a normalization-sensitive file system any change of form would make
 * files unreachable, so names must stay as they are.
 *
 * @param fuseForm normalization form of names passed to the FUSE host (listings, link targets), or {@code null} to pass them through unchanged
 * @param vfsForm normalization form of names passed to the VFS, or {@code null} to pass them through unchanged
 */
public record FileNameTranscoder(Normalizer.@Nullable Form fuseForm, Normalizer.@Nullable Form vfsForm) {

	/**
	 * Passes names through unchanged in both directions.
	 */
	public static final FileNameTranscoder VERBATIM = new FileNameTranscoder(null, null);

	/**
	 * Creates the transcoder matching the running operating system: NFD towards FUSE on macOS, NFC everywhere else, NFC towards the VFS.
	 *
	 * @return the platform transcoder
	 */
	public static FileNameTranscoder forCurrentPlatform() {
		var osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
		var fuseForm = osName.contains("mac") || osName.contains("darwin") ? Normalizer.Form.NFD : Normalizer.Form.NFC;
		return new FileNameTranscoder(fuseForm, Normalizer.Form.NFC);
	}

	/**
	 * Creates the transcoder for a file system with the given capabilities: the {@linkplain #forCurrentPlatform() platform transcoder} if the file system
	 * resolves all normalization forms of a name to the same node, otherwise {@link #VERBATIM}.
	 *
	 * @param capabilities capabilities of the file system to expose
	 * @return the matching transcoder
	 */
	public static FileNameTranscoder forFileSystem(VfsCapabilities capabilities) {
		return capabilities.normalizationSensitive() ? VERBATIM : forCurrentPlatform();
	}

	/**
	 * Normalizes a path or name received from FUSE for use with the VFS.
	 *
	 * @param fuseName path or name as passed by the FUSE host
	 * @return the same path or name in {@link #vfsForm()}, or unchanged if there is none
	 */
	public String toVfs(String fuseName) {
		return vfsForm == null ? fuseName : Normalizer.normalize(fuseName, vfsForm);
	}

	/**
	 * Normalizes a path or name produced by the VFS for the FUSE host.
	 *
	 * @param vfsName path or name as returned by the VFS
	 * @return the same path or name in {@link #fuseForm()}, or unchanged if there is none
	 */
	public String toFuse(String vfsName) {
		return fuseForm == null ? vfsName : Normalizer.normalize(vfsName, fuseForm);
	}
}
