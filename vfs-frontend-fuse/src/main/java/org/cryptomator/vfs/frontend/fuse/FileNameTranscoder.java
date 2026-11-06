package org.cryptomator.vfs.frontend.fuse;

import java.text.Normalizer;
import java.util.Locale;

/**
 * Translates names between the Unicode normalization form the FUSE host uses and the NFC form the VFS expects.
 * <p>
 * macOS hands names to FUSE in decomposed form (NFD) and keys its kernel nodes by the exact name bytes, so a name listed in NFC and looked up in NFD would
 * become two different nodes. Returning NFD to macOS and normalizing everything to NFC towards the VFS keeps one node per file.
 *
 * @param fuseForm normalization form of names passed to the FUSE host (listings, link targets)
 * @param vfsForm normalization form of names passed to the VFS
 */
public record FileNameTranscoder(Normalizer.Form fuseForm, Normalizer.Form vfsForm) {

	/**
	 * Creates the transcoder matching the running operating system: NFD towards FUSE on macOS, NFC everywhere else.
	 *
	 * @return the platform transcoder
	 */
	public static FileNameTranscoder forCurrentPlatform() {
		var osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
		var fuseForm = osName.contains("mac") || osName.contains("darwin") ? Normalizer.Form.NFD : Normalizer.Form.NFC;
		return new FileNameTranscoder(fuseForm, Normalizer.Form.NFC);
	}

	/**
	 * Normalizes a path or name received from FUSE for use with the VFS.
	 *
	 * @param fuseName path or name as passed by the FUSE host
	 * @return the same path or name in {@link #vfsForm()}
	 */
	public String toVfs(String fuseName) {
		return Normalizer.normalize(fuseName, vfsForm);
	}

	/**
	 * Normalizes a path or name produced by the VFS for the FUSE host.
	 *
	 * @param vfsName path or name as returned by the VFS
	 * @return the same path or name in {@link #fuseForm()}
	 */
	public String toFuse(String vfsName) {
		return Normalizer.normalize(vfsName, fuseForm);
	}
}
