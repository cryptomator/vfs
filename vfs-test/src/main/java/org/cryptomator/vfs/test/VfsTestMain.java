package org.cryptomator.vfs.test;

import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.jfuse.api.Fuse;
import org.cryptomator.jfuse.api.FuseMountFailedException;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.backend.nio.NioVfsFileSystem;
import org.cryptomator.vfs.frontend.fuse.FuseVfsOperations;
import org.cryptomator.vfs.middleware.uvf.UvfFileSystem;
import org.cryptomator.vfs.middleware.uvf.VaultUnlocker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeoutException;

/**
 * Mounts an encrypted vault directory through the NIO backend, UVF middleware, and FUSE frontend.
 */
public final class VfsTestMain {

	private static final Logger LOG = LoggerFactory.getLogger(VfsTestMain.class);
	private static final String PASSWORD_ENV = "VFS_VAULT_PASSWORD";
	private static final String MOUNT_FLAGS_ENV = "VFS_MOUNT_FLAGS";
	private static final String VAULT_CONFIG_FILE = "vault.uvf";
	private static final String VAULT_DATA_DIR = "d";

	public static void main(String[] args) throws Exception {
		if (args.length < 2 || args.length > 3) {
			printUsage();
			return;
		}

		var vaultDir = Path.of(args[0]).toAbsolutePath().normalize();
		var mountPoint = Path.of(args[1]).toAbsolutePath().normalize();
		var libraryPath = args.length == 3 ? args[2] : null;

		if (!Files.isDirectory(vaultDir)) {
			throw new IllegalArgumentException("Vault directory does not exist: " + vaultDir);
		}
		if (!Files.isDirectory(mountPoint)) {
			throw new IllegalArgumentException("Mount point does not exist: " + mountPoint);
		}

		var backend = new NioVfsFileSystem(vaultDir);
		var ciphertextLoggingMiddleware = new LoggingVfsFileSystem("ciphertext", backend);
		var password = readPassword();
		var csprng = SecureRandom.getInstanceStrong();
		boolean createNewVault = Files.notExists(vaultDir.resolve(VAULT_CONFIG_FILE)) && Files.notExists(vaultDir.resolve(VAULT_DATA_DIR));

		var builder = Fuse.builder();
		if (libraryPath != null && !libraryPath.isBlank()) {
			builder.setLibraryPath(libraryPath);
		}

		try (var uvfMiddleware = createNewVault ? initializeVault(ciphertextLoggingMiddleware, password, csprng) : UvfFileSystem.create(ciphertextLoggingMiddleware, VaultUnlocker.withPassword(password, csprng));
			 var fuse = builder.build(new FuseVfsOperations(new LoggingVfsFileSystem("cleartext", uvfMiddleware), builder.errno()))) {
			Runtime.getRuntime().addShutdownHook(new Thread(() -> closeQuietly(fuse), "vfs-test-shutdown"));
			LOG.info("Mounting {} at {}", vaultDir, mountPoint);
			fuse.mount("vfs-test", mountPoint, mountFlags());
			LOG.info("Enter anything to unmount...");
			System.in.read();
		} catch (FuseMountFailedException | TimeoutException e) {
			LOG.error("Un/Mounting failed. ", e);
			System.exit(1);
		} catch (IOException e) {
			LOG.error("Failed to create mirror", e);
			System.exit(1);
		}
	}

	private static void printUsage() {
		System.out.println("Usage: VfsTestMain <vaultDir> <mountPoint> [fuseLibraryPath]");
		System.out.println("Opens the vault in <vaultDir>, or creates a new one if neither " + VAULT_CONFIG_FILE + " nor " + VAULT_DATA_DIR + "/ exist yet.");
		System.out.println("The vault password is read from the " + PASSWORD_ENV + " environment variable or prompted on the console.");
	}

	// creates a password-protected vault with a throwaway recovery key, which is only logged, this is a test tool
	private static UvfFileSystem initializeVault(VfsFileSystem delegate, String password, SecureRandom csprng) throws IOException, GeneralSecurityException {
		var keyGen = KeyPairGenerator.getInstance("EC");
		keyGen.initialize(new ECGenParameterSpec("secp384r1"), csprng);
		var recoveryKeyPair = keyGen.generateKeyPair();
		var vault = UvfUnlockedVault.create(csprng);
		vault.setPassword(password);
		vault.setRecoveryKey((ECPublicKey) recoveryKeyPair.getPublic());
		LOG.warn("Creating a new vault. Recovery key (PKCS#8, base64, not stored anywhere else): {}", Base64.getEncoder().encodeToString(recoveryKeyPair.getPrivate().getEncoded()));
		return UvfFileSystem.initialize(delegate, vault);
	}

	// single-threaded; on macOS the same macFUSE flags as Cryptomator (kernel-side permission checks, no AppleDouble sidecars), which cut Finder's
	// per-interaction call storm by roughly 8x; additional flags can be supplied via the environment
	private static String[] mountFlags() {
		var flags = new java.util.ArrayList<>(List.of("-s"));
		if (System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("mac")) {
			flags.addAll(List.of("-oatomic_o_trunc", "-oauto_xattr", "-oauto_cache", "-onoappledouble", "-odefault_permissions"));
		}
		var extra = System.getenv(MOUNT_FLAGS_ENV);
		if (extra != null && !extra.isBlank()) {
			flags.addAll(List.of(extra.trim().split("\\s+")));
		}
		return flags.toArray(String[]::new);
	}

	private static String readPassword() {
		var fromEnv = System.getenv(PASSWORD_ENV);
		if (fromEnv != null) {
			return fromEnv;
		}
		var console = System.console();
		if (console == null) {
			throw new IllegalStateException("No console available, set " + PASSWORD_ENV);
		}
		return new String(console.readPassword("Vault password: "));
	}

	private static void closeQuietly(Fuse fuse) {
		try {
			fuse.close();
		} catch (Exception e) {
			System.err.println("Failed to close FUSE mount: " + e.getMessage());
		}
	}
}
