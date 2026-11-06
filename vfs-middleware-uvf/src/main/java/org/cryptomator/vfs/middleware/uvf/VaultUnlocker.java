package org.cryptomator.vfs.middleware.uvf;

import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;

import java.io.IOException;
import java.security.SecureRandom;

/**
 * Callback that turns the parsed {@code vault.uvf} into an unlocked vault, e.g. by asking the user for a password or by supplying a Hub member key.
 */
@FunctionalInterface
public interface VaultUnlocker {

	/**
	 * Unlocks the vault.
	 *
	 * @param lockedVault the parsed but not yet authenticated {@code vault.uvf}; {@link UvfLockedVault#keyEncryptionKid()} tells which secret is needed
	 * @return the unlocked vault
	 * @throws IOException if the secret cannot be obtained
	 * @throws VaultKeyInvalidException if the secret is wrong
	 * @throws VaultConfigLoadException if the configuration is malformed
	 */
	UvfUnlockedVault unlock(UvfLockedVault lockedVault) throws IOException;

	/**
	 * Creates an unlocker for password-protected vaults.
	 *
	 * @param password the password
	 * @param csprng secure random for cryptographic operations
	 * @return an unlocker that calls {@link UvfLockedVault#unlock(CharSequence, SecureRandom)}
	 */
	static VaultUnlocker withPassword(CharSequence password, SecureRandom csprng) {
		return lockedVault -> lockedVault.unlock(password, csprng);
	}
}
