package org.cryptomator.vfs.middleware.uvf.vault;

import org.cryptomator.vfs.api.VfsFile;
import org.cryptomator.vfs.api.VfsFileSystem;
import org.cryptomator.vfs.middleware.uvf.VaultConfigDecryptor;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Set;

import static java.nio.file.StandardOpenOption.READ;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;

class VaultConfigTest {

	private static final String SAMPLE_PAYLOAD = """
			{
			    "fileFormat": "AES-256-GCM-32k",
			    "nameFormat": "AES-SIV-512-B64URL",
			    "seeds": {
			        "HDm38i": "ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs",
			        "gBryKw": "PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0",
			        "QBsJFo": "Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y"
			    },
			    "initialSeed": "HDm38i",
			    "latestSeed": "QBsJFo",
			    "kdf": "HKDF-SHA512",
			    "kdfSalt": "NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8"
			}""";

	@Test
	void loadValidVault() throws IOException {
		var delegate = mockDelegateWithVaultFile("encrypted-jwe-data".getBytes(StandardCharsets.UTF_8));
		VaultConfigDecryptor jweDecryptor = _ -> SAMPLE_PAYLOAD;

		var config = new VaultConfig(delegate, jweDecryptor, new SecureRandom());

		assertNotNull(config.cryptor());
		assertNotNull(config.cryptor().directoryContentCryptor());
	}

	@Test
	void failsWhenVaultFileUnreadable() throws IOException {
		var delegate = mock(VfsFileSystem.class);
		Mockito.doThrow(new IOException("not found")).when(delegate).openFile(eq("/vault.uvf"), eq(Set.of(READ)));

		assertThrows(IOException.class, () -> new VaultConfig(delegate, _ -> SAMPLE_PAYLOAD, new SecureRandom()));
	}

	@Test
	void failsWhenDecryptorFails() throws IOException {
		var delegate = mockDelegateWithVaultFile("some-jwe".getBytes(StandardCharsets.UTF_8));
		VaultConfigDecryptor failing = _ -> { throw new IOException("decryption failed"); };

		assertThrows(IOException.class, () -> new VaultConfig(delegate, failing, new SecureRandom()));
	}

	private VfsFileSystem mockDelegateWithVaultFile(byte[] content) throws IOException {
		var delegate = mock(VfsFileSystem.class);
		var vaultFile = mock(VfsFile.class);
		Mockito.doReturn(vaultFile).when(delegate).openFile(eq("/vault.uvf"), eq(Set.of(READ)));
		Mockito.doAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			if (buf.position() >= content.length) {
				return -1;
			}
			buf.put(content);
			return content.length;
		}).when(vaultFile).read(org.mockito.ArgumentMatchers.any(ByteBuffer.class), anyLong());
		return delegate;
	}
}
