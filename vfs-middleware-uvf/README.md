# vfs-middleware-uvf

Decorates the underlying VFS with encryption and decryption using the [universal vault format](https://github.com/encryption-alliance/unified-vault-format).

## Glossary

| Term | Meaning |
|------|---------|
| **cleartext** | The frontend-facing (unencrypted) side — paths and file content as seen by the user |
| **ciphertext** | The backend-facing (encrypted) side — paths and file content as stored on disk |
| **delegate** | The underlying `VfsFileSystem` that stores ciphertext |

In code, variables and parameters use these prefixes to indicate which side they belong to (e.g. `ciphertextPath`, `ciphertextFile`, `cleartextName`). The `delegate` field refers to the ciphertext-side filesystem.
