# vfs-middleware-uvf

Decorates the underlying VFS with encryption and decryption using the [universal vault format](https://github.com/encryption-alliance/unified-vault-format).

## Glossary

| Term | Meaning |
|------|---------|
| **cleartext** | The frontend-facing (unencrypted) side — paths and file content as seen by the user |
| **ciphertext** | The backend-facing (encrypted) side — paths and file content as stored on disk |
| **delegate** | The underlying `VfsFileSystem` that stores ciphertext |

In code, variables and parameters use these prefixes to indicate which side they belong to (e.g. `ciphertextPath`, `ciphertextFile`, `cleartextName`). The `delegate` field refers to the ciphertext-side filesystem.

## Division of labour with cryptolib

cryptolib (3.x) knows the vault format: `vault.uvf` parsing and unlocking, name encryption, the `d/XX/YYY` layout, `dir.uvf` / `symlink.uvf` contents and the chunked file format. This module only performs I/O on the delegate.

| cryptolib type | Used by | For |
|---|---|---|
| `UvfLockedVault` / `UvfUnlockedVault` | `UvfFileSystem.create` via `VaultUnlocker` | unlocking `vault.uvf`, key material (destroyed on `close()`) |
| `VaultDirectory`, `VaultNode` | `DirectoryPathResolver` | resolving cleartext paths to content directories and encrypted entry names |
| `VaultReader`, `VaultWriter` | `UvfFileSystem` | the only way cryptolib reads or writes metadata files (`dir.uvf`, `symlink.uvf`); backed by `openFile` / `createFile` on the delegate |
| `VaultFile` | `UvfVfsFile` | positional read, write and truncate with `CiphertextReader` / `CiphertextWriter` callbacks mapped to the delegate's `VfsFile` |

Node types are decided here, not by cryptolib: a regular file is a plain `*.uvf` file, whereas directories and symbolic links are `*.uvf` directories containing `dir.uvf` or `symlink.uvf`. Every directory's content directory also holds a `dir.uvf` metadata backup, which listings skip and `deleteDirectory` removes.

## Directory cache

Every operation on `/a/b/c/file` would otherwise read three `dir.uvf` files. `DirectoryPathResolver` therefore caches resolved `VaultDirectory` objects in a [Caffeine](https://github.com/ben-manes/caffeine) cache keyed by the ciphertext path of the `dir.uvf` file (see `CacheSettings`, default 10 000 entries, 5 s time to live).

- Keyed by ciphertext path on purpose: a rename moves only the renamed entry's `dir.uvf`; descendants live in `d/XX/…` content directories and keep their paths, so one invalidation suffices. Cleartext keys would need prefix invalidation and suffer from path aliasing.
- `UvfFileSystem` invalidates on `createDirectory`, `deleteDirectory` and `rename`. Caffeine's per-key atomic load makes this race-free: an invalidation that overlaps a running load waits for it and discards its result.
- Misses and failures are never cached.
- The time to live bounds staleness caused by changes made to the ciphertext behind this process's back (e.g. a sync client). It cannot detect them; after a stale hit, operations on the vanished content directory fail with `NoSuchFileException` until the entry expires.

Not supported yet: extended attributes, and name shortening (`name.c9s`), which UVF does not use.
