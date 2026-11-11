# vfs-middleware-uvf-shortening

Keeps every stored path component short, according to the [UVF file name shortening spec](https://github.com/encryption-alliance/unified-vault-format/pull/37). It sits between a name-producing layer (e.g. `vfs-middleware-uvf-encryption`) and the storage, involves no keys and does not need to understand the names it shortens.

The name format (hashing, Base32, suffixes, sidecar verification, reserved names) comes from cryptolib's `NameShortener.uvf(threshold)`. This module performs the I/O: ordering of file operations, listing, caching and sync conflicts.

```java
new ShorteningFileSystem(delegate, threshold) // threshold: nameShorteningThreshold from vault.uvf, at least 46 (220 recommended), or -1 to disable shortening
```

## Glossary

| Term | Meaning |
|------|---------|
| **name** | a path component as passed in by the upper layer |
| **stored name** | the path component on the delegate: the name itself, or `{hash}.shortened.uvf` if the name is longer than the threshold |
| **sidecar** | `{hash}.original.uvf`, a regular file next to the shortened node holding the original name as UTF-8 |

All lengths refer to UTF-8 bytes. `{hash}` is the leftmost 160 bits of SHA-256 of the name, Base32-encoded without padding (32 characters).

## Operations

- **Ordering.** The sidecar is written before the node and deleted after it, so an interrupted operation leaves at most a harmless orphaned sidecar. An existing sidecar is only overwritten if it is invalid, so a failing `createFile(CREATE_NEW)` never touches the sidecar of the existing node.
- **Rename** writes the target sidecar, moves the node atomically, then deletes the source sidecar unless source and target share it.
- **Listing** hides sidecars (including conflicting copies of them), verifies every sidecar with `NameShortener.unshorten` and skips shortened nodes with a missing or invalid sidecar as well as stored names exceeding the threshold.
- **Reserved names.** Short names that look like stored names (`*.shortened*.uvf`, `*.original*.uvf`) are rejected when passed in and skipped when found in storage.
- **Name length.** Names up to `MAX_NAME_LENGTH` (1024) bytes are accepted and reported as `VfsMetadata.maxNameLength()`, regardless of the delegate's limit.
- **Capabilities.** Always reported as case- and normalization-sensitive: a long name is stored under the hash of its exact bytes, so variants differing only in case or Unicode form never alias, even on an insensitive delegate. Optional features (symbolic links, xattrs) are passed through from the delegate.
- **Caching.** Verified sidecar contents are cached by shortened name (LRU, 10 000 entries). The hash determines the content, so an entry never becomes wrong; it does not say whether the node still exists.
- **Disabled.** With threshold -1 all names pass through unchanged and `*.shortened.uvf` / `*.original.uvf` have no special meaning.

## Sync conflicts

Conflict resolution is enabled by the constructor flag `resolveConflicts` and follows [docs/conflict-resolution.md](../docs/conflict-resolution.md): this layer turns conflicting copies of its own files back into canonical form while listing, and passes everything else up as an ordinary conflicting copy.

- **Recognition.** `ConflictName` strips a suffix that starts with a character other than an ASCII letter or digit before the last extension, and cryptolib decides whether the remainder is a shortened name or sidecar.
- **Sidecar copies** (`{hash}.original (x).uvf`) are always hidden. If the regular sidecar is missing or invalid, a valid copy replaces it; if none is valid, the node is skipped and nothing is deleted.
- **Node copies** (`{hash}.shortened (x).uvf`) of a node with full name `N` are renamed to the regular shortened node of `N'` (`N` with the suffix inserted before its extension), after writing the sidecar of `N'`. The upper layer then sees `N'` like a conflict on an unshortened name. The sidecar of `N` stays with the original. If `N'` is taken, exceeds `MAX_NAME_LENGTH`, or the storage refuses the rename, the copy is skipped.
- **Shared sidecars.** Deleting or renaming away a long-named node keeps its sidecar while the directory still holds a conflicting copy of the node, which costs one directory listing per such operation.

With `resolveConflicts` disabled, listings never write: conflicting copies of shortened nodes are not listed, and broken sidecars are not restored.
