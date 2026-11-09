# vfs-middleware-shortening

Keeps every stored path component short, according to the [UVF file name shortening spec](https://github.com/encryption-alliance/unified-vault-format/pull/37). It sits between a name-producing layer (e.g. `vfs-middleware-uvf`) and the storage, involves no cryptography and does not need to understand the names it shortens.

```java
new ShorteningFileSystem(delegate, threshold) // threshold: nameShorteningThreshold from vault.uvf, at least 46, 220 recommended
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
- **Listing** hides sidecars (including conflicting copies of them), verifies every sidecar (valid UTF-8, longer than the threshold, matching hash) and skips shortened nodes with a missing or invalid sidecar as well as stored names exceeding the threshold.
- **Reserved names.** Names that look like stored names (`{hash}.shortened*.uvf`, `{hash}.original*.uvf`) are rejected.
- **Name length.** Names up to `MAX_NAME_LENGTH` (1024) bytes are accepted and reported as `VfsMetadata.maxNameLength()`, regardless of the delegate's limit.
- **Capabilities.** Always reported as case- and normalization-sensitive: a long name is stored under the hash of its exact bytes, so variants differing only in case or Unicode form never alias, even on an insensitive delegate. Optional features (symbolic links, xattrs) are passed through from the delegate.
- **Caching.** Verified sidecar contents are cached by hash (LRU, 10 000 entries). The hash determines the content, so an entry never becomes wrong; it does not say whether the node still exists.

## Sync conflicts

A sync service may produce `{hash}.shortened (conflicted copy).uvf`. Listings report it as the original name with the suffix inserted before the last extension (e.g. `abc (conflicted copy).uvf`), so the upper layer treats it like a conflict on an unshortened name. Renaming it converts it back into regular shortened form.

The mapping from reported conflict name to stored name is learned while listing and kept in memory, so operations on a conflict name require a prior listing of its parent, which is what any upper layer does to discover it. A conflicting copy shares its sidecar with the regular node, so deleting or renaming either keeps the sidecar while the other one is known to exist.
