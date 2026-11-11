# Sync conflict resolution

This document records how the layers deal with conflicting copies created by sync services. Decision date: November 2026.

## Decision

Every layer resolves conflicts internally: it detects conflicting copies of the names it stores and turns them back into canonical form, using only its own knowledge of its name format. Whatever a layer cannot decide on its own is passed up as a regular conflict copy in the upper layer's namespace, keeping the conflict suffix, so the next layer handles it with its own knowledge. Only the topmost layer asks the application for a policy decision.

There is no dedicated conflict resolution layer and there are no callbacks between middleware layers.

## Background

Sync services that cannot merge concurrent changes keep both versions and give one of them a new name. Almost all of them insert a suffix before the last extension:

| Service | Example |
|---|---|
| Dropbox | `name (Alice's conflicted copy 2026-11-11).ext` |
| Nextcloud / ownCloud | `name (conflicted copy 2026-11-11 104009).ext` |
| Google Drive | `name (1).ext` |
| iCloud Drive | `name 2.ext` |
| OneDrive | `name-HOSTNAME.ext` |
| Syncthing | `name.sync-conflict-20261111-104009-ABCDEFG.ext` |

Below the encryption layer, every name follows a strict format (base64url ciphertext, hash-based shortened names, fixed metadata file names), so a conflict copy is easy to tell apart from a canonical name. Finding the canonical name it belongs to, however, requires knowledge only the layer that produced the name has: a hash, a key, the meaning of a metadata file.

## Rejected alternative: a separate conflict layer

A conflict layer between the lowest middleware and the backend would have to:

- ask every upper layer whether a candidate name is canonical, e.g. by trial decryption through a callback, before the name ever reaches that layer
- translate the alternative name chosen by the application down through every layer (encrypt, shorten, write sidecars)
- execute renames and deletes itself, because a conflict copy has no name in the upper layers and cannot be addressed through regular VFS operations

This couples all layers through callbacks in both directions. With resolution inside each layer, a layer resolves through regular operations on its delegate, and the layers below treat those like any other operation.

## Per layer

### File name shortening (`vfs-middleware-uvf-shortening`)

Conflicts can affect both files of a shortened node. The sidecar is resolved first, because resolving a node needs the verified full name from its sidecar.

**Sidecar copies** (`H.original (x).uvf`): every copy shares the hash `H` from its name and is verified on its own. Equal contents are just the common case.

| Canonical `H.original.uvf` | Copy | Action |
|---|---|---|
| valid | any | hide the copy; it MAY be deleted |
| missing or invalid | valid | rename the copy over the canonical sidecar |
| missing or invalid | invalid | hide both, skip the node with a warning, delete nothing (may be needed for recovery) |

**Node copies** (`H.shortened (x).uvf`): the layer normalizes the copy into a regular shortened node with a name of its own:

1. read and verify the full name `N` from sidecar `H` (resolving sidecar copies first if needed)
2. derive `N' = stem(N) + suffix + extension(N)`, e.g. `abc (x).uvf` for `abc.uvf`
3. write the sidecar `H'.original.uvf` holding `N'`, where `H'` is the hash of `N'`
4. rename `H.shortened (x).uvf` to `H'.shortened.uvf`

The usual ordering applies (sidecar before node, atomic move of the node), so an interruption leaves at most an orphaned sidecar. `H.original.uvf` remains untouched, as it still belongs to `H.shortened.uvf`. The result is deterministic: two devices resolving the same copy produce identical files.

`N'` is not a valid ciphertext name, so the upper layer sees an ordinary conflict copy and resolves it with its own knowledge. Since reported and stored names are related by the hash again, the shortening layer needs no in-memory mapping of conflict names.

Notes:

- Resolution happens on demand while listing a directory, per hash. Only if the canonical sidecar is missing or invalid is the directory scanned for sidecar copies.
- A node renamed during a listing may or may not show up again in the same iteration; the listing reports it only once.
- If normalization is impossible (read-only storage, failing rename, `N'` exceeding the maximum name length), the entry is skipped with a warning.

### Encryption (`vfs-middleware-uvf-encryption`)

UVF ciphertext names are unpadded base64url of variable length, so the end of the canonical name is not marked. A conflict copy is recognized by trial decryption:

1. try the full name first: names that decrypt are canonical, so listings only pay for entries that fail
2. cut the stem at the first character outside the base64url alphabet (covers Dropbox, Nextcloud, Google Drive, iCloud and Syncthing)
3. only if the suffix consists of base64url characters only (OneDrive's `-HOSTNAME`), try the positions of `-` and `_`
4. skip candidates whose length or final character is not valid unpadded base64url before decrypting

Authenticated decryption (AES-SIV) decides unambiguously: a wrong cut decrypts successfully with negligible probability. The directory key is already at hand while listing, so trying candidates costs CPU but no I/O. Entries that fail all candidates should be cached as such to avoid repeating the work on every listing.

Once the canonical name is found, its cleartext `n` is known and the application's policy is applied, e.g. keep both under a new cleartext name derived from `n` and the suffix, encrypted and renamed through the delegate (where the shortening layer handles a long new name like any other). Conflicts of UVF metadata files (`dir.uvf`, `symlink.uvf`) are resolved here as well, since only this layer knows their meaning.

### Application

The topmost layer is the only one that asks the application for a decision: discard the copy, replace the original, or keep both under an alternative name.

## Shared code

The knowledge of how sync services name copies (suffix inserted before the last extension, candidate cut points) is not specific to any name format and may be shared as a pure helper in `vfs-common`. Each layer supplies its own check of what is canonical.

## Out of scope

- Suffixes appended after the extension (e.g. `name.uvf (1)`) are not recognized.
- Cryptomator Vault Format 8 is not supported by the shortening layer: a long-named file changes its node type there (`H.c9s/contents.c9r`), which rules out the per-component mapping described above.

## Status

The shortening layer implements the behaviour above, switchable by a constructor flag. Conflict detection in the UVF layer is not implemented yet.
