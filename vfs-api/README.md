# vfs-api

Defines the common VFS I/O API used between frontends, middleware, and backends.

## Design

The API is the common denominator of the frontends we target: FUSE (libfuse / macFUSE / FUSE-T / WinFsp-FUSE), FSKit, native WinFsp, SMB2/3 and WebDAV.

- **Path-based namespace, handle-based data I/O.** Every frontend has a path-based lookup/create step (FUSE paths, WinFsp `Create`/`Open`, SMB2 `CREATE`, WebDAV URLs; FSKit's `FSItem` tree is mapped to paths by its frontend). Afterwards, reads, writes, truncation, timestamps and metadata on an open file go through `VfsFile`, because WinFsp, SMB and FSKit never see a path again after open.
- **Open handles survive rename and delete.** WinFsp (POSIX unlink/rename mode), SMB delete-on-close and FSKit open-unlink emulation all delete or move files while handles are open. Backends must keep a `VfsFile` usable until it is closed.
- **Rename has an explicit replace flag.** FUSE `RENAME_NOREPLACE`, FSKit `overItem`, WinFsp/SMB `ReplaceIfExists` and WebDAV `Overwrite:` all need it; emulating it with a pre-check is not atomic.
- **Directory listings are lazy and carry metadata per entry** (readdirplus). FUSE offsets, FSKit cookies, WinFsp markers and SMB `QUERY_DIRECTORY` cursors are frontend concerns; a frontend keeps the `VfsDirectoryStream` open across calls or buffers it.
- **`deleteDirectory` is never recursive.** WebDAV `DELETE` on a collection recurses in the frontend.
- **Metadata** carries the four timestamps (modified, accessed, changed, created) and an optional stable file id, because WinFsp, SMB and FSKit report all of them.
- **Optional features** (xattrs, symbolic links) are advertised via `VfsCapabilities` and throw `UnsupportedOperationException` otherwise. Frontends translate that to `ENOTSUP` or an equivalent status.

Out of scope on purpose, since they are missing or emulable on at least two frontends: hard links, byte-range locks (kernel or frontend state), server-side copy, preallocation, uid/gid, Windows hidden/archive bits and ACLs.
