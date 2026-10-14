# File system operations across frontends

This document records the research behind the shape of `vfs-api`: which operations the frontends we target (FUSE via jfuse, FSKit, native WinFsp, SMB2/3 and WebDAV) expose, and which subset is the common denominator. Research date: October 2026.

## Identity model

| | FUSE (jfuse, high-level) | FSKit | WinFsp | SMB2/3 | WebDAV |
|---|---|---|---|---|---|
| Namespace | path per call | `FSItem` handles, lookup by (parent item, name); no paths at all | path for `Create`/`Open`/`GetSecurityByName`, then `FileContext` | path only in `CREATE`, then `FileId` | URL path only, no handles |
| I/O handle | `fi->fh` from open/create | item + optional `openItem`/`closeItem` | `FileContext` | `FileId` | none (stateless) |

Common denominator: a **path-based namespace plus an opaque open handle for data operations**. FSKit is the odd one out; its frontend keeps an `FSItem` to path map (libfuse's high-level layer does the same internally), which works as long as the API never requires item identity.

## Operation matrix

✓ native, ~ emulable or partial, ✗ absent. The last column maps each row to `vfs-api`.

| Operation | FUSE | FSKit | WinFsp | SMB2 | WebDAV | vfs-api |
|---|---|---|---|---|---|---|
| readattr (stat by path) | ✓ `getattr` | ✓ `lookupItem` + `getAttributes` | ✓ `GetSecurityByName`, `GetFileInfo(ctx)` | ✓ `CREATE` + `QUERY_INFO` on handle | ✓ `PROPFIND Depth:0` | `readNodeMetadata(path)` and `VfsFile.readMetadata()`, since WinFsp, SMB and FSKit stat on the open handle, not a path |
| create file / dir | ✓ `create`/`mkdir` | ✓ `createItem(.file/.directory)` | ✓ `Create` | ✓ `CREATE` dispositions | ✓ `PUT` 0 bytes / `MKCOL` | `createFile`, `createDirectory` |
| delete file / dir | ✓ `unlink`/`rmdir` | ✓ `removeItem` | ✓ `SetDelete` + `Cleanup(Delete)` on last close | ✓ `FileDisposition`, applied on last close | ✓ `DELETE` (dir is recursive) | `deleteFile`, `deleteDirectory`. Contract: `deleteFile` must succeed while a `VfsFile` is open (WinFsp/SMB POSIX-unlink mode, FSKit open-unlink); `deleteDirectory` is never recursive |
| rename | ✓ `rename(flags)` with `RENAME_NOREPLACE` | ✓ `renameItem(..., overItem:)` | ✓ `Rename(ReplaceIfExists)` | ✓ `FileRenameInformation(ReplaceIfExists)` | ✓ `MOVE` + `Overwrite: T/F` | `rename(src, dst, replaceExisting)`; every frontend needs the flag and a pre-check is not atomic |
| read, random access | ✓ `read(off, fh)` | ✓ `read(item, offset, length)` | ✓ `Read(ctx, Offset, Length)` | ✓ `READ(Offset)` | ✓ `GET` + `Range` (Finder, gvfs use it) | `VfsFile.read(buf, offset)` |
| write, random access | ✓ `write(off, fh)` | ✓ `write(item, offset)` | ✓ `Write(ctx, Offset)`, `WriteToEndOfFile`, `ConstrainedIo` | ✓ `WRITE(Offset)` | ✗ `PUT` replaces whole body; partial PUT forbidden by RFC 9110 | `VfsFile.write(buf, offset)`; the WebDAV frontend streams sequentially |
| truncate / set size | ✓ `truncate(path, fi)` | ✓ `setAttributes(size)` on item | ✓ `SetFileSize(ctx)` | ✓ `FileEndOfFile` on handle | ~ implicit via `PUT` | `truncate(path, size)` and `VfsFile.truncate(size)`; three of five do it on the handle |
| flush / fsync | ✓ `flush`, `fsync` | ~ volume-wide `synchronize` only | ✓ `Flush(ctx)` | ✓ `FLUSH` | ✗ | `VfsFile.force(metadata)` |
| set times | ✓ `utimens` (atime, mtime); macFUSE `setcrtime` | ✓ access, modify, birth, backup, added | ✓ `SetBasicInfo`: creation, access, write, change | ✓ `FileBasicInformation`: all four | ~ Windows PROPPATCH `Win32LastModifiedTime` only | `setTimes` with nullable access, modified and creation time, on path and handle |
| read times | atime, mtime, ctime, birth (mac) | access, modify, change, birth | creation, access, write, change | same four | lastmodified, creationdate | `VfsNodeMetadata` carries all four |
| permissions | ✓ `chmod`/`chown` | ✓ `setAttributes(mode, uid, gid)` | ~ ACL via `SetSecurity`; FUSE layer maps mode to SD | ~ `FileAttributes` readonly bit, security descriptor | ✗ | `setPermissions(path, perms)`; uid/gid left out, frontends map to the mount user |
| statfs | ✓ `statfs` | ✓ `volumeStatistics` | ✓ `GetVolumeInfo` | ✓ `FileFsSize/FullSize` | ~ `quota-available/used-bytes` (RFC 4331) | `readVfsMetadata` |
| access check | ✓ `access` (not on WinFsp-FUSE, FUSE-T ignores) | ✓ optional `checkAccess` | ~ kernel checks against SD | ~ server-side | ✗ | `checkAccess`; frontends may skip it |
| dir listing, streamable | ✓ `readdir` with offset cookie | ✓ `enumerateDirectory(cookie, verifier, packer)` | ✓ `ReadDirectory(Marker)`, resumable by last name | ✓ `QUERY_DIRECTORY` chunks on an open dir handle | ✗ `PROPFIND Depth:1` is one XML document, no paging | `openDirectory` returns a lazy, closeable `VfsDirectoryStream`; cookies and markers stay in the frontend |
| readdirplus (attrs per entry) | ~ libfuse3 `FUSE_FILL_DIR_PLUS` on Linux; macFUSE no; WinFsp-FUSE yes | ✓ `attributes:` request + `packEntry(attributes:)` | ✓ `FSP_FSCTL_DIR_INFO` embeds `FILE_INFO` | ✓ every info class carries times, size, attrs, id | ✓ properties per child | `VfsDirectoryEntry(name, metadata)` |
| file id / inode | ~ `st_ino` optional (`use_ino`) | ✓ `fileID`, `parentID` required per item and entry | ~ `IndexNumber` | ~ `FileIdBothDirectoryInformation`; Windows clients default to it | ✗ (etag instead) | optional `fileId` in `VfsNodeMetadata` (`NO_FILE_ID` = none); the FSKit frontend can synthesize ids |
| xattr | ✓ get/set/list/remove; FUSE-T via NFSv4 named attrs; WinFsp-FUSE ≥1.5 as NTFS EAs | ✓ optional `XattrOperations`, set with policy create/replace/delete | ~ `GetEa`/`SetEa` (NTFS EAs) or named streams | ~ named streams (`file:name:$DATA`); this is how macOS stores xattrs over SMB; EAs are legacy | ~ dead properties via PROPPATCH; Finder writes `._` sidecars instead | optional: `listXattrs`, `getXattr`, `setXattr(name, value, policy)`, `removeXattr`, gated by `VfsCapabilities.supportsXattrs()` |
| symlink | ✓ `symlink`/`readlink` | ✓ `createSymbolicLink`/`readSymbolicLink` | ~ reparse points, relative targets only | ~ reparse point + `STATUS_STOPPED_ON_SYMLINK`; usually resolved server-side | ✗ | optional: `readSymbolicLink`, `createSymbolicLink`, gated by `VfsCapabilities.supportsSymbolicLinks()` |
| hard link | ✓ Linux/macFUSE; ✗ WinFsp-FUSE; jfuse doesn't wire `link` | ✓ `createLinkToItem` | ✗ `HardLinks` unimplemented | ~ `FileLinkInformation`, rarely issued | ✗ | not in the API |
| byte-range locks | ✓ `lock`/`flock` (FUSE-T never forwards) | ✗ kernel-side | ✗ kernel-side | ~ `LOCK`, server-side table | ~ `LOCK`/`UNLOCK`, server-side | not in the API; frontend state |
| copy / fallocate / lseek holes | ✓ libfuse3 only; jfuse no | `preallocateSpace`, `SeekRegionHandler` | `SetAllocationSize` | `COPYCHUNK`, `FileAllocation` | `COPY` (emulate) | not in the API; all emulable |

## Capabilities

Every frontend negotiates features up front: FSKit `SupportedCapabilities` and `PathConfOperations`, WinFsp `FSP_FSCTL_VOLUME_PARAMS`, SMB `FileFsAttributeInformation`, libfuse `fuse_conn_info`. `VfsCapabilities` carries the subset that matters to all of them: case sensitivity, symbolic link support, xattr support and the maximum xattr value size.

## Deliberately out of scope

Hard links, byte-range locks, server-side copy, preallocation and hole seeking, uid/gid, Windows hidden/archive bits and ACLs. Each is either unavailable on at least two of the five frontends or emulable in the frontend.

## Frontend quirks worth remembering

- **macFUSE and Unicode normalization.** macOS passes names in NFD; macFUSE keys kernel nodes by exact name bytes, so an NFC name from `readdir` and an NFD lookup of the same file yield two inode numbers and Finder reloads the listing on every selection. The FUSE frontend returns NFD on macOS and normalizes to NFC towards the VFS. cryptolib itself normalizes names to NFC before encryption.
- **FUSE `symlink` argument order.** libfuse passes the link content first and the link path second. jfuse's parameter names (`linkname`, `target`) suggest the opposite.
- **libfuse3 readdirplus** is only enabled when the `init` callback is wired, so `INIT` must be in jfuse's supported operation set.
- **macFUSE** is a libfuse 2.x API without readdirplus; **FUSE-T** ignores `access`, never forwards locks and cannot set atime and mtime independently.
- **WinFsp** buffers whole directories itself and always calls `readdir` with offset 0; it emulates `RENAME_NOREPLACE` with a non-atomic pre-check; absolute symlink targets are rejected unless `-o rellinks`.
- **SMB delete and rename are handle operations.** The unlink happens on last close; the server, not the file system, must track share modes. Windows clients default to `FileIdBothDirectoryInformation`, so stable file ids matter.
- **WebDAV** has no random-access writes, no handles, no paging in listings, and clients (Finder, Windows) require class 2 locking to write at all. Windows PROPPATCHes `Win32*` properties and breaks on copy if PROPPATCH is unimplemented.
- **FSKit** has no per-file fsync (only volume-wide `synchronize`), no locking callback, and in macOS 27 the `Operations` protocols are deprecated in favour of `Handler` protocols with an `FSContext` parameter.

## Sources

- libfuse: <https://github.com/libfuse/libfuse> (`include/fuse.h`, `include/fuse_lowlevel.h`, `lib/fuse.c`)
- jfuse: <https://github.com/cryptomator/jfuse>
- macFUSE: <https://github.com/macfuse/library>; FUSE-T: <https://github.com/macos-fuse-t/fuse-t/wiki/FAQ>
- FSKit: <https://developer.apple.com/documentation/fskit> and the `FSKit.framework` headers of the macOS 27 SDK
- WinFsp: <https://winfsp.dev/doc/WinFsp-API-winfsp.h/>, <https://winfsp.dev/doc/NTFS-Compatibility/>, <https://github.com/winfsp/winfsp> (`inc/winfsp/winfsp.h`, `src/dll/fuse/fuse_intf.c`)
- MS-SMB2: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/>; MS-FSCC: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/>; Samba `source3/include/vfs.h`
- WebDAV: RFC 4918, RFC 4331, RFC 9110 §14.5; <https://sabre.io/dav/clients/finder/>, <https://sabre.io/dav/clients/windows/>; MS-WDVME
