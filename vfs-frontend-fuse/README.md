# vfs-frontend-fuse

Frontend module. Adapts the VFS API to jFUSE operations.

## Platform notes

- **Ownership.** The VFS API has no uid/gid, so every node is reported as owned by the mounting user (`FuseVfsOperations` reads the home directory's owner, or takes explicit ids).
- **Unicode normalization.** macOS hands names to FUSE in NFD and keys its kernel nodes by the exact bytes. A name listed in NFC and looked up in NFD becomes two nodes with two inode numbers, which makes Finder reload the directory on every selection. `FileNameTranscoder` therefore normalizes everything towards the VFS to NFC and returns NFD to FUSE on macOS (NFC elsewhere), the same scheme as Cryptomator's fuse-nio-adapter. This is only done for file systems that advertise `normalizationSensitive() == false` (UVF, APFS, HFS+); for byte-exact file systems such as ext4 the transcoder is `VERBATIM`, since any change of form would make files unreachable.
