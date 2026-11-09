# vfs-backend-nio

Backend module. Implements the VFS API on top of Java NIO.

## Known limitations

- `rename` without `replaceExisting` is an existence check followed by `rename(2)`, because NIO has no `RENAME_NOREPLACE`. A node created at the target between the two steps is overwritten.
- Extended attributes go through NIO's user-defined attribute view. On Linux that view only addresses the `user.` namespace, so names in other namespaces (`security.`, `system.`, `trusted.`) are rejected with `UnsupportedOperationException`; on macOS names are passed verbatim.
- Symbolic links are stored and read verbatim but never followed. The root directory itself may be reached through symbolic links; below it, a link in any path component makes the path unresolvable, and a link as the final component cannot be opened, truncated, listed or chmodded.
- Case and normalization sensitivity are probed, not asked: case sensitivity by looking the root up with swapped case, normalization sensitivity from the file store type (APFS and HFS+ resolve all forms, everything else is assumed byte-exact). Both can be overridden through the three-argument constructor, e.g. for network mounts whose behaviour differs from the local file store type.
