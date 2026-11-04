# vfs-backend-nio

Backend module. Implements the VFS API on top of Java NIO.

## Known limitations

- `rename` without `replaceExisting` is an existence check followed by `rename(2)`, because NIO has no `RENAME_NOREPLACE`. A node created at the target between the two steps is overwritten.
- Extended attributes go through NIO's user-defined attribute view. On Linux that view only addresses the `user.` namespace, so names in other namespaces (`security.`, `system.`, `trusted.`) are rejected with `UnsupportedOperationException`; on macOS names are passed verbatim.
