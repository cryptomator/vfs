# vfs-backend-nio

Backend module. Implements the VFS API on top of Java NIO.

## Known limitations

- `rename` without `replaceExisting` is an existence check followed by `rename(2)`, because NIO has no `RENAME_NOREPLACE`. A node created at the target between the two steps is overwritten.
