# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
./mvnw clean install          # Build all modules and run tests
./mvnw test                   # Run all tests
./mvnw test -pl vfs-api       # Run tests for a single module
./mvnw test -pl vfs-backend-nio -Dtest=SomeTest  # Run a single test class
./mvnw package -DskipTests    # Build without tests
```

Requires Java 25. Uses Maven wrapper (./mvnw), no local Maven install needed.

## Architecture

Layered VFS with a pipeline design: **Frontend → Middleware → Backend**, all communicating through `vfs-api`.

- **vfs-api**: Core interfaces (`VfsFileSystem`, `VfsFile`, `VfsNodeMetadata`, etc.) that define the contract between layers. All path arguments are absolute POSIX-style strings (e.g., `/dir/file.txt`).
- **vfs-backend-nio**: `NioVfsFileSystem` implements `VfsFileSystem` by delegating to `java.nio.file`. Resolves VFS paths against a root `Path` with traversal protection.
- **vfs-frontend-fuse**: `FuseVfsOperations` adapts `VfsFileSystem` to jFUSE callbacks. Manages open file handles via `ConcurrentMap<Long, VfsFile>`. Translates `IOException` subtypes to errno values.
- **vfs-frontend-webdav**: WebDAV frontend (placeholder).
- **vfs-middleware-crypto**: Encryption middleware (placeholder).
- **vfs-common**: Shared utilities across implementations.
- **vfs-test**: `VfsTestMain` wires NIO backend → FUSE frontend for manual end-to-end testing. Run with args: `<sourceDir> <mountPoint> [fuseLibraryPath]`.

## Important Rules

- Avoid introducing new dependencies. If a dependency would be beneficial, always ask the user first.
- This project handles only I/O. All cryptographic operations live in the separate `org.cryptomator:cryptolib` Maven dependency.
- New Maven subprojects must use JSpecify's `@NullMarked` on the module declaration. All nullable fields must be explicitly annotated with `@Nullable`.
- Each subproject has a README.md with architectural context and subproject-specific hints. Always read a subproject's README.md before working in it.
- Cross-cutting design documentation lives in `docs/`. Read `docs/*.md` before changing `vfs-api` or adding a frontend; `docs/file-system-ops.md` explains which operations each target frontend (FUSE, FSKit, WinFsp, SMB, WebDAV) supports and why the API looks the way it does.
- Strive for small incremental commits. For non-trivial tasks, always make a plan first to break work into small committable steps.

## Code Conventions

- Java modules (JPMS): every module has a `module-info.java` with `@NullMarked`
- Nullability: uses JSpecify (`@Nullable` from `org.jspecify.annotations`)
- Indentation: tabs (not spaces)
- Imports: no wildcard imports (threshold set to 99)
- Logging: SLF4J
- Testing: JUnit Jupiter 6, Mockito (loaded as javaagent via surefire config)
- Mockito stubbing: always use `Mockito.doReturn().when()` style, never `Mockito.when().thenReturn()`
