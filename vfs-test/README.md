# vfs-test

Executable wiring for manual end-to-end testing.

## FUSE flow (`VfsTestMain`)

```mermaid
flowchart LR
    FUSE -->|VFS API| LogCleartext["Logging (cleartext)"]
    LogCleartext -->|VFS API| UVF["UVF Encryption"]
    UVF -->|VFS API| LogCiphertext["Logging (ciphertext)"]
    LogCiphertext -->|VFS API| NIO
```

## FSKit flow (`FskitVfsBootstrap`)

A plain directory mirror driven by the Swift FSKit extension in [`vfs-frontend-fskit`](../vfs-frontend-fskit) through the `FskitVfsAdapter` facade — no encryption middleware, so the bridge can be exercised in isolation. `FskitVfsBootstrap.create(rootDir)` is the single entry point the extension calls.

```mermaid
flowchart LR
    FSKit["FSKit extension (Swift)"] -->|SwiftJava/JNI| Adapter["FskitVfsAdapter"]
    Adapter -->|VFS API| Log["Logging (mirror)"]
    Log -->|VFS API| NIO
```

`mvn package` additionally copies all runtime dependencies to `target/libs/`, which `vfs-frontend-fskit/fskit/scripts/package.sh` bundles into the extension together with `target/vfs-test-*.jar` (the jar holding `FskitVfsBootstrap` itself).
