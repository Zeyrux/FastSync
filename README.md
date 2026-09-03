#FastSync

FastSync is a high-performance file synchronization tool designed to become a
drop-in replacement for common `rsync` workflows. It keeps the familiar
source/destination model and rsync-style options while adding optional
multithreading, streaming zstd compression, chunking, zero-copy TCP transfers,
and native TCP/TLS transports.

The compatibility target is straightforward:

- Existing rsync commands should keep the same meaning.
- FastSync-only performance options should be additive and optional.
- A normal compatibility-mode transfer should prioritize rsync filesystem
  semantics over maximum throughput.

FastSync currently speaks its own protocol to `fastsync-server`. SSH mode
starts that server remotely; it does not yet interoperate with an unmodified
rsync client or rsync daemon. See [Compatibility Status](#compatibility-status)
for the current boundary.

## Why FastSync

FastSync uses a producer-consumer transfer pipeline and can combine several
optimizations for large or high-latency transfers:

- Multithreaded scanning, loading, and sending.
- Streaming zstd compression with levels 1 through 22.
- Configurable file chunking and compact chunk serialization.
- `sendfile()` zero-copy transfers over TCP.
- Batched incremental checks to reduce round trips.
- Optional block-level delta transfer for FastSync peers.
- Bandwidth limiting, progress reporting, statistics, and backups.
- TCP, SSH, and TLS transports.
- Atomic temporary-file writes by default.

These optimizations are disabled or selected independently. Users can start
with rsync-style commands and add FastSync options when they are useful.

## Compatibility Status

FastSync is currently an rsync-compatible CLI in progress, not a complete
replacement for every rsync feature or protocol mode.

### Working today

- Recursive directory scanning.
- Rsync-style source and destination arguments.
- SSH transport using `user@host:destination` paths below the remote authorized root.
- TCP client/server transfers.
- Dry runs, excludes, includes, size filters, backups, statistics, and
  bandwidth limiting.
- Incremental size/mtime checks and optional xxHash64 content checks.
- FastSync-native delta transfer for changed files.
- Optional mode and timestamp preservation.
- Delete manifests with server-side delete authorization.
- Temporary-file writes with atomic rename by default.
- Path traversal checks and destination-root confinement.

### Not yet equivalent to rsync

- The FastSync wire protocol is not the rsync wire protocol.
- SSH mode requires `fastsync-server` on the remote host.
- Archive mode does not yet provide all of rsync's `-rlptgoD` behavior.
- Symlink transfer is incomplete; link targets are not yet recreated in all
  modes.
- Owner/group, ACL, xattr, hard-link, device, and special-file handling is
  incomplete or unavailable.
- Sparse-file handling does not yet preserve all holes correctly.
- `--partial`, `--partial-dir`, `--append`, and `--append-verify` are not yet
  full rsync-style resumable transfers.
- Several rsync short options currently have FastSync-specific meanings. Do
  not assume every short option is interchangeable yet.

The detailed flag matrix is maintained in
[`RSYNC_COMPAT.md`](RSYNC_COMPAT.md). It distinguishes implemented,
partial, alternate, and planned behavior.

## Quick Start

### Build

### Client

| Argument | Description |
|----------|-------------|
| Positional | `<source> <dest>` — automatic SSH detection if dest contains `:` |
| `-c [level]` | Compression with optional level (1–22, default 5) |
| `-z [level]` | Alias for `-c` |
| `-a, --archive` | Archive mode: enables `-c -m -M` (no `-s`) |
| `-m` | Multithreading mode |
| `-s` | Chunk serialization (batch all files per chunk) |
| `-f, --sendfile` | Sendfile zero-copy. Incompatible with `-c` / `-s`. TCP only. |
| `-M, --preserve` | Preserve supported file metadata (mode and mtime; ownership and atime are unsupported) |
| `-n, --dry-run` | Scan and print what would be transferred |
| `-p <port>` | SSH port (default: 22) |
| `-v, --verbose` | Enable debug logging |
| `--progress` | Show real-time transfer speed |
| `--delete` | Delete files on receiver not present in source |
| `--exclude <pattern>` | Exclude files matching glob pattern (repeatable) |
| `--exclude-from <file>` | Read exclude patterns from a file (one per line) |
| `--include <pattern>` | Only transfer files matching glob pattern (repeatable, whitelist) |
| `--max-size <n>` | Skip files larger than n bytes |
| `--min-size <n>` | Skip files smaller than n bytes |
| `--max-alloc <SIZE>` | Maximum single allocation (binary units: B, K, M, G, T, P, E; default 1G) |
| `--incremental` | Skip files unchanged since last transfer (size + mtime). Auto-enables `--preserve`. Incompatible with `-s`. |
| `--bwlimit <KB/s>` | Bandwidth limit in kilobytes per second |
| `--chunk-size <n>` | Chunk size in bytes (default: 10485760) |
| `--timeout <sec>` | I/O timeout in seconds (default: 30) |
| `--contimeout <sec>` | Connection timeout in seconds (default: 10) |
| `--backup` | Backup existing destination files before overwriting |
| `--backup-dir <dir>` | Target directory for backups (requires `--backup`) |
| `--stats` | Print transfer statistics at end (bytes, files, timing) |
| `--max-depth <n>` | Maximum directory depth to recurse (0 = unlimited, default: 0) |
| `--log-file <path>` | Write log messages to file instead of stderr |
| `--source-dir <path>` | Source directory (overrides `FASTSYNC_SOURCE_DIR`) |
| `--dest-dir <path>` | Server destination directory (overrides `FASTSYNC_DEST_DIR`) |
| `--save-to-disk` | Write received files to disk |
| `--server-host <ip>` | Server IP address (default: `127.0.0.1`) |
| `--server-port <n>` | Server port (default: `8080`) |
| `--tls` | Enable TLS encryption |
| `--cert <path>` | TLS certificate file (PEM) |
| `--key <path>` | TLS private key file (PEM) |
| `--ca <path>` | TLS CA certificate file for verification (PEM) |
| `--client-cn <name>` | Required TLS client certificate common name |

### Server

| Argument | Description |
|----------|-------------|
| `--stdio` | Run in stdio mode (for SSH transport; single connection then exits) |
| `-p <port>` | TCP listen port (default: 8080, range: 1–65535) |
| `--tls` | Enable TLS encryption |
| `--cert <path>` | TLS certificate file (PEM) |
| `--key <path>` | TLS private key file (PEM) |
| `--ca <path>` | TLS CA certificate file for verification (PEM) |
| `--destination-root <path>` | Authorized destination root (default: `.`) |
| `--allow-delete` | Permit manifest deletion |
| `--allow-unauthenticated` | Permit plaintext TCP clients |
| `-v, --verbose` | Enable debug logging |
| `--help` | Show help |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSYNC_SOURCE_DIR` | — | Source directory fallback |
| `FASTSYNC_DEST_DIR` | — | Destination directory fallback |
| `FASTSYNC_SAVE_TO_DISK` | `false` | Disk persistence fallback |
| `FASTSYNC_SSH_PORT` | `22` | Default SSH port |
| `FASTSYNC_SERVER_HOST` | `127.0.0.1` | Default server host |
| `FASTSYNC_SERVER_PORT` | `8080` | Default server port |
| `FASTSYNC_TLS_CERT` | — | Default TLS certificate path |
| `FASTSYNC_TLS_KEY` | — | Default TLS private key path |
| `FASTSYNC_TLS_CA` | — | Default TLS CA certificate path |

## Implementation Details

### Data Structures
1. **Chunk** — collection of files (~10 MB total by default)
2. **File** — path, content (`Data`), optional `FileMetadata` pointer
3. **FileMetadata** — `mode`, `uid`, `gid`, `mtime_sec`, `mtime_nsec`;
uid / gid are advisory wire fields and are never applied by the receiver;
atime is unsupported
4. **Config** — runtime parameters (transported over wire, TLS settings excluded). Includes `timeout`, `contimeout`, `quiet`, `backup`, `backup_dir`, `stats`, `max_depth`, `log_file`, `queue_size`.
5. **Queue** — thread-safe bounded queue with condition variables
6. **DirectoryScanner** — recursive BFS traversal with exclude and include pattern support, max-depth enforcement

### Key Algorithms
1. **File scanning** — BFS directory traversal;
entries matched against exclude and include patterns,
    max - depth enforced 2. * *Chunking ** — files accumulated until `chunk_size` threshold,
    then flushed 3. *
            *Compression ** — streaming zstd
                via `ZSTD_compressStream2` / `ZSTD_decompressStream` 4. *
            *Network protocol ** — status -
        code - driven exchange with metadata packing,
    keep - alive,
    and abort support 5. * *Incremental check ** — client sends `STATUS_CHECK` + path + size +
        mtime and,
    with `--checksum`, XXH64 content checksum; server compares against destination. Can be batched via `STATUS_CHECK_BATCH` for reduced round-trips.
6. **Bandwidth limiting** — token-bucket algorithm with `nanosleep` throttling on 64 KB write chunks
7. **Metadata restoration** — `chmod()`, `chown()`, `utimensat()` on the receiving side
8. **`--delete`** — sender tracks all sent paths;
receiver walks destination tree and removes unlisted files / directories 9. *
        *SSH transport *
            * — `socketpair()` + `fork()` + `execvp("ssh",
                                                    ...)` with `ControlMaster` and port support
                                                10. *
                                                *TLS transport ** — OpenSSL `SSL_CTX` with TLS
                                                1.2 minimum,
    mutual CA verification,
    transparent `SSL_read`/`SSL_write` via `io_set_ssl()` 11. *
        *Path traversal protection ** — `has_path_traversal()` rejects any file path
         containing `..` components,
    preventing directory escape attacks 12. *
            *Connection limiting ** — server tracks active connections and rejects
            new ones beyond `max_connections` (default 100)13. *
            *Keep
        - alive ** — idle connections receive periodic `STATUS_KEEPALIVE` to detect half
        - open TCP connections 14. * *Abort handling ** — `SIGINT` sets an abort flag; the next protocol operation sends `STATUS_ABORT` for clean server cleanup
15. **Atomic writes** — files are written to a `.tmp` suffix then atomically renamed via `rename()`, preventing partial files
16. **Backup** — before overwriting, existing files are moved to `--backup-dir` (or same directory with `~` suffix) preserving the original

## Security Features

### Path Traversal Protection
All received file paths are validated by `has_path_traversal()` before any disk operation. Any path containing `..` components is rejected with `STATUS_ERROR`, preventing directory escape attacks.

### TLS Certificate Verification
TLS requires `--ca` and performs mutual TLS verification (`SSL_VERIFY_PEER` with depth 4). Connections without certificate verification are rejected.

### Connection Limits
The server enforces a maximum of 100 concurrent connections (configurable via `max_connections` in `Server`). When the limit is reached, new connections are immediately rejected and closed.

### Abort Handling
If the client receives `SIGINT` (Ctrl+C) during a transfer, it sends `STATUS_ABORT` to the server. The server then cleans up temporary files and exits the child process, preventing incomplete files from remaining on disk.

### Atomic Writes
Received files are written to a temporary path (suffixed with `.tmp`) and then atomically renamed to the final filename via `rename()`. This prevents partial or corrupted files from appearing at the destination if the transfer is interrupted.

## Build Requirements

- C11 compiler
- CMake >= 3.22
- zstd library
- OpenSSL (development headers and libraries)
- pthreads
- SSH client (for SSH transport mode only)

### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt install cmake build-essential libzstd-dev libssl-dev openssh-client
```

**Nix:**
```bash
nix-shell  # provides zstd, openssl, cmake, gcc
```

## Building

```bash
cmake -B build -S .
cmake --build build -j$(nproc)
```

With Nix:

```bash
nix-shell
cmake -B build -S .
cmake --build build -j$(nproc)
```

### SSH transfer

The remote host must have `fastsync-server` available in `PATH`, or use
`--fastsync-server-path`. SSH starts `fastsync-server --stdio` in its remote
working directory, so use a destination below that directory unless the
remote server is otherwise configured with a matching authorized root.

```bash
ssh user@host 'mkdir -p destination'
./build/client /path/to/source user@host:destination
```

### TCP transfer

Start the FastSync server:

```bash
./build/server --destination-root /path/to -p 8080
```

Then run the client:

```bash
./build/client --server-host 127.0.0.1 --server-port 8080 \
  --source-dir /path/to/source --dest-dir /path/to/destination \
  --save-to-disk
```

Plain TCP requires the explicit `--allow-unauthenticated` server option. Use TLS for
authenticated network connections.

### TLS transfer
```bash
./build/server --destination-root /path/to --tls --cert server.pem --key server-key.pem -p 8443
./build/client --tls --cert client.pem --key client-key.pem --ca ca.pem \
  --server-host example.com --server-port 8443 \
  --source-dir /path/to/source --dest-dir /path/to/destination \
  --save-to-disk
```

## Common Workflows

These examples show the intended rsync-style workflow. Options marked as
FastSync-native are optional performance or transport extensions.

```bash
#Basic synchronization
./build/client /source/ /destination/

#Archive - style synchronization(current FastSync archive behavior)
./build/client -a /source/ user@host:destination/

#Preview a transfer without changing the destination
./build/client -n /source/ /destination/

#Exclude temporary and object files
./build/client --exclude '*.tmp' --exclude '*.o' \
  /source/ user@host:destination/

#Remove destination entries not present in the source
./build/client --delete /source/ user@host:destination/

#Skip unchanged files using size and modification time
./build/client --incremental /source/ user@host:destination/

#Verify content when size and time are not sufficient
./build/client --incremental --checksum /source/ user@host:destination/

#Preserve supported mode and timestamp metadata
./build/client -M /source/ user@host:destination/

#Keep backups of overwritten destination files
./build/client --backup --backup-dir backups \
  /source/ user@host:destination/
```

## FastSync Extensions

FastSync-native options are intended to add performance or operational
features without changing the meaning of ordinary compatibility options.

| Option | Purpose |
|---|---|
| `-m` | Enable the multithreaded scanner/loader/sender pipeline. |
| `-c [level]`, `-z [level]` | Enable streaming zstd compression, levels 1-22. |
| `--compress-level <n>` | Set the zstd compression level. |
| `--chunk-size <bytes>` | Set the transfer chunk size. |
| `-s` | Enable FastSync chunk serialization. |
| `-f`, `--sendfile` | Use TCP `sendfile()` zero-copy transfer. Incompatible with compression and chunk serialization. |
| `--delta` | Use FastSync-native block delta transfer. Requires `--incremental`. |
| `--delta-block <bytes>` | Set the FastSync delta block size. |
| `--delta-max <bytes>` | Limit files eligible for FastSync delta transfer. |
| `--server-host <host>` | Select the TCP server host. |
| `--server-port <port>` | Select the TCP server port. |
| `--tls` | Enable TLS for TCP transport. |
| `--bwlimit <KB/s>` | Apply token-bucket bandwidth limiting. |
| `--progress` | Show transfer progress and throughput. |
| `--stats` | Print transfer statistics. |
| `--timeout <seconds>` | Set I/O timeout. |
| `--contimeout <seconds>` | Set connection timeout. |

Current short-option conflicts are tracked as compatibility work. In
particular, FastSync currently uses `-p` for SSH port, `-s` for chunk
serialization, and `-S` for sparse handling. These meanings must be reconciled
before FastSync can claim full rsync CLI compatibility.

## Client Options

### Selection and transfer

| Option | Description |
|---|---|
| `-a`, `--archive` | Enable current archive preset. Full rsync archive semantics are planned. |
| `-n`, `--dry-run` | Scan and report without writing files. |
| `--delete` | Request removal of destination entries absent from the source. The server must allow deletion. |
| `--exclude <pattern>` | Exclude matching paths. Repeatable. |
| `--include <pattern>` | Include matching paths. Repeatable. |
| `--exclude-from <file>` | Read exclude patterns from a file. |
| `--include-from <file>` | Read include patterns from a file. |
| `--max-size <bytes>` | Skip files larger than the limit. |
| `--min-size <bytes>` | Skip files smaller than the limit. |
| `--max-depth <n>` | Limit recursive scanning depth;
zero means unlimited.| | `--incremental` | Skip files matching destination size and mtime.|
    | `--checksum` | Include xxHash64 content checks in incremental comparisons.| | `--backup` |
    Back up overwritten files.| | `--backup - dir<dir>` | Store backups under a separate directory.|
    | `--suffix<suffix>` | Set the backup filename suffix.| | `--partial` |
    Select partial - transfer handling.With `--partial - dir`,
    completed files are written there;
resumable transfers are not implemented.| | `--partial - dir<dir>` |
    Set a relative partial - transfer directory below the server destination root;
use with `--partial`. |
| `--inplace` | Write directly to the destination instead of using a temporary file. |

### Metadata and links

| Option | Description |
|---|---|
| `-M`, `--preserve` | Preserve supported file metadata, currently mode and modification time. |
| `-l`, `--links` | Request symlink preservation;
link-target transfer remains incomplete. |
| `--copy-links` | Copy symlink referents. |
| `--safe-links` | Skip symlinks that point outside the transfer tree. |
| `--copy-unsafe-links` | Copy unsafe symlink referents. |
| `-S`, `--sparse` | Request sparse-file handling; full hole preservation is planned. |

### Output and logging

| Option | Description |
|---|---|
| `-v`, `--verbose` | Enable debug logging. |
| `--progress` | Show live transfer progress. |
| `--stats` | Print transfer statistics. |
| `--log-file <path>` | Write log output to a file. |
| `-V`, `--version` | Print the FastSync protocol version. |
| `--help` | Print command usage. |

### Paths and transport

| Option | Description |
|---|---|
| `-p <port>` | SSH port in the current CLI. This conflicts with rsync's `-p` permissions option and is planned for correction. |
| `--fastsync-server-path <path>` | Remote FastSync server path for SSH mode. |
| `--source-dir <path>` | Set the source directory explicitly. |
| `--dest-dir <path>` | Set the destination directory explicitly. |
| `--save-to-disk` | Enable server-side disk persistence. |
| `--server-host <host>` | TCP server address. |
| `--server-port <port>` | TCP server port. |
| `--tls` | Enable TLS. Requires `--cert` and `--key`. |
| `--cert <path>` | TLS certificate file. |
| `--key <path>` | TLS private key file. |
| `--ca <path>` | CA file for peer verification. |

## Server Options

| Option | Description |
|---|---|
| `--stdio` | Serve one SSH connection over standard input/output. |
| `-p <port>` | TCP listen port. |
| `--tls` | Enable TLS. |
| `--cert <path>` | TLS certificate file. |
| `--key <path>` | TLS private key file. |
| `--ca <path>` | CA file for peer verification. |
| `--destination-root <path>` | Confine received files to this server-side root;
defaults to the current directory. |
| `--allow-delete` | Permit client delete manifests. Deletion is refused by default. |
| `-v`, `--verbose` | Enable debug logging. |
| `--help` | Print server usage. |

## Architecture

### Client

- Recursively scans the source tree with include, exclude, size, and depth
  filters.
- Sends individual files or serialized chunks.
- Performs incremental checks and optional content checksums.
- Uses a multithreaded producer-consumer pipeline when requested.
- Sends over TCP, TLS-wrapped TCP, or an SSH subprocess.
- Supports progress, statistics, backups, timeouts, and bandwidth limiting.

### Server

- Runs as a TCP listener or one-shot SSH `--stdio` server.
- Receives and reassembles files and decompresses streaming zstd data.
- Applies supported metadata and writes files through a confined destination
  root.
- Uses temporary files and atomic rename by default.
- Handles delete manifests only when explicitly authorized.
- Enforces connection, message-size, and path-safety limits.

## Protocol and Security

FastSync protocol version `2.2.0` is shared by the client and server. The
current protocol is sender-driven and includes configuration negotiation,
incremental checks, checksums, manifests, keep-alives, abort handling, and
FastSync-native delta messages. Client and server versions must currently
match exactly.

TLS provides encrypted TCP transport. Supplying `--ca` enables certificate
verification; without it, traffic is encrypted but peer identity is not
verified. Use certificate verification for deployments where authentication
matters. The default TCP transport is not encrypted.

The receiver protects its destination root with path validation, `openat()`
directory traversal, `O_NOFOLLOW`, temporary files, and atomic renames. Delete
operations require the server's explicit `--allow-delete` policy.

## Compatibility Roadmap

The project will reach the drop-in replacement goal in stages:

1. Correct rsync option meanings, including short options, combined options,
   and `--option=value` syntax.
2. Add differential tests that compare FastSync and rsync contents, metadata,
   links, deletes, filters, dry runs, and exit codes.
3. Make `-a` implement the expected recursive, links, permissions, times,
   owner/group, and supported special-file behavior.
4. Complete symlink, sparse-file, metadata, delete-policy, and resumable-write
   semantics.
5. Add rsync remote-shell and daemon protocol interoperability.
6. Keep FastSync performance options as negotiated, optional extensions.

The exhaustive implementation matrix and compatibility notes are in
[`RSYNC_COMPAT.md`](RSYNC_COMPAT.md).

## Testing

Run the unit test binary:

```bash
./build/tests
```

Run the Python integration suite:

```bash
python3 -m pytest tests/
```

For stricter local validation:

```bash
cmake -B build-strict -S . -DSTRICT_WARNINGS=ON
cmake --build build-strict -j$(nproc)
cmake -B build-asan -S . -DSANITIZER=address
cmake --build build-asan -j$(nproc)
```

The benchmark tool compares FastSync configurations with rsync under
controlled local and network conditions:

```bash
python3 benchmark/bench.py --help
```

Benchmark results measure transfer performance only. They do not establish
rsync protocol or filesystem-semantic compatibility.

## Performance Guidance

- Use `-m` for workloads with many files or enough CPU parallelism.
- Use `-c` or `-z` when network bandwidth is more constrained than CPU.
- Tune `--chunk-size` for file sizes, memory limits, and network latency.
- Use `-f` for large uncompressed TCP transfers where zero-copy I/O helps.
- Use `--incremental` to avoid retransmitting unchanged files.
- Use `--delta` for changed files when both endpoints are FastSync peers.
- Use `--bwlimit` when sharing a link with other traffic.

Always validate the compatibility behavior required by a deployment before
replacing an existing rsync job.
