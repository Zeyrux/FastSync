# FastSync

A high-performance file synchronization system with SSH and TCP transport, TLS encryption, streaming zstd compression, multithreaded transfer, incremental sync, metadata preservation, and rsync-compatible CLI flags.

## Technical Overview

1. **Dual transport**: custom TCP client-server or SSH subprocess (rsync-style `user@host:/path`)
2. **TLS encryption**: OpenSSL-based TLS 1.2+ for encrypted TCP connections with optional CA verification
3. **Chunked file transfer**: files grouped into configurable-size chunks (default ~10 MB)
4. **Streaming zstd compression** (levels 1–22) using `ZSTD_compressStream2`
5. **Multithreading**: producer-consumer pipeline with thread-safe queues (scanner → loader → sender)
6. **Incremental sync**: skip files unchanged since last transfer (compares size + mtime)
7. **Batch incremental**: send incremental checks in batched groups for reduced round-trips
8. **Metadata preservation**: file mode and mtime are restored when enabled; ownership and atime are intentionally not restored
9. **`sendfile()` zero-copy** on TCP (~2× faster on loopback)
10. **SSH ControlMaster** for connection reuse across repeated invocations
11. **Bandwidth limiting**: token-bucket throttling (`--bwlimit`)
12. **`--delete`**: receiver removes files not present in sender manifest
13. **`--exclude` / `--include`**: glob-pattern filename filtering
14. **Path traversal protection**: `..` sequences in file paths are rejected automatically
15. **Connection limits**: server enforces maximum concurrent connections (default 100)
16. **Keep-alive**: periodic `STATUS_KEEPALIVE` messages detect stalled connections
17. **Abort handling**: `SIGINT` sends `STATUS_ABORT` for clean server-side teardown
18. **Atomic writes**: received files are written to a temporary name then atomically renamed
19. **Backup mode**: `--backup` preserves overwritten files with optional `--backup-dir`
20. **Log file**: `--log-file` redirects log output to a file instead of stderr
21. **Transfer statistics**: `--stats` prints summary of transferred bytes, files, and timing

## System Architecture

### Client
- Recursively scans source directories (BFS), supports exclude and include patterns
- Groups files into chunks (configurable size)
- Streaming zstd compression with configurable level
- Chunk serialization (compact binary format) or per-file transfer
- Incremental transfer: sends file metadata to server, skips unchanged files
- Batch incremental: groups incremental checks to minimize round-trips
- Manifests all sent paths when `--delete` is active
- Sends via TCP `sendfile()` or SSH pipe
- Optional progress display with throughput
- Bandwidth limiting via token-bucket algorithm
- Configurable I/O and connection timeouts (`--timeout`, `--contimeout`)
- Quiet mode (`-q`/`--quiet`) suppresses all non-error output
- Backup overwritten files (`--backup`) with optional directory (`--backup-dir`)
- Transfer statistics summary (`--stats`)
- Maximum directory depth control (`--max-depth`)
- Log file output (`--log-file`)
- Configurable multithreaded queue size (`--queue-size`)
- Exclude patterns from file (`--exclude-from`)

### Server
- TCP mode: listens on configurable port (default 8080); SSH mode: runs via `--stdio`
- TLS mode: wraps TCP connections with OpenSSL with optional CA verification
- Receives and reassembles files
- Decompresses (streaming zstd), deserializes, restores metadata
- Handles incremental checks: compares size + mtime against destination files
- Handles batch incremental checks for reduced round-trips
- Processes `STATUS_MANIFEST` for `--delete`: walks destination tree, removes extras
- Per-connection concurrency via `fork()` with configurable connection limit (default 100)
- Thread pool for parallel processing
- Atomic writes: files written to `.tmp` path then atomically renamed on success
- Abort handling: cleanly shuts down on `STATUS_ABORT` from client
- Path traversal protection: rejects file paths containing `..`

## Protocol Details

### Status Codes
| Code | Meaning |
|------|---------|
| `STATUS_OK` | Operation successful |
| `STATUS_ERROR` | Error occurred |
| `STATUS_FINISHED` | Transfer complete |
| `STATUS_NEXT` | Ready for next file (per-file mode) |
| `STATUS_CHUNK` | Following data is a serialized chunk |
| `STATUS_MANIFEST` | Following data is a file manifest (for `--delete`) |
| `STATUS_CHECK` | Incremental check: client sends file path + size + mtime and, when negotiated, checksum; server responds with OK (skip) or NEXT (send) |
| `STATUS_CHECK_BATCH` | Batch incremental check: multiple file checks sent in one message |
| `STATUS_KEEPALIVE` | Keep-alive heartbeat to detect stalled connections |
| `STATUS_ABORT` | Abort signal: client interrupts, server cleans up and exits |
| `STATUS_DELTA_SIGNATURE` | Delta sync: following data is a file signature (rsync-style rolling hash) |
| `STATUS_DELTA_DATA` | Delta sync: following data is a delta patch for a file |

### Wire Format — Metadata

When `use_metadata` is enabled (`-M`), each file entry carries a 4-byte `present` flag followed by five fields (`mode`, `uid`, `gid`, `mtime_sec`, `mtime_nsec`). When disabled globally, no metadata bytes are sent — zero wire overhead.

### Transfer Flow
```
Config → (STATUS_NEXT | STATUS_CHUNK | STATUS_CHECK | STATUS_CHECK_BATCH)* → [STATUS_MANIFEST] → STATUS_FINISHED → STATUS_OK
```

Keep-alive (`STATUS_KEEPALIVE`) may be sent at any point during the transfer. The receiver resets its inactivity timer on receipt. If no data arrives within the receive timeout, the connection is aborted.

Abort (`STATUS_ABORT`) may be sent at any point. On receipt the server cleans up temporary files and exits the child process.

### Protocol Version

`2.2.0` — server and client must match. This version adds a 64-bit XXH64 checksum to checksum-enabled `STATUS_CHECK` messages and validates the negotiated compression choice (`zstd` or `none`). Older clients and servers must not be mixed with this version; mismatch results in `STATUS_ERROR`.

Config negotiation is sender-driven: the client serializes transfer options and the server applies them while receiving and writing files. `--checksum` compares size and content checksum instead of timestamps. `--compress-choice zstd` enables zstd; `none` disables it. Unsupported choices are rejected during config exchange.

## Command-Line Arguments

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
| `-q, --quiet` | Suppress all non-error output |
| `--silent` | Alias for `--quiet` |
| `--progress` | Show real-time transfer speed |
| `--delete` | Delete files on receiver not present in source |
| `--exclude <pattern>` | Exclude files matching glob pattern (repeatable) |
| `--exclude-from <file>` | Read exclude patterns from a file (one per line) |
| `--include <pattern>` | Only transfer files matching glob pattern (repeatable, whitelist) |
| `--max-size <n>` | Skip files larger than n bytes |
| `--min-size <n>` | Skip files smaller than n bytes |
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
| `--queue-size <n>` | Queue capacity for multithreaded mode (default: 100) |
| `--source-dir <path>` | Source directory (overrides `FASTSYNC_SOURCE_DIR`) |
| `--dest-dir <path>` | Server destination directory (overrides `FASTSYNC_DEST_DIR`) |
| `--save-to-disk` | Write received files to disk |
| `--server-host <ip>` | Server IP address (default: `127.0.0.1`) |
| `--server-port <n>` | Server port (default: `8080`) |
| `--tls` | Enable TLS encryption |
| `--cert <path>` | TLS certificate file (PEM) |
| `--key <path>` | TLS private key file (PEM) |
| `--ca <path>` | TLS CA certificate file for verification (PEM) |

### Server

| Argument | Description |
|----------|-------------|
| `--stdio` | Run in stdio mode (for SSH transport; single connection then exits) |
| `-p <port>` | TCP listen port (default: 8080, range: 1–65535) |
| `--tls` | Enable TLS encryption |
| `--cert <path>` | TLS certificate file (PEM) |
| `--key <path>` | TLS private key file (PEM) |
| `--ca <path>` | TLS CA certificate file for verification (PEM) |
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
3. **FileMetadata** — `mode`, `uid`, `gid`, `mtime_sec`, `mtime_nsec`; uid/gid are advisory wire fields and are never applied by the receiver; atime is unsupported
4. **Config** — runtime parameters (transported over wire, TLS settings excluded). Includes `timeout`, `contimeout`, `quiet`, `backup`, `backup_dir`, `stats`, `max_depth`, `log_file`, `queue_size`.
5. **Queue** — thread-safe bounded queue with condition variables
6. **DirectoryScanner** — recursive BFS traversal with exclude and include pattern support, max-depth enforcement

### Key Algorithms
1. **File scanning** — BFS directory traversal; entries matched against exclude and include patterns, max-depth enforced
2. **Chunking** — files accumulated until `chunk_size` threshold, then flushed
3. **Compression** — streaming zstd via `ZSTD_compressStream2` / `ZSTD_decompressStream`
4. **Network protocol** — status-code-driven exchange with metadata packing, keep-alive, and abort support
5. **Incremental check** — client sends `STATUS_CHECK` + path + size + mtime and, with `--checksum`, XXH64 content checksum; server compares against destination. Can be batched via `STATUS_CHECK_BATCH` for reduced round-trips.
6. **Bandwidth limiting** — token-bucket algorithm with `nanosleep` throttling on 64 KB write chunks
7. **Metadata restoration** — `chmod()`, `chown()`, `utimensat()` on the receiving side
8. **`--delete`** — sender tracks all sent paths; receiver walks destination tree and removes unlisted files/directories
9. **SSH transport** — `socketpair()` + `fork()` + `execvp("ssh", ...)` with `ControlMaster` and port support
10. **TLS transport** — OpenSSL `SSL_CTX` with TLS 1.2 minimum, optional CA verification, transparent `SSL_read`/`SSL_write` via `io_set_ssl()`
11. **Path traversal protection** — `has_path_traversal()` rejects any file path containing `..` components, preventing directory escape attacks
12. **Connection limiting** — server tracks active connections and rejects new ones beyond `max_connections` (default 100)
13. **Keep-alive** — idle connections receive periodic `STATUS_KEEPALIVE` to detect half-open TCP connections
14. **Abort handling** — `SIGINT` sets an abort flag; the next protocol operation sends `STATUS_ABORT` for clean server cleanup
15. **Atomic writes** — files are written to a `.tmp` suffix then atomically renamed via `rename()`, preventing partial files
16. **Backup** — before overwriting, existing files are moved to `--backup-dir` (or same directory with `~` suffix) preserving the original

## Security Features

### Path Traversal Protection
All received file paths are validated by `has_path_traversal()` before any disk operation. Any path containing `..` components is rejected with `STATUS_ERROR`, preventing directory escape attacks.

### TLS Certificate Verification
When `--ca` is provided, the server performs mutual TLS verification (`SSL_VERIFY_PEER` with depth 4). Without `--ca`, TLS is still encrypted but peer certificates are not verified.

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
cmake -B build -S . && cmake --build build -j$(nproc)
```

## Running

### Server (TCP mode)
```bash
./build/server
```

### Server with TLS
```bash
./build/server --tls --cert server.pem --key server-key.pem
```

### Server via SSH
Place the `fastsync-server` binary in the remote `$PATH`. The client runs `ssh user@host fastsync-server --stdio` automatically when an SSH-style destination is given.

### Client — SSH (rsync-style)
```bash
./build/client /path/to/send user@host:/path/to/receive
```

### Client — TCP
```bash
./build/client --source-dir /path/to/send --dest-dir /path/to/receive --save-to-disk
```

### Client — TCP with TLS
```bash
./build/client --tls --cert client.pem --key client-key.pem --ca ca.pem \
  --source-dir /path/to/send --dest-dir /path/to/receive --save-to-disk
```

### Common Options
```bash
# Archive mode (compression + multithreading + metadata)
./build/client -a /path/to/send user@host:/path

# Dry run
./build/client -n /path/to/send /path/to/receive

# With progress and custom chunk size
./build/client --progress --chunk-size 2097152 /src user@host:/dst

# Exclude temporary files + delete extras on receiver
./build/client --exclude "*.tmp" --exclude "*.o" --delete /src user@host:/dst

# Incremental sync (skip unchanged files)
./build/client --incremental /src user@host:/dst

# Bandwidth limit to 1 MB/s
./build/client --bwlimit 1024 /src user@host:/dst

# With timeouts, quiet mode, and stats
./build/client --timeout 60 --contimeout 15 --quiet --stats /src user@host:/dst

# Backup overwritten files to a directory
./build/client --backup --backup-dir /backups /src user@host:/dst

# Exclude patterns from file, limit depth
./build/client --exclude-from ignore.txt --max-depth 3 /src user@host:/dst

# Custom queue size for multithreading
./build/client -m --queue-size 200 /src user@host:/dst

# Log to file
./build/client --log-file /tmp/fastsync.log /src user@host:/dst

# All features
./build/client -a --progress --chunk-size 5242880 --exclude "*.log" --delete /src /dst
```

## Testing

```bash
# Unit tests (18 suites — array_list, chunk, compression, config, data, delta, file, glob,
#                      metadata, property, protocol, queue, robustness, scanner,
#                      shared_utils, stress, transport_tcp, transport_ssh, transport_tls)
./build/tests

# Integration + benchmark suite
python3 test.py
```

The benchmark prints throughput metrics, best configuration, and speedup vs rsync.

## Performance Considerations

1. Chunk size (~10 MB default) balances memory and transfer efficiency
2. Compression level trades CPU for bandwidth
3. `sendfile()` bypasses userspace — ~2× faster on localhost for large files
4. Multithreading scales with core count; `--queue-size` controls pipeline buffering
5. Metadata transfer adds negligible overhead (~24 bytes per file when enabled)
6. SSH socketpair buffer set to 1 MB for improved pipe throughput
7. SSH ControlMaster reuses connections across repeated invocations
8. Incremental sync eliminates redundant transfers entirely
9. Batch incremental reduces round-trips by grouping multiple checks into one message
10. Bandwidth limiting uses token-bucket with nanosleep for accurate throttling
11. Atomic writes add a single `rename()` per file — negligible overhead
12. Path traversal check is O(n) in path length with negligible cost

## Benchmark Results

25 MB of mixed file sizes over `localhost` with disk I/O throttled (reads ≤ 15 MB/s, writes ≤ 10 MB/s) and network emulation via `tc netem`. Each test was run 3×; the median is reported below.

### LAN (1000 Mbit, 20 ms ±1 ms, 0.1% loss)

| Configuration | Time | vs rsync (archive) | vs rsync (compress) |
|---|---|---|---|
| **Best: `-m -c`** | **0.20 s** | **11.2× faster** | **3.6× faster** |
| Compression (`-c`) | 0.31 s | 7.3× faster | 2.3× faster |
| Standard | 1.27 s | 1.8× faster | — |
| rsync (archive) | 2.27 s | — | — |
| rsync (archive + compress) | 0.72 s | — | — |

### WAN (100 Mbit, 50 ms ±10 ms, 1% loss)

| Configuration | Time | vs rsync (archive) | vs rsync (compress) |
|---|---|---|---|
| **Best: `-m -c`** | **0.39 s** | **44.8× faster** | **3.8× faster** |
| Compression (`-c`) | 0.64 s | 27.3× faster | 2.3× faster |
| Standard | 7.12 s | 2.4× faster | — |
| rsync (archive) | 17.44 s | — | — |
| rsync (archive + compress) | 1.47 s | — | — |

Compression reduces the data on the wire enough that the transfer becomes latency-bound rather than bandwidth-bound. On WAN, the best configuration runs 10.8× faster than the theoretical limit for uncompressed data, since zstd shrinks the 25 MB payload to a fraction of its original size over the wire.
