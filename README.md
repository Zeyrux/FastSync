# FastSync

A high-performance file synchronization system with SSH and TCP transport, TLS encryption, streaming zstd compression, multithreaded transfer, incremental sync, metadata preservation, and rsync-compatible CLI flags.

## Technical Overview

1. **Dual transport**: custom TCP client-server or SSH subprocess (rsync-style `user@host:/path`)
2. **TLS encryption**: OpenSSL-based TLS 1.2+ for encrypted TCP connections
3. **Chunked file transfer**: files grouped into configurable-size chunks (default ~10 MB)
4. **Streaming zstd compression** (levels 1–22) using `ZSTD_compressStream2`
5. **Multithreading**: producer-consumer pipeline with thread-safe queues (scanner → loader → sender)
6. **Incremental sync**: skip files unchanged since last transfer (compares size + mtime)
7. **Metadata preservation**: `mode`, `uid`, `gid`, `mtime` restored on disk when enabled
8. **`sendfile()` zero-copy** on TCP (~2× faster on loopback)
9. **SSH ControlMaster** for connection reuse across repeated invocations
10. **Bandwidth limiting**: token-bucket throttling (`--bwlimit`)
11. **`--delete`**: receiver removes files not present in sender manifest
12. **`--exclude` / `--include`**: glob-pattern filename filtering

## System Architecture

### Client
- Recursively scans source directories (BFS), supports exclude and include patterns
- Groups files into chunks (configurable size)
- Streaming zstd compression with configurable level
- Chunk serialization (compact binary format) or per-file transfer
- Incremental transfer: sends file metadata to server, skips unchanged files
- Manifests all sent paths when `--delete` is active
- Sends via TCP `sendfile()` or SSH pipe
- Optional progress display with throughput
- Bandwidth limiting via token-bucket algorithm

### Server
- TCP mode: listens on configurable port (default 8080); SSH mode: runs via `--stdio`
- TLS mode: wraps TCP connections with OpenSSL
- Receives and reassembles files
- Decompresses (streaming zstd), deserializes, restores metadata
- Handles incremental checks: compares size + mtime against destination files
- Processes `STATUS_MANIFEST` for `--delete`: walks destination tree, removes extras
- Per-connection concurrency via `fork()`
- Thread pool for parallel processing

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
| `STATUS_CHECK` | Incremental check: client sends file path + size + mtime, server responds with OK (skip) or NEXT (send) |

### Wire Format — Metadata

When `use_metadata` is enabled (`-M`), each file entry carries a 4-byte `present` flag followed by five fields (`mode`, `uid`, `gid`, `mtime_sec`, `mtime_nsec`). When disabled globally, no metadata bytes are sent — zero wire overhead.

### Transfer Flow
```
Config → (STATUS_NEXT | STATUS_CHUNK | STATUS_CHECK)* → [STATUS_MANIFEST] → STATUS_FINISHED → STATUS_OK
```

### Protocol Version

`1.1.0` — server and client must match. Mismatch results in `STATUS_ERROR`.

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
| `-M, --preserve` | Preserve file metadata (mode, uid, gid, mtime) |
| `-n, --dry-run` | Scan and print what would be transferred |
| `-p <port>` | SSH port (default: 22) |
| `-v, --verbose` | Enable debug logging |
| `--progress` | Show real-time transfer speed |
| `--delete` | Delete files on receiver not present in source |
| `--exclude <pattern>` | Exclude files matching glob pattern (repeatable) |
| `--include <pattern>` | Only transfer files matching glob pattern (repeatable, whitelist) |
| `--max-size <n>` | Skip files larger than n bytes |
| `--min-size <n>` | Skip files smaller than n bytes |
| `--incremental` | Skip files unchanged since last transfer (size + mtime). Auto-enables `--preserve`. Incompatible with `-s`. |
| `--bwlimit <KB/s>` | Bandwidth limit in kilobytes per second |
| `--chunk-size <n>` | Chunk size in bytes (default: 10485760) |
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

## Implementation Details

### Data Structures
1. **Chunk** — collection of files (~10 MB total by default)
2. **File** — path, content (`Data`), optional `FileMetadata` pointer
3. **FileMetadata** — `mode`, `uid`, `gid`, `mtime_sec`, `mtime_nsec`
4. **Config** — runtime parameters (transported over wire, TLS settings excluded)
5. **Queue** — thread-safe bounded queue with condition variables
6. **DirectoryScanner** — recursive BFS traversal with exclude and include pattern support

### Key Algorithms
1. **File scanning** — BFS directory traversal; entries matched against exclude and include patterns
2. **Chunking** — files accumulated until `chunk_size` threshold, then flushed
3. **Compression** — streaming zstd via `ZSTD_compressStream2` / `ZSTD_decompressStream`
4. **Network protocol** — status-code-driven exchange with metadata packing
5. **Incremental check** — client sends `STATUS_CHECK` + path + size + mtime; server compares against destination
6. **Bandwidth limiting** — token-bucket algorithm with `nanosleep` throttling on 64 KB write chunks
7. **Metadata restoration** — `chmod()`, `chown()`, `utimensat()` on the receiving side
8. **`--delete`** — sender tracks all sent paths; receiver walks destination tree and removes unlisted files/directories
9. **SSH transport** — `socketpair()` + `fork()` + `execvp("ssh", ...)` with `ControlMaster` and port support
10. **TLS transport** — OpenSSL `SSL_CTX` with TLS 1.2 minimum, optional CA verification, transparent `SSL_read`/`SSL_write` via `io_set_ssl()`

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

# All features
./build/client -a --progress --chunk-size 5242880 --exclude "*.log" --delete /src /dst
```

## Testing

```bash
# Unit tests (7 suites)
./build/tests

# Integration + benchmark suite
python3 test.py
```

The benchmark prints throughput metrics, best configuration, and speedup vs rsync.

## Performance Considerations

1. Chunk size (~10 MB default) balances memory and transfer efficiency
2. Compression level trades CPU for bandwidth
3. `sendfile()` bypasses userspace — ~2× faster on localhost for large files
4. Multithreading scales with core count
5. Metadata transfer adds negligible overhead (~24 bytes per file when enabled)
6. SSH socketpair buffer set to 1 MB for improved pipe throughput
7. SSH ControlMaster reuses connections across repeated invocations
8. Incremental sync eliminates redundant transfers entirely
9. Bandwidth limiting uses token-bucket with nanosleep for accurate throttling

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
