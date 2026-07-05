# FastSync

A high-performance file synchronization system with a custom TCP-based protocol, optional metadata preservation, compression, multithreading, and zero-copy `sendfile()` support.

## Technical Overview

1. Custom TCP-based client-server protocol with status codes
2. Chunked file transfer (files grouped into ~10 MB chunks)
3. Optional zstd compression (levels 1–22)
4. Multithreading for parallel file processing (producer-consumer with thread-safe queues)
5. Optional file metadata preservation (`mode`, `uid`, `gid`, `mtime`) — restored on disk
6. In-memory and disk-based storage options
7. `sendfile()` zero-copy path (~2× faster on localhost)

## System Architecture

### Client
- Recursively scans source directories (BFS)
- Groups files into chunks (default ~10 MB total)
- Optionally compresses with zstd
- Optionally serializes chunks into a compact binary format
- Optionally attaches per-file metadata (mode, ownership, timestamps)
- Sends via custom protocol or `sendfile()` zero-copy path

### Server
- Listens on port 8080
- Receives and reassembles files
- Decompresses, deserializes, restores metadata on disk
- Thread pool for parallel processing

## Protocol Details

Status codes:
| Code | Meaning |
|------|---------|
| `STATUS_OK` | Operation successful |
| `STATUS_ERROR` | Error occurred |
| `STATUS_FINISHED` | Transfer complete |
| `STATUS_NEXT` | Ready for next file (per-file mode) |
| `STATUS_CHUNK` | Following data is a serialized chunk |

### Wire Format — Metadata

When `use_metadata` is enabled (`-M`), each file entry carries a 4-byte `present` flag followed by five fields (`mode`, `uid`, `gid`, `mtime_sec`, `mtime_nsec`). When disabled globally, no metadata bytes are sent — zero wire overhead.

## Configuration

### Command-Line Arguments
| Argument | Description |
|----------|-------------|
| `-m` | Multithreading mode |
| `-c [level]` | Compression with optional level (1–22, default 5) |
| `-s` | Chunk serialization (batch all files per chunk) |
| `-f` | Sendfile zero-copy. Incompatible with `-c` / `-s`. |
| `-M, --preserve` | Preserve file metadata (mode, uid, gid, mtime) |
| `--source-dir <path>` | Source directory (overrides `FASTSYNC_SOURCE_DIR`) |
| `--dest-dir <path>` | Server destination directory (overrides `FASTSYNC_DEST_DIR`) |
| `--save-to-disk` | Write received files to disk |

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSYNC_SOURCE_DIR` | User documents | Source directory fallback |
| `FASTSYNC_DEST_DIR` | `./data_copied` | Destination directory fallback |
| `FASTSYNC_SERVER_IP` | `127.0.0.1` | Server address |
| `FASTSYNC_SERVER_PORT` | `8080` | Server port |
| `FASTSYNC_SAVE_TO_DISK` | `false` | Disk persistence fallback |

## Implementation Details

### Data Structures
1. **Chunk** — collection of files (~10 MB total)
2. **File** — path, content (`Data`), optional `FileMetadata` pointer
3. **FileMetadata** — `mode`, `uid`, `gid`, `mtime_sec`, `mtime_nsec`
4. **Config** — runtime parameters
5. **Queue** — thread-safe queue with condition variables

### Key Algorithms
1. **File scanning** — recursive BFS directory traversal
2. **Chunking** — files grouped by size limit
3. **Compression** — zstd with configurable level
4. **Network protocol** — custom TCP with status codes and optional metadata packing
5. **Metadata restoration** — `chmod()`, `chown()`, `utimensat()` on the receiving side

## Build Requirements

- C11 compiler
- CMake 4.1+
- zstd library
- pthreads

## Building

```bash
cmake -B build -S . && cmake --build build -j$(nproc)
```

## Running

### Server
```bash
./build/server
```

### Client
```bash
# Basic
./build/client --source-dir /path/to/send --dest-dir /path/to/receive --save-to-disk

# With metadata preservation
./build/client -M --source-dir ... --dest-dir ...

# Multithreaded + compression
./build/client -m -c 10

# Sendfile (zero-copy)
./build/client -f

# All features
./build/client -m -c -s -M
```

## Testing

```bash
# Unit tests
./build/tests

# Integration benchmark (~50 MB data, 13 configurations + rsync comparison)
python3 test.py

# Profiles: --wan (100 Mbit, 50 ms, 1% loss), --unlimited (no throttling)
python3 test.py --wan
```

The benchmark prints throughput metrics for the best configuration and speedup vs rsync.

## Performance Considerations

1. Chunk size (~10 MB) balances memory and transfer efficiency
2. Compression level trades CPU for bandwidth
3. `sendfile()` bypasses userspace — ~2× faster on localhost for large files
4. Multithreading scales with core count
5. Metadata transfer adds negligible overhead when disabled, ~24 bytes per file when enabled
