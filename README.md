# FastFileTransfer

A high-performance file synchronization system that implements a custom client-server protocol for efficient file transfer with compression and multithreading support.

## Technical Overview

FastFileTransfer is a C implementation of a file synchronization system that:

1. Uses a custom TCP-based protocol for client-server communication
2. Implements chunked file transfer (10MB chunks by default)
3. Supports zstd compression with configurable levels (1-22)
4. Utilizes multithreading for parallel file processing
5. Implements producer-consumer patterns with thread-safe queues
6. Provides both in-memory and disk-based storage options
7. Supports `sendfile()` for zero-copy file transfer

## System Architecture

The system consists of two main components:

### Client
- Scans source directories recursively
- Creates file chunks with configurable size (10MB default)
- Compresses data using zstd algorithm
- Serializes chunks into a compact binary format for batch transfer
- Sends files to server using custom protocol
- Supports sendfile for zero-copy file transfer (`-f`)
- Supports both single-threaded and multi-threaded operation

### Server
- Listens for client connections on port 8080
- Receives files using the custom protocol
- Decompresses received data
- Stores files either in memory or on disk
- Implements thread pool for parallel processing

## Protocol Details

The client-server communication uses the following status codes:
- `STATUS_OK`: Operation successful
- `STATUS_ERROR`: Error occurred
- `STATUS_FINISHED`: Transfer complete
- `STATUS_NEXT`: Ready for next file (per-file mode)
- `STATUS_CHUNK`: Following data is a serialized chunk (chunk mode)

## Configuration Options

### Command Line Arguments
| Argument | Description |
|----------|-------------|
| `-m` | Enable multithreading mode |
| `-c [level]` | Enable compression with optional level (1-22, default: 5) |
| `-s` | Enable chunk serialization (batch-transfer all files per chunk) |
| `-f` | Enable sendfile (zero-copy file transfer, bypasses userspace memory). Can be combined with `-m`. Incompatible with `-c` and `-s`. |
| `--source-dir <path>` | Source directory to sync (overrides `FASTSYNC_SOURCE_DIR`) |
| `--dest-dir <path>` | Server-side destination directory (overrides `FASTSYNC_DEST_DIR`) |
| `--save-to-disk` | Persist received files to disk |

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `FASTSYNC_SOURCE_DIR` | Source directory for files (fallback, overridden by `--source-dir`) | Current user's documents directory |
| `FASTSYNC_DEST_DIR` | Destination directory (fallback, overridden by `--dest-dir`) | `./data_copied` |
| `FASTSYNC_SERVER_IP` | Server IP address | `127.0.0.1` |
| `FASTSYNC_SERVER_PORT` | Server port | `8080` |
| `FASTSYNC_SAVE_TO_DISK` | Save to disk (fallback, overridden by `--save-to-disk`) | `false` |

## Implementation Details

### Data Structures

1. **Chunk**: Collection of files (default 10MB total size)
2. **File**: File metadata with path and content
3. **FileReceive**: Received file data structure
4. **Config**: Configuration parameters structure
5. **Queue**: Thread-safe queue implementation using condition variables

### Key Algorithms

1. **File Scanning**: Recursive directory traversal with BFS
2. **Chunking**: Files grouped into chunks with size limit
3. **Compression**: zstd compression with configurable levels
4. **Network Protocol**: Custom TCP-based protocol with status codes
5. **Thread Synchronization**: Condition variables and mutexes for thread coordination

## Build Requirements

- C11 compatible compiler
- CMake 4.1 or later
- zstd library
- pthread support

## Building

```bash
mkdir -p build && cd build
cmake ..
make
```

## Running

### Server
```bash
./build/server
```

### Client
```bash
# Basic usage with default settings (sends from ~/Documents/...)
./build/client -m -c 10

# Specify source and destination directories
./build/client --source-dir /path/to/send --dest-dir /path/to/receive --save-to-disk

# Chunk serialization mode (batch per chunk)
./build/client -s

# Compressed chunk serialization
./build/client -s -c 3

# Multithreaded with compressed chunk serialization
./build/client -m -s -c 3

# Sendfile (zero-copy, bypasses userspace for large files)
./build/client -f

# Sendfile with multithreading
./build/client -f -m
```

## Testing

The project includes comprehensive unit tests for core functionality:

```bash
./build/tests
```

An integration test / benchmark script runs all configurations against ~50 MB of generated test data with byte-for-byte verification:

```bash
python3 test.py
# Skip the throttled suite (disk I/O limits + 100ms network delay) if sudo is unavailable:
python3 test.py --no-throttled
```

## Code Organization

```
src/
  client/    # Client implementation
  server/    # Server implementation
  shared/    # Shared data structures and utilities
tests/      # Unit tests
```

## Performance Considerations

1. Chunk size (10MB default) affects memory usage and transfer efficiency
2. Compression level (1-22) trades CPU usage for space savings
3. `sendfile()` (`-f`) bypasses userspace memory, ~2x faster on localhost for large files
4. Multithreading improves performance on multi-core systems
5. Thread-safe queues minimize contention between producer/consumer threads

## Extensibility

The system is designed with clear interfaces that allow for:
1. Additional compression algorithms
2. Different transport protocols
3. Custom storage backends
4. Extended metadata support