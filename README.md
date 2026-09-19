# FastSync

FastSync is a high-performance file synchronization tool designed to become a
drop-in replacement for common `rsync` workflows. It keeps the familiar
source/destination model and rsync-style options while adding optional
multithreading, streaming zstd compression, chunking, zero-copy TCP transfers,
and native TCP/TLS transports.

The release version is FastSync's client/server protocol version (printed by
`./build/client --version`); client and server must match. See
[CHANGELOG.md](CHANGELOG.md) for the history.

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
- Streaming compression (zstd by default, plus lz4/zlib/zlibx) with levels 1 through 22.
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
- Dry runs (server-contacting since protocol 2.21.0 for server-routed targets),
  excludes, includes, size filters, backups, statistics, and bandwidth
  limiting.
- Incremental size/mtime checks and optional content checks (`xxh128` by
  default, selectable with `--checksum-choice`).
- FastSync-native delta transfer for changed files.
- Optional mode and timestamp preservation.
- Delete manifests with server-side delete authorization.
- Temporary-file writes with atomic rename by default.
- Path traversal checks and destination-root confinement.

### Boundaries and documented divergences

The items below summarize FastSync's rsync compatibility status — recently
closed gaps and the remaining known divergences. Each row of the detailed
matrix is classified as parity, caveat, or divergent in
[`RSYNC_COMPAT.md`](RSYNC_COMPAT.md).

- The FastSync wire protocol is not the rsync wire protocol.
- SSH mode requires `fastsync-server` on the remote host.
- Archive mode covers rsync's `-rlptgoD` behavior — links, permissions, times,
  owner, group, devices, and special files — and does not imply compression or
  multithreading (see [Client](#client)). Ownership application is still
  privilege-gated: a receiver that cannot `chown` logs a warning and skips it.
  Under `-p` the source mode is copied exactly, including setuid/setgid/sticky
  and group/other-write bits (strict rsync parity; see
  [`RSYNC_COMPAT.md`](RSYNC_COMPAT.md)).
- Symlink transfer stores targets **verbatim** (`-l`/`--links`), including
  absolute and `..`-bearing targets, matching rsync. The receiver does not
  enforce a containment predicate by default; `--safe-links` drops unsafe
  targets on the sender, and `--munge-links` rewrites them with rsync's
  `/rsyncd-munged/` marker. `--trust-sender` does not affect symlink targets.
  A destination later consumed by a link-following tool can therefore follow a
  link outside the receive root — use `--safe-links` for untrusted sources.
- Hard links (`-H`/`--hard-links`), extended attributes (`-X`/`--xattrs`), and
  POSIX ACLs (`-A`/`--acls`) are preserved; owner/group is applied through
  `-o`/`-g` (or an `-a`/`--archive` transfer), through the opt-in identity flags
  (`--chown`/`--usermap`/`--groupmap`/`--numeric-ids`/`--copy-as`), and only when
  the receiver has permission. See
  [`RSYNC_COMPAT.md`](RSYNC_COMPAT.md) for the exact semantics and documented
  divergences.
- Device and special-file preservation is implemented with documented
  divergences: recreated device nodes require `CAP_MKNOD` on the receiver (a
  non-root receiver skips the entry), while FIFOs **and unix sockets** are
  recreated (`--specials`).
- Sparse-file hole preservation (`-S`, `--sparse`) is implemented receiver-side:
  long all-zero runs are written as holes (no wire change; the full file image
  is already in memory).
- `--partial`, `--partial-dir`, `-P`, `--append`, and `--append-verify` keep
  the write atomic (temp + rename). With `--partial`, a failed/interrupted write
  now retains the already-written temp at the destination path (best-effort) so
  a later `--append`/`--append-verify` run can resume it.
- `-d`/`--dirs` and its aliases `--old-dirs`/`--old-d` transfer the named
  directory entries without recursing into their contents.
- Short-option names are now rsync-parity (Phase 7 Wave A): FastSync's former
  collisions were renamed (`-j`/`--threads`, `--preserve`, `--sendfile`,
  `--chunk-serialization`, `--timeout`, `--ssh-port`), so `-m`, `-M`, `-f`,
  `-s`, `-T`, `-p`, `-c`, `-a`, and `-z` follow rsync.
- Short-option clustering (`-av`, `-aAX`, `-rlpt`) and attached values
  (`-B1000`, `-essh`, `-MOPT`, `--opt=value`) are accepted, matching rsync.
- `-r`, `-b`, `-L`, and `-B` are parsed with the rsync short names.
- `--stats` prints the counters FastSync can observe plus the receiver-only
  counters reported over the wire (`Matched data`, deleted files, and the
  created/literal counters); `Number of files` and `Number of created files`
  carry rsync's per-type breakdown. `--progress` prints rsync-style per-file
  blocks including the leading `./` line, and (when progress is requested) a
  paths-only pre-count supplies rsync's `to-chk` denominator.
- Codecs match rsync 3.4.1: `zstd`/`lz4`/`zlib`/`zlibx` compression and
  `xxh128`/`xxh3`/`xxh64`/`md5`/`md4`/`sha1`/`none` checksums. `auto` honors
  `RSYNC_COMPRESS_LIST`/`RSYNC_CHECKSUM_LIST` and otherwise follows rsync's
  compiled-in order. An omitted `--compress-level` uses the codec's rsync
  default (zstd 3, zlib/zlibx 6, lz4 ignored); `zlib`/`zlibx` share the
  literal-only zlib path (rsync's zlibx semantics), and the transfer checksum is
  not separately selectable.

The detailed flag matrix is maintained in
[`RSYNC_COMPAT.md`](RSYNC_COMPAT.md). It reports each row as **parity**,
**caveat** (works with a documented divergence), or **divergent** (not
supported), rather than treating "parsed" as parity.

## Quick Start

### Build

```bash
cmake -B build -S .
cmake --build build -j$(nproc)
```

This produces `./build/client` and `./build/server`. `compile_commands.json` is a symlink to `build/compile_commands.json` and is used by clangd/editor tooling; its target is generated by the build, so it dangles until the first build.

### Client

| Argument | Description |
|----------|-------------|
| Positional | `<source> <dest>` — automatic SSH detection if dest contains `:` |
| `-c, --checksum` | Verify content by checksum instead of size+mtime (implies the incremental checksum quick-check) |
| `--checksum-choice <alg>` | Whole-file checksum algorithm: `xxh128` (default), `xxh3`, `xxh64`/`xxhash`, `md5`, `md4`, `sha1`, `none`, or `auto` (plus rsync's two-name `transfer,pre-transfer` form) |
| `-z, --compress [level]` | Enable streaming compression (default `zstd`; level 1–22, default 5) |
| `--compress-choice <alg>` | Compression algorithm: `zstd` (default), `lz4`, `zlib`, `zlibx`, `none`, or `auto` |
| `--skip-compress <list>` | Skip compression for suffixes (`/`- or `,`-separated); defaults to rsync 3.4.1's built-in suffix list |
| `-a, --archive` | rsync archive mode (`-rlptgoD`): links, perms, times, owner, group, devices and specials; ownership application stays privilege-gated (not compression/multithreading) |
| `-j, --threads[=N]` | Multithreading mode; `N` (1–256) sets the parallel scanner worker count, bare `-j`/`--threads` uses the default |
| `-m` | rsync `--prune-empty-dirs` (short form now rsync-parity) |
| `-r, --recursive` | Recurse into directories (FastSync is always recursive; accepted for rsync compatibility) |
| `-d, --dirs` | Transfer the named directory entries without recursing into their contents; aliases `--old-dirs`/`--old-d` |
| `-R, --relative` | Use rsync's relative path semantics (including the `/./` cut); with `--files-from`, preserve each listed entry's relative path below the destination root |
| `--chunk-serialization` | Chunk serialization (batch all files per chunk; long form only) |
| `-s` | rsync `--secluded-args` compatibility no-op (remote SSH argv is already injection-safe) |
| `--sendfile` | Sendfile zero-copy. Incompatible with compression / chunk serialization. TCP only. Long form only. |
| `--preallocate` | Allocate destination file space up front (fail-fast on a full disk) |
| `--append` | Resume a shorter destination by appending only its tail (prefix not verified; requires `--incremental`) |
| `--append-verify` | Like `--append`, but verifies the retained prefix checksum first (falls back to a full transfer on mismatch) |
| `-W, --whole-file` | Transfer changed files without delta processing; `--no-whole-file` clears it |
| `-B <n>, --block-size <n>` | Delta block size in bytes (alias `--delta-block`) |
| `--checksum-seed <n>` | Seed for the whole-file xxHash digest; an unset/`0` seed is randomized per transfer, matching rsync |
| `-I, --ignore-times` | Transfer files even when size and mtime match |
| `--size-only` | Skip incremental files matching in size, ignoring mtime |
| `--preserve` | Preserve mode and mtime (`-p` + `-t`; add `-o`/`-g` for owner/group or `-U`/`--atimes` for atime; `-N`/`--crtimes` captures birth time but cannot apply it) |
| `-U, --atimes` | Preserve access times. Captured with the metadata payload; does not enable ownership. |
| `-N, --crtimes` | Capture birth time; cannot be applied (documented divergence) |
| `-p, --perms` | Preserve permission bits. Strict rsync parity: the source mode is copied exactly, including setuid/setgid/sticky and group/other-write bits |
| `-t, --times` | Preserve modification times |
| `-o, --owner` | Preserve the source owner (privilege-gated; mapped by name on the receiver with a numeric fallback) |
| `-g, --group` | Preserve the source group (privilege-gated; mapped by name on the receiver with a numeric fallback) |
| `--no-perms`, `--no-times`, `--no-owner`, `--no-group`, `--no-preserve` | Negate the per-attribute flags (short `--no-p`/`--no-t`/`--no-o`/`--no-g`; `--no-preserve` clears all four) |
| `-E, --executability` | Preserve executable permission bits |
| `-X, --xattrs` | Preserve user `user.*` extended attributes |
| `-A, --acls` | Preserve POSIX ACLs |
| `--chmod <changes>` | Modify transferred permissions (rsync syntax) |
| `--chown=USER:GROUP` | Override the ownership of transferred files |
| `--usermap=MAP` | Map usernames when applying ownership |
| `--groupmap=MAP` | Map group names when applying ownership |
| `--numeric-ids` | Apply source numeric uid/gid directly instead of mapping by name |
| `--copy-as=USER[:GROUP]` | Force every written entry to USER[:GROUP] (requires a privileged receiver) |
| `--fake-super` | Record the resolved owner plus mode/time in a reserved `user.fastsync.stat` xattr and replay mode/time; never performs a real chown |
| `--super` | Permit the receiver to attempt confined super-user activities (device nodes) |
| `-D` | Preserve device and special files (implies `--devices --specials`) |
| `--devices` | Recreate device nodes on the destination (privileged; skipped without `CAP_MKNOD`) |
| `--specials` | Recreate special files: FIFOs and unix sockets |
| `--remove-source-files` | Remove regular source files after a successful transfer |
| `--exclude <pattern>` | Exclude files matching glob pattern (repeatable) |
| `--exclude-from <file>` | Read exclude patterns from a file (one per line) |
| `--include <pattern>` | Only transfer files matching glob pattern (repeatable, whitelist) |
| `--include-from <file>` | Read include patterns from a file |
| `--files-from <file>` | Read the source file list from FILE (paths relative to the source root) |
| `--max-size <n>` | Skip files larger than n bytes |
| `--min-size <n>` | Skip files smaller than n bytes |
| `-x, --one-file-system` | Do not cross filesystem boundaries; the mount-point directory entry is emitted (empty at the destination) without descending |
| `--max-alloc <SIZE>` | Maximum single allocation (binary units: B, K, M, G, T, P, E; default 1G; `0` = no local limit, matching rsync) |
| `-u, --update` | Skip files newer than the source on the receiver |
| `--incremental` | Skip files unchanged since last transfer (size + mtime). Auto-enables `--preserve`. Incompatible with `--chunk-serialization`. |
| `--existing` | Skip files not already present at the destination; update existing files normally. |
| `--compare-dest <dir>` | Extra comparison basis: unchanged files are not transferred (requires/implies `--incremental`) |
| `--copy-dest <dir>` | Like `--compare-dest`, but copies the unchanged file from DIR into the destination |
| `--link-dest <dir>` | Like `--copy-dest`, but hard-links the unchanged file from DIR (repeatable; earlier DIRs win) |
| `--verify-basis` | FastSync-only: require a basis hit (`--compare-dest`/`--copy-dest`/`--link-dest`) to match the source by whole-file digest instead of trusting the size+mtime quick-check (default matches rsync) |
| `--delete` | Delete files on receiver not present in source (default timing: delete-during, matching rsync, so destination space is freed progressively). Scoped to the synchronized directories, so `--files-from` subsets are safe |
| `--delete-before` | Delete extras before the transfer starts (implies `--delete`) |
| `--delete-during`, `--del` | Delete extras once the keep-set is known, before data is applied (implies `--delete`) |
| `--delete-delay` | Delete extras only after a successful transfer (implies `--delete`) |
| `--delete-after` | Explicit delete-after timing (implies `--delete`) |
| `--delete-commit` | FastSync-only: keep the pre-2.28 atomic timing — delete only after the whole transfer succeeded (identical timing to `--delete-after`) |
| `--delete-excluded` | Also delete filter-excluded destination mirrors (size-pruned mirrors stay protected) |
| `--max-delete <n>` | Delete at most n destination entries; the rest are skipped and the run exits 25 (partial), matching rsync |
| `--delay-updates` | Put updated files into place only at the end of the transfer (`--force` is honored at publication) |
| `-T, --temp-dir <dir>` | Scratch directory for temp files before the atomic install; confined to the receive root (relative only), with an `EXDEV` non-atomic copy fallback |
| `-n, --dry-run` | Report what would be transferred without mutating the destination. Since protocol 2.21.0 a server-routed target contacts the receiver and reports would-transfer based on receiver state; a plain local destination keeps the client-side scan. Never mutates or deletes. |
| `-v, --verbose` | Enable debug logging |
| `-q, --quiet` | Suppress non-error output |
| `--progress` | Show rsync-style per-file progress blocks from the receiver's wire counters (FastSync does not print rsync's leading `./` line) |
| `-P` | Enables partial-transfer mode + progress output; interrupted writes retain the already-written temp for resumption |
| `--stats` | Print transfer statistics at end (bytes, files, timing), including the receiver-only counters reported over the wire; rsync's per-type `Number of files` breakdown is not reproduced |
| `-i, --itemize-changes` | Print an rsync-style per-file change line |
| `--out-format=FORMAT` | Output format for changed files (`%f %n %l %b %M %%`) |
| `--list-only` | List source files instead of transferring |
| `--fsync` | Fsync every written file before publication |
| `-h, --human-readable` | Format transfer byte/rate counts with rsync's decimal (base-1000) units |
| `--max-depth <n>` | Maximum directory depth to recurse (0 = unlimited, default: 0) |
| `--log-file <path>` | Write log messages to file instead of stderr |
| `--write-batch=FILE` | Run the normal live transfer and also emit a self-contained batch file of the source tree |
| `--only-write-batch=FILE` | Emit the batch file only (no destination, no server) |
| `--read-batch=FILE` | Apply a batch file to the destination (no source, no server) |
| `--source-dir <path>` | Source directory (overrides `FASTSYNC_SOURCE_DIR`) |
| `--dest-dir <path>` | Server destination directory (overrides `FASTSYNC_DEST_DIR`) |
| `--save-to-disk` | Write received files to disk |
| `--server-host <ip>` | Server IP address (default: `127.0.0.1`) |
| `--server-port <n>` | Server port (default: `8080`) |
| `--ssh-port <port>` | SSH port (default: 22) |
| `-e, --rsh <command>` | Remote shell to launch for the SSH transport (default: `ssh`; may include arguments, e.g. `-e "ssh -p 2222"`) |
| `-M, --remote-option=OPT` | Append OPT to the remote server invocation over SSH (repeatable) |
| `--address <ip>` | Bind the outgoing client socket to this source address |
| `-4, --ipv4` | Force IPv4 for destination resolution |
| `-6, --ipv6` | Force IPv6 for destination resolution |
| `--sockopts=OPTS` | Comma-separated OPT=VAL socket options applied before connect (`TCP_NODELAY`, `SO_KEEPALIVE`, `SO_RCVBUF`, `SO_SNDBUF`, `SO_REUSEADDR`) |
| `--bwlimit <KB/s>` | Bandwidth limit in kilobytes per second |
| `--chunk-size <n>` | Chunk size in bytes (default: 10485760) |
| `--timeout <sec>` | I/O timeout in seconds, applied to both the socket (`SO_RCVTIMEO`/`SO_SNDTIMEO`) and the per-message protocol poll deadline. Default `0` = disabled (matching rsync); `0` disables it. `--no-timeout` is the negation. The value is not sent on the wire; the server side keeps its own safe floor. |
| `--contimeout <sec>` | Connection timeout in seconds (default: 60, matching rsync); `0` disables it (`--no-contimeout` is the negation) |
| `--stop-after=MINS` | Stop the transfer after MINS minutes (a positive integer); whatever was already transferred is kept |
| `--stop-at=TIME` | Stop at an absolute time (`HH:MM`, `HH:MM:SS`, or `now+N[smhd]`); an early stop skips the late `--delete` keep-set |
| `-b, --backup` | Backup existing destination files before overwriting |
| `--backup-dir <dir>` | Target directory for backups (requires `--backup`) |
| `--tls` | Enable TLS encryption |
| `--cert <path>` | TLS certificate file (PEM) |
| `--key <path>` | TLS private key file (PEM) |
| `--ca <path>` | TLS CA certificate file for verification (PEM) |

The exhaustive rsync flag matrix is in [`RSYNC_COMPAT.md`](RSYNC_COMPAT.md).

**Per-message vs. connection timeouts.** `--timeout` bounds each individual protocol
send/receive (the `poll()` deadline), so a peer that stops mid-frame is dropped. It
does not, by itself, stop a peer that keeps sending well-formed frames forever. The
receiver therefore also enforces two wall-clock (`CLOCK_MONOTONIC`) bounds on a
connection: a **1 hour** idle limit and a **24 hour** overall session cap. Only
frames that move real work (not `STATUS_KEEPALIVE`/`STATUS_ABORT` and not an
empty `STATUS_CHECK_BATCH`/`STATUS_DIR_TIMES`) refresh the idle timestamp, so a
peer cannot hold a connection slot by emitting cheap empty frames; a peer that
fabricates minimal non-empty frames can still occupy a slot until the 24 hour
cap, since no bound can require actual payload without risking a legitimate
long operation. Both are deliberately generous so a legitimate long-running
transfer is never aborted.

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
| `--allow-super` | Standalone TCP listener only: keep super-user activities enabled for a **root** receiver. Without it a root standalone server forces `SUPER_MODE_OFF`, so client `--devices`/`--write-devices`/`--super` and client-chosen ownership requests are skipped/refused. **Rejected with `--stdio`** (the SSH remote argv is client-composed, so a client could otherwise pass it and defeat the secure default; operators exposing `fastsync-server --stdio` over SSH must use a forced command if the default must hold). No effect when not root. |
| `--allow-unauthenticated` | Permit plaintext TCP clients. For an `auth users` module this opts in **loopback plaintext only**; remote auth still requires verified TLS, so the flag never permits remote plaintext auth. |
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

1. **Chunk** — collection of files (~10 MB total by default).
2. **File** — path, content (`Data`), optional `FileMetadata` pointer.
3. **FileMetadata** — `mode`, `uid`, `gid`, `mtime_sec`, `mtime_nsec` (plus
   atime/crtime fields). `uid`/`gid` are applied only through the opt-in
   identity path; atime is preserved with `-U`/`--atimes`; crtime is captured
   but cannot be set on the destination.
4. **Config** — runtime parameters. Most cross the wire (TLS settings
   excluded); `backup` and `backup_dir` are in the serialized wire table, while
   `timeout`, `contimeout`, `quiet`, `stats`, `max_depth`, and `log_file` are
   client-only.
5. **Queue** — thread-safe bounded queue with condition variables.
6. **DirectoryScanner** — recursive BFS traversal with exclude and include
   pattern support, max-depth enforcement.

### Key Algorithms

1. **File scanning** — BFS directory traversal; entries matched against exclude
   and include patterns, with max-depth enforced.
2. **Chunking** — files accumulated until the `chunk_size` threshold (default
   10 MiB) is reached, then flushed.
3. **Compression** — streaming zstd via `ZSTD_compressStream2()` /
   `ZSTD_decompressStream()`.
4. **Network protocol** — status-code-driven exchange with metadata packing,
   keep-alive, and abort support.
5. **Incremental check** — the client sends `STATUS_CHECK` + path + size +
    mtime and, with `--checksum`, a whole-file content checksum (`xxh128` by
    default; selectable via `--checksum-choice`/`--cc`, seeded by
    `--checksum-seed`); the server compares against the destination. Can be
    batched via `STATUS_CHECK_BATCH` for reduced round-trips.
6. **Bandwidth limiting** — token-bucket algorithm with sleep throttling on
   64 KiB write chunks.
7. **Metadata restoration** — mode via `chmod()`/`fchmod()`, times via
   `utimensat()`/`futimens()`, and ownership only with an identity flag via
   fd-relative `fchown()`/`fchownat()`.
8. **`--delete`** — the sender tracks all sent paths; the receiver walks the
   destination tree and removes unlisted files and directories.
9. **SSH transport** — `socketpair()` + `fork()` + `execvp("ssh", ...)` with
   `ControlMaster` and port support.
10. **TLS transport** — OpenSSL `SSL_CTX` with TLS 1.2 minimum, mutual CA
    verification, and transparent `SSL_read()`/`SSL_write()` via
    `io_set_ssl()`.
11. **Path traversal protection** — `has_path_traversal()` rejects any file
    path containing `..` components, preventing directory escape attacks.
12. **Connection limiting** — the server tracks active connections and rejects
    new ones beyond `max_connections` (default 100).
13. **Keep-alive** — idle connections receive periodic `STATUS_KEEPALIVE` to
    detect half-open TCP connections.
14. **Abort handling** — `SIGINT` sets an abort flag; the next protocol
    operation sends `STATUS_ABORT` for clean server cleanup.
15. **Atomic writes** — files are written to a `.tmp` suffix then atomically
    renamed via `rename()`, preventing partial files.
16. **Backup** — before overwriting, existing files are moved to `--backup-dir`
    (or the same directory with a `~` suffix), preserving the original.

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

The remote host must have `fastsync-server` available in `PATH` (install or
copy the built `./build/server` there as `fastsync-server`), or use
`--fastsync-server-path`. SSH starts `fastsync-server --stdio` in its remote
working directory, so use a destination below that directory unless the
remote server is otherwise configured with a matching authorized root.

The remote `--stdio` server argv is composed by the client, so it must never
be trusted to opt a root receiver into super-user activities: `--allow-super`
is rejected with `--stdio` and super stays off on that path. Operators
exposing `fastsync-server --stdio` over SSH must use a forced command (e.g. an
`authorized_keys` `command=` entry) if the default must hold.

```bash
ssh user@host 'mkdir -p destination'
./build/client /path/to/source user@host:destination
```

FastSync is **push-only**: the source (first argument) is always a local
directory and only the destination may be remote. A remote source such as
`client user@host:src ./local` (a "pull") is intentionally not supported; see
[RSYNC_COMPAT.md](RSYNC_COMPAT.md#direction).

### TCP transfer

Start the FastSync server:

```bash
./build/server --destination-root /path/to -p 8080 --allow-unauthenticated
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

Server TLS requires `--cert`, `--key`, `--ca`, and `--client-cn`; the client
requires `--cert`, `--key`, and `--ca`.

```bash
./build/server --destination-root /path/to --tls --cert server.pem --key server-key.pem \
  --ca ca.pem --client-cn client -p 8443
./build/client --tls --cert client.pem --key client-key.pem --ca ca.pem \
  --server-host example.com --server-port 8443 \
  --source-dir /path/to/source --dest-dir /path/to/destination \
  --save-to-disk
```

## Common Workflows

These examples show the intended rsync-style workflow. Options marked as
FastSync-native are optional performance or transport extensions.

```bash
# Basic synchronization
./build/client /source/ /destination/

# Archive-style synchronization (current FastSync archive behavior)
./build/client -a /source/ user@host:destination/

# Preview a transfer without changing the destination
./build/client -n /source/ /destination/

# Exclude temporary and object files
./build/client --exclude '*.tmp' --exclude '*.o' \
  /source/ user@host:destination/

# Remove destination entries not present in the source
./build/client --delete /source/ user@host:destination/

# Skip unchanged files using size and modification time
./build/client --incremental /source/ user@host:destination/

# Verify content when size and time are not sufficient
./build/client --incremental --checksum /source/ user@host:destination/

# Preserve supported mode and timestamp metadata
./build/client --preserve /source/ user@host:destination/

# Keep backups of overwritten destination files
./build/client --backup --backup-dir backups \
  /source/ user@host:destination/
```

## FastSync Extensions

FastSync-native options are intended to add performance or operational
features without changing the meaning of ordinary compatibility options.

| Option | Purpose |
|---|---|
| `-j`, `--threads[=N]` | Enable the multithreaded scanner/loader/sender pipeline. `N` (1–256) sets the parallel scanner worker count; bare `-j`/`--threads` uses the default. |
| `-z [level]`, `--compress [level]` | Enable streaming compression (default `zstd`), levels 1-22. |
| `--compress-level <n>` | Set the compression level (1-22). Omitted, each codec uses its rsync default: zstd 3, zlib/zlibx 6, lz4 ignored. |
| `--zc <alg>` | Alias for `--compress-choice`. FastSync supports `zstd` (default), `lz4`, `zlib`, `zlibx`, `none`, and `auto`; `zlib`/`zlibx` share the same literal-only zlib path. |
| `--zl <n>` | Alias for `--compress-level`. |
| `--skip-compress <list>` | Skip compression for `/`- or `,`-separated suffixes; defaults to rsync 3.4.1's built-in list. Incompatible with `--chunk-serialization`. |
| `--compress-threads <n>` | Use `n` zstd compression workers. Requires compression and a zstd build with threaded support; the setting affects sender CPU work only. |
| `--chunk-size <bytes>` | Set the transfer chunk size. |
| `--chunk-serialization` | Enable FastSync chunk serialization (long form only; `-s` is rsync's `--secluded-args`). |
| `--sendfile` | Use TCP `sendfile()` zero-copy transfer. Incompatible with compression and chunk serialization. Long form only. |
| `--delta` | Use FastSync-native block delta transfer. Requires `--incremental`. |
| `--delta-block <bytes>` | Set the FastSync delta block size (`--block-size` is an alias). |
| `--delta-max <bytes>` | Limit files eligible for FastSync delta transfer. |
| `--server-host <host>` | Select the TCP server host. |
| `--server-port <port>` | Select the TCP server port (`--port <port>` and `--port=<port>` are rsync-friendly aliases). |
| `--tls` | Enable TLS for TCP transport. |
| `--bwlimit <KB/s>` | Apply token-bucket bandwidth limiting. |
| `--progress` | Show rsync-style per-file progress blocks from the receiver's wire counters (FastSync omits rsync's leading `./` line). |
| `--stats` | Print transfer statistics, including the receiver-only counters reported over the wire; rsync's per-type `Number of files` breakdown is not reproduced. |
| `--timeout <seconds>` | Set the socket **and** per-message protocol I/O timeout. Default `0` = disabled (matching rsync); `0` disables it. |
| `--contimeout <seconds>` | Connection timeout (default 60, matching rsync); `0` disables it. |

Short-option conflicts with rsync have been resolved for the CLI namespace
(Phase 7): `-c` is now rsync's `--checksum`, `-m` is `--prune-empty-dirs`, `-M`
is `--remote-option`, `-f` is `--filter`, `-s` is `--secluded-args`, `-p` is
`--perms`, and `-T` is `--temp-dir`. FastSync's own flags were renamed to
long-form-only or new shorts: multithreading is `-j`/`--threads`, metadata
is `--preserve`, sendfile is `--sendfile`, chunk serialization is
`--chunk-serialization`, timeout is `--timeout`, and SSH port is `--ssh-port`.
`-a`/`--archive` is now rsync archive `-rlptgoD` (owner/group implied, but the
receiver still needs privilege to apply them).

`--secluded-args` (and its short form `-s`) is accepted as a compatibility
no-op. It does not change FastSync's transport or protocol behavior, because
remote SSH argv is already built injection-safe.

## Client Options

### Selection and transfer

| Option | Description |
|---|---|
| `-a`, `--archive` | rsync archive mode (`-rlptgoD`): links, perms, times, owner, group, devices and specials; ownership application stays privilege-gated. |
| `-n`, `--dry-run` | Report what would be transferred without mutating the destination. Since protocol 2.21.0 a server-routed target contacts the receiver and reports would-transfer based on receiver state; a plain local destination keeps the client-side scan. Never mutates or deletes. |
| `--remove-source-files` | Remove regular source files after a successful transfer. |
| `--incremental` | Skip files matching destination size and mtime. Auto-enables `--preserve`. Incompatible with `--chunk-serialization`. |
| `-c, --checksum` | Verify content by checksum (implies the incremental quick-check). Algorithm selectable with `--checksum-choice`. |
| `--checksum-choice <alg>` | Whole-file checksum algorithm: `xxh64`/`xxhash` (default), `xxh3`, `xxh128`, `md5`, or `auto`. |
| `--checksum-seed <n>` | Seed for the whole-file xxHash digest; an unset/`0` seed is randomized per transfer, matching rsync. |
| `--size-only` | Skip incremental files matching in size, ignoring mtime. |
| `-I, --ignore-times` | Transfer files even when size and mtime match. |
| `-u, --update` | Skip files newer than the source on the receiver. |
| `-W, --whole-file` | Transfer changed files without delta processing (`--no-whole-file` clears it). |
| `-B <n>, --block-size <n>` | Delta block size in bytes (alias `--delta-block`). |
| `-d, --dirs` | Transfer the named directory entries without recursing into their contents (aliases `--old-dirs`/`--old-d`). |
| `-R, --relative` | Use rsync's relative path semantics (including the `/./` cut); with `--files-from`, preserve each listed entry's relative path below the destination root. |
| `--files-from <file>` | Read the source file list from FILE (paths relative to the source root). |
| `--delay-updates` | Put updated files into place only at the end of the transfer. |
| `--compare-dest <dir>` | Extra comparison basis: unchanged files are not transferred (requires/implies `--incremental`). |
| `--copy-dest <dir>` | Like `--compare-dest`, but copies the unchanged file from DIR into the destination. |
| `--link-dest <dir>` | Like `--copy-dest`, but hard-links the unchanged file from DIR (repeatable; earlier DIRs win). |
| `--verify-basis` | FastSync-only: require a basis hit to match the source by whole-file digest instead of trusting the size+mtime quick-check (default matches rsync). |
| `--preallocate` | Allocate destination file space up front (fail-fast on a full disk). |
| `--append` | Resume a shorter destination by appending only its tail (prefix not verified; requires `--incremental`). |
| `--append-verify` | Like `--append`, but verifies the retained prefix checksum first (falls back to a full transfer on mismatch). |
| `--delete` | Request removal of destination entries absent from the source. The server must allow deletion. Default timing is delete-after: extras are removed only after the whole transfer succeeded. Scoped to the synchronized directories, so `--files-from` subsets are safe. |
| `--delete-before` | Delete extras before the transfer starts (implies `--delete`). |
| `--delete-during`, `--del` | Delete extras once the keep-set manifest is known, before data is applied (implies `--delete`; early mode, same engine behaviour as `--delete-before`). |
| `--delete-delay` | Delete extras only after a successful transfer (implies `--delete`; commit mode, same behaviour as `--delete-after`). |
| `--delete-commit` | FastSync-only: atomic delete-after timing (only after the whole transfer succeeded). |
| `--delete-after` | Explicit delete-after timing: delete only after the transfer succeeded (implies `--delete`). |
| `--delete-excluded` | Also delete filter-excluded destination mirrors (size-pruned mirrors stay protected). |
| `--max-delete <n>` | Delete at most n destination entries; the rest are skipped and the run exits 25 (partial), matching rsync. |
| `--force` | Allow an incoming file/symlink to replace a destination directory (also during `--delay-updates` publication). |
| `--exclude <pattern>` | Exclude matching paths. Repeatable. |
| `--include <pattern>` | Include matching paths. Repeatable. |
| `--exclude-from <file>` | Read exclude patterns from a file. |
| `--include-from <file>` | Read include patterns from a file. |
| `-f, --filter=RULE` | Add an rsync-style filter rule (`+`/`-`, `include`/`exclude`, `merge`/`.`, `dir-merge`/`:`, `hide`/`H`, `show`/`S`, `protect`/`P`, `risk`/`R`, `clear`/`!`, and modifiers; repeatable). |
| `--max-size <bytes>` | Skip files larger than the limit. |
| `--min-size <bytes>` | Skip files smaller than the limit. |
| `--max-alloc <SIZE>` | Maximum single allocation (binary units; default 1G; `0` = no local limit). |
| `--max-depth <n>` | Limit recursive scanning depth; zero means unlimited. |
| `-b, --backup` | Back up overwritten files. |
| `-T, --temp-dir <dir>` | Scratch directory for temp files before the atomic install (confined to the receive root; `EXDEV` falls back to a non-atomic copy). |
| `--backup-dir <dir>` | Store backups under a separate directory (requires `--backup`). |
| `--suffix <suffix>` | Set the backup filename suffix (default: `~`). |
| `--partial` | Select partial-transfer handling. On failed/interrupted writes the already-written temp file is retained (best-effort) for resumption. With `--partial --partial-dir <dir>`, completed files are written under the partial directory and installed atomically. |
| `--partial-dir <dir>` | Set a relative partial-transfer directory below the server destination root. Use with `--partial`. |
| `--inplace` | Write directly to the destination instead of using a temporary file. |
| `--fsync` | Fsync every written file before publication. |
| `--write-batch=FILE` | Run the normal live transfer and also emit a self-contained batch file of the source tree. |
| `--only-write-batch=FILE` | Emit the batch file only (no destination, no server). |
| `--read-batch=FILE` | Apply a batch file to the destination (no source, no server). |
| `--stop-after=MINS` | Stop the transfer after MINS minutes; whatever was already transferred is kept. |
| `--stop-at=TIME` | Stop at an absolute time (`HH:MM`, `HH:MM:SS`, or `now+N[smhd]`). An early stop skips the late `--delete` keep-set. |

### Metadata and links

| Option | Description |
|---|---|
| `--preserve` | Preserve mode and mtime (long form only; equivalent to `-p` + `-t`). Add `-o`/`-g` for owner/group, `-U`/`--atimes` for atime, or an identity flag (`--chown`/`--usermap`/`--groupmap`/`--numeric-ids`/`--copy-as`) for mapped ownership. |
| `-U`, `--atimes` | Preserve access times. Captured with the metadata payload; does not enable ownership. |
| `-N`, `--crtimes` | Capture birth time and transmit it; it cannot be applied because no portable filesystem call can set a birth time (documented divergence). |
| `-p`, `--perms` | Preserve permission bits. One of the four per-attribute preserve flags (with `-t`/`-o`/`-g`); under `-p` the source mode is copied exactly (setuid/setgid/sticky and group/other-write included), matching rsync. |
| `-t`, `--times` | Preserve modification times. Independent of the other attributes; `-O`/`--omit-dir-times` suppresses directories only. |
| `-o`, `--owner` | Preserve the source owner (uid). Mapped by name on the receiver with a raw-numeric fallback (only numeric ids cross the wire); application is privilege-gated. |
| `-g`, `--group` | Preserve the source group (gid). Same name-mapping/numeric-fallback and privilege gating as `-o`. |
| `--no-perms`, `--no-times`, `--no-owner`, `--no-group` | Negate each per-attribute flag (also `--no-p`/`--no-t`/`--no-o`/`--no-g`); `--no-preserve` clears all four. |
| `-E`, `--executability` | Preserve executable permission bits. |
| `-X`, `--xattrs` | Preserve user `user.*` extended attributes. |
| `-A`, `--acls` | Preserve POSIX ACLs. |
| `--chmod <changes>` | Modify transferred permissions (rsync syntax, including `D`/`F`/`X` selectors and `s`/`t`); does not imply `-p`. |
| `--chown=USER:GROUP` | Override the ownership of transferred files (`USER:GROUP`, `USER`, or `:GROUP`); conflicts with `--usermap`/`--groupmap` on the same side. |
| `--usermap=MAP` | Map usernames when applying ownership (`FROM:TO` rules; names, ids, `LOW-HIGH` ranges, `*`, empty-`FROM`). |
| `--groupmap=MAP` | Map group names when applying ownership (same syntax as `--usermap`). |
| `--numeric-ids` | Mapping modifier: apply the source numeric uid/gid directly instead of mapping by name (combine with `-o`/`-g`, `-a`, or a map). |
| `--copy-as=USER[:GROUP]` | Force every written entry to USER[:GROUP]; requires a privileged receiver. |
| `--fake-super` | Record the resolved owner plus mode/time in a reserved `user.fastsync.stat` xattr and replay mode/time; never performs a real chown. |
| `--super` | Permit the receiver to attempt confined super-user activities (device nodes). |
| `--no-super` | Forbid those super-user activities even when the receiver is root. |
| `-l`, `--links` | Copy symlinks as symlinks; the target is stored verbatim (absolute and `..`-bearing targets included), matching rsync. |
| `-L`, `--copy-links` | Copy symlink referents (a broken referent makes the run exit 23, matching rsync). |
| `--safe-links` | Skip symlinks whose target points outside the transfer tree (applied on the sender). |
| `--copy-unsafe-links` | Copy unsafe symlink referents. |
| `--munge-links` | Rewrite stored symlink targets with rsync's `/rsyncd-munged/` marker. |
| `-k`, `--copy-dirlinks` | Treat a symlink to a directory as a real directory on the sender. |
| `-K`, `--keep-dirlinks` | Follow an existing destination symlink-to-directory (confined to the receive root). |
| `-H`, `--hard-links` | Preserve hard-link relationships across the transfer. |
| `-D` | Preserve device and special files (implies `--devices --specials`). |
| `--devices` | Recreate device nodes on the destination (privileged; skipped without `CAP_MKNOD`). |
| `--specials` | Recreate special files: FIFOs and unix sockets. |
| `-S`, `--sparse` | Sparse-file handling: receiver preserves holes (zero runs are written as holes; no wire change). |

### Output and logging

| Option | Description |
|---|---|
| `-v`, `--verbose` | Enable debug logging. |
| `-q`, `--quiet` | Suppress non-error output. |
| `--progress` | Show rsync-style per-file progress blocks (not rsync's leading `./` line). |
| `--stats` | Print transfer statistics, including the receiver-only counters reported over the wire. |
| `-i`, `--itemize-changes` | Print an rsync-style per-file change line. |
| `--out-format=FORMAT` | Output format for changed files (`%f %n %l %b %M %%`). |
| `--list-only` | List source files instead of transferring. |
| `--log-file <path>` | Write log output to a file. |
| `-V`, `--version` | Print the FastSync protocol version. |
| `--help` | Print command usage. |

### Paths and transport

| Option | Description |
|---|---|
| `--ssh-port <port>` | SSH port for the SSH transport (default: 22). Note the short `-p` is now rsync's `--perms`. |
| `-e`, `--rsh <command>` | Remote shell to launch for the SSH transport (default: `ssh`; may include arguments). |
| `--fastsync-server-path <path>` | Remote FastSync server path for SSH mode (client-only; never crosses the wire). |
| `--rsync-path <path>` | Alias for `--fastsync-server-path`. |
| `-M`, `--remote-option=OPT` | Append OPT to the remote server invocation over SSH (repeatable; rejected for daemon/TCP destinations). |
| `--trust-sender` | Receiver-local: trust the remote sender's file list and skip path re-validation (does not affect symlink targets). |
| `--timeout <sec>` | Socket + per-message I/O timeout; default `0` = disabled. |
| `--contimeout <sec>` | Connection timeout; default 60; `0` disables. |
| `--source-dir <path>` | Set the source directory explicitly. |
| `--dest-dir <path>` | Set the destination directory explicitly. |
| `--save-to-disk` | Enable server-side disk persistence. |
| `--server-host <host>` | TCP server address. |
| `--server-port <port>` | TCP server port. `--port <port>` / `--port=<port>` is an alias. |
| `--address <ip>` | Bind the outgoing client socket to this source address. |
| `-4`, `--ipv4` | Force IPv4 for destination resolution. |
| `-6`, `--ipv6` | Force IPv6 for destination resolution. |
| `--sockopts=OPTS` | Comma-separated OPT=VAL socket options applied before connect. |
| `--tls` | Enable TLS. Requires `--cert`, `--key`, and `--ca`. |
| `--cert <path>` | TLS certificate file. |
| `--key <path>` | TLS private key file. |
| `--ca <path>` | CA file for peer verification (always required with `--tls`). |

## Server Options

| Option | Description |
|---|---|
| `--stdio` | Serve one SSH connection over standard input/output. |
| `--daemon` | Run as a persistent daemon listener using a module config file; the daemon default port is 873 (unlike `-p`, which defaults to 8080). |
| `--config=FILE` | Daemon config file (default: `~/.config/fastsync/fastsyncd.conf`, else `/etc/fastsyncd.conf`). Requires `--daemon`. |
| `--dparam=KEY=VALUE` | Override one global config key on the command line. Requires `--daemon`. |
| `--no-detach` | Stay in the foreground (default detaches to the background when running `--daemon`). |
| `-p, --port <port>` | TCP listen port (default: 8080, range: 1–65535). |
| `--tls` | Enable TLS. |
| `--cert <path>` | TLS certificate file (PEM). |
| `--key <path>` | TLS private key file (PEM). |
| `--ca <path>` | CA file for peer verification (PEM). |
| `--client-cn <name>` | TLS client certificate CN; mandatory with `--tls` (the server verifies the client CN). |
| `--destination-root <path>` | Confine received files to this server-side root; defaults to the current directory. |
| `--address <addr>` | Bind the listening socket to this address. |
| `-4`, `--ipv4` | Bind an IPv4 socket (default). |
| `-6`, `--ipv6` | Bind an IPv6 socket. |
| `--allow-delete` | Permit client delete manifests. Deletion is refused by default. This also gates `--force` (which can recursively replace/remove a destination directory tree). |
| `--allow-super` | Standalone TCP listener only: keep super-user activities enabled for a **root** receiver. Without it a root standalone server forces `SUPER_MODE_OFF`, so client `--devices`/`--write-devices`/`--super` and client-chosen ownership requests are skipped/refused. Rejected with `--stdio` (the SSH remote argv is client-composed; use a forced command if the default must hold). No effect when not root. Daemon modules opt in per module with `client owner = yes`. |
| `--trust-sender` | Trust the remote sender's file list: skip the receiver's up-front path-traversal re-validation (fewer checks, faster, potentially unsafe; off by default). It does not affect symlink targets, which are stored verbatim either way. |
| `--no-super` | Operator veto: never attempt super-user activities (ownership, device nodes) even as root, and refuse any client `--copy-as`/`--super` request. |
| `--allow-unauthenticated` | Permit plaintext/anonymous network clients; an auth-required module still accepts only opted-in loopback plaintext. |
| `--iconv=LOCAL[,REMOTE]` | Declare this server's LOCAL charset for file-name conversion. |
| `--password-file=FILE` | Credential store for modules that declare `auth users`. Requires `--daemon`. |
| `--early-input=FILE` | Second credential store layered over `--password-file`. Requires `--daemon`. |
| `--hash-credentials <file>` | Read `<file>`'s `user:password` lines and print PBKDF2 credential-store lines to stdout, then exit. Cannot be combined with `--daemon` or `--stdio`. |
| `--iterations N` | PBKDF2 iteration count for `--hash-credentials` (default 600000, range 100000–10000000). Requires `--hash-credentials`. |
| `-v`, `--verbose` | Enable debug logging. |
| `--help` | Print server usage. |

### Daemon configuration

`fastsync-server --daemon --config FILE` reads a line-based module config (an
implicit global section, then `[module]` sections). Besides `port`, `motd file`,
and `address`, the global section accepts:

- `max connections = N` — global cap on concurrent connections, default 100. The
  listener enforces it; `0`, negative, and non-numeric values are parse errors.
- `max connections per host = N` — cap on concurrent connections from a single
  source IP, default 0 (unlimited). Enforced across all forked connection
  children through a shared registry.
- `auth failure delay = MS` — milliseconds to sleep after a failed
  authentication, default 500. `0` disables it and the value is capped at 5000,
  so online password guessing is rate-limited per connection. Successful auths
  are never delayed.
- `auth lockout threshold = N` — number of failed authentications from one source
  IP before that source is locked out, default 10; `0` disables the lockout. The
  failure counter is shared across every connection child, so the lockout holds
  even when the next attempt is handled by a different forked child.
- `auth lockout duration = SECONDS` — how long a locked-out source is refused
  (default 300). A locked-out client is refused before any SCRAM challenge is
  sent; a successful authentication clears the counter.
- `hosts allow` / `hosts deny` — comma- and/or whitespace-separated host access
  patterns.

A `[module]` requires `path`, and may also set `read only`, `client owner`,
`auth users`, `max connections` (0 = unlimited; enforced per module across all
connection children), and its own `hosts allow`/`hosts deny`.

The per-host cap and the shared auth lockout identify a source by its numeric
peer IP. **Loopback peers (127.0.0.0/8, IPv6 `::1`) are exempt**: every local
client shares that one address, so counting or locking them out would let one
local process deny service to all the others. The per-module and global
`max connections` caps still apply to loopback. Because the key is the peer IP,
`max connections per host` and `auth lockout` also cannot distinguish clients
behind the same NAT, proxy, or reverse-proxy address — they share one budget and
one lockout counter, so an over-aggressive lockout can affect unrelated users
behind that address. Prefer TLS client certificates (`--client-cn`) plus
`hosts allow`/`hosts deny` for per-client policy when clients share an address,
and size `auth lockout threshold` accordingly.

The shared per-source table has a bounded lifetime: an entry with no live
connection is reclaimed once its lockout has expired, or after it has been idle
(300 s). If every entry is still live or locked, a new source is admitted without
per-host accounting (fail open) and a rate-limited warning is logged; the
per-module cap and host ACLs still apply. The occupancy counters are re-derived
from the shared slot table after every child exit, so a child killed mid-transfer
(or mid-registration) cannot leak a slot or an occupancy count.

Host patterns are `*` (match all), IPv4/IPv6 literals, or IPv4/IPv6 CIDR
(`10.0.0.0/8`, `2001:db8::/32`). Hostnames are not resolved, so hostname globs
are rejected at parse time rather than silently never matching. A matching
`hosts deny` rejects; if any `hosts allow` entries exist, a peer matching none of
them is rejected; deny takes precedence over allow. The global list is checked
before the module list, before authentication, and the connecting peer address
(IPv4 or IPv6) appears in the connection and authentication audit log lines.

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

FastSync protocol version `2.27.0` is shared by the client and server. The
current protocol is sender-driven and includes configuration negotiation,
including the maximum allocation limit, incremental checks, checksums,
manifests, keep-alives, abort handling, per-file remove-source results, and
FastSync-native delta messages.
Client and server versions must currently match exactly.

Daemon modules that declare `auth users` authenticate with a SCRAM-SHA-256-style
challenge/response against a salted PBKDF2 verifier store: no password and no
replayable bearer credential crosses the wire or is stored on the daemon. All
store entries share one iteration count, and an unknown user is answered with a
deterministic per-username dummy challenge, so probing the daemon cannot
enumerate users. Store lines are generated with
`fastsync-server --hash-credentials <plaintext-file>` (see `RSYNC_COMPAT.md`);
redirect that output to an owner-only (mode 0600) file, and note that legacy
`user:SHA256HEX` stores are rejected. FastSync also maintains an owner-only
(mode 0600) `<store>.dummykey` sidecar next to the store: it holds the store-wide
dummy key, is auto-created on first load, and must be preserved across daemon
restarts so the dummy challenge for an unknown user stays stable (the key is
never regenerated while the sidecar exists). The sidecar is secret material and
must be protected like the credential store: keep it owner-only (mode 0600) and
include it with the store in backups and credential rotation. If the sidecar
cannot be created (a process-substitution/FIFO store path such as `/dev/fd/N`, a
read-only filesystem, a missing directory, or a create, write, fsync, link, or
fchmod failure), the daemon logs a warning and uses a transient key, so the
cross-restart guarantee does not hold for those deployments. One residual is
accepted: the store
iteration count is observable pre-auth by design, since the miss path must match
a hit.

An `auth users` module accepts credentials only when one of two conditions
holds: (a) the connection is an encrypted, verified TLS connection whose client
certificate matches the server's `--client-cn`, or (b) the connection is
plaintext from a loopback peer **and** the operator explicitly passed
`--allow-unauthenticated`. A remote plaintext peer is refused before any
challenge is sent, and `--allow-unauthenticated` never permits remote plaintext
auth: remote peers still require verified TLS regardless of the flag. Clients
sending daemon credentials with `--password-file` to a non-loopback daemon must
therefore use `--tls`; the client rejects a non-local plaintext credential
destination before any network I/O. Daemon modules are a `--daemon`-only
feature: the SSH `--stdio` path never loads a daemon config and is not an auth
transport for them.

Because the loopback allowance trusts whichever peer the kernel reports as
`127.0.0.1`, it assumes nothing relays remote connections to the daemon. A local
TCP forwarder or a TLS-terminating proxy in front of an auth-module listener
makes remote clients appear as loopback and bypasses the mutual-TLS identity
check, so do not front an auth-module listener with such a relay. `--tls` always
mandates `--client-cn`, so a TLS connection to an auth-required module always
has its client CN verified (`--client-cn` matches the certificate's CN only, not
a subjectAltName, which is acceptable for a private CA).

TLS provides encrypted TCP transport. Both the client and the server require
`--ca` together with `--tls`, so peer certificates are always verified
(`SSL_VERIFY_PEER`, depth 4). The default TCP transport is not encrypted.

The receiver protects its destination root with path validation, `openat()`
directory traversal, `O_NOFOLLOW`, temporary files, and atomic renames. Delete
operations require the server's explicit `--allow-delete` policy.

## Compatibility Roadmap

The project will reach the drop-in replacement goal in stages:

1. Correct rsync option meanings, including short options, combined options,
   and `--option=value` syntax — **done** in the rsync-parity wave: `-r`/`-b`/
   `-L`/`-B`, short-option clustering (`-av`, `-aAX`, `-rlpt`), and attached
   values (`-B1000`, `-essh`, `-MOPT`) all parse.
2. Add differential tests that compare FastSync and rsync contents, metadata,
   links, deletes, filters, dry runs, and exit codes — **done** for the
   completion wave's scope; the tests live in `tests/integration/` and skip
   cleanly when rsync is unavailable.
3. `-a` implements full rsync `-rlptgoD`; under `-p` the source mode is copied
   exactly (no masking). Ownership application stays privilege-gated, as in
   rsync.
4. Symlink (verbatim storage), sparse-file, metadata, delete-policy (including
   `--max-delete` partial + exit 25, per-directory `--delete-during`/
   `--delete-delay`), codecs, and resumable-write semantics are implemented;
   remaining work is the documented edge cases, which the **Parity Completion
   Wave** section of `RSYNC_COMPAT.md` enumerates honestly.
5. Add rsync remote-shell and daemon protocol interoperability.
6. Keep FastSync performance options as negotiated, optional extensions.

The exhaustive implementation matrix and compatibility notes are in
[`RSYNC_COMPAT.md`](RSYNC_COMPAT.md); each row is classified as parity, caveat,
or divergent.

## Testing

Run the unit test binary:

```bash
./build/tests
```

Run the Python integration suite:

```bash
python3 -m pytest tests/integration/ -n 4 --dist=load -m "not setpriv"
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

- Use `-j`/`--threads` for workloads with many files or enough CPU parallelism
  (`-m` is `--prune-empty-dirs`).
- Use `-z` when network bandwidth is more constrained than CPU (`-c` is
  `--checksum`, not a bandwidth option).
- Tune `--chunk-size` for file sizes, memory limits, and network latency.
- Use `--sendfile` for large uncompressed TCP transfers where zero-copy I/O
  helps (`-f` is `--filter`).
- Use `--incremental` to avoid retransmitting unchanged files.
- Use `--delta` for changed files when both endpoints are FastSync peers.
- Use `--bwlimit` when sharing a link with other traffic.

Always validate the compatibility behavior required by a deployment before
replacing an existing rsync job.
