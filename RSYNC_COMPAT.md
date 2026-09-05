# Rsync Feature Compatibility

This document maps rsync's full feature set to FastSync's current implementation status.

## Summary

| Status | Count | Description |
|--------|-------|-------------|
| ✅ Implemented | 35 | Feature works end-to-end |
| 🔀 Alt Arg | 4 | Functionality exists but under different flag/semantics |
| ⚠️ Partial | 5 | Flag parsed/stored but behavior incomplete |
| 🔄 Compatibility No-op | 1 | Flag is accepted for CLI compatibility but has no effect |
| ❌ Not Implemented | 95 | Flag not recognized or no behavior |
| **Total** | **141** | |

---

## 1. General Options

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-a`, `--archive` | Archive mode is -rlptgoD | 🔀 Alt Arg | Maps to -c -m -M (compression + multithread + metadata) |
| `-v`, `--verbose` | Increase verbosity | ✅ Implemented | Sets `log_level=DEBUG` |
| `-q`, `--quiet` | Suppress non-error messages | ✅ Implemented | Suppresses client output while preserving errors |
| `--help` | Show help | ✅ Implemented | Prints usage and exits; `-h` is not accepted |
| `-V`, `--version` | Print version | ✅ Implemented | |
| `--info=FLAGS` | Fine-grained info verbosity | ✅ Implemented | Supports `copy`, `misc`, `skip`, `stats`, `all`, and `none`; explicit flags override `--verbose`, and `none` suppresses info output; unsupported names are rejected |
| `--debug=FLAGS` | Fine-grained debug verbosity | ✅ Implemented | `io`, `proto`, `pack`, and `util` are supported; `--debug=help` lists flags; other rsync categories are rejected |
| `--stderr=MODE` | Change stderr output mode | ⚠️ Partial | `errors` (default) and `all` are supported; `client` is rejected because FastSync has no rsync message channel |
| `--no-motd` | Suppress daemon MOTD | ❌ Not Implemented | |
| `--exclude=PATTERN` | Exclude files matching pattern | ✅ Implemented | Glob matching in scanner |
| `--include=PATTERN` | Include files matching pattern | ✅ Implemented | Glob matching in scanner |
| `-C`, `--cvs-exclude` | Auto-ignore CVS files | ❌ Not Implemented | Removed because it had no effect |

## 2. Modifying Output

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--stats` | Give transfer stats | ✅ Implemented | Prints file/byte counts |
| `-h`, `--human-readable` | Human-readable numbers | ✅ Implemented | Formats transfer byte sizes using binary units |
| `-i`, `--itemize-changes` | Per-file change summary | ❌ Not Implemented | Removed because it had no effect |
| `--progress` | Show progress | ✅ Implemented | Progress callback in sender |
| `-P` | Same as --partial --progress | ⚠️ Partial | Parses and enables progress, but interrupted files are not retained for resumable transfers |
| `--out-format=FORMAT` | Custom output format | ❌ Not Implemented | Removed because it had no effect |
| `--log-file=FILE` | Log to file | ✅ Implemented | `log_file` config field |
| `--log-file-format=FMT` | Log format | ❌ Not Implemented | |
| `--8-bit-output`, `-8` | Leave high-bit chars unescaped | ✅ Implemented | Applies to displayed paths and protocol debug output |
| `--list-only` | List files instead of copying | ❌ Not Implemented | Removed because it had no effect |

## 3. File Selection

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--exclude-from=FILE` | Read exclude patterns from file | ✅ Implemented | Reads patterns from file |
| `--include-from=FILE` | Read include patterns from file | ✅ Implemented | Reads patterns from file |
| `--filter=RULE` | Add file-filtering rule | ❌ Not Implemented | Removed because it had no effect |
| `--files-from=FILE` | Read source file list from file | ❌ Not Implemented | Removed because it had no effect |
| `-0`, `--from0` | Delimit *-from files with NULs | ❌ Not Implemented | |
| `--max-size=SIZE` | Skip files larger than SIZE | ✅ Implemented | `max_size` in scanner |
| `--min-size=SIZE` | Skip files smaller than SIZE | ✅ Implemented | `min_size` in scanner |
| `-I`, `--ignore-times` | Don't skip files matching size+time | ❌ Not Implemented | |
| `--size-only` | Skip based on size only | ✅ Implemented | With `--incremental`, ignores mtime |
| `-@`, `--modify-window=NUM` | Mod-time comparison accuracy | ✅ Implemented | Whole-second tolerance with nanosecond-aware comparisons |
| `--existing` | Skip creating new files on receiver | ✅ Implemented | Existing destination files continue through normal update handling |
| `--ignore-existing` | Skip updating existing files | ❌ Not Implemented | |
| `--remove-source-files` | Sender removes regular files after confirmed transfer | ✅ Implemented | |

## 4. Directory Options

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-r`, `--recursive` | Recurse into directories | ✅ Implemented | Default behavior |
| `-R`, `--relative` | Use relative path names | ❌ Not Implemented | Removed because it had no effect |
| `--no-implied-dirs` | Don't send implied dirs with -R | ❌ Not Implemented | |
| `-d`, `--dirs`, `--old-dirs`, `--old-d` | Transfer dirs without recursing | ❌ Not Implemented | The aliases are recognized and rejected explicitly; they depend on the unimplemented `--dirs` behavior |
| `--mkpath` | Create missing path components | ❌ Not Implemented | |

## 5. Transfer Modifications

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-u`, `--update` | Skip files newer on receiver | ❌ Not Implemented | Removed because it had no effect |
| `--inplace` | Update files in-place | ✅ Implemented | Direct write mode |
| `--append` | Append data to shorter files | ❌ Not Implemented | Removed because it had no effect |
| `--append-verify` | Append with old-data checksum | ❌ Not Implemented | Removed because it had no effect |
| `-W`, `--whole-file` | Copy whole file (no delta) | ❌ Not Implemented | |
| `--block-size=SIZE` | Force checksum block-size | ⚠️ Partial | Parsed as `--delta-block`; controls delta transfer block size |

## 6. Destination Handling

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-n`, `--dry-run` | Trial run with no changes | ✅ Implemented | `dry_run` config field |
| `-b`, `--backup` | Make backups of overwritten files | ✅ Implemented | Backup before overwrite |
| `--backup-dir=DIR` | Backup directory hierarchy | ✅ Implemented | `backup_dir` config field |
| `--suffix=SUFFIX` | Backup suffix (default ~) | ✅ Implemented | `suffix` config field |
| `--delay-updates` | Put updated files in place at end | ❌ Not Implemented | |

## 7. Deletion

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--delete` | Delete extraneous files from dest | ✅ Implemented | `use_delete` config field |
| `--delete-before` | Delete before transfer | ❌ Not Implemented | Removed because it had no effect |
| `--delete-during` | Delete during transfer | ❌ Not Implemented | |
| `--delete-delay` | Find deletions during, delete after | ❌ Not Implemented | |
| `--delete-after` | Delete after transfer | ❌ Not Implemented | Removed because it had no effect |
| `--delete-excluded` | Also delete excluded files | ❌ Not Implemented | Removed because it had no effect |
| `--max-delete=NUM` | Max files to delete | ❌ Not Implemented | Removed because it had no effect |
| `--ignore-errors` | Delete even with I/O errors | ❌ Not Implemented | |
| `--force` | Force deletion of non-empty dirs | ❌ Not Implemented | |
| `--prune-empty-dirs` | Prune empty dir chains | ❌ Not Implemented | Removed because it had no effect |

## 8. Metadata Preservation

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-M`, `--preserve` | Preserve file metadata | ✅ Implemented | Mode, uid, gid, mtime |
| `-p`, `--perms` | Preserve permissions | 🔀 Alt Arg | `-p` means SSH port; permissions preserved via `-M`/`--preserve` |
| `-o`, `--owner` | Preserve owner | ✅ Implemented | Part of -M |
| `-g`, `--group` | Preserve group | ✅ Implemented | Part of -M |
| `-t`, `--times` | Preserve modification times | ✅ Implemented | Part of -M |
| `-E`, `--executability` | Preserve executability | ✅ Implemented | Preserves executable permission bits (implies metadata preservation) |
| `--chmod=CHMOD` | Affect file permissions | ✅ Implemented | Supports numeric and symbolic `ugo` `rwx` changes; retains receiver safety masking |
| `-A`, `--acls` | Preserve ACLs | ❌ Not Implemented | Removed because it had no effect |
| `-X`, `--xattrs` | Preserve extended attributes | ❌ Not Implemented | Removed because it had no effect |
| `-H`, `--hard-links` | Preserve hard links | ❌ Not Implemented | Removed because it had no effect |
| `-D` | Same as --devices --specials | ❌ Not Implemented | Removed because device-file handling is not implemented |
| `--devices` | Preserve device files | ❌ Not Implemented | Removed because it had no effect |
| `--specials` | Preserve special files | ❌ Not Implemented | |
| `--copy-devices` | Copy device contents as file | ❌ Not Implemented | |
| `--write-devices` | Write to devices as files | ❌ Not Implemented | |
| `-U`, `--atimes` | Preserve access times | ❌ Not Implemented | |
| `-N`, `--crtimes` | Preserve create times | ❌ Not Implemented | |
| `-O`, `--omit-dir-times` | Omit dirs from --times | ❌ Not Implemented | |
| `-J`, `--omit-link-times` | Omit symlinks from --times | ❌ Not Implemented | |
| `--super` | Receiver attempts super-user activities | ❌ Not Implemented | |
| `--fake-super` | Store/recover privileged attrs via xattrs | ❌ Not Implemented | |

## 9. Symlink Handling

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-l`, `--links` | Copy symlinks as symlinks | ⚠️ Partial | Scanner includes symlinks; target path not transmitted |
| `-L`, `--copy-links` | Transform symlink to referent | ✅ Implemented | `copy_links` config field |
| `--copy-unsafe-links` | Transform unsafe symlinks | ✅ Implemented | `copy_unsafe_links` config field |
| `--safe-links` | Ignore symlinks outside tree | ✅ Implemented | `safe_links` config field |
| `--munge-links` | Munge symlinks for safety | ❌ Not Implemented | |
| `-k`, `--copy-dirlinks` | Transform symlink to dir | ❌ Not Implemented | |
| `-K`, `--keep-dirlinks` | Treat symlinked dir as dir | ❌ Not Implemented | |

## 10. Sparse & Device

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-S`, `--sparse` | Sparse block handling | ⚠️ Partial | Flag is accepted, but full hole preservation is not implemented |
| `--preallocate` | Allocate dest files before writing | ❌ Not Implemented | |

## 11. Checksum & Comparison

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--checksum` | Skip based on checksum | ✅ Implemented | With `--incremental`, compares xxHash64 content checksums; `-c` remains compression |
| `--checksum-choice=STR` | Choose checksum algorithm | ❌ Not Implemented | xxHash used internally |
| `--compare-dest=DIR` | Compare dest files relative to DIR | ❌ Not Implemented | Removed because it had no effect |
| `--copy-dest=DIR` | Include copies of unchanged files | ❌ Not Implemented | Removed because it had no effect |
| `--link-dest=DIR` | Hardlink to files when unchanged | ❌ Not Implemented | Removed because it had no effect |
| `--fuzzy`, `--no-fuzzy` | Find similar file for basis | ❌ Not Implemented | |

## 12. Compression

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-z`, `--compress` | Compress file data | 🔀 Alt Arg | Always uses zstd (rsync supports multiple algorithms) |
| `--compress-choice=STR`, `--zc=STR` | Choose compression algorithm | ✅ Implemented | FastSync supports `zstd` and `none` |
| `--compress-level=NUM`, `--zl=NUM` | Set compression level | ✅ Implemented | 1-22, default 5 |
| `--compress-threads=NUM` | Set compression threads | ❌ Not Implemented | |
| `--skip-compress=LIST` | Skip compress for suffixes | ✅ Implemented | Comma-separated, case-insensitive suffix list; empty list skips none; incompatible with FastSync chunk serialization (`-s`) |

## 13. Connectivity

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-e`, `--rsh=COMMAND` | Remote shell to use | ❌ Not Implemented | Removed; SSH invokes `ssh` directly |
| `--rsync-path=PROGRAM` | rsync binary on remote | ❌ Not Implemented | Removed; use `--fastsync-server-path` |
| `--port=PORT` | Alternate daemon port | ✅ Implemented | `server_port` config field |
| `--sockopts=OPTIONS` | Custom TCP options | ❌ Not Implemented | |
| `--blocking-io` | Use blocking I/O for remote shell | ❌ Not Implemented | |
| `--outbuf=N\|L\|B` | Set output buffering | ❌ Not Implemented | |
| `--address=ADDRESS` | Bind address for outgoing socket | ❌ Not Implemented | Removed because it had no effect |
| `-4`, `--ipv4` | Prefer IPv4 | ❌ Not Implemented | Removed because it had no effect |
| `-6`, `--ipv6` | Prefer IPv6 | ❌ Not Implemented | Removed because it had no effect |

## 14. Daemon Mode

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--daemon` | Run as rsync daemon | ❌ Not Implemented | Removed because it had no effect |
| `--config=FILE` | Alternate rsyncd.conf file | ❌ Not Implemented | Removed because it had no effect |
| `--dparam=OVERRIDE` | Override global daemon config | ❌ Not Implemented | |
| `--no-detach` | Don't detach from parent | ❌ Not Implemented | |
| `--password-file=FILE` | Read daemon password from file | ❌ Not Implemented | |
| `--early-input=FILE` | Use FILE for daemon early exec | ❌ Not Implemented | |

## 15. Safety & Security

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| Path escape detection | Ensure files stay within root | ✅ Implemented | `has_path_traversal()` + realpath |
| Symlink-safe delete | Skip symlinks in delete walk | ✅ Implemented | `delete_extras_walk()` |
| Protocol version check | Verify compatible versions | ✅ Implemented | `config_receive()` |
| Max data/string/chunk sizes | Prevent OOM attacks | ✅ Implemented | Per-message limits |
| Per-connection memory limit | 1GB per connection | ✅ Implemented | `MAX_CONNECTION_MEMORY` |
| `--trust-sender` | Trust remote sender's file list | ❌ Not Implemented | |
| `--old-args` | Disable modern arg protection | ✅ Implemented | SSH-only legacy mode; restores raw remote command construction and permits shell interpretation of the configured server path |
| `--ignore-missing-args` | Ignore missing source args | ❌ Not Implemented | |
| `--delete-missing-args` | Delete missing source args | ❌ Not Implemented | |

## 16. Batch Operations

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--write-batch=FILE` | Write batched update to file | ❌ Not Implemented | |
| `--only-write-batch=FILE` | Write batch without updating dest | ❌ Not Implemented | |
| `--read-batch=FILE` | Read batched update from file | ❌ Not Implemented | |

## 17. Advanced

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--stop-after=MINS` | Stop after N minutes | ❌ Not Implemented | |
| `--stop-at=TIME` | Stop at specified time | ❌ Not Implemented | |
| `--fsync` | Fsync every written file before publication | ✅ Implemented | |
| `--protocol=NUM` | Force older protocol version | ❌ Not Implemented | |
| `--iconv=CONVERT_SPEC` | Charset conversion | ❌ Not Implemented | |
| `--checksum-seed=NUM` | Set checksum seed | ❌ Not Implemented | |
| `--secluded-args` | Use protocol to send args | 🔄 Compatibility No-op | Accepted for CLI compatibility; it does not change FastSync transport or protocol behavior. `-s` remains chunk serialization. |
| `--no-OPTION` | Turn off implied option | ✅ Supported | Supported boolean FastSync options and archive-implied options; unsafe or value-taking options are rejected. |

---

## Recommendations: Top Features to Implement Next

Ranked by user demand, implementation complexity, and interoperability impact:

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| 1 | `--whole-file` / `-W` | Low | High — users expect opt-out of delta |
| 2 | `--ignore-times` / `-I` | Low | Medium — useful for forcing re-transfer |
| 3 | `--size-only` | Low | Medium — common migration scenario |
| 4 | `--ignore-existing` | Low | Medium — common sync patterns |
| 5 | `--existing` | Low | Medium — common sync patterns |
| 6 | `--remove-source-files` | Low | High — common for moves/backup |
| 7 | `--delete-during` | Medium | High — performance improvement |
| 8 | `--delay-updates` | Medium | High — atomic updates |
| 9 | `--chmod` | Low | Medium — permission flexibility |
| 10 | `--executability` / `-E` | Low | Low — simple flag |
| 11 | `--skip-compress` | Low | Medium — performance tuning |

---

## FastSync-Specific Features (Not in rsync)

| Feature | Description |
|---------|-------------|
| `-m` | Multithreaded pipeline (scanner/loader/sender) |
| `-s` | Chunk serialization mode |
| `-f` / `--sendfile` | Zero-copy sendfile() syscall (TCP only) |
| `-c [level]` | zstd compression level (1-22) |
| `--chunk-size` | Configurable chunk size |
| `--tls` | TLS encryption (mutual auth) |
| `--fastsync-server-path` | Path to fastsync-server binary |
| `--server-host` / `--server-port` | Direct TCP connection |
| Incremental sync | Skip unchanged files (size+mtime) |
| Delta transfer | Block-level delta for changed files |
