# Rsync Feature Compatibility

This document maps rsync's full feature set to FastSync's current implementation status.

## Summary

| Status | Count | Description |
|--------|-------|-------------|
| ✅ Implemented | 44 | Feature works end-to-end |
| ⚠️ Partial | 31 | Flag parsed/stored but behavior incomplete |
| ❌ Not Implemented | 66 | Flag not recognized or no behavior |
| **Total** | **141** | |

---

## 1. General Options

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-v`, `--verbose` | Increase verbosity | ✅ Implemented | Sets `log_level=DEBUG` |
| `-q`, `--quiet` | Suppress non-error messages | ✅ Implemented | `quiet` config field |
| `-h`, `--help` | Show help | ✅ Implemented | Prints usage and exits |
| `-V`, `--version` | Print version | ❌ Not Implemented | |
| `--info=FLAGS` | Fine-grained info verbosity | ⚠️ Partial | `info_level` stored, not wired |
| `--debug=FLAGS` | Fine-grained debug verbosity | ⚠️ Partial | `debug_level` stored, not wired |
| `--stderr=MODE` | Change stderr output mode | ❌ Not Implemented | |
| `--no-motd` | Suppress daemon MOTD | ❌ Not Implemented | |
| `--exclude=PATTERN` | Exclude files matching pattern | ✅ Implemented | Glob matching in scanner |
| `--include=PATTERN` | Include files matching pattern | ✅ Implemented | Glob matching in scanner |
| `-C`, `--cvs-exclude` | Auto-ignore CVS files | ⚠️ Partial | `cvs_exclude` stored, not wired |

## 2. Modifying Output

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--stats` | Give transfer stats | ✅ Implemented | Prints file/byte counts |
| `-h`, `--human-readable` | Human-readable numbers | ⚠️ Partial | `human_readable` stored, not wired |
| `-i`, `--itemize-changes` | Per-file change summary | ⚠️ Partial | `itemize_changes` stored, not wired |
| `--progress` | Show progress | ✅ Implemented | Progress callback in sender |
| `-P` | Same as --partial --progress | ❌ Not Implemented | |
| `--out-format=FORMAT` | Custom output format | ⚠️ Partial | `out_format` stored, not wired |
| `--log-file=FILE` | Log to file | ✅ Implemented | `log_file` config field |
| `--log-file-format=FMT` | Log format | ❌ Not Implemented | |
| `--8-bit-output` | Leave high-bit chars unescaped | ❌ Not Implemented | |
| `--list-only` | List files instead of copying | ⚠️ Partial | `list_only` stored, not wired |

## 3. File Selection

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--exclude-from=FILE` | Read exclude patterns from file | ✅ Implemented | Reads patterns from file |
| `--include-from=FILE` | Read include patterns from file | ✅ Implemented | Reads patterns from file |
| `--filter=RULE` | Add file-filtering rule | ⚠️ Partial | `filters` ArrayList stored, not wired |
| `--files-from=FILE` | Read source file list from file | ⚠️ Partial | `files_from` stored, not wired |
| `-0`, `--from0` | Delimit *-from files with NULs | ❌ Not Implemented | |
| `--max-size=SIZE` | Skip files larger than SIZE | ✅ Implemented | `max_size` in scanner |
| `--min-size=SIZE` | Skip files smaller than SIZE | ✅ Implemented | `min_size` in scanner |
| `-I`, `--ignore-times` | Don't skip files matching size+time | ❌ Not Implemented | |
| `--size-only` | Skip based on size only | ❌ Not Implemented | |
| `-@`, `--modify-window=NUM` | Mod-time comparison accuracy | ❌ Not Implemented | |
| `--existing` | Skip creating new files on receiver | ❌ Not Implemented | |
| `--ignore-existing` | Skip updating existing files | ❌ Not Implemented | |
| `--remove-source-files` | Sender removes synced files | ❌ Not Implemented | |

## 4. Directory Options

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-r`, `--recursive` | Recurse into directories | ✅ Implemented | Default behavior |
| `-R`, `--relative` | Use relative path names | ⚠️ Partial | `relative` stored, not wired |
| `--no-implied-dirs` | Don't send implied dirs with -R | ❌ Not Implemented | |
| `-d`, `--dirs` | Transfer dirs without recursing | ❌ Not Implemented | |
| `--mkpath` | Create missing path components | ❌ Not Implemented | |

## 5. Transfer Modifications

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-u`, `--update` | Skip files newer on receiver | ⚠️ Partial | `update` stored, not wired |
| `--inplace` | Update files in-place | ✅ Implemented | Direct write mode |
| `--append` | Append data to shorter files | ⚠️ Partial | `append` stored, not wired |
| `--append-verify` | Append with old-data checksum | ⚠️ Partial | `append_verify` stored, not wired |
| `-W`, `--whole-file` | Copy whole file (no delta) | ❌ Not Implemented | |
| `--block-size=SIZE` | Force checksum block-size | ⚠️ Partial | `delta_block_size` configurable |

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
| `--delete-before` | Delete before transfer | ⚠️ Partial | `delete_before` stored, not wired |
| `--delete-during` | Delete during transfer | ❌ Not Implemented | |
| `--delete-delay` | Find deletions during, delete after | ❌ Not Implemented | |
| `--delete-after` | Delete after transfer | ⚠️ Partial | `delete_after` stored, not wired |
| `--delete-excluded` | Also delete excluded files | ⚠️ Partial | `delete_excluded` stored, not wired |
| `--max-delete=NUM` | Max files to delete | ⚠️ Partial | `max_delete` stored, not wired |
| `--ignore-errors` | Delete even with I/O errors | ❌ Not Implemented | |
| `--force` | Force deletion of non-empty dirs | ❌ Not Implemented | |
| `--prune-empty-dirs` | Prune empty dir chains | ⚠️ Partial | `prune_empty_dirs` stored, not wired |

## 8. Metadata Preservation

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-M`, `--preserve` | Preserve file metadata | ✅ Implemented | Mode, uid, gid, mtime |
| `-p`, `--perms` | Preserve permissions | ✅ Implemented | Part of -M |
| `-o`, `--owner` | Preserve owner | ✅ Implemented | Part of -M |
| `-g`, `--group` | Preserve group | ✅ Implemented | Part of -M |
| `-t`, `--times` | Preserve modification times | ✅ Implemented | Part of -M |
| `-E`, `--executability` | Preserve executability | ❌ Not Implemented | |
| `--chmod=CHMOD` | Affect file permissions | ❌ Not Implemented | |
| `-A`, `--acls` | Preserve ACLs | ⚠️ Partial | `preserve_acls` stored, not wired |
| `-X`, `--xattrs` | Preserve extended attributes | ⚠️ Partial | `preserve_xattrs` stored, not wired |
| `-H`, `--hard-links` | Preserve hard links | ⚠️ Partial | `preserve_hard_links` stored, not wired |
| `-D` | Same as --devices --specials | ✅ Implemented | Device file preservation |
| `--devices` | Preserve device files | ⚠️ Partial | `preserve_devices` stored, not wired |
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
| `-l`, `--links` | Copy symlinks as symlinks | ✅ Implemented | Scanner symlink handling |
| `-L`, `--copy-links` | Transform symlink to referent | ✅ Implemented | `copy_links` config field |
| `--copy-unsafe-links` | Transform unsafe symlinks | ✅ Implemented | `copy_unsafe_links` config field |
| `--safe-links` | Ignore symlinks outside tree | ✅ Implemented | `safe_links` config field |
| `--munge-links` | Munge symlinks for safety | ❌ Not Implemented | |
| `-k`, `--copy-dirlinks` | Transform symlink to dir | ❌ Not Implemented | |
| `-K`, `--keep-dirlinks` | Treat symlinked dir as dir | ❌ Not Implemented | |

## 10. Sparse & Device

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-S`, `--sparse` | Sparse block handling | ✅ Implemented | `preserve_sparse` config field |
| `--preallocate` | Allocate dest files before writing | ❌ Not Implemented | |

## 11. Checksum & Comparison

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-c`, `--checksum` | Skip based on checksum | ⚠️ Partial | `checksum` stored, forwarded to scanner |
| `--checksum-choice=STR` | Choose checksum algorithm | ❌ Not Implemented | xxHash used internally |
| `--whole-file` | Disable delta-xfer algorithm | ❌ Not Implemented | |
| `--compare-dest=DIR` | Compare dest files relative to DIR | ⚠️ Partial | `compare_dest` stored, not wired |
| `--copy-dest=DIR` | Include copies of unchanged files | ⚠️ Partial | `copy_dest` stored, not wired |
| `--link-dest=DIR` | Hardlink to files when unchanged | ⚠️ Partial | `link_dest` stored, not wired |
| `--fuzzy`, `--no-fuzzy` | Find similar file for basis | ❌ Not Implemented | |

## 12. Compression

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-z`, `--compress` | Compress file data | ✅ Implemented | zstd streaming compression |
| `--compress-choice=STR` | Choose compression algorithm | ⚠️ Partial | `compress_choice` stored, always zstd |
| `--compress-level=NUM` | Set compression level | ✅ Implemented | 1-22, default 5 |
| `--compress-threads=NUM` | Set compression threads | ❌ Not Implemented | |
| `--skip-compress=LIST` | Skip compress for suffixes | ❌ Not Implemented | Smart skip for known types |

## 13. Connectivity

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-e`, `--rsh=COMMAND` | Remote shell to use | ✅ Implemented | SSH transport support |
| `--rsync-path=PROGRAM` | rsync binary on remote | ✅ Implemented | `rsync_path` config field |
| `--port=PORT` | Alternate daemon port | ✅ Implemented | `server_port` config field |
| `--sockopts=OPTIONS` | Custom TCP options | ❌ Not Implemented | |
| `--blocking-io` | Use blocking I/O for remote shell | ❌ Not Implemented | |
| `--outbuf=N\|L\|B` | Set output buffering | ❌ Not Implemented | |
| `--address=ADDRESS` | Bind address for outgoing socket | ✅ Implemented | `bind_address` config field |
| `-4`, `--ipv4` | Prefer IPv4 | ✅ Implemented | `ipv4` config field |
| `-6`, `--ipv6` | Prefer IPv6 | ✅ Implemented | `ipv6` config field |

## 14. Daemon Mode

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--daemon` | Run as rsync daemon | ⚠️ Partial | `daemon` stored, not wired |
| `--config=FILE` | Alternate rsyncd.conf file | ⚠️ Partial | `daemon_config` stored, not wired |
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
| `--secluded-args` | Send args via protocol | ❌ Not Implemented | |
| `--old-args` | Disable modern arg protection | ❌ Not Implemented | |
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
| `--fsync` | Fsync every written file | ❌ Not Implemented | |
| `--protocol=NUM` | Force older protocol version | ❌ Not Implemented | |
| `--iconv=CONVERT_SPEC` | Charset conversion | ❌ Not Implemented | |
| `--checksum-seed=NUM` | Set checksum seed | ❌ Not Implemented | |
| `-s`, `--secluded-args` | Use protocol to send args | ❌ Not Implemented | |
| `--no-OPTION` | Turn off implied option | ❌ Not Implemented | |

---

## Recommendations: Top Features to Implement Next

Ranked by user demand, implementation complexity, and interoperability impact:

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| 1 | `--whole-file` / `-W` | Low | High — users expect opt-out of delta |
| 2 | `--ignore-times` / `-I` | Low | Medium — useful for forcing re-transfer |
| 3 | `--size-only` | Low | Medium — common migration scenario |
| 4 | `--existing` / `--ignore-existing` | Low | Medium — common sync patterns |
| 5 | `--remove-source-files` | Low | High — common for moves/backup |
| 6 | `--delete-during` | Medium | High — performance improvement |
| 7 | `--delay-updates` | Medium | High — atomic updates |
| 8 | `--chmod` | Low | Medium — permission flexibility |
| 9 | `--executability` / `-E` | Low | Low — simple flag |
| 10 | `--skip-compress` | Low | Medium — performance tuning |

---

## FastSync-Specific Features (Not in rsync)

| Feature | Description |
|---------|-------------|
| `-m` | Multithreaded pipeline (scanner/loader/sender) |
| `-s` | Chunk serialization mode |
| `-f` / `--sendfile` | Zero-copy sendfile() syscall (TCP only) |
| `-c [level]` | zstd compression level (1-22) |
| `--chunk-size` | Configurable chunk size |
| `--queue-size` | Pipeline queue capacity |
| `--tls` | TLS encryption (mutual auth) |
| `--fastsync-server-path` | Path to fastsync-server binary |
| `--server-host` / `--server-port` | Direct TCP connection |
| Incremental sync | Skip unchanged files (size+mtime) |
| Delta transfer | Block-level delta for changed files |
