# Rsync Feature Compatibility

This document maps rsync's full feature set to FastSync's current implementation status.

## Summary

| Status | Count | Description |
|--------|-------|-------------|
| ✅ Implemented | 74 | Feature works end-to-end |
| 🔀 Alt Arg | 3 | Functionality exists but under different flag/semantics |
| ⚠️ Partial | 5 | Flag parsed/stored but behavior incomplete |
| 🔄 Compatibility No-op | 1 | Flag is accepted for CLI compatibility but has no effect |
| ❌ Not Implemented | 64 | Flag not recognized or no behavior |
| **Total** | **147** | |

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
| `-C`, `--cvs-exclude` | Auto-ignore CVS files | ✅ Implemented | Applies the well-known rsync default exclude set as exclude rules during scanning (RCS SCCS CVS CVS.adm RCSLOG cvslog.* tags TAGS .make.state .nse_depinfo *~ #* .#* ,* _$* *$ *.old *.bak *.BAK *.orig *.rej .del-* *.a *.olb *.o *.obj *.so *.exe *.Z *.elc *.ln core .svn/ .git/ .hg/ .bzr/); `.git/`-style repo dirs are pruned without descending |

## 2. Modifying Output

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--stats` | Give transfer stats | ✅ Implemented | Prints file/byte counts |
| `-h`, `--human-readable` | Human-readable numbers | ✅ Implemented | Formats transfer byte sizes using binary units |
| `-i`, `--itemize-changes` | Per-file change summary | ✅ Implemented | Prints rsync-style `>f+++++++++` lines to stdout only for files actually sent (also under `-m`); unchanged files print nothing, matching single-`-i` behavior |
| `--progress` | Show progress | ✅ Implemented | Progress callback in sender |
| `-P` | Same as --partial --progress | ⚠️ Partial | Parses and enables progress, but interrupted files are not retained for resumable transfers |
| `--out-format=FORMAT` | Custom output format | ✅ Implemented | Per-transfer template on stdout; tokens `%f` `%n` `%l` `%b` `%M` `%%` (`%b` is the source length, always `== %l`; post-compression/delta wire bytes are not counted); unknown escapes preserved |
| `--log-file=FILE` | Log to file | ✅ Implemented | `log_file` config field |
| `--log-file-format=FMT` | Log format | ✅ Implemented | Requires `--log-file`; writes one template line per transferred file using the same token set as `--out-format` (including `%b` `==` source length) |
| `--8-bit-output`, `-8` | Leave high-bit chars unescaped | ✅ Implemented | Applies to displayed paths and protocol debug output |
| `--list-only` | List files instead of copying | ✅ Implemented | `ls -l`-style listing of files that would be transferred; scans the source only, contacts no server, writes nothing; also works with `-n` |

## 3. File Selection

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--exclude-from=FILE` | Read exclude patterns from file | ✅ Implemented | Reads patterns from file |
| `--include-from=FILE` | Read include patterns from file | ✅ Implemented | Reads patterns from file |
| `--filter=RULE` | Add file-filtering rule | ✅ Implemented | Long option only: rsync's short `-f` conflicts with FastSync sendfile (see FastSync-specific list), so `-f` is not reassigned. Supported subset: `+`/`-` include/exclude, implicit-exclude patterns, `include`/`exclude` word forms, a leading `/` anchor (to the transfer root, or to a `.rsync-filter` file's directory), and a trailing `/` for dir-only rules; first match wins with a default of include inside the filter layer. Filters are an independent layer from `--exclude`/`--include` (an entry must pass both). Rejected with a clear error (no silent no-ops): `merge`/`dir-merge`/`hide`/`show`/`protect`/`risk`/`clear` words, rules that begin with `:`/`.`/`!` (merge/dir-merge/list-clear shorthands), and include/exclude modifiers other than `/` (`! C s r p x`) |
| `--files-from=FILE` | Read source file list from file | ✅ Implemented | Entries are paths relative to the source root (leading `./` stripped, `..`/absolute entries rejected at parse time, blank lines ignored; NUL-delimited with `-0`). A listed regular file is transferred; a listed directory transfers its whole subtree (FastSync recursion is always on, unlike rsync's non-recursive default). Non-listed paths and their subtrees are pruned by the scanner. A listed entry that does not exist under the source (and an empty list) is a hard error reported before any transfer; listing `.` (whole tree) and empty listed directories are fine. Scalability note: `file_list_affects` is O(list size) per scanned entry, so a very large `--files-from` list against a huge tree is quadratic; lists are typically small enough that this is acceptable, but it is the documented bound. The delete manifest still derives from what was actually sent, so `--delete` stays consistent with the subset |
| `-0`, `--from0` | Delimit *-from files with NULs | ✅ Implemented | `--files-from` entries become NUL-delimited; the flag may appear before or after `--files-from` on the command line. NUL mode preserves entry bytes exactly (trailing CR/LF are part of the name; only newline mode trims them) |
| `--max-size=SIZE` | Skip files larger than SIZE | ✅ Implemented | `max_size` in scanner |
| `--min-size=SIZE` | Skip files smaller than SIZE | ✅ Implemented | `min_size` in scanner |
| `-I`, `--ignore-times` | Don't skip files matching size+time | ❌ Not Implemented | |
| `--size-only` | Skip based on size only | ✅ Implemented | With `--incremental`, ignores mtime |
| `-@`, `--modify-window=NUM` | Mod-time comparison accuracy | ✅ Implemented | Whole-second tolerance with nanosecond-aware comparisons |
| `--existing` | Skip creating new files on receiver | ✅ Implemented | Existing destination files continue through normal update handling |
| `--ignore-existing` | Skip updating existing files | ❌ Not Implemented | |
| `--remove-source-files` | Sender removes regular files after confirmed transfer | ✅ Implemented | |
| `-x`, `--one-file-system` | Do not cross filesystem boundaries | ✅ Implemented | Sender scanner captures the root device and skips descending into mount-point crossings (`st_dev` differs); cross-filesystem mount-point subdirectories are dropped entirely, matching rsync |
| `-F` | Add the default `.rsync-filter` rules | ✅ Implemented | Reads one filter rule per line from each directory's `.rsync-filter` file during traversal and applies it to that directory's subtree; the current directory's rules are evaluated before its ancestors', so deeper files override shallower ones and per-directory files override the command-line `--filter`/`-C` base by default (matching rsync's first-match-wins precedence); `.rsync-filter` files are never transferred. The rsync `-FF` behavior (also `.cvsignore`) is out of scope; unsupported rule types inside the file abort with a clear error |

## 4. Directory Options

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-r`, `--recursive` | Recurse into directories | ✅ Implemented | Default behavior |
| `-R`, `--relative` | Use relative path names | ✅ Implemented | Meaningful together with `--files-from` (FastSync's default full-tree scan always mirrors the full source argument path below the destination root, so -R does not change it). With `-R` + `--files-from` each listed entry is transmitted under its bare relative destination path: an entry `sub/x.txt` lands at `<dest>/sub/x.txt` (its leading components preserved) instead of under the `<dest>/<full source path>` mirror. Only the path sent on the wire changes; the client still reads the absolute source path, and the delete manifest derives from the sent (relative) paths so `--delete` and `--remove-source-files` stay consistent in both layouts. Works single-threaded and under `-m` (including chunk serialization) |
| `--no-implied-dirs` | Don't send implied dirs with -R | ✅ Implemented | Client-side, meaningful only with `-R` + `--files-from`. rsync would normally create the ancestor directories implied by a listed file so it can be written; with `--no-implied-dirs` a listed file whose parent directory is not itself (or via an ancestor) explicitly listed cannot be placed, and FastSync fails the whole run up front with a clear error (`--no-implied-dirs: cannot place file '...': parent directory '...' is not explicitly listed`). Listing the directory (or an ancestor of it, or the whole tree `.`) permits the file. In every other mode the option has no effect. FastSync has no per-entry skip channel, so the rsync "omit the file" case is surfaced as a hard pre-transfer error |
| `-d`, `--dirs`, `--old-dirs`, `--old-d` | Transfer dirs without recursing | ✅ Implemented | `-d <dir>` transmits an explicit directory entry for the source-root directory, so the destination mirror is created empty and nothing is descended into. With `--files-from` exactly the listed items are transferred: a listed directory is created empty (no descent) and a listed file is transferred with its content; the dest layout follows the same -R rules as plain files. A new wire frame (`STATUS_MKDIR`) carries each directory entry (path only); the receiver creates it with the same confined mkdir-parent semantics as regular writes, in single-threaded and `-m` receivers (chunk serialization carries a per-entry type marker). Directory entries appear in the delete manifest so `--delete` prunes correctly. FastSync divergences: directory mtimes/modes are not transmitted, filter/`--exclude` rules are not re-applied to the listed dirs mode (there is no descent during which they would apply), and `-d` never creates the intermediate directories between the destination root and a listed file beyond the usual on-demand parent creation. Under `--delay-updates` only regular files are staged: directory entries are created immediately, so a delayed run that fails part way can leave the already-created empty directories behind (matching rsync, which also creates directories as it processes the file list and only delays regular-file data) |
| `--mkpath` | Create missing path components | ✅ Implemented | Wire option (client → server). At connection start the server creates the client's destination root directory (and any missing leading components below its own authorized root) when `--mkpath` is set, failing the connection cleanly if it cannot. Without `--mkpath` a destination root that does not exist yet is rejected up front (rsync semantics), so the flag is the only way to transfer into a not-yet-created destination directory. Creation is confined by the same secure mkdir walk as file writes (`O_NOFOLLOW`, no `..`) |

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
| `--delay-updates` | Put updated files in place at end | ✅ Implemented | Successfully received files are staged under a private 0700 `.fastsync-stage` dir inside the receive root and atomically renamed into their final destinations only after the whole transfer (manifest/delete handling included) succeeds, just before the success/outcome frame is sent. The delete walker deliberately skips the staging dir at the receive root, so `--delete` removes genuine extras but never the staged files (deletion runs before publication; rsync's delete-after ordering is not implemented). `--existing`/`--ignore-existing`/`--update` decide against the final destination path at stage time; `--backup` moves the old file aside at publication. Incompatible with `--inplace` and with `--backup-dir=.fastsync-stage` (the internal staging name is reserved; both are rejected). The staging dir name is fixed, so two simultaneous delayed transfers to the same destination root are serialized with an exclusive advisory lock held for the whole transfer: the second session fails cleanly instead of corrupting the first. Aborting or failing before publication installs nothing and removes the staging tree; a crash between stage and publish leaves staged leftovers that the next delayed run wipes at start (process death releases the lock). A stage→publish failure aborts the transfer (best-effort cleanup of the not-yet-published staged files; already-published files are not rolled back). Works in single-threaded and `-m` modes |
| `-T`, `--temp-dir=DIR` | Create temporary files in DIR | ✅ Implemented | `--temp-dir` only; `-T` stays FastSync's `--timeout` alias. Scratch dir is resolved under the receive root; temp copies use a unique name there and are atomically renamed into place. If the scratch dir and destination are on different filesystems the atomic rename fails with EXDEV and the file save fails, which aborts the whole transfer (FastSync has no per-file skip/resume on a save error; rsync's non-atomic copy fallback is deliberately not used). `--inplace` and `--partial-dir` writes bypass the scratch dir |

## 7. Deletion

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--delete` | Delete extraneous files from dest | ✅ Implemented | `use_delete` config field. Deletion is always derived from the transmitted keep-set manifest of the paths the sender sent/keeps (never from unchecked input), runs through the symlink-safe walker bounded by `MAX_SERVER_DELETE_COUNT`, and skips the `.fastsync-stage` staging dir under `--delay-updates`. FastSync's default timing when no timing flag is given is **delete-after** (extras are removed only once the whole transfer succeeded) — intentionally NOT rsync's `--del`/delete-during default, to preserve FastSync's commit-style safety |
| `--delete-before` | Delete before transfer | ✅ Implemented | Implies `--delete`. The sender runs a full source pre-scan (paths only) and transmits the keep-set manifest BEFORE any file data; the receiver validates it, removes every destination entry not listed (bounded walk, staging-dir skip), then acks `STATUS_OK`. The sender only starts streaming after the deletion committed, or aborts if the receiver reported a deletion error. By definition the deletions already happened when a later transfer phase fails — rsync's delete-before is destructive the same way; a subsequent failure does not restore the removed files. Divergence: the keep-set is the pre-scan snapshot, so a file that appears on the source between the pre-scan and the data pass is still transferred but was not protected from deletion |
| `--del`, `--delete-during` | Delete during transfer | ✅ Implemented | Both spellings accepted; imply `--delete`. FastSync streams the source in a single directory scan and has no per-directory generator pass, so deletions cannot be interleaved per-directory the way rsync's delete-during does. `--delete-during` therefore selects the same early engine mode as `--delete-before` (manifest transmitted before any data, extras removed and acknowledged before data is applied); observable success/failure behaviour equals `--delete-before`. That is the documented divergence from rsync, where `--del` is the default meaning of `--delete` |
| `--delete-delay` | Find deletions during, delete after | ✅ Implemented | Implies `--delete`. Commit-mode timing: extras are removed only after the whole transfer succeeded. rsync's delete-delay records the deletion list during its scan and applies it at the end; FastSync never snapshots the destination while data flows (the keep-set is the transmitted manifest and the destination is listed only at deletion time), so `--delete-delay` is implemented as the same end-of-transfer commit as `--delete-after` with identical safety. That is the documented divergence |
| `--delete-after` | Delete after transfer | ✅ Implemented | Implies `--delete`. The delete-after timing is also what plain `--delete` does: the keep-set manifest closes the data stream and the receiver commits the bounded deletion only after the terminal `STATUS_FINISHED` proves the whole transfer (every data frame received and stored) succeeded. A failed or aborted transfer removes nothing |
| `--delete-excluded` | Also delete excluded files | ❌ Not Implemented | Removed because it had no effect |
| `--max-delete=NUM` | Max files to delete | ❌ Not Implemented | Removed because it had no effect |
| `--ignore-errors` | Delete even with I/O errors | ❌ Not Implemented | |
| `--force` | Force deletion of non-empty dirs | ❌ Not Implemented | |
| `--prune-empty-dirs` | Prune empty dir chains | ❌ Not Implemented | Removed because it had no effect |

**Deletion-timing implementation notes (Phase 3):** the delete flags above are
real. Two new config booleans (`delete_during`, `delete_delay`) join the already
serialized `delete_before`/`delete_after`, so the on-the-wire config layout
changed and `PROTOCOL_VERSION` was bumped **2.7.0 → 2.8.0** (peers must match).
The `STATUS_MANIFEST` frame is count-delimited and position-independent: the
receiver commits the deletion either when the manifest arrives (early modes:
`--delete-before`/`--delete-during`, which additionally acknowledge with
`STATUS_OK` before data flows) or after the terminal `STATUS_FINISHED` proves
the whole transfer succeeded (commit modes: plain `--delete`/`--delete-after`/
`--delete-delay`). Timing is chosen purely from the config, so server policy
(`--allow-delete` off) still disables deletion without deadlocking the early
manifest ack. `--delete-delay` and `--delete-during` are each implemented as
the closest safe approximation their engine mode allows; the divergences are
noted in the rows above.

Manifest size: the sender's keep-set collection (streaming or early pre-scan)
is unbounded, but the receiver rejects any manifest beyond `MAX_MANIFEST_ENTRIES`
(1 048 576 entries) / `MAX_MANIFEST_BYTES` (16 MB of paths) as a hard protocol
error. In the commit modes this only means the deletion is refused after the
data already arrived; in the NEW early modes (`--delete-before`/`--delete-during`)
the manifest is the first frame, so an oversized keep-set now aborts the whole
transfer BEFORE any data is sent (previously all data transferred and only the
deletion step failed). Keep the source tree small enough for the receiver's
manifest caps when using the early timing.

Early-delete ACK wait: after committing a large deletion (up to
`MAX_SERVER_DELETE_COUNT` unlinks) the receiver's `STATUS_OK`/`STATUS_ERROR`
reply can legitimately take much longer than a normal round trip, so the sender
waits for that single ACK with an extended explicit deadline (1 hour) instead
of the default 60 s per-message receive window. A receiver that is genuinely
gone still aborts the wait via connection close/error; the extended bound only
protects against aborting after the deletion already committed on the receiver.

Flag-conflict policy: unlike rsync's last-one-wins behaviour, every deletion
timing flag implies `--delete`, and combining a timing flag with `--no-delete`
(in either argument order) — or more than one timing flag — is rejected as a
configuration error rather than silently resolved. Note the check is
order-independent because it runs over the fully parsed config.

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
| `--open-noatime` | Avoid changing access time when opening files | ❌ Not Implemented | |
| `--numeric-ids` | Do not map uid/gid by name | ❌ Not Implemented | |
| `--usermap=STRING` | Map usernames | ❌ Not Implemented | |
| `--groupmap=STRING` | Map group names | ❌ Not Implemented | |
| `--chown=USER:GROUP` | Map owner and group | ❌ Not Implemented | |
| `--copy-as=USER[:GROUP]` | Perform the copy as another user/group | ❌ Not Implemented | |

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
| `--compare-dest=DIR` | Compare dest files relative to DIR | ✅ Implemented | DIR is a receiver-side basis relative to the destination root (confined below it; absolute/`..`/`.` rejected, `//` collapsed and trailing `/` dropped). On the receiver's per-file check (implies `--incremental`) an exact match = same size + mtime (unless `--size-only`; `-I` disables matching) **and** equal xxHash64 of the sender's file; a match suppresses the data transfer. compare-dest never copies: it only skips a file the destination does **not** already hold (sparse destination, rsync parity), and is consulted before the normal delta/full paths. Repeatable; searched in command-line order, first match wins. Divergences: when the destination already holds a *different* version rsync deletes it but FastSync instead transfers the data (keeps the mirror complete; never deletes without `--delete`); attribute-only differences on a match are not re-applied (data is skipped so the sender never sends metadata); content is verified by xxHash64, stricter than rsync's default quick check. Sizing: FastSync's whole-file payload limit is 256 MiB on **every** transfer path (not basis-specific); rsync applies basis dirs to arbitrary sizes, so FastSync refuses a basis run whose source contains a larger file up front with a clear error before any transfer. Wire: a basis-count field is always present on the config frame (protocol 2.9.0, so clients and servers must both be 2.9.0) |
| `--copy-dest=DIR` | Include copies of unchanged files | ✅ Implemented | Same basis rules as `--compare-dest`, but an exact match materializes a **local copy** of the DIR file into the destination (via the normal atomic temp+rename store path, so `--existing`/`--ignore-existing`/`--update`/`--backup`/`--delay-updates` all still apply) instead of transferring data. Repeatable; command-line order = priority. Content is xxHash64-verified before the copy. Divergences: a basis-hit destination keeps the basis file's own mode/uid/gid and mtime (the sender sends no metadata on a skip), so with `--size-only` its mtime can differ from the source and attribute-only differences are copied with the basis attributes rather than rsync's "copy + fix attributes". Requires `--incremental` (implied); incompatible with `-s`. Wire: protocol 2.9.0 |
| `--link-dest=DIR` | Hardlink to files when unchanged | ✅ Implemented | Same basis rules as `--copy-dest`, but an exact match installs an atomic **hard link** to the DIR file (temp hard link + rename) so no data or disk space is used; where the link is impossible (basis on another filesystem, filesystem refuses links) it falls back cleanly to a byte-identical local copy, never a corrupt/partial file. `--delay-updates` stages the link and publishes by rename, so the final entry stays a real hard link. Repeatable (searched in command-line order, first match wins). Content is xxHash64-verified before linking. Divergences and caveats: an already up-to-date destination file is not re-linked to a basis file (only files that would otherwise be written are linked); a link keeps the basis inode's own mode/uid/gid and mtime — metadata is never written through the shared inode (that would mutate the basis file), so a later `--inplace` run that rewrites such a destination path **will mutate the basis snapshot** through the shared inode (use `--copy-dest` when the destination must stay independently writable); with `--size-only` the linked mtime can differ from the source; a `--remove-source-files` source satisfied by a basis dir is treated as skipped and therefore **retained** (never removed); basis dirs are excluded from `--delete`. Requires `--incremental` (implied); incompatible with `-s`. Wire: protocol 2.9.0 |
| `-y`, `--fuzzy`, `--no-fuzzy` | Find similar file for basis | ✅ Implemented | `-y/--fuzzy` is a pure bandwidth optimization on the existing receiver-driven delta path: when a file must be transferred and the destination holds no usable content at the exact path (file absent, or the destination file is outside the delta engine's size bounds), the receiver searches the SAME destination directory for an existing regular file whose basename is similar to the incoming name and uses it as the delta basis, so the sender transmits only the differences instead of the whole file. The output is always byte-exact regardless of which (or whether any) basis is chosen. Decision location: the receiver performs the candidate search inside `receive_incremental_check` and sends the normal `STATUS_DELTA_SIGNATURE`; the sender never learns the basis was a different file, so no new frame type or sender logic was needed — only the config frame grew a `fuzzy` boolean, so `PROTOCOL_VERSION` was bumped **2.8.0 → 2.9.0** (peers must match). Similarity heuristic (deterministic, simpler than rsync's deliberately-fuzzy matching, and documented precisely): candidates are the target's sibling entries in its destination directory, opened `O_NOFOLLOW`/`AT_SYMLINK_NOFOLLOW` under the confined root (symlinks never followed; nothing outside the destination root is ever read or hashed); dotfiles, directories, the target's own name, and the `.fastsync-stage`/temp scratch names are excluded; the size gate is the delta engine's own bounds (both files ≥ 16 KiB, ≤ `--delta-max`, ratio ≤ 10×) rather than rsync's ~1.5× size window; the name gate is a Levenshtein edit distance between the basenames accepted only when ≤ half the length of the longer basename; the single best candidate (smallest distance, tie-break size closest to the incoming file then lexicographically smaller basename) is read; the directory scan is capped at 4096 entries so a pathological directory cannot stall a transfer. When fuzzy applies: only to files the receiver would otherwise send whole — the destination's own file is always preferred as the delta basis when it exists and fits the delta size bounds, so fuzzy does NOT replace an existing-but-different destination basis; FastSync's 10× delta size-ratio bound means an existing destination file that is too far away in size still lets the fuzzy search run. When no similar candidate exists the transfer falls back to the normal whole-file transfer. rsync-divergence note: rsync's own matching uses a fuzzy name/size rule set; FastSync implements the closest safe deterministic approximation above. Because FastSync's delta machinery is off by default (rsync's is on), `--fuzzy` implies `--incremental` + `--delta` (unless `--whole-file`/`-W` or an explicit `--no-delta` switched delta off, in which case fuzzy is inert — matching rsync where `--whole-file` makes fuzzy irrelevant); `--no-fuzzy` negates it. All surrounding semantics are untouched: a fuzzy-reconstructed file is stored as a normal file, so `--remove-source-files`, itemize/`-i`, `--stats`, `--backup`, `--delay-updates`, `--existing`/`--ignore-existing`/`--update` behave exactly as for a whole-file transfer (the fuzzy delta does not skip the file) |

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
| `--remote-option=OPT`, `-M` | Send an option only to the remote side | ❌ Not Implemented | `-M` is FastSync's metadata-preservation flag |

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
| `--max-alloc=SIZE` | Limit a single memory allocation | ✅ Implemented | Caps the largest single allocation; binary units, default 1G |
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

## Implementation Difficulty Plan

The estimates below cover the currently unimplemented features in this document. They assume one engineer familiar with the codebase, include implementation and focused tests, and exclude production rollout time. A feature should not be marked implemented until its behavior is tested in both local and SSH/TCP paths where applicable.

> **Note:** This plan is a superset snapshot written while several of the listed features were still outstanding. The Summary matrix above is the authoritative record of what is already shipped (for example quiet/info/debug output, `--existing`, `--remove-source-files`, `-h`, and `--size-only` are now implemented on `dev`). Treat the phases as sequencing guidance for the work that remains unimplemented.

| Effort | Typical duration | Meaning |
|--------|------------------|---------|
| XS | 0.5-1 day | CLI alias or a local formatting/validation change |
| S | 1-3 days | Isolated behavior with little or no protocol change |
| M | 3-7 days | Cross-cutting client, server, or scanner behavior |
| L | 1-3 weeks | Protocol, filesystem, privilege, or compatibility work |
| XL | 3+ weeks | New transfer mode, daemon subsystem, or broad interoperability effort |

### Phase 1: Low-Risk CLI and Local Behavior

These are the best first changes because they require limited wire-format work and can be tested with existing transfer fixtures.

| Features | Effort | Implementation plan |
|----------|--------|--------------------|
| `--quiet`, `-q`; `--human-readable`, `-h`; `--8-bit-output`, `-8`; `--stderr=MODE`; `--info=FLAGS`; `--debug=FLAGS` | S | Extend logging and output formatting without changing transferred data. |
| `--no-OPTION`; `--old-args`; `--secluded-args`, `-s` | M | Add option implication/negation and safely serialize or protect remote arguments. `-s` currently has FastSync-specific semantics and needs a compatibility decision. |
| `-P`; `--del`; `--old-dirs`, `--old-d`; `--cc`; `--zc`; `--zl` | XS | Add aliases and composed behaviors after the underlying options exist. |
| `--whole-file`, `-W`; `--ignore-times`, `-I`; `--size-only`; `--modify-window`, `-@`; `--update`, `-u` | S | Extend the existing incremental comparison decision. |
| `--existing`; `--ignore-existing`; `--remove-source-files` | S | Add scanner/receiver eligibility checks and remove successfully synchronized source files. |
| `--executability`, `-E`; `--chmod=CHMOD` | M | Apply permission transformations safely while preserving current metadata behavior. |
| `--skip-compress=LIST`; `--compress-threads=NUM` | S | Make compression selection configurable and validate the thread setting against zstd behavior. |
| `--max-alloc=SIZE`; `--fsync` | S | Reuse existing allocation limits and add an explicit durability step after file writes. |

### Phase 2: Filesystem Selection and Update Semantics

These features are moderate because they affect traversal, temporary files, manifests, or the receiver's update policy.

| Features | Effort | Implementation plan |
|----------|--------|--------------------|
| `--one-file-system`, `-x` | M | Track the source device during scanner traversal and skip mount-point crossings. |
| `--relative`, `-R`; `--no-implied-dirs`; `--dirs`, `-d`; `--mkpath` | M | Extend path-list construction and destination directory creation while preserving traversal safety. |
| `--temp-dir`, `-T` | M | Separate temporary-file placement from FastSync's timeout alias and define collision, permissions, and cleanup rules. |
| `--delay-updates` | L | Stage all successful updates and publish them at completion, including crash and cancellation cleanup. |
| `--files-from=FILE`; `--from0`, `-0`; `--filter=RULE`, `-f`; `-F`; `--cvs-exclude`, `-C` | L | Build a complete filter/parser layer and integrate it with scanner pruning, manifests, and delete behavior. `-f` conflicts with FastSync sendfile mode. |
| `--list-only`; `--itemize-changes`, `-i`; `--out-format=FORMAT`; `--log-file-format=FMT` | M | Add a structured change-event model so output modes share one source of truth. |

### Phase 3: Deletion, Comparison, and Delta Compatibility

These features require careful interaction with manifests, incremental checks, backups, and the existing delta protocol.

| Features | Effort | Implementation plan |
|----------|--------|--------------------|
| `--delete-during`; `--delete-before`; `--delete-after`; `--delete-delay`; `--del` | L | Add deletion timing to the transfer state machine and ensure failures cannot remove files unexpectedly. |
| `--delete-excluded`; `--max-delete=NUM`; `--ignore-errors`; `--force`; `--prune-empty-dirs`, `-m` | M | Extend delete walks with policy limits, error handling, empty-directory pruning, and the `-m` short-flag conflict. |
| `--ignore-missing-args`; `--delete-missing-args` | M | Distinguish missing source arguments from traversal errors and apply explicit deletion policy. |
| `--compare-dest=DIR`; `--copy-dest=DIR`; `--link-dest=DIR` | L | Add alternate basis roots and hard-link handling, including metadata and cross-filesystem failures. |
| `--fuzzy`, `-y`; `--no-fuzzy` | L | Index candidate files and select a safe similar basis without making transfer time unbounded. |
| `--append`; `--append-verify` | M | Negotiate file length and verify the retained prefix before resuming. |
| `--checksum-choice=STR`, `--cc`; `--checksum-seed=NUM` | M | Negotiate checksum algorithms/seeds and preserve compatibility with existing xxHash checks. |

### Phase 4: Metadata, Links, and Devices

These features are platform-sensitive and need Linux permission, ACL, xattr, and special-file integration tests.

| Features | Effort | Implementation plan |
|----------|--------|--------------------|
| `--numeric-ids`; `--usermap=STRING`; `--groupmap=STRING`; `--chown=USER:GROUP` | L | Define identity mapping, privilege failures, and wire representation before applying ownership. |
| `--open-noatime`; `--atimes`, `-U`; `--crtimes`, `-N`; `--omit-dir-times`, `-O`; `--omit-link-times`, `-J` | L | Extend metadata capture/apply with platform capability checks and explicit unsupported-attribute handling. |
| `--acls`, `-A`; `--xattrs`, `-X`; `--fake-super` | XL | Add portable serialization, size limits, privilege behavior, and security tests for ACL/xattr data. |
| `--hard-links`, `-H` | L | Preserve inode relationships across the file list and coordinate hard-link creation order. |
| `--munge-links`; `--copy-dirlinks`, `-k`; `--keep-dirlinks`, `-K` | L | Define symlink trust boundaries and receiver-side directory/link collision behavior. |
| `--devices`; `--specials`; `-D`; `--copy-devices`; `--write-devices` | XL | Add privileged special-file handling with strict type, path, and authorization checks. |
| `--super`; `--copy-as=USER[:GROUP]` | XL | Requires a deliberate privilege model, identity switching, and refusal paths; do not implement by blindly elevating the process. |
| `--preallocate` | S | Use platform allocation APIs before writes and fall back cleanly when unsupported. |

### Phase 5: Connectivity and Daemon Compatibility

These options affect process startup, authentication, sockets, and remote execution. They should follow the filesystem and protocol work rather than being added as parser-only flags.

| Features | Effort | Implementation plan |
|----------|--------|--------------------|
| `--rsh=COMMAND`, `-e`; `--rsync-path=PROGRAM`; `--blocking-io`; `--outbuf=N\|L\|B` | M | Generalize SSH command construction and subprocess I/O while retaining argument escaping and timeout guarantees. |
| `--address=ADDRESS`; `--ipv4`, `-4`; `--ipv6`, `-6`; `--sockopts=OPTIONS`; `--port=PORT` daemon semantics | M | Add explicit socket-family/bind configuration and validate it independently for TCP client and daemon modes. |
| `--remote-option=OPT`, `-M`; `--trust-sender` | L | Add authenticated remote-option/config negotiation and reject unsafe sender-controlled values. `-M` conflicts with FastSync metadata mode. |
| `--daemon`; `--config=FILE`; `--dparam=OVERRIDE`; `--no-detach`; `--password-file=FILE`; `--early-input=FILE`; `--no-motd` | XL | Implement a real daemon lifecycle, module configuration, authentication, privilege separation, and process management. |

### Phase 6: Batch, Encoding, and Protocol Interoperability

These are the hardest compatibility items because they require durable formats or behavior that must interoperate with rsync itself.

| Features | Effort | Implementation plan |
|----------|--------|--------------------|
| `--write-batch=FILE`; `--only-write-batch=FILE`; `--read-batch=FILE` | XL | Specify a versioned batch format, persist all required metadata, and test replay, corruption, and partial application. |
| `--protocol=NUM` | XL | Add protocol-version negotiation and compatibility branches without weakening current validation. |
| `--iconv=CONVERT_SPEC` | L | Convert filenames at the protocol boundary with invalid-sequence and normalization tests. |
| `--stop-after=MINS`; `--stop-at=TIME` | M | Add deadline propagation, interruptible I/O, and safe checkpoint/cleanup behavior. |
| `--early-input=FILE`; `--password-file=FILE` | M | Securely read startup credentials/input with permission checks and no secret disclosure in logs. |

### Recommended Delivery Order

1. Resolve short-option conflicts (`-m`, `-M`, `-T`, `-f`, `-s`) and define the compatibility contract.
2. Implement Phase 1 comparison, update, output, and alias features with unit and integration coverage.
3. Implement Phase 2 traversal/filtering and Phase 3 deletion semantics.
4. Implement metadata and link features that are safe on the supported platforms.
5. Treat daemon mode, special files, batch mode, and protocol-version compatibility as separate projects.

The existing priority list below is a feature shortlist, not an implementation schedule; this plan supersedes it for effort and sequencing.

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
