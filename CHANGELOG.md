# Changelog

All notable changes to FastSync are documented here. Versions match
`PROTOCOL_VERSION` (printed by `fastsync --version`); the client and server must
run the same version because the handshake is strict.

## [Unreleased]

## [2.29.0] - 2026-09-23

The rsync-parity cycle 2.29 (no wire change; `PROTOCOL_VERSION` stays 2.28.0).
`RSYNC_COMPAT.md` moves from **116 ✅ / 14 ⚠️ / 27 ❌** to
**120 ✅ / 10 ⚠️ / 27 ❌** of 157 rows.

An audit cycle follows on the same wire version (`PROTOCOL_VERSION` stays
2.28.0): a security-and-correctness pass over the parity-2.29 baseline, plus a
set of audit follow-ups (filter merge modifiers, the `--inplace`/`--partial-dir`
conflict, credential-file hardening, and small leak/log/test fixes). It fixes
a `--temp-dir` symlink escape, gates client-controlled special permission bits,
corrects `--partial-dir`/`--bwlimit`/`-z` behavior, handles unsupported filter
modifiers, and tightens client and wire validation. The only parity
reclassification is `--filter=RULE` moving ✅ → ⚠️, because its merge-only
`e`/`n`/`w`/`-` modifiers are now accepted and consumed but their semantics
remain unimplemented (accepted-but-ignored); the matrix is therefore **119 ✅ /
11 ⚠️ / 27 ❌** of 157 rows. The affected rows' notes and the summary tally in
`RSYNC_COMPAT.md` were updated. A following triage-fix cycle (see **Triage
fixes** below) moves `-F` and `-i` to ⚠️, for a final **117 ✅ / 13 ⚠️ / 27 ❌**
of 157 rows.

A no-wire parity burn-down cycle follows on 2.28.0: it accepts
`--inc-recursive`/`--no-inc-recursive` as inert no-ops, accepts an absolute
`--temp-dir` that canonicalizes inside the receive root, closes the
`--delete-before` phase-0 divergence (both the single-threaded and `--threads`
data passes replay the pre-scan list), makes `--fake-super` interoperable with
rsync's `user.rsync.%stat` key/grammar (regular files and char/block devices
faked as regular files), turns a failed device `mknod` into a continuing
per-entry failure, and accepts a practical subset of rsync's `rsyncd.conf`
grammar (modules are read-only by default, and accepted-but-unenforced
access-control keys emit a startup warning). The matrix moves to **119 ✅ /
14 ⚠️ / 24 ❌** of 157 rows.

A structural cycle then lands a transport I/O vtable over TCP/TLS (fixing the
TLS-multithreaded sendfile path and making the per-thread SSL resolution
explicit) and bumps the wire to **2.29.0**: the `STATUS_SYMLINK` frame grows an
optional symlink-xattr block (captured no-follow with `llistxattr`/`lgetxattr`,
applied no-follow with `lsetxattr`). Because the handshake is strict, 2.28.0 and
2.29.0 peers are incompatible. Note: Linux refuses to associate xattrs with a
symlink at all, so the symlink-xattr block is a no-op on Linux and is carried
for correctness on platforms/filesystems that do support it; the config-frame
layout is unchanged (golden length still 886).

### Changed

- **rsync-exact traversal order.** The sequential scanner now walks each
  directory's entries in rsync 3.4.1's flist order (non-directories ascending,
  then directories ascending, depth-first), so `--info=name`, the
  `--delete-during`/`--delete-delay`/`-n` would-delete order and the partial
  `--max-delete` survivor set match rsync byte-for-byte. `--threads` has no
  rsync analogue and stays unordered.
- **Delete timing.** The complete `--delete-during`/`--delete-delay`
  per-directory plan set is transmitted before the first data frame, so a
  mid-transfer abort has already removed every planned extra like rsync's
  generator; `-d/--dirs` uses per-directory plans (shielded untraversed
  subdirectories) instead of the end-of-transfer commit. `-n`, `--delete`,
  `--del`/`--delete-during` and `--delete-delay` are now ✅ Parity.
- **Basis directories.** A relative `--compare-dest`/`--copy-dest`/`--link-dest`
  DIR resolves against the destination directory with the transfer-relative
  name appended, exactly like rsync 3.4.1.
- **`-y`/`--fuzzy`.** The candidate search no longer inherits the ordinary delta
  engine's 16 KiB minimum or 10× size-ratio bound, so an oversized or
  sub-16-KiB sibling is reused exactly as rsync reuses it.
- `--info=mount` prints rsync's mount-point skip line (repeated `-xx` drops the
  mount-point directory); `--info=stats` enables the `--stats` block; `-x` is
  repeatable. `--stats` counts traversed directories for the `Number of files`
  breakdown under a plain `-r` scan. `--debug` emits real output for
  `flist`/`del`/`hash`/`deltasum`/`recv`/`filter`/`send`.

### Known residuals

- `--progress` and `--info` still need a receiver→sender event channel for the
  root `./` line, ancestor-directory suppression, receiver-side `skip`/`backup`
  wording, and symlink/empty-directory quick-checks.
- `--delete-before`'s phase-0 late-file divergence remains (rsync's pre-scan
  fixes the file list before the data pass).
- A single file larger than 256 MiB cannot be streamed in the default path
  (a general whole-file limit, not basis-specific).
- `--stats` byte totals and `--msgs2stderr` stay documented divergences.

### Security

- **`--temp-dir` symlink escape fixed.** The receiver's scratch directory was
  opened with a bare `open()`, so a symlink planted under the receive root could
  redirect receiver scratch files outside the authorized root. The opened
  directory is now judged by the real path of its fd (`/proc/self/fd` via
  `realpath`) and an escaping target is refused (`EACCES`, logged); an in-root
  link to another filesystem (the `EXDEV` fallback case) still works.
- **Client-controlled special bits masked when super-user activities are not
  permitted.** Setuid/setgid/sticky bits (`--perms`, `--chmod`, the symlink and
  special-node paths, and deferred directory modes) are now stripped when the
  connection forbids super activities (`--no-super`, a non-opted daemon module,
  a privileged listener without `--allow-super`); exact rsync semantics are
  preserved wherever super activities are permitted.
- **Daemon umask no longer forced to `0`.** `daemonize()` now sets the
  conventional `022`, so implied parent directories created without `-p` are no
  longer world-writable `0777`.
- **Daemon modules are read-only by default.** A `--daemon` module is now
  served read-only unless it sets `read only = no` (or rsync's `write only =
  yes`), matching rsync: a real `rsyncd.conf` that omits `read only` is no
  longer silently writable. A global `read only` still sets the default for
  later modules, and an explicit module value wins. This is a behavior change
  for existing FastSync-native configs that relied on the old writable default;
  add `read only = no` to keep them writable. An rsync `write only = yes` is
  mapped to writability (FastSync is push-only, so a module can never be read
  from the network).
- **Accepted-but-unenforced rsync security keys now warn at startup.** The
  rsync keys FastSync recognizes but does not implement — `secrets file`,
  `refuse options`, `exclude`/`include`/`filter`, `max size`/`min size`,
  `pre-xfer exec`/`post-xfer exec`, `incoming chmod`/`outgoing chmod`,
  `name converter`, `use chroot`, `uid`/`gid`, and the rest of the
  access-control set — load for migration compatibility but now emit a
  `WARN` naming the key (and module) so an operator does not believe the
  restriction is enforced. `auth users`/`secrets file` stay fail-closed: a
  module declaring `auth users` still requires a FastSync credential store.
- **Credentials and signal handling hardened.** Secret files are opened with
  `O_NOFOLLOW|O_NONBLOCK` (while allowing fd-backed store paths and bound-waiting
  a FIFO read for ~3 s so a slow process substitution works but a connected-but-
  silent FIFO cannot hang), and signal handlers use `sigaction` with
  async-signal-safe bodies.

### Fixed

- **`-z` on 100–256 MiB files.** The decompressor's internal ceiling was 100 MiB
  while the receiver advertises and the sender compresses whole files up to
  `MAX_RECEIVE_WHOLE_FILE_SIZE` (256 MiB), so `-z` on a 100–256 MiB regular file
  failed with `Declared decompressed size exceeds 104857600 bytes`. The ceiling
  is now defined in terms of the protocol whole-file bound (still an
  allocation-clamped bomb guard).
- **`--bwlimit` now paces `--sendfile`.** The plaintext-TCP `--sendfile` fast
  path bypassed the protocol's token bucket, so the limit was ignored there. It
  now throttles through the same per-session leaky bucket as the TLS path.
- **`--partial-dir` implies `--partial`.** Matching rsync 3.4.1 (which sets
  `keep_partial` after option parsing), `--partial-dir=DIR` alone retains an
  interrupted transfer's partial and wins over an explicit `--no-partial`;
  `--inplace` still bypasses the partial machinery, and combining `--inplace`
  with `--partial-dir` is now rejected up front with rsync's message
  (`--inplace cannot be used with --partial-dir`).
- **Filter modifiers handled.** The `x` xattr-name modifier is rejected with a
  clear error everywhere. The merge-only `e`/`n`/`w` and `-` modifiers are now
  accepted and consumed on `merge`/`dir-merge` rules (so they no longer leak
  into the merge filename) while still being rejected on non-merge rules,
  matching rsync; their semantics remain unimplemented (accepted-but-ignored).
  Glued patterns (`-newfile`, `-e2e`) and mixed tokens (`H,!secret`) keep their
  historical parsing.
- **Credential-file reads hardened.** Secret files (`--password-file`/
  `--early-input`/`--hash-credentials` input) are opened with `O_NOFOLLOW`, so a
  symlinked credential path now fails closed (`ELOOP`) instead of being followed
  before the owner/mode gate; literal fd-backed paths (`/dev/fd/<digits>`,
  `/proc/self/fd/<digits>`) are exempt so process substitution still works. A
  FIFO/process-substitution read now waits under a bounded ~3 s deadline for its
  writer, so a slow producer works while a connected-but-silent FIFO fails
  instead of hanging.
- **Miscellaneous correctness fixes:** `--filter` rule count is checked
  client-side against `MAX_FILTER_RULES` before any network I/O (the receiver
  still re-checks the expanded count); unknown wire `Status` values are rejected
  as protocol errors; a mutex leak on an init-failure path, an `errno` read
  after `free()` in deferred delete application, `log_perror` misuse for
  non-`errno` conditions, and a `NULL` `server_host`/`ssh_destination`
  allocation path were fixed (the `config_create` failure now releases through
  `config_delete`); the decompression-limit log now prints the effective bound
  rather than the compile-time ceiling; the daemon umask and root test fixtures
  were hardened; `SSL_read` length is clamped and `sendfile` `poll()` retries on
  `EINTR`.

### Refactored / Docs

- Dropped dead `filter_rules_apply` and dead `--old-args` plumbing, unified
  `set_error`, deduplicated `path_is_within` and shared constants, and added
  printf format attributes (fixing format mismatches). `RSYNC_COMPAT.md`,
  `CHANGELOG.md` and `HANDOFF.md` were updated for the audit cycle; the
  `RSYNC_COMPAT.md` summary tally was corrected to match the rows.

### Triage fixes

- **`--dirs` directory xattrs applied inline.** A `-d/--dirs` transfer now
  applies captured directory `-X`/`-A` xattrs fd-relative on the directory entry
  instead of dropping them, so directory xattrs survive the non-recursive path
  (`src/shared/file_save.c`, `tests/test_xattr.c`).
- **Directory/root itemize and `--out-format` lines.** `-i`/`--itemize-changes`
  and `--out-format` now emit the transfer-root `./` line and per-directory
  `cd...`/`.d..t...` lines, rendered by the shared itemize code. This matches
  rsync's fresh-transfer output; because the root line is unconditional and an
  incremental re-run may itemize directories/symlinks that rsync's quick-check
  leaves silent, `-i` is now a ⚠️ Caveat row.
- **FROM name globs for identity maps.** `--usermap`/`--groupmap` `FROM` tokens
  now accept `*`/`?`/`[...]` globs, expanded sender-side against the passwd/group
  database and collapsed into bounded numeric ranges (`MAX_IDENTITY_MAP`),
  matching rsync.
- **Transport fallback unit tests.** Added unit coverage for the TCP/TLS
  transport fallback paths (`tests/test_transport_tcp.c`,
  `tests/test_transport_tls.c`).
- **Docs corrections.** `RSYNC_COMPAT.md`/`README.md` corrected stale parity
  claims for issues #286–#297: the `-F` and `-i` reclassifications, the
  `--munge-links` direction, the accepted checksum/compression name sets,
  `--bwlimit` parsing, `--stop-at` grammar, `--trust-sender`, symlink xattrs, and
  the native/non-interoperable batch and credential notes. The summary tally is
  now **117 ✅ / 13 ⚠️ / 27 ❌** of 157 rows.

## [2.28.0] - 2026-09-20

The rsync-parity cycle. `PROTOCOL_VERSION` moves `2.26.0 → 2.27.0 → 2.28.0`;
client and server must run the same version (the handshake is strict). See
`RSYNC_COMPAT.md` for the per-option matrix, now **116 ✅ / 14 ⚠️ / 27 ❌** of
157 rows.

### Added

- **Differential rsync 3.4.1 parity gate** (`tests/integration/
  test_differential_parity.py`, `parity_harness.py`, `parity_caveats.py`): runs
  real `rsync` and FastSync over generated corpora and diffs the destination
  tree, normalized stdout and exit code. A fast subset runs on pull requests and
  the full strict set on push; the residual allowlist is empty.
- FastSync-only long option **`--verify-basis`**: require a
  `--compare-dest`/`--copy-dest`/`--link-dest` hit to match the source by
  whole-file digest instead of trusting the size+mtime quick-check.
- FastSync-only long option **`--delete-commit`** (implies `--delete`): the old
  atomic late whole-tree commit.
- `--bwlimit` now parses rsync's units exactly and paces like rsync's leaky
  bucket; `--ignore-errors` reproduces rsync's skip-unreadable-subdir and
  IO-error-suppressed deletion (exit 23).
- `--info=name/flist/del/remove/nonreg/progress` emit rsync's line format,
  including real-run `deleting`/`*deleting` lines carried by a new
  `report_deletes` wire bool.
- Receiver-observed `--stats` counters: `Number of created files` now carries
  rsync's `(reg/dir/link/special)` breakdown and `Literal data` is exact for a
  delta transfer (extended `STATUS_STATS`).
- `--progress` uses an opt-in paths-only pre-count so the `to-chk` denominator
  counts every entry like rsync, and emits per-directory/symlink/special names.
- Receiver-side `protect`/`risk` filter engine (new bounded filter-rule wire
  block): `--filter='P ...'` now shields a destination-only entry like rsync.
- `auto` for `--compress-choice`/`--checksum-choice` honors
  `RSYNC_COMPRESS_LIST`/`RSYNC_CHECKSUM_LIST`, and per-codec compression-level
  defaults match rsync.
- Empty source directories are recreated recursively; `-R --no-implied-dirs
  --files-from` places listed files under missing implied parents; `--iconv`
  matches rsync's push direction; `--delete-delay` reports actual removals and
  recursively removes a refilled deferred directory.

### Changed

- **`--delete` now defaults to delete-during (rsync `--del`) timing.** With no
  explicit timing flag, a plain `--delete` removes each directory's extras as
  that directory is processed instead of committing one whole-tree deletion only
  after the entire transfer succeeds. This matches rsync, frees destination
  space progressively, and avoids the whole-old+new-tree peak that could
  `ENOSPC` a tight destination. The client maps the default onto the existing
  `delete_during` wire boolean, so `PROTOCOL_VERSION` stays `2.28.0`.
- Basis directories (`--compare-dest`/`--copy-dest`/`--link-dest`) now default
  to rsync's metadata quick-check (equal size and mtime; `--size-only` drops the
  mtime leg) instead of FastSync's historical always-verify content hash.
  `--copy-dest` re-applies the source attributes, and basis materialization is
  streamed so the 256 MiB whole-file cap no longer applies to a basis hit.
- The per-directory `STATUS_DELETE_PLAN` frame gained a one-int `apply` flag:
  the one-shot per-run config block (protected prefixes, size-pruned mirrors,
  `--delete-missing-args` exact paths) is now always transmitted first on a
  config-only carrier (`apply=false`), fixing a latent bug where a
  `--delete-missing-args` run whose `--files-from` list synchronized no directory
  never sent its exact deletions.

### Notes

- `--delete`/`--delete-during` remain caveats for the mid-transfer abort
  boundary (rsync's generator removes all planned extras ahead of its throttled
  sender; FastSync removes only reached directories — final trees agree).
  `--delete-before`, `--progress`, `--stats`, `--fuzzy` and the basis rows keep
  their documented residuals in `RSYNC_COMPAT.md`; `--filter` and
  `--delete-excluded` are now parity, including protection of a destination-only
  excluded entry under default `--delete`.

### Migration

- Scripts that relied on plain `--delete` deleting nothing until the transfer
  fully succeeded must pass **`--delete-commit`** (or `--delete-after`) to keep
  that behavior. Plain `--delete` now removes reached directories' extras during
  the transfer, exactly like rsync's default; on a completed run the final tree
  is unchanged.
- Deployments that relied on FastSync's stricter basis verification should pass
  **`--verify-basis`**; the default now trusts the size+mtime quick-check like
  rsync.

## [2.26.0] - 2026-09-17


### Added

- **Parity-completion wave.** Closed the remaining rsync-parity gaps against
  rsync 3.4.1 and reclassified the inherently non-rsync rows. It moved the wire
  protocol three times (`2.23.0 → 2.24.0 → 2.25.0 → 2.26.0`).
  - **Delete timing (2.24.0):** per-directory delete plans
    (`STATUS_DELETE_PLAN`) for `--delete-during`/`--delete-delay`. An interrupted
    during-transfer has already removed the reached directories' extras, while a
    delayed transfer commits per directory only after the whole transfer
    succeeds (a late-created extra survives `--delete-delay` but not
    `--delete-after`). `-R --delete` is scoped to the transferred prefix; empty
    in-scope source directories survive; dry-run never deletes.
  - **Wire stats (2.25.0):** `STATUS_STATS` carries the receiver counters
    (matched data, deleted files) and the dry-run would-delete list. `--stats`
    prints rsync's protocol-independent lines; `--progress`/`-P` print per-file
    blocks; `--out-format` gains `%b` (wire bytes), `%c` (block-sum bytes) and
    `%C` (whole-file digest); `-n --delete` prints escaped `*deleting` lines in
    the sequential and `--threads` paths.
  - **Codecs (2.26.0):** `lz4`/`zlib`/`zlibx` compression and `md4`/`sha1`/
    `none` checksums, with rsync-style `auto` negotiation (default `xxh128` +
    `zstd`) and exit-4 rejection of unknown names; the resolved `compression_algo`
    crosses the wire.
  - General `-R`/`--relative` (including the `/./` cut) and `--no-implied-dirs`;
    one-level `-d`/`--dirs` listing for `dir`, `dir/` and `.`; the full filter
    grammar (`merge`/`dir-merge`/`hide`/`show`/`protect`/`risk`/`clear` and
    modifiers) with `-f` bound to `--filter`; a single `-F` transfers
    `.rsync-filter` and `-FF` excludes it.
  - Receiver-side `--chown`/`--usermap`/`--groupmap` TO-name resolution; absolute
    basis directories and a `--link-dest` relink of an up-to-date destination;
    a receiver-side `--ignore-existing` short-circuit before any payload;
    `--preallocate` now wins over `--sparse` via `fallocate(2)`.
  - Client quick wins: `--iconv=.`/`-`/`--no-iconv`, a lone `-h` prints help, an
    empty `--files-from` succeeds (exit 0), a broken referent under
    `-L`/`--copy-unsafe-links` exits 23, the full `--info`/`--debug`
    vocabularies, and the aliases `--ignore-non-existing`, `--protect-args`,
    `--msgs2stderr`.

### Changed

- `PROTOCOL_VERSION` bumped `2.23.0 → 2.24.0` (delete plans),
  `2.24.0 → 2.25.0` (`STATUS_STATS` + `report_stats`), and
  `2.25.0 → 2.26.0` (codec negotiation + `md4`/`sha1`/`none`).
- `--checksum-choice`/`--cc` now accepts `md4`, `sha1`, `none` and the two-name
  form; the negotiated whole-file default is `xxh128`.
- `--compress-choice`/`--zc` now accepts `lz4`, `zlib`, `zlibx`.
- `RSYNC_COMPAT.md` reclassifies the matrix: 9 already-parity rows to ✅, 17
  inherently non-rsync rows to ❌ (native daemon config/auth, batch, privileged
  xattr namespaces, and the safe-subset device/privilege flags), and the genuine
  fixes to ✅; new rows cover `--bwlimit`, `--partial`, `--partial-dir`,
  `--no-whole-file`, `--inc-recursive`/`--no-inc-recursive`, `--protect-args`
  and `--msgs2stderr`.
- The client `--help` `--max-delete` text now describes the implemented partial
  semantics (delete up to N, skip the rest, exit 25).

### Notes

- Remaining documented divergences include the `--stats` per-type file-count
  breakdown, `%b`/`%c` being FastSync wire counts, `-n --delete` line ordering,
  the default `--delete` timing (delete-after, not rsync's delete-during),
  destination-only exclude protection (still sender-derived), `--temp-dir`
  absolute paths, basis-dir attribute re-application and the 256 MiB whole-file
  cap, `--fuzzy` tie-breaking, `--bwlimit=0`/decimal rates, `zlibx`==`zlib`, and
  recursive empty-directory creation.
- Build: adds zlib and lz4 as link dependencies.

## [2.23.0] - 2026-09-16

### Added

- **Rsync-parity wave.** Closed the remaining CLI, filesystem, ownership,
  deletion, and output gaps against rsync 3.4.1.
  - Short options `-r` (`--recursive`), `-b` (`--backup`), `-L`
    (`--copy-links`), and `-B` (`--block-size`/`--delta-block`); rsync
    short-option clustering (`-av`, `-aAX`, `-rlpt`) and attached/inline values
    (`--opt=value`, `-B1000`, `-essh`, `-MOPT`). A value that starts with `-`
    is not mistaken for a cluster.
  - `-c`/`--checksum` now implies the incremental checksum quick-check (and,
    like rsync, does not imply `-t`).
  - `--checksum-choice`/`--cc` accepts `xxh64`/`xxhash`/`xxh3`/`xxh128`/`md5`/
    `auto` and rejects `md4`/`sha1`/`none` and the two-name form by name;
    `--checksum-seed=0` (the default) is randomized per transfer and the chosen
    seed is sent to the receiver.
  - `--compress-choice`/`--zc` accepts `zstd`/`none`/`auto` and rejects
    `lz4`/`zlib`/`zlibx` by name; `--skip-compress` defaults to rsync 3.4.1's
    built-in suffix list; `--no-whole-file` is accepted.
  - `--timeout` defaults to 0 (disabled) and `--contimeout` to 60 s (both `0`
    disables), matching rsync; `--max-alloc=0` means no local limit.
  - `--temp-dir` is confined to the receive root (absolute/`..` rejected by the
    receiver) and an `EXDEV` install falls back to a non-atomic copy.
  - `--numeric-ids` is documented as a mapping modifier only;
    `--usermap`/`--groupmap` support inclusive `LOW-HIGH` ranges, `*`,
    empty-`FROM` (unnamed ids), and receiver-resolved `TO` names; `--chown`
    conflicts with a map on the same side are rejected.
  - `--fake-super` records the *resolved* owner (never a real chown) and replays
    mode/time; directory ownership and directory xattrs/ACLs are preserved.
  - `-l`/`--links` stores symlink targets verbatim (absolute and `..`-bearing
    included), matching rsync; `--safe-links`/`--copy-unsafe-links` are applied
    sender-side and `--munge-links` uses rsync's `/rsyncd-munged/` marker;
    `--trust-sender` no longer affects symlink targets.
  - `--specials` recreates unix sockets with `mknod(S_IFSOCK)` (so `-D` covers
    the full rsync node set).
  - Deletion: the manifest carries a synchronized-directory section so
    `--files-from` subsets no longer delete untransmitted paths;
    `--delete-excluded` leaves size-pruned mirrors protected; extraneous
    destination symlinks are unlinked (never followed); `--max-delete=N` is
    partial (delete up to N, skip the rest, exit 25) and `--delete-missing-args`
    removals draw from the same budget; `--force` is honored during
    `--delay-updates` publication.
  - `-x`/`--one-file-system` emits the mount-point directory entry; the
    `--include`/`--exclude` layers are an ordered first-match rule list.
  - `--chmod` is a faithful port of rsync 3.4.1 (numeric/symbolic, `D`/`F`/`X`,
    `s`/`t`, append semantics, no `-p` implication, no sanitization).

### Changed

- `PROTOCOL_VERSION` bumped `2.22.0 → 2.23.0`: the delete manifest gains a
  synchronized-directory section and the terminal status gains
  `STATUS_DELETE_LIMIT` (client exit 25 on a `--max-delete`-capped commit).
- **The 2.22.0 mode-masking divergence is removed.** Under `-p` the source mode
  is copied exactly, including `S_IWGRP`/`S_IWOTH` and setuid/setgid/sticky;
  `--chmod` no longer implies `-p`. New files without `-p` still use
  `source_mode & ~umask` when metadata is present (else `0644`), and new
  directories without `-p` still use the `0755` creation default.
- `--protocol=NUM` accepts only the current `2.23.0` version string.

### Notes

- The rsync-compatibility matrix (`RSYNC_COMPAT.md`) now classifies every row
  as **parity**, **caveat** (works with a documented divergence), or
  **divergent** (not supported/no-op/impossible), replacing the previous
  misleading "N implemented / 0 divergence" summary. Durable documented
  divergences remain: receiver-side symlink target containment is not enforced
  by default (verbatim storage is rsync parity; use `--safe-links`),
  `--temp-dir` rejects absolute/foreign-filesystem paths, `--copy-devices`
  reads a bounded `st_size`, a broken referent under `--copy-links` exits 0,
  new directories without `-p` use `0755`, `--stats` receiver-only counters are
  0, and `--password-file`/`--early-input`/`--hash-credentials`/`--iterations`
  and the batch format are FastSync-native.

## [2.22.0] - 2026-09-15

### Added

- **Per-attribute metadata preservation (protocol 2.22.0).** The former single
  metadata bundle is split into four independent, rsync-compatible flags:
  `-p/--perms`, `-t/--times`, `-o/--owner`, and `-g/--group`, each applied
  independently on the receiver, with negations `--no-perms`/`--no-times`/
  `--no-owner`/`--no-group` (short `--no-p`/`--no-t`/`--no-o`/`--no-g`) and
  `--no-preserve` clearing all four. `-a/--archive` is now full rsync
  `-rlptgoD` (owner and group included; their application stays
  privilege-gated). `-A/--acls` and `--chmod` imply `-p`, `-X/--xattrs` does
  not, `-E/--executability` sets only executability, and `-U`/`-N` do not imply
  `-t`. `--incremental`/`--delta` still auto-preserve perms+times unless the
  user explicitly negated them.
- Receiver applies directory modes under `-p` (at the end of the transfer,
  alongside the deferred directory times) and symlink mode under `-p`; `-O`
  suppresses directory times only.

### Changed

- `PROTOCOL_VERSION` bumped `2.21.0 → 2.22.0`: the binary config frame gains
  four appended booleans (`preserve_perms`/`preserve_times`/`preserve_owner`/
  `preserve_group`) after `omit_link_times`. The fixed-width `FileMetadata`
  layout is unchanged; the receiver derives the metadata-frame gate
  (`use_metadata`) from the four attributes.

### Notes

- Documented divergences from rsync: a client-supplied mode never grants
  group/other write (`S_IWGRP|S_IWOTH` are stripped for files, directories,
  symlinks, and specials; rsync's `-p` preserves them exactly); a brand-new file
  without `-p` gets `source_mode & ~umask` (sanitized) when metadata is present,
  else the historical fixed `0644`; `--chmod` implies `-p` (rsync does not);
  `-o`/`-g` map by name on the receiver with a raw-numeric fallback (only
  numeric ids cross the wire); and a daemon module without `client owner = yes`
  does not refuse a plain `-a`/`-o`/`-g` but forces super-user activities off,
  applies no ownership, and logs a warning (explicit `--chown`/`--usermap`/
  `--groupmap`/`--numeric-ids`/`--copy-as`/`--super` are still refused).

## [2.21.0] - 2026-09-14

### Added

- Optional server→client rejection detail (protocol 2.21.0). A rejected
  operation may now carry a bounded human-readable reason via
  `STATUS_ERROR_DETAIL` instead of a bare `STATUS_ERROR`, so the client can
  report *why* the server refused (daemon module gate, config validation,
  receiver-side path/node validation). `receive_status()` transparently maps the
  new status back to `STATUS_ERROR` for every existing call site and captures
  the reason into a thread-local buffer exposed by `protocol_last_error()`. The
  detail body is always consumed, so the stream cannot desynchronize, and
  messages are sliced to `MAX_ERROR_DETAIL_BYTES` (4096) on send.
- **Server-contacting `--dry-run` (protocol 2.21.0).** `--dry-run` now performs
  a real handshake with a remote/daemon receiver and reports exactly what WOULD
  change based on receiver state (existing destination files, mtimes, checksums,
  basis dirs). The wire config carries the dry-run intent (`Config.dry_run`) and
  the receiver answers each per-file check with `STATUS_DRY_RUN_TRANSFER` (would
  transfer) or `STATUS_OK` (already up to date); the sender prints the
  would-transfer set and its trailer without sending any file data. The receiver
  performs the normal read-only incremental decision but mutates nothing: no temp
  files, writes, renames, deletes, metadata/xattr/chown, or directory creation.
  A plain local destination (no explicit `--server-port`/remote) keeps the
  original client-side dry-run. Would-delete reporting for `--delete*` is
  deferred to a follow-up; dry-run never deletes.
- Daemon `max connections per host` (per-source-IP concurrent cap, default 0 =
  unlimited), `auth lockout threshold` (default 10; 0 disables) and
  `auth lockout duration` (default 300 s) config keys.
- `fastsync-server --allow-super` opt-in for a privileged standalone TCP server;
  without it a root standalone receiver forces super-user activities off (device
  nodes, `--write-devices`, ownership). The `--stdio` SSH argv is client-composed,
  so super activities always stay off there.

### Changed

- Config wire fields are now declared once in an X-macro table
  (`CONFIG_WIRE_FIELDS` in `src/shared/config.h`) that generates the struct
  members, defaults, and the send/receive sequence, removing the manual
  six-site field sync. Wire bytes and `PROTOCOL_VERSION` are unchanged.
- `receive_incremental_check()` (the per-file `STATUS_CHECK` fast path) is split
  into small static helpers with a short linear orchestrator. Pure refactor: the
  wire byte stream and all cleanup are unchanged.
- `authorized_root` state has a single owner (`utils.c`) with read accessors; the
  duplicated statics in `file.c` and the server were removed.
- `Data` records its owning `ProtocolSession` so its memory charge is returned to
  the session that reserved it, regardless of the destroying thread.
- The receiver pipeline moved out of `shared` into `server/receiver_pipeline.[ch]`;
  the build now uses explicit `fastsync_shared` / `fastsync_client_core` /
  `fastsync_server_core` targets instead of a GLOB, and the client no longer links
  server code.
- The benchmark tool generates the requested random/compressible data mix
  accurately, verifies each transfer before recording it, computes correct
  percentiles, adds a MB/s column, handles `tc`/netem without requiring `sudo`
  when already root, builds into a dedicated `build-bench/` directory, and adds a
  `--warm` incremental-transfer mode.
- The `nix-shell` dev environment provides the full toolchain (clang-format,
  cppcheck, pytest-xdist, OpenSSH, rsync, iproute2, valgrind, lcov) and no longer
  builds on entry.

### Security

- Enforce the daemon's per-module `max connections` cap (0 = unlimited) and add
  the shared per-source `max connections per host` cap plus a cross-process
  `auth lockout`. Because the listener forks one child per connection, the
  counters live in an anonymous shared mapping created before the accept loop and
  reclaimed by the parent's `SIGCHLD` handler, so the per-module, per-source and
  auth-failure state is shared across every child (including after `SIGKILL`). The
  per-source table has a bounded lifetime (expired/idle entries are reclaimed,
  with a rate-limited warning when genuinely full), and the occupancy counters are
  re-derived from the shared slot table on every child exit. Trusted loopback
  peers are exempt (they share one address); clients behind a shared NAT/proxy
  share a single per-host budget and lockout, which is documented.
- Hardening from a full security audit:
  - Fail a truncated zstd frame instead of spinning forever (remote DoS).
  - Open receiver destination/basis/hard-link entries `O_NONBLOCK` so a
    client-planted FIFO cannot block a worker indefinitely.
  - Require a regular file before `--inplace` writes, closing a FIFO-hang and a
    raw-device write that bypassed the `--write-devices` gate.
  - Reject SSH destinations whose user/host begins with `-` and insert `--` before
    the host token, closing `-o ProxyCommand=…` argument injection (RCE).
  - Gate client `--force` recursive removal behind the server `--allow-delete`
    policy.
  - Reject empty `hosts allow`/`hosts deny`/`auth users` values instead of
    silently meaning "unrestricted".
  - Restrict TLS 1.2 to AEAD suites and set server cipher preference; load the
    private key TOCTOU-safely from an `O_NOFOLLOW` fd; verify IP literals against
    IP SANs; guard client-cert CN truncation.
  - Make `--dry-run` content-blind: it neither reads destination files nor
    hashes basis files, removing a 1-bit content oracle against `read only`
    modules.
  - Bound glob matching (iterative DP, no exponential backtracking) and bound
    line reads for filter/`--files-from`/pattern files.
  - Gate `system.posix_acl_*` xattrs on `--acls` and charge decompression/chunk
    allocations against the per-connection memory budget.

### Fixed

- Pre-auth NULL dereference in `config_delete()` when an over-long
  `basis_count` (and the analogous count fields) was received and then failed
  validation; received counts are now validated before being published.
- Leaked inherited `Data` in the forked compression-truncation unit test
  (valgrind definite leak).
- `receive_status()` no longer loses a captured rejection reason when owed
  keepalives are drained.

## [2.20.0] - 2026-09-13

### Security

- Cap cumulative `DirTimeList` growth and bound pre-auth config-string memory
  (remote memory-exhaustion DoS).
- Daemon host access control (`hosts allow`/`hosts deny`, IPv4/IPv6/CIDR),
  configurable global `max connections`, connection audit logging, and a
  bounded `auth failure delay` throttle. IPv4-mapped peers are normalized and
  invalid patterns are rejected at parse time (no silent fail-open).
- Honor `--timeout` for protocol I/O and bound idle/session time to defeat
  keepalive slowloris; child-safe signal handling in the forked daemon.
- Compiler/linker hardening (`_FORTIFY_SOURCE`, stack protector, PIE, RELRO)
  and pinned build dependencies.

### Fixed

- Use-after-free in the basis-dir oversize preflight.
- Placeholder `Data` leaks, `missing_args` leak, scanner chunk leak.
- Thread-safe logging; single fd owner and cleanup epilogue in the server
  handler.

### Performance

- Metadata now crosses the wire as one packed frame (protocol 2.20.0).
- Delete keep-set and `--files-from` lookups indexed (O(n*m) → O(n)).
- Reused per-thread zstd contexts; `TCP_NODELAY` by default.
- Byte-bounded sender queues; removed a redundant scanner `stat()`.

## [2.19.0] - 2026-09-12

### Security

- **Daemon authentication rewritten as SCRAM-SHA-256 challenge/response**
  (`STATUS_AUTH_CHALLENGE` → `STATUS_AUTH_RESPONSE` → `STATUS_AUTH_OK`/`STATUS_AUTH_FAILED`),
  replacing the old replayable static `SHA-256(password)` bearer credential.
  Each proof is bound to a fresh per-connection server nonce plus a client
  nonce, so a captured response can never be reused.
- **Salted verifier store.** `--password-file`/`--early-input` now hold
  `user:$fastsync$1$pbkdf2-sha256$<iters>$<salt>$<stored_key>$<server_key>`
  (PBKDF2-HMAC-SHA256, default 600000 iterations, range 100000–10000000). The
  legacy `user:SHA256HEX` form is hard-rejected; there is no auto-upgrade.
  Generate stores offline with `fastsync-server --hash-credentials FILE
  [--iterations N]`.
- **Username-enumeration hardening.** Unknown/off-list users are answered with a
  dummy verifier whose salt is a deterministic per-username value
  (`HMAC-SHA256(dummy_key, username)`), using the store-wide uniform iteration
  count and a constant-time full-length membership scan. The dummy key is
  persisted in an owner-only `<store>.dummykey` sidecar (atomic publish, exact
  mode 0600) so challenges are stable across restarts.
- **Verified transport for auth-required modules.** A module with `auth users`
  accepts credentials only over verified TLS whose client certificate matches
  `--client-cn`, or — when `--allow-unauthenticated` is explicitly set —
  plaintext from a loopback peer. Remote plaintext is refused before any
  challenge. Clients must use `--tls` to send `--password-file` credentials to a
  non-loopback daemon; `--client-cn` is mandatory with `--tls`.
- **Secret hygiene.** The plaintext password, derived keys, nonces/proofs and
  the dummy key are wiped from memory on every path and never logged.
- Carried-over hardening: `-K` TOCTOU-safe directory walk
  (`openat(O_NOFOLLOW)` per component), always shell-quoted SSH remote path,
  TLS compression/renegotiation disabled, race-free (open-then-`fstat`)
  `--password-file`/`--early-input` checks, log-injection escaping, and lazy
  protocol debug escaping.

### Added

- `fastsync-server --hash-credentials FILE [--iterations N]` offline tool.
- `<store>.dummykey` sidecar (auto-created, owner-only, 0600).
- Integration tests for auth replay rejection, malformed frames, legacy-store
  refusal, and the loopback/TLS transport policy; fuzz targets for config
  receive and daemon-auth parsing.

### Changed

- **Protocol version 2.18.0 → 2.19.0 (breaking).** The config-frame auth block
  is now `[present][username]` (digest removed) and the auth challenge/response
  frames are interleaved between the config frame and its `STATUS_OK`. A 2.19.0
  client and a 2.18.0 server (or vice versa) fail cleanly at the handshake.
- Daemon modules declaring `auth users` require a configured credential store at
  startup (fail closed); operators regenerate stores from plaintext with
  `--hash-credentials`.

### Notes

- First tagged release. FastSync implements rsync-compatible file
  synchronization over TCP and SSH with TLS (OpenSSL), streaming zstd
  compression, multithreaded transfers, and incremental sync. See
  [RSYNC_COMPAT.md](RSYNC_COMPAT.md) for the flag-parity matrix.
