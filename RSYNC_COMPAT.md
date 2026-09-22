# Rsync Feature Compatibility

This document maps rsync's full feature set to FastSync's current implementation status.

## Summary

| Status | Count | Description |
|--------|-------|-------------|
| ✅ Parity | 118 | Reproduces rsync's semantics for this option's scope |
| ⚠️ Caveat | 13 | Wired and tested, but carries a documented behavioral difference from rsync (named in the row and/or the wave notes) |
| ❌ Divergent | 26 | Rejected, an accepted no-op, deliberately non-rsync (native config/auth/batch, privileged namespaces, safe-subset privilege), or impossible on any portable filesystem call |
| **Total** | **157** | One row per rsync option/feature group; a row may name several spellings |

This matrix reports honest rsync parity, not "implemented" as a synonym for
"parsed". A ✅ row matches rsync for the option's scope. A ⚠️ row is real and
tested but diverges in at least one documented way. An ❌ row is either
rejected (`--protocol` with any value but the current one),
an accepted no-op (`-s`/`--secluded-args`, `--protect-args`, `--old-args`),
deliberately non-rsync and non-interoperable (the FastSync daemon config/auth,
the batch container, `--fake-super`'s xattr format, `--copy-as` credential
switching), or impossible (`-N`/`--crtimes`). The counts are derived from the
rows below; update them together with the table.

**Option wave (protocol 2.26.0 → 2.27.0).** A differential pass against rsync
3.4.1 over the remaining option caveats. `--bwlimit` now parses rsync's units
exactly and paces like rsync's leaky bucket; `--ignore-errors` reproduces
rsync's default (an I/O error skips deletion unless the flag is set, while the
readable tree still transfers and the run exits 23); the `--info` categories
that map to a FastSync event (`name`, `flist`, `del`, `remove`, `nonreg`,
`progress`) now emit rsync's line format, including real-run `deleting PATH` /
`*deleting` lines carried over a new `report_deletes` wire bool; and two
genuinely non-interoperable residuals are reclassified divergent (`-M` over a
daemon/TCP connection, which FastSync's binary config handshake has no argv
channel for, and receiver-side `protect`/`risk` re-derivation for
destination-only entries, which would need a receiver filter engine; the
latter was later implemented in parity track 4a below, so only `-M` over a
daemon remains divergent). After the
combined `fix/parity-stats` + `fix/parity-options` + `fix/parity-fs` passes (and
the later `fix/parity-review` correction that moved `--delete-delay` to ⚠️) the
matrix is **111 ✅ / 13 ⚠️ / 33 ❌ = 157**.

**Parity track 1 (no-wire, on `feat/parity-2.28`).** Three residual burn-downs that required no protocol change: (1) `-n --delete` now propagates the filter-excluded and size-pruned protected prefixes (and the synchronized-directory scope) into the dry-run keep-set manifest, so its would-delete report matches rsync for source-derived protections and no longer lists the file merely being updated (the destination-only exclude/filter residual was closed by track 4a below; readdir ordering remains, leaving the row ⚠️); (2) `--delete-delay` now charges `--max-delete` on actual removals and re-scans a queued directory at commit to remove content created after the plan, with an independent cap bounding the deferred list and the row's prior caveat closed (ordering of partial removals remains, leaving the row ⚠️); and (3) `--info=name2` now emits `NAME is uptodate` and `--info=name` emits the leading `./` root name line (only the root-line trigger condition and the receiver-side `skip` wording remain, leaving the row ⚠️). The matrix is now **111 ✅ / 14 ⚠️ / 32 ❌ = 157**.

**Parity track 2b (no-wire, on `feat/parity-2.28`).** An opt-in, paths-only metadata pre-count for `--progress`/`-P`/`--info=progress` (only when not `--quiet`) now gives the `to-chk` denominator rsync's full file-list total (every regular file, directory, symlink and special plus the transfer root) and emits the per-directory/symlink/special name lines, in both the sequential and `--threads` paths; `--delete-during`/`--delete-delay` reuse their keep-set pre-scan so no second walk happens, and non-progress runs are unaffected. A fresh multi-directory differential against rsync 3.4.1 matches the name set and the `to-chk` denominator, while a single-file transfer stays byte-identical; the remaining caveats are emission order (rsync's sorted depth-first vs FastSync's readdir/BFS stream, so the `to-chk` numerator and interleaving differ) and re-run/receiver-state-driven over-naming (unconditional `./`, ancestor dirs emitted with a transferred child, and no quick-check for symlinks/empty dirs), keeping the row ⚠️. The matrix is unchanged at **111 ✅ / 14 ⚠️ / 32 ❌ = 157**.

**Parity track 3a (no-wire, on `feat/parity-2.28`).** Three codec refinements, none of which change the wire layout (`PROTOCOL_VERSION` stays 2.28.0): (1) an omitted `--compress-level` now resolves to rsync 3.4.1's per-codec default (zstd 3, zlib/zlibx 6, lz4 ignored) and an explicit level is clamped per codec (zstd 1-22, zlib/zlibx 1-9), verified against `rsync --debug=NSTR1`; (2) `auto` now honors `RSYNC_COMPRESS_LIST`/`RSYNC_CHECKSUM_LIST` (rsync's whitespace-separated preference syntax, unknown names skipped, first supported wins, all-unknown is exit 4) before the compiled-in order, with an explicit `--zc`/`--cc` still winning; and (3) `--compress-choice=zlibx` is reclassified out of the caveat list — FastSync's zlib stream already carries only the literal/delta bytes (rsync's zlibx semantics) and is observably identical to `--zc=zlib`, so the zlib/zlibx aliasing is only an implementation detail. The matrix is now **113 ✅ / 12 ⚠️ / 32 ❌ = 157**.

**Parity track 3b (no-wire, on `feat/parity-2.28`).** `--checksum-choice`/`--cc` is reclassified out of the caveat list: its only documented residual was the delta BLOCK strong checksum (rsync applies the negotiated algorithm there; FastSync keeps a fixed xxHash32, `DeltaBlockSig`). A pre-seeded delta-transfer differential against rsync 3.4.1 (probe: `--no-whole-file -B8192 --stats --out-format=%c|%C %n` for rsync vs `--incremental --delta` for FastSync) shows the choice is **not observable** in the surface the parity gate compares — across `xxh64`/`xxh128`/`xxh3`/`md5`/`md4`/`sha1` and both two-name orders the destination tree is byte-identical, the `Matched data`/`Literal data`/`Total transferred file size` counters are unchanged (and, with the block size pinned, equal to rsync's), the `%c` block-checksum token is invariant, and the exit code is 0. The negotiated algorithm is only visible in `%C`, which renders the whole-file transfer digest and is already byte-identical to rsync. No wire field is added (`PROTOCOL_VERSION` stays 2.28.0). The matrix is now **114 ✅ / 11 ⚠️ / 32 ❌ = 157**.

**Parity track 4a (wire, on `feat/parity-2.28`; `PROTOCOL_VERSION` stays 2.28.0).** The receiver now has a filter engine for deletion: the sender compiles its root-level selection rules exactly as the scanner does (`filter_base_build`, covering `--filter`/`-f`, `--exclude`/`--include`, `-C` and the `protect`/`risk`/`hide`/`show` words) and streams them as one bounded, self-describing block appended to the config frame (per rule: action, sides, anchored, dir-only, negate, owner, pattern; strictly validated with a bounded rule count and total pattern+owner bytes, and an unknown action/sides is a protocol error). The receiver reconstructs `protect_rules` and evaluates them first-match-wins against each extraneous destination path in every delete timing — the whole-tree commit walker (plain `--delete`/`--delete-before`/`--delete-after`), the `--delete-during`/`--delete-delay` per-directory plans, and the `-n` would-delete enumeration — so a `protect`/`P` rule now shields a DESTINATION-ONLY entry that never appeared on the sender, with `risk`/`R` cancelling. The existing sender-derived protected-prefix behavior is preserved when no rules are sent (and for source-derived protections), and `--delete-excluded` semantics are unchanged. Per-directory merge (`:`/`.`) receiver-side re-derivation is the remaining residual: those rules are still enforced only through the sender-derived protected prefixes, so a destination-only entry matching ONLY a per-directory merge rule is not yet shielded (the `-F` row keeps this documented). Differential-tested against rsync 3.4.1: `filter_protect`, `filter_protect_during`, `filter_protect_delay` (`-a --delete[-during|-delay] --filter='P *.log'` over seeded destination-only `.log` extras) plus a FastSync regression test for the dry-run would-delete enumeration (`TestFilterProtect`). The `--filter=RULE` row moves ❌ → ✅. The matrix is now **115 ✅ / 11 ⚠️ / 31 ❌ = 157**.

**Parity track 5a (wire, on `feat/parity-2.28`; `PROTOCOL_VERSION` stays 2.28.0 by project decision).** The three basis-dir options (`--compare-dest`/`--copy-dest`/`--link-dest`) now default to rsync's metadata quick-check instead of FastSync's historical xxHash64 content equality: a basis hit is accepted on equal size plus equal mtime (or size alone under `--size-only`; `-I` disables matching), so a same-size/different-content basis is trusted exactly as rsync trusts it. A new FastSync-only, long-only `--verify-basis` flag restores the stricter whole-file content equality, and its bool is appended to the basis block of the config frame (the golden wire frame grew by one int to 886 bytes; still 2.28.0). `--verify-basis` hashes the basis by streaming its confined descriptor, so an arbitrarily large basis is verified without buffering. Basis materialization is also no longer capped at the 256 MiB whole-file payload bound: a `--copy-dest` hit streams the basis through a bounded buffer, a `--link-dest` copy fallback streams from the basis, and a hit of any size is materialized (a basis MISS still falls back to the normal transfer, which keeps its own bound). A `--copy-dest` hit re-applies the SOURCE attributes (the sender now transmits the source metadata with the basis check frame), matching rsync's "copy then fix attributes"; a `--link-dest` success keeps the shared inode's own attributes exactly as before (writing through the shared inode would mutate the basis). The `--compare-dest`/`--copy-dest`/`--link-dest` rows move ❌ → ⚠️ (residuals: the relative-DIR resolution base and the over-limit MISS refusal). The matrix is now **116 ✅ / 13 ⚠️ / 28 ❌ = 157**.

**Parity track 5b (no-wire, on `feat/parity-2.28`; `PROTOCOL_VERSION` stays 2.28.0 by project decision).** `-y`/`--fuzzy` is reclassified ❌ → ⚠️: the receiver-side similar-file basis is an internal bandwidth optimization (the config `fuzzy` bool over the existing receiver-driven delta handshake, unchanged since 2.9.0), and the transferred tree is byte-exact by design regardless of which basis — or no basis — is chosen. A probe against real rsync 3.4.1 showed the remaining difference is not the name rule (FastSync already ports `util1.c fuzzy_distance`/`find_filename_suffix` plus the exact size+mtime pass) but candidate ELIGIBILITY: rsync will pick a fuzzy basis whose size ratio to the source is unrestricted (empirically from 0.25× to 10000×, and for files as small as 300 B), while FastSync's `delta_should_attempt` gate caps the ratio at 10× and requires both files ≥ 16 KiB, so an out-of-window sibling is declined and the file is sent whole. The choice is observable only as bandwidth (`Matched data`/`Literal data`/`Total transferred file size` in `--stats`); the destination tree and exit code are identical either way. A new differential case (`fuzzy_basis`: same-suffix sibling one name-edit away, content identical, block size pinned to 8192) asserts tree **and** normalized `--stats` parity where the two tools' choices coincide; `TestFuzzy` pins the window boundary on both sides (a >10× and a <16 KiB sibling are declined by FastSync while rsync uses them, both trees byte-identical). No wire field changed. The matrix is now **116 ✅ / 14 ⚠️ / 27 ❌ = 157**.

**Lockstep track 6 (delete default; `PROTOCOL_VERSION` stays 2.28.0).** Plain `--delete` with no explicit timing flag now defaults to rsync's delete-during (`--del`) timing: the client normalizes it onto the existing `delete_during` wire bool in `cli_finalize_config`, so no config-frame field was added, and a tight destination no longer has to hold the whole old+new tree at once (the old atomic commit could hit `ENOSPC`). The old late whole-tree commit is opt-in via `--delete-after` or the FastSync-only long spelling `--delete-commit`, which selects the identical `delete_after` timing (documented equivalence). Precedence is unchanged and order-independent: each timing flag implies `--delete`, at most one timing flag may be given, and a timing flag with `--no-delete` is rejected. `-d/--dirs` still falls back to the end commit; `--delay-updates` still deletes genuine extras before publication (the per-directory skip list protects the staging dir); `--files-from`/`-R` scope is unchanged. The per-directory `STATUS_DELETE_PLAN` frame gained a one-int `apply` flag (still 2.28.0): the one-shot per-run config block (protected prefixes, size-pruned mirrors, `--delete-missing-args` exact paths) is now always sent first on a config-only carrier with `apply=false`, fixing a latent bug where a `--delete-missing-args` run whose `--files-from` list synchronized no directory never transmitted its exact deletions. Differential evidence: `delete` (plain, vs rsync's default), `delete_commit` (FastSync `--delete-commit` vs rsync `--delete-after`), and `filter_protect_after` (whole-tree protect) cases; `TestDeleteTimingFinalStateParity` compares plain `--delete`/`--delete-commit` against rsync on completed runs, and `TestDeleteTimingFailure` proves plain `--delete` removes reached extras on a mid-transfer abort while `--delete-commit` removes nothing. The matrix is unchanged at **116 ✅ / 14 ⚠️ / 27 ❌ = 157** (the `--delete`/`--delete-during` rows stay ⚠️ for the abort boundary; `--delete-after` stays ✅).

**Parity cycle 2.29 (on `feat/parity-2.29`; `PROTOCOL_VERSION` stays 2.28.0 — no wire change was needed).** Five independent residuals were closed and four rows moved to ✅:
- **Scanner order.** The sequential scanner now buffers and sorts each directory's inspected entries (non-directories ascending, then directories ascending) and walks them depth-first, reproducing rsync 3.4.1's flist order. This makes the `--info=name` transfer order, the `--delete-during`/`--delete-delay`/`-n` would-delete order, and the partial-`--max-delete` survivor set byte-identical to rsync (`test_parity_order.py`). `--threads` has no rsync analogue and stays unordered.
- **Delete timing.** The complete per-directory plan set is transmitted before the first data frame, so a mid-transfer abort has already removed every planned extra like rsync's generator; `-d/--dirs` uses the same per-directory plans (shielded untraversed subdirectories) instead of the end-of-transfer commit (`test_delete_boundary_parity.py`). `-n`/`--delete`/`--del`/`--delete-delay` move ⚠️ → ✅.
- **Basis relative-DIR.** A relative `--compare-dest`/`--copy-dest`/`--link-dest` DIR resolves against the destination directory with the transfer-relative name appended, exactly like rsync (`test_parity_basis_fuzzy.py`); the >256 MiB basis-MISS limit remains (a general whole-file limit, not basis-specific).
- **Fuzzy eligibility.** The `-y/--fuzzy` candidate search no longer inherits the ordinary delta engine's 16 KiB minimum or 10× ratio bound, so an oversized or sub-16-KiB sibling is reused as rsync reuses it (`test_parity_basis_fuzzy.py`).
- **Output partials.** `--info=mount`/`--info=stats`, the `--stats` `dir:` breakdown under `-r`, and real `--debug` output for `flist`/`del`/`hash`/`deltasum`/`recv`/`filter`/`send` were added (`test_parity_info_mount_stats.py`, `test_output_parity.py`, `test_parity_debug.py`); those rows stay ⚠️ for their remaining documented residuals. `--delete-before`'s phase-0 late-file divergence and the `--progress` root/ancestor/symlink feedback remain open (they need a receiver→sender event channel), and the >256 MiB single-file streaming limit (B4) was not addressed. The matrix is now **120 ✅ / 10 ⚠️ / 27 ❌ = 157**.

**Audit cycle (no wire change; `PROTOCOL_VERSION` stays 2.28.0).** A security-and-correctness audit pass ran against the parity-2.29 baseline, followed by a set of audit follow-ups (filter merge modifiers, the `--inplace`/`--partial-dir` conflict, credential-file hardening, and small leak/log/test fixes). The only classification change is `--filter=RULE` moving ✅ → ⚠️, because its merge-only `e`/`n`/`w`/`-` modifiers are now accepted and consumed but their semantics remain unimplemented (accepted-but-ignored); the matrix is therefore **119 ✅ / 11 ⚠️ / 27 ❌ = 157**. The affected rows (`-z`/`--compress`, `--bwlimit`, `-T`/`--temp-dir`, `-p`/`--chmod`, `--partial-dir`, `--filter`) had their notes updated in place. A later triage cycle moved `-F` and `-i` ✅ → ⚠️ (see the triage-cycle note below), giving **117 ✅ / 13 ⚠️ / 27 ❌ = 157**:

- **Decompression ceiling.** `MAX_DECOMPRESSED_SIZE` was 100 MiB while the receiver advertises and the sender compresses whole files up to `MAX_RECEIVE_WHOLE_FILE_SIZE` (256 MiB), so `-z` on a 100–256 MiB regular file failed with `Declared decompressed size exceeds 104857600 bytes`. The ceiling is now defined in terms of the protocol whole-file bound (still a real allocation-clamped bomb guard), so the two cannot drift; `-z` on 100–256 MiB files now works.
- **`--bwlimit` with `--sendfile`.** The plaintext-TCP `--sendfile` fast path wrote through `sendfile(2)` without passing through the protocol's token bucket, so `--bwlimit` was ignored on that path. It is now paced through the same per-session leaky bucket, so TLS and plaintext transports share identical `--bwlimit` semantics.
- **`--temp-dir` confinement.** The receiver's scratch dir was opened with a bare `open()`, so a client-planted symlink under the receive root could redirect receiver scratch files outside the authorized root. The opened directory is now judged by the real path of its fd (`/proc/self/fd` via `realpath`), and an escaping target is refused (`EACCES`, logged); an in-root link to another filesystem (the `EXDEV` fallback case) still works.
- **Special-bit masking and daemon umask.** Setuid/setgid/sticky bits from the client (`--perms`, `--chmod`, symlink and special-node paths, deferred directory modes) were applied even when the connection forbade super-user activities. They are now stripped when the super policy is off (`FileAttrPolicy.super_permitted`), and exact rsync semantics are preserved when permitted. The daemon's forced `umask(0)` is now `umask(022)`, so implied parent directories are no longer world-writable `0777`.
- **`--partial-dir` implies `--partial`.** Matching rsync 3.4.1 (which sets `keep_partial` after option parsing), `--partial-dir=DIR` alone now retains an interrupted transfer's partial and wins over an explicit `--no-partial`; `--inplace` still bypasses the partial machinery, and combining `--inplace` with `--partial-dir` is now rejected up front with rsync's message (`--inplace cannot be used with --partial-dir`) instead of silently ignoring the partial dir.
- **Filter modifiers.** The `x` xattr-name modifier is rejected everywhere with a clear error. The merge-only `e`/`n`/`w` and `-` modifiers are now accepted and consumed on `merge`/`dir-merge` rules (so they no longer leak into the merge filename) while still being rejected on non-merge rules, matching rsync; their semantics remain unimplemented (accepted-but-ignored). Glued patterns (`-newfile`, `-e2e`) and mixed tokens (`H,!secret`) keep their historical parsing.
- **Bounds and wire validation.** `--filter` rule count is now checked client-side against `MAX_FILTER_RULES` (with an actionable message before any network I/O) rather than surfacing as an opaque receiver protocol error; `send_protect_entries()` still re-checks the expanded count. Unknown wire `Status` values are rejected as protocol errors (`status_is_valid()`), and the audit also fixed a mutex leak on an init-failure path, an `errno`-after-`free()` in deferred delete application, `log_perror` misuse for non-`errno` conditions, `SSL_read` length clamping, `sendfile` `poll` `EINTR` retry, and printf-format/attribute issues.
- **Credential-file hardening follow-up.** `secret_file_open()` now opens `--password-file`/`--early-input`/`--hash-credentials` inputs with `O_NOFOLLOW`, so a symlinked credential path fails closed (`ELOOP`) instead of being followed before the owner/mode gate; literal fd-backed paths (`/dev/fd/<digits>`, `/proc/self/fd/<digits>`, which is what a bash process substitution passes) are exempt, so process substitution still works. A FIFO/process-substitution read now waits under a bounded ~3 s deadline for its writer, so a slow producer works while a connected-but-silent FIFO fails instead of hanging. The follow-up also fixed a `config_create` allocation leak on its `server_host` failure path (`config_delete` now releases it), corrected the decompression-limit log message to print the effective bound rather than the compile-time ceiling, and hardened the daemon umask/root test fixtures.

**Triage cycle (no wire change; `PROTOCOL_VERSION` stays 2.28.0).** A documentation-and-correctness triage pass over the parity baseline corrected stale prose and reclassified two rows that carried a real behavioral residual: `-F` moves ✅ → ⚠️ (its own note already documented that per-directory merge rules are not carried to the receiver filter engine, so a destination-only entry matching ONLY a `.rsync-filter` rule is not shielded from `--delete`), and `-i`/`--itemize-changes` moves ✅ → ⚠️ (directory and transfer-root lines are now emitted, but the root `./` line is emitted unconditionally and an incremental re-run itemizes directories/symlinks that rsync's quick-check leaves silent). The matrix is **117 ✅ / 13 ⚠️ / 27 ❌ = 157**.

**Parity completion wave (protocol 2.23.0 → 2.26.0).** This wave closed the
remaining gaps the rsync-parity wave left open (delete timing, wire counters and
output, codec breadth, general `-R`/`-d`, the filter grammar (the unsupported
`x` xattr-name modifier is explicitly rejected everywhere, while the merge-only
`e`/`n`/`w`/`-` modifiers are accepted and consumed on merge/dir-merge rules and
rejected elsewhere — see the audit-cycle follow-up note above), receiver-side
name resolution, absolute basis dirs, and the remaining client quick wins) and
reclassified the inherently non-rsync rows as **divergent** (native daemon
config/auth, the non-interoperable batch container, `--fake-super`'s xattr
format, `-X`'s privileged namespaces, and the safe-subset device/privilege
flags). It moved `PROTOCOL_VERSION` three times (`2.23.0 → 2.24.0` delete
timing, `2.24.0 → 2.25.0` wire stats, `2.25.0 → 2.26.0` codecs). See the
**Parity Completion Wave (protocol 2.26.0)** section near the end for the full
list and the remaining limitations.

**Previous wave — rsync-parity (protocol 2.23.0).** That wave wired up
the short options `-r`, `-b`, `-L`, `-B`; rsync short-option clustering
(`-av`, `-aAX`, `-rlpt`) and attached/inline values (`--opt=value`, `-B1000`,
`-essh`, `-MOPT`); `-c` now implies the checksum quick-check; and the codec
and choice limits it introduced were broadened by the completion wave.
Every one of those has an entry below with its remaining caveats.

---

## 1. General Options

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-a`, `--archive` | Archive mode is -rlptgoD (rsync includes owner/group) | ✅ Parity | Phase 7 Wave A: real rsync archive. `-a`/`--archive` now implies `--links` + the four per-attribute preserve flags (perms/times/owner/group) + `--devices` + `--specials`, i.e. **`-rlptgoD`**. Owner/group **are** implied, but their application stays privilege-gated exactly like rsync: a receiver that cannot `chown` logs a warning and skips it (see the preserve-attribute split note below). FastSync is always recursive, so no `-r` is needed. It no longer implies compression or multithreading (those moved to `-z`/`-j`). The short-option namespace is now rsync-parity (see the Phase 7 note) |
| `-v`, `--verbose` | Increase verbosity | ✅ Parity | Sets `log_level=DEBUG` |
| `-q`, `--quiet` | Suppress non-error messages | ✅ Parity | Suppresses client output while preserving errors |
| `--help` | Show help | ✅ Parity | Prints usage and exits. A lone `-h` with no other transfer arguments also prints help (protocol 2.26.0), matching the rsync idiom; `-h` alongside a transfer keeps its rsync meaning of `--human-readable` (see that row) |
| `-V`, `--version` | Print version | ✅ Parity | |
| `--info=FLAGS` | Fine-grained info verbosity | ⚠️ Caveat | Accepts rsync 3.4.1's full `--info` vocabulary — `backup`, `copy`, `del`, `flist`, `misc`, `mount`, `name`, `nonreg`, `progress`, `remove`, `skip`, `stats`, `symsafe`, `all`, `none` — with optional level suffixes (`--info=stats2`), so a valid rsync invocation is never rejected up front. Protocol 2.27.0 wires the categories that map to a real FastSync event, matching rsync's line format: `name` prints the updated entry names (with the ` -> target` link suffix), `flist` prints `sending incremental file list`, `del` prints `deleting PATH` (or `*deleting   PATH` under `-i`/`--out-format`) for both dry-run would-delete and real deletions (real runs carry the removed paths over the new `report_deletes` wire bool), `remove` prints `sender removed PATH`, `nonreg` prints `skipping non-regular file "NAME"`, `progress` drives the per-file progress output, `copy`/`misc`/`skip` keep their existing channels, `stats` enables the same transfer-statistics block as `--stats`, and `mount` prints rsync's `[sender] skipping mount-point dir NAME` when `-xx` drops a mount-point directory (plain `-x` keeps the empty directory entry and stays silent, matching rsync; both differential-tested). `none` suppresses info output, explicit flags override `--verbose`, and a genuinely unknown name is still rejected by name (matching rsync). **Fixed (no-wire):** `--info=name2` (and higher) also prints rsync's `NAME is uptodate` lines for entries the receiver already has, and `--info=name` emits the leading transfer-root `./` name line before the first transferred entry (the marker rides in the existing `info_level` bitset; differential tests vs rsync 3.4.1). **Caveat:** the root `./` line is emitted before the first transferred name rather than keyed off rsync's root-attribute-change decision, so a pre-existing root that rsync leaves untouched can differ; the categories with no client-observable event stay accepted-but-silent — `symsafe` and `backup` (the backup happens on the receiver, which FastSync's protocol does not echo back); and `skip` maps to FastSync's sender-side skip logging rather than rsync's receiver-side "not creating new file" lines |
| `--debug=FLAGS` | Fine-grained debug verbosity | ⚠️ Caveat | Protocol 2.26.0 accepts rsync 3.4.1's full `--debug` vocabulary with optional level suffixes. FastSync emits for its own channels (`io`, `proto`, `pack`, `util`, plus the aliases `hl`/`owner`) and maps the remaining categories that have a natural FastSync event onto real debug output: `flist` (per-directory scan progress), `del` (receiver-removed paths, riding the existing `report_deletes` wire bool), `hash`/`deltasum` (whole-file hashing and delta-sum generation), `recv` (receiver verdicts/signatures), `filter` (selection/exclusion decisions) and `send` (files handed to the sender). A normal run prints none of it; `--debug=help` lists the flags and a genuinely unknown name is rejected by name. **Caveat:** the output is FastSync's own timestamped debug format (it does not reproduce rsync's exact per-category lines), and the synthetic/rsync-internal categories (`acl`, `backup`, `bind`, `time`, ...) stay accepted-but-silent, so the row remains ⚠️ |
| `--stderr=MODE` | Change stderr output mode | ❌ Divergent | `errors` (default) and `all` are supported; `client` is rejected with a clear error (`--stderr=client is not supported`) because FastSync has no rsync client-message channel — the rejection itself is the documented behavior (Phase 7 Wave B decision). The modes that exist work; the missing rsync channel cannot be emulated without a wire change |
| `--msgs2stderr`, `--no-msgs2stderr` | Deprecated `--stderr` aliases | ⚠️ Caveat | `--msgs2stderr` maps to `--stderr=all` (supported, matching rsync). `--no-msgs2stderr` is rsync's spelling of `--stderr=client`, which FastSync has no client-message channel for, so it maps to the errors-only default instead of reproducing rsync's client mode. See `--stderr=MODE` |
| `--no-motd` | Suppress daemon MOTD | ✅ Parity | Client-only display switch (Wave C): the daemon still sends the configured `motd file` on a `host::module/path` connection; the client reads and discards the frame without showing it. Without the flag the MOTD is printed to stdout after the config/auth handshake and escaped so control bytes cannot inject terminal sequences |
| `--exclude=PATTERN` | Exclude files matching pattern | ✅ Parity | Glob matching in scanner |
| `--include=PATTERN` | Include files matching pattern | ✅ Parity | Glob matching in scanner |
| `-C`, `--cvs-exclude` | Auto-ignore CVS files | ✅ Parity | Applies the well-known rsync default exclude set as exclude rules during scanning (RCS SCCS CVS CVS.adm RCSLOG cvslog.* tags TAGS .make.state .nse_depinfo *~ #* .#* ,* _$* *$ *.old *.bak *.BAK *.orig *.rej .del-* *.a *.olb *.o *.obj *.so *.exe *.Z *.elc *.ln core .svn/ .git/ .hg/ .bzr/); `.git/`-style repo dirs are pruned without descending |

## 2. Modifying Output

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--stats` | Give transfer stats | ⚠️ Caveat | Prints transfer statistics. Protocol 2.25.0 populates the receiver-only counters the sender cannot observe (`Matched data`, `Number of deleted files`) from the receiver's `STATUS_STATS` report; the sender tracks the scanned file list per type so `Number of files` carries rsync's `(reg: X, dir: Y, link: Z, special: W)` breakdown (directories come from the scanner's captured directory list for `-a`/`-t`/`-p`, or from a lightweight traversed-directory counter on a plain `-r` run so the `dir:` category is present there too), `Number of regular files transferred` excludes symlinks/specials and up-to-date files, `Total file size` includes symlink target lengths, and `Total transferred file size` counts only transferred files. **Protocol 2.28.0 extends `STATUS_STATS`** with receiver-observed `literal_bytes` and the four `created_*` counters: `Number of created files` now carries rsync's `(reg/dir/link/special)` breakdown (the receiver reports which destination entries it newly created, including implicitly-created parent directories below the transfer root) and `Literal data` is exact for a delta transfer (the receiver counts the literal fragments it stored, not the whole source size) — all differential-tested in the sequential and `--threads` paths against rsync 3.4.1 for fresh-create, update and delta shapes. **Remaining divergences:** rsync's per-type breakdown on `Number of deleted files` is not reproduced; and `Total bytes sent`/`received` are FastSync wire bytes framed differently from rsync's, so they are not numerically comparable |
| `-h`, `--human-readable` | Human-readable numbers | ✅ Parity | Formats transfer byte and rate counts using rsync's **decimal** (base-1000) units, matching rsync `-h` (e.g. `1.23M`), not binary units. **A lone `-h` with no transfer arguments prints help instead** (protocol 2.26.0), matching the rsync idiom; `-h` alongside a transfer remains human-readable |
| `-i`, `--itemize-changes` | Per-file change summary | ⚠️ Caveat | Prints rsync-style itemize lines to stdout for files actually sent (also under `-j`/`--threads`). Directory and transfer-root lines are now emitted too: a run produces rsync's `./` root line and per-directory `cd+++++++++`/`.d..t......` lines, rendered by the shared itemize code. **Residual:** the root `./` line is emitted unconditionally rather than keyed off rsync's root-attribute-change decision; **every** non-root directory is rendered as created (`cd+++++++++`) because the sender never probes a directory's destination state, so a pre-existing destination directory that rsync reports as unchanged (`.d..t......`) is still itemized as created — this is not limited to re-runs; an incremental re-run additionally itemizes directories/symlinks that lack a quick-check where rsync stays silent (unchanged regular files still print nothing, matching single-`-i`); and directory attribute columns (`%M`/`%U`/`%G`) come from the source |
| `--progress` | Show progress | ⚠️ Caveat | Protocol 2.25.0 prints rsync-style per-file progress blocks (percent, transferred/total bytes, rate, elapsed, `(xfr#N, to-chk=M/T)`) fed by the receiver's `STATUS_STATS`, in both the sequential and `--threads` send paths. FastSync also prints rsync's leading `./` transfer-root line and, when progress is requested (`--progress`/`-P`/`--info=progress`) and not `--quiet`, runs a **paths-only metadata pre-scan** (no file reads, no hashing) that supplies rsync's file-list total `T` for the `to-chk` denominator and the directory names; `--delete-during`/`--delete-delay` reuse their existing keep-set pre-scan instead of walking twice, and non-progress runs are untouched. Per-directory name lines are emitted (trailing `/`), and symlink (` -> target`) and special entries are named too, so a **fresh multi-directory tree's name set and `to-chk` denominator match rsync 3.4.1** (differential test, sequential and `--threads`) and a **single-file transfer's name lines and deterministic frames remain byte-identical** to rsync. **Order parity (parity-2.29):** the sequential scanner now emits entries in rsync's sorted depth-first flist order (non-directories ascending, then directories ascending), so the interleaving and the `to-chk` numerator match rsync for the default single-threaded transfer (differential `test_parity_order.py`; `--threads` has no rsync analogue and stays unordered). **Remaining divergences:** the leading `./` root line is emitted unconditionally rather than keyed off rsync's root-attribute-change decision, and an ancestor directory line is emitted whenever a child transfers (rsync suppresses it when the directory itself is unchanged); on a re-run, entries without a quick-check (symlinks, empty directories) are still named where rsync stays silent; and the rate/ETA are wall-clock dependent |
| `-P` | Same as --partial --progress | ✅ Parity | Parses to `--partial` + `--progress`. The independent `--partial` retention semantics are rsync parity: an interrupted write retains the already-written temp at the destination (best-effort) so a later `--append`/`--append-verify` can resume. Progress presentation is owned by the `--progress` row; there is no separate `-P` divergence |
| `--out-format=FORMAT` | Custom output format | ❌ Divergent | Per-transfer template on stdout; tokens `%f` `%n` `%l` `%b` `%c` `%C` `%i` `%M` `%o` `%U` `%G` `%t` `%%`. `%C` now uses the negotiated transfer algorithm (`--checksum-choice`, default `xxh128`, seed 0) and renders every algorithm exactly like rsync — xxh128 high-then-low, xxh64/xxh3 big-endian, md5/md4/sha1 standard hex, `none` a blank 2-char column — differential-tested across all algorithms. `%f`/`%n`/`%l`/`%i`/`%M`/`%U`/`%G`/`%B` also match. **Reclassified because `%b`/`%c` are protocol-specific and cannot match:** a differential against rsync 3.4.1 shows whole-file `%c = 16` for both, but rsync whole-file `%b = filesize + 27 + transfer-digest-bytes` (39 for a 0-byte file; 43/35/47 for xxh128/xxh64/sha1 on a 12-byte file) while FastSync `%b` counts its own framing; in delta mode rsync `%c = 16 + 6·ceil(filesize/block_size)` (verified at block sizes 512/700/1024/2048) while FastSync counts its own signature handshake, and rsync `%b` is its token stream. FastSync's wire bytes are a different quantity, so exact `%b`/delta-`%c` equality is impossible. Directory and transfer-root lines are now emitted (rsync's `./` root line and per-directory `cd...`/`.d..t...` lines), with the same residual as `-i`: the root line is emitted unconditionally, every non-root directory renders as created because the sender does not probe directory destination state (so a pre-existing unchanged directory still shows `cd+++++++++`), and directory attribute columns (`%M`/`%U`/`%G`) come from the source |
| `--log-file=FILE` | Log to file | ✅ Parity | `log_file` config field |
| `--log-file-format=FMT` | Log format | ✅ Parity | Requires `--log-file`; writes one template line per transferred file using the same token set as `--out-format` (including `%b` as the wire byte count) |
| `--8-bit-output`, `-8` | Leave high-bit chars unescaped | ✅ Parity | Applies to displayed paths and protocol debug output |
| `--list-only` | List files instead of copying | ✅ Parity | `ls -l`-style listing of files that would be transferred; scans the source only, contacts no server, writes nothing; also works with `-n` |

## 3. File Selection

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--exclude-from=FILE` | Read exclude patterns from file | ✅ Parity | Reads patterns from file |
| `--include-from=FILE` | Read include patterns from file | ✅ Parity | Reads patterns from file |
| `--filter=RULE` | Add file-filtering rule | ⚠️ Caveat | The short `-f` **is** bound to `--filter` (the old FastSync sendfile conflict is gone; sendfile is long-only `--sendfile`), and `-f RULE`, `-f=RULE`, `--filter=RULE` and the two-argument form all parse. Protocol 2.26.0 implements rsync's filter grammar: `+`/`-`, `include`/`exclude`, a leading `/` anchor (to the transfer root or a `.rsync-filter` file's directory), a trailing `/` dir-only rule, and the `merge`/`.`, `dir-merge`/`:`, `hide`/`H`, `show`/`S`, `protect`/`P`, `risk`/`R` and `clear`/`!` words, including the `:`/`.` modifiers. The xattr-name `x` modifier is **explicitly rejected everywhere with a clear error**. The merge-only `e`/`n`/`w` and `-` modifiers are **accepted and consumed on `merge`/`dir-merge` rules** (so they no longer leak into the merge filename) while still being **rejected on non-merge rules**, matching rsync; their semantics remain unimplemented, so they are accepted-but-ignored (the reason this row is a caveat rather than parity). A token made up solely of modifier characters that names an unsupported modifier is rejected on non-merge rules, while glued patterns (`-newfile`, `-e2e`) and mixed tokens (`H,!secret`) keep their historical parsing. First match wins; the filter layer is independent of `--exclude`/`--include`. **Track 4a (protocol 2.28.0) adds the receiver filter engine:** the sender compiles its root-level rules exactly as the scanner does (`filter_base_build`) and streams them as one bounded, self-describing config-frame block; the receiver reconstructs them and re-applies first-match-wins to every extraneous destination path during deletion, so a `P *.log` rule protects a destination-only `extra.log` (differential `filter_protect`/`filter_protect_during`/`filter_protect_delay` vs rsync 3.4.1, plus the `-n` would-delete enumeration) — matching rsync's dual-sided engine for the command-line rule set. **Remaining residual:** per-directory merge (`:`/`.`, and therefore `-F`) is not yet re-derived on the receiver; a destination-only entry that matches ONLY a per-directory merge rule is still protected only through the sender-derived source-mirror prefixes, not by the received base rule list |
| `--files-from=FILE` | Read source file list from file | ✅ Parity | Entries are paths relative to the source root (leading `./` stripped, `..`/absolute rejected at parse time, blank lines ignored; NUL-delimited with `-0`). A listed regular file is transferred; a listed directory transfers its whole subtree (FastSync recursion is always on). Non-listed paths are pruned by the scanner; the delete manifest is scoped to the listed directory subtrees. A listed entry that does not exist is a hard error unless `--ignore-missing-args`/`--delete-missing-args` is given. **An empty list is a zero-transfer success (exit 0), matching rsync 3.4.1** — the earlier claim that rsync reports "no source files specified" was wrong. Scalability note: `file_list_affects` is O(list size) per scanned entry, so a very large list against a huge tree is quadratic (the documented bound) |
| `-0`, `--from0` | Delimit *-from files with NULs | ✅ Parity | `--files-from` entries become NUL-delimited; the flag may appear before or after `--files-from` on the command line. NUL mode preserves entry bytes exactly (trailing CR/LF are part of the name; only newline mode trims them) |
| `--max-size=SIZE` | Skip files larger than SIZE | ✅ Parity | `max_size` in scanner |
| `--min-size=SIZE` | Skip files smaller than SIZE | ✅ Parity | `min_size` in scanner |
| `-I`, `--ignore-times` | Don't skip files matching size+time | ✅ Parity | `ignore_times` config field (crosses the wire). Disables the size+mtime quick-check in the `--incremental` per-file handshake and the basis-dir quick-match, forcing the file to be transferred rather than skipped as unchanged. Receiver-side policy: `match_by_metadata` (file_receive.c) is bypassed, so the receiver never replies `STATUS_OK` for a matching size+mtime. Requires `--incremental` to have the handshake to act on (rsync does its quick check by default; FastSync's `-I`/`--size-only`/`--modify-window` only take effect under `--incremental`, exactly like they take effect through the basis check) |
| `--size-only` | Skip based on size only | ✅ Parity | With `--incremental`, ignores mtime. Applies identically to the basis-dir quick-check (track 5a): a same-size basis is a hit on size alone, and under the FastSync-only `--verify-basis` the content digest is still required (size-only drops the mtime leg, never the explicit verify) |
| `-@`, `--modify-window=NUM` | Mod-time comparison accuracy | ✅ Parity | Whole-second tolerance with nanosecond-aware comparisons |
| `--existing` | Skip creating new files on receiver | ✅ Parity | Existing destination files continue through normal update handling. The rsync man-page alias `--ignore-non-existing` sets the same flag |
| `--ignore-existing` | Skip updating existing files | ✅ Parity | `ignore_existing` config field (crosses the wire; receiver-side policy). Protocol 2.26.0 short-circuits in the per-file check **before any payload**: when the destination entry already exists, the receiver answers the skip during the incremental handshake instead of letting the sender stream data that would be discarded, so an existing 4 MiB destination costs only the config/check frames (verified with a counting proxy, matching rsync). The write-time paths (regular, delay-updates-staged, hardlink-sibling, special/device) still return `FILE_SAVE_SKIPPED` without overwriting, and `--backup` is disabled for skipped files. Like rsync, it does not apply to directories/symlinks. Combines with `-j`/`--threads` and `--delay-updates` |
| `--remove-source-files` | Sender removes regular files after confirmed transfer | ✅ Parity | |
| `-x`, `--one-file-system` | Do not cross filesystem boundaries | ✅ Parity | Sender scanner captures the root device and does not descend into mount-point crossings (`st_dev` differs). **Protocol 2.23.0 matches rsync's entry emission:** the mount-point directory itself is emitted as a payload-less directory entry (so the destination gets an empty directory) while its contents are skipped; previously the crossing subdirectory was dropped entirely |
| `-F` | Add the default `.rsync-filter` rules | ⚠️ Caveat | Reads one filter rule per line from each directory's `.rsync-filter` file during traversal and applies it to that directory's subtree; the current directory's rules are evaluated before its ancestors', so deeper files override shallower ones and per-directory files override the command-line `--filter`/`-C` base by default (first match wins). **A single `-F` transfers the `.rsync-filter` files themselves, matching rsync; a repeated `-FF` additionally excludes them** (rsync 3.4.1's `-F`/`-FF` are exactly these two rules, with no `.cvsignore` branch). Unsupported/unparseable rules inside a per-directory file fail the scan with a clear error. **Residual (track 4a):** per-directory rules are still enforced receiver-side only through the sender-derived source-mirror protected prefixes; the base-rule receiver filter engine does not carry per-directory rules, so a destination-only entry matching ONLY a `.rsync-filter` rule is not yet shielded from `--delete` |

## 4. Directory Options

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-r`, `--recursive` | Recurse into directories | ✅ Parity | Default behavior |
| `-R`, `--relative` | Use relative path names | ✅ Parity | Protocol 2.26.0 implements rsync's general `-R` path semantics: without a cut the source argument is mirrored in full below the destination root; a `/./` cut in the source argument (`src/./foo`) makes everything after the cut the destination prefix, so the layout matches rsync's relative reconstruction; and `--files-from` entries land under their bare relative path. The delete manifest derives from the sent (relative) paths and is scoped to the transferred prefix subtree, so `--delete` cannot remove destination content outside that prefix (a blocker fix). Works single-threaded and under `-j`/`--threads` |
| `--no-implied-dirs` | Don't send implied dirs with -R | ✅ Parity | With `-R`, rsync creates the ancestor directories implied by a listed path and, with `--no-implied-dirs`, omits their attributes from the transfer so they keep the destination's own state (or are created with default attributes when absent). Protocol 2.26.0 matches this: without `--files-from` the implied-dir walk applies per-attribute metadata only to explicitly transferred directories, and with `-R --files-from` a listed file whose parent is not itself listed is placed normally — the missing implied parent is created with default attributes (not the source's) and the file transfers with `rc 0`, exactly like rsync 3.4.1 (a differential test verifies the modes and mtimes with and without the flag). Works single-threaded and under `-j`/`--threads` |
| `-d`, `--dirs`, `--old-dirs`, `--old-d` | Transfer dirs without recursing | ✅ Parity | Protocol 2.26.0 implements rsync's one-level `-d` listing for `dir`, `dir/` and `.`: the source's immediate contents are transferred (files with content, directories as explicit entries), matching rsync's destination tree in a differential test. `--dirs --files-from` transfers exactly the listed items — a listed directory is created empty and a listed file with content — under the same `-R` layout rules. A plain recursive scan also recreates empty source directories now: the scanner emits a payload-less directory entry (with metadata) for every traversed directory that produced no transferred or descended child, unless `-m/--prune-empty-dirs` suppresses it or the run is `--files-from`/`--list-only` (a directory emptied by filtering is recreated too, matching rsync). Directory entries cross as `STATUS_MKDIR` and appear in the delete manifest, so `--delete` prunes correctly and an empty listed directory survives; an incoming directory replaces a destination regular file (rsync removes the non-directory and creates the directory), verified differentially. Directory times are applied at the end of the transfer; modes/ownership follow the per-attribute policy. Under `--delay-updates` directories are created immediately while only regular files are staged, exactly as rsync does |
| `--mkpath` | Create missing path components | ✅ Parity | Wire option (client → server). At connection start the server creates the client's destination root directory (and any missing leading components below its own authorized root) when `--mkpath` is set, failing the connection cleanly if it cannot. Without `--mkpath` a destination root that does not exist yet is rejected up front (rsync semantics), so the flag is the only way to transfer into a not-yet-created destination directory. Creation is confined by the same secure mkdir walk as file writes (`O_NOFOLLOW`, no `..`) |
| `--inc-recursive`, `--no-inc-recursive` | Incremental recursion mode | ✅ Parity | rsync's man-page-only scanning-mode switch. FastSync always performs a single full recursive scan, so both spellings are accepted as inert no-ops and the destination is identical whichever mode the caller requests — the same treatment as `-r`/`--recursive`, which is likewise a no-op. The switch is a scan-implementation detail with no observable effect on the final tree (rsync's own `--no-inc-recursive` selects a full scan, which is exactly FastSync's behavior) |

## 5. Transfer Modifications

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-u`, `--update` | Skip files newer on receiver | ✅ Parity | `update` config field (crosses the wire; receiver-side policy, implies metadata transmission). Before writing a regular file, the receiver checks `file_destination_is_newer_secure()` (via `stat_is_newer`, second-then-nanosecond strict `>` on the existing destination) and skips the write when the destination is newer than the source (`FILE_SAVE_SKIPPED`); equal-or-older destination (or a newer source) is transferred normally. Applied at write time on the regular-file, delay-updates-staged, hardlink-sibling, and special/device paths. Only regular destinations can be guarded (the newer-check requires `S_ISREG`), and like the other write-time policies it does not short-circuit the data transfer for a differing-size dest. `--remove-source-files` correctly respects the receiver's skip outcome so a skipped source is not removed |
| `--inplace` | Update files in-place | ✅ Parity | Direct write mode |
| `--append` | Append data to shorter files | ✅ Parity | Tail-only resume: when an existing destination file is shorter than the source, the receiver negotiates a resume offset and only the tail is transferred; the receiver rebuilds the full file (retained prefix + tail) and installs it atomically. Differential tests confirm the result is byte-identical to rsync both when the retained prefix matches and (for plain `--append`, which does not verify the prefix) when it differs. FastSync reconstructs and atomically installs rather than appending in place — a crash-safety superset (an interrupted resume never leaves a half-written file) with identical normal-run behavior |
| `--append-verify` | Append with old-data checksum | ✅ Parity | Like `--append`, but the retained prefix is verified: the sender transmits the source prefix checksum, the receiver compares it to the xxHash64 of the retained destination prefix, and on a mismatch the run falls back to a clean full transfer (always byte-identical to the source). Differential tests match rsync for both a matching and a mismatching prefix. Same atomic-install crash-safety superset as `--append` |
| `-W`, `--whole-file` | Copy whole file (no delta) | ✅ Parity | `whole_file` config field. Forces a full (whole-file) copy, disabling the block-level delta machinery: the sender only sends `STATUS_NEXT` + full data (client_send.c) and the receiver never requests a delta signature/reconstruction — the receiver's `try_delta = use_delta && !whole_file && ...` short-circuits. `whole_file` crosses the wire folded into `use_delta` (the wire carries `use_delta && !whole_file`), so no separate field/bump is needed. Delta is opt-in (`--delta` needs `--incremental`); `-W` additionally makes `--fuzzy` inert (no similar-file delta basis). `--append`/`--append-verify` are incompatible with `-W` and rejected up front (both sides). See the delta/append notes below |
| `--no-whole-file` | Negate `-W`/`--whole-file` | ✅ Parity | rsync spelling that clears `--whole-file`, re-enabling the delta path where `--delta`/`--incremental` are active. Accepted as a boolean negation of `-W` |
| `--block-size=SIZE` | Force checksum block-size | ✅ Parity | Phase 7 Wave B: `--block-size` is an alias for `--delta-block`; both set `config->delta_block_size` (default `DELTA_BLOCK_SIZE_DEFAULT`, bounds `DELTA_BLOCK_SIZE_MIN..MAX`, out-of-range values are rejected with the default kept). The value is genuinely honored by the delta engine end-to-end: `delta_signature_create_seeded(old, size, config->delta_block_size, seed)` on the sender and receiver, `delta_apply(old, ...)` with the same size, so a non-default block size changes the block count of every signature the harnesses exchange (verified by unit + integration tests) |

## 6. Destination Handling

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-n`, `--dry-run` | Trial run with no changes | ✅ Parity | Server-contacting since protocol 2.21.0. The routing predicate `dry_run_targets_server()` selects the server-contacting path for any target a real run would reach over the wire (SSH, daemon `host::module`, explicit `--server-host`/`--server-port`, TLS, source-bind `--address`); the client handshakes with the receiver, which runs the normal read-only per-file check and answers `STATUS_DRY_RUN_TRANSFER`/`STATUS_OK` without mutating anything. Protocol 2.25.0 also reports would-delete lines: with `--delete` the receiver's `STATUS_STATS` carries the extras it would have removed and the client prints rsync-style `*deleting` lines (sequential and `--threads`; control bytes escaped). Dry-run never deletes. **Fixed (no-wire):** the dry-run keep-set manifest now carries the same filter-excluded and size-pruned protected prefixes and synchronized-directory scope a real run sends, and the would-be-transferred entries are in the keep-set, so `-n --delete` lists exactly rsync's extras for source-derived protections — the file merely being updated is kept and an excluded/pruned source entry is protected (`test_dry_run_delete_lines_match_rsync`, differential vs rsync 3.4.1). **Track 4a (protocol 2.28.0):** the received receiver-side `protect`/`risk` rules are also applied to the would-delete enumeration, so a destination-only entry matching a `P` rule is no longer reported (or removed in a real run) — matching rsync (`TestFilterProtect::test_protect_dest_only_dry_run_enumeration`). **Order parity (parity-2.29):** the sequential scanner now walks the tree in rsync's sorted depth-first flist order (non-directories ascending, then directories ascending) and the delete walkers sort each directory the same way, so the would-delete lines are emitted in rsync's exact reverse-sorted order — differential `test_parity_order.py::test_dry_run_delete_order_matches_rsync` compares the ordered sequence, not a sorted set |
| `-b`, `--backup` | Make backups of overwritten files | ✅ Parity | Backup before overwrite |
| `--backup-dir=DIR` | Backup directory hierarchy | ✅ Parity | `backup_dir` config field |
| `--suffix=SUFFIX` | Backup suffix (default ~) | ✅ Parity | `suffix` config field |
| `--delay-updates` | Put updated files in place at end | ❌ Divergent | Successfully received files are staged under a private 0700 `.fastsync-stage` dir inside the receive root and atomically renamed into their final destinations only after the whole transfer (manifest/delete handling included) succeeds, just before the success/outcome frame is sent. The delete walker deliberately skips the staging dir at the receive root, so `--delete` removes genuine extras but never the staged files (deletion runs before publication; rsync's delete-after ordering is not implemented). `--existing`/`--ignore-existing`/`--update` decide against the final destination path at stage time; `--backup` moves the old file aside at publication, and **`--force` is honored at publication** (protocol 2.23.0): a staged regular file or symlink may replace a destination directory that blocks it. Incompatible with `--inplace` and with `--backup-dir=.fastsync-stage` (the internal staging name is reserved; both are rejected). The staging dir name is fixed, so two simultaneous delayed transfers to the same destination root are serialized with an exclusive advisory lock held for the whole transfer: the second session fails cleanly instead of corrupting the first. Aborting or failing before publication installs nothing and removes the staging tree; a crash between stage and publish leaves staged leftovers that the next delayed run wipes at start (process death releases the lock). A stage→publish failure aborts the transfer (best-effort cleanup of the not-yet-published staged files; already-published files are not rolled back). **Reclassified Divergent (differential evidence):** the staging name is fixed and a delayed run wipes a pre-existing destination tree of that name at start even without `--delete`, whereas rsync uses its own internal temp name and leaves a genuine destination entry named `.fastsync-stage` untouched (`test_delay_updates_staging_name_collision_residual`); deletion also runs before publication while rsync's `--delay-updates` implies `--delete-after`. Works in single-threaded and `-j`/`--threads` modes |
| `-T`, `--temp-dir=DIR` | Create temporary files in DIR | ❌ Divergent | `--temp-dir` with the rsync short `-T` (the timeout alias moved to long-only `--timeout`). A **relative** dir matches rsync exactly: it is resolved below the receive/destination root and must already exist (differentially verified: `rsync -a --temp-dir=scratch src/ dst/` and FastSync produce identical trees and an empty scratch dir). An **absolute** dir is accepted when it canonicalizes (`realpath(3)`) inside the receive root, so an in-root absolute scratch path is usable and used (unit- and integration-tested for both the local batch apply and a live TCP transfer). **Remaining divergence:** an absolute `--temp-dir` that escapes the receive root is rejected, and so is a relative one containing `..` — rsync standalone resolves an absolute `--temp-dir` verbatim (it will use `/tmp` or any other directory, including one outside the destination), but FastSync's security-reviewed receiver confines the scratch dir to the authorized receive root and refuses an out-of-root path before writing anything. **Audit-cycle hardening:** the opened dir is additionally judged by the real path of its fd (`/proc/self/fd`), so a client-planted symlink under the receive root cannot redirect receiver scratch files outside the authorized root (an escaping target is refused with `EACCES`), while an in-root symlink to another filesystem — the `EXDEV` fallback case — still works. A differential test confirms rsync exits 0 using an out-of-root absolute scratch dir while FastSync refuses before writing anything into it (the scratch dir stays empty). Its daemon mode also confines relative to the module. Temp copies use a unique name in the scratch dir and are atomically renamed into place; **on `EXDEV` (scratch dir and destination on different filesystems, reachable via a confined relative symlink) the receiver falls back to a non-atomic copy instead of aborting**, matching rsync. `--inplace` and `--partial-dir` writes bypass the scratch dir |
| `--partial` | Keep partially transferred files | ✅ Parity | On a failed/interrupted write the already-written temp file is retained at the destination path (best-effort rename instead of unlink) so a later `--append`/`--append-verify` run can resume it. Retention never runs when no data was actually written or under `--ignore-existing`/`--existing` (the destination is not ours to overwrite), and it only ever renames the already-written temp. A failed rename falls back to the normal unlink |
| `--partial-dir=DIR` | Keep partial files in DIR | ✅ Parity | The working file is written under the confined partial directory (a relative dir below the receive root) and atomically renamed into place once complete, so an interrupted transfer leaves a resumable copy there and completed transfers do not linger under it. `--inplace` bypasses the partial dir (rsync parity), and combining `--inplace` with `--partial-dir` is now **rejected up front** with rsync's message (`--inplace cannot be used with --partial-dir`) instead of silently ignoring the partial dir. **Implies `--partial`** (audit-cycle fix, matching rsync 3.4.1, which sets `keep_partial` after option parsing): `--partial-dir=DIR` alone retains an interrupted transfer's partial, and the implication wins over an explicit `--no-partial` regardless of order |

## 7. Deletion

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--delete` | Delete extraneous files from dest | ✅ Parity | `use_delete` config field. Deletion is always derived from the keep-set the sender actually transmitted (the per-directory `STATUS_DELETE_PLAN` set by default, or the whole-tree manifest for the late timings — never from unchecked input), runs through the symlink-safe walker bounded by `MAX_SERVER_DELETE_COUNT`, and skips the `.fastsync-stage` staging dir under `--delay-updates`. **Lockstep track 6 (protocol 2.28.0): plain `--delete` with no explicit timing flag now defaults to `--delete-during`**, exactly like rsync's `--del` (the client normalizes it to the existing `delete_during` wire bool; no new wire field). This frees destination space progressively during the transfer and avoids the whole-old+new-tree peak that could `ENOSPC` a tight destination. The old late whole-tree commit is opt-in via `--delete-after` or the FastSync-only long spelling `--delete-commit`. **Abort/ordering parity (parity-2.29):** the complete per-directory plan set is transmitted before the first data frame, so a mid-transfer abort has already applied every planned removal exactly like rsync's generator (which runs ahead of its throttled sender); `-d/--dirs` uses the same per-directory plans (the generator records only the directories whose direct children it enumerated, so an untraversed subdirectory's mirror is shielded); and the sorted depth-first traversal makes the removal order — and therefore the survivor set under a partial `--max-delete` — match rsync exactly (`test_delete_boundary_parity.py`, `test_parity_order.py`). By default the destination mirror of a path the source scan pruned (filter/exclude/size rules) is **protected** from deletion — matching rsync, which does not delete excluded files under `--delete`; `--delete-excluded` opts back into deleting them (see below). Deletion is scoped to the **synchronized directories** sent on the wire (protocol 2.23.0), so a `--files-from` subset no longer deletes untransmitted paths outside the listed directory subtrees. The walk is bounded: a client `--max-delete=NUM` (or the 100000-entry server bound) makes it **partial** — entries up to the bound are removed, the rest are skipped, and the client exits **25** (`RERR_PARTIAL`), matching rsync, rather than failing the transfer. Extraneous destination symlinks are unlinked by name (never followed); a directory still holding a kept/protected entry is left behind rather than failing |
| `--delete-before` | Delete before transfer | ⚠️ Caveat | Implies `--delete`. The sender runs a full source pre-scan (paths only) and transmits the keep-set manifest BEFORE any file data; the receiver validates it, removes every destination entry not listed (bounded walk, staging-dir skip, protected prefixes honored), then acks `STATUS_OK`. The sender only starts streaming after the deletion committed, or aborts if the receiver reported a deletion error. By definition the deletions already happened when a later transfer phase fails — rsync's delete-before is destructive the same way; a subsequent failure does not restore the removed files. **Phase-0 divergence (sharpened):** rsync builds the full file list first, so a source file created after that scan is NOT transferred and its destination extra is deleted; FastSync's single-threaded data pass re-scans the source, so the late file IS transferred (a safe superset), while FastSync `--threads` pipelines the scan and matches rsync |
| `--del`, `--delete-during` | Delete during transfer | ✅ Parity | Both spellings accepted; imply `--delete`, and since lockstep track 6 this is also the default timing of a plain `--delete`. **Protocol 2.24.0 implements per-directory delete plans:** as the sender reaches each source directory it streams a `STATUS_DELETE_PLAN` for that directory and the receiver removes that directory's extras (verified with a byte-slicing proxy). The one-shot per-run config block (protected prefixes, size-pruned mirrors, `--delete-missing-args` exact paths) rides a dedicated config-only carrier frame with an `apply=false` flag, so it reaches the receiver even when the scope allows no directory plan at all (a `--files-from` list of bare files synchronizes no directory). **Abort/ordering parity (parity-2.29):** the complete plan set is transmitted before the first data frame, so on a mid-transfer abort every planned extra has already been removed exactly like rsync's generator (which runs ahead of its throttled sender); `-d/--dirs` no longer falls back to the end-of-transfer commit but records only the directories whose direct children it enumerated; and the sorted depth-first traversal makes the removal order — and the partial-`--max-delete` survivor set — identical to rsync (`test_delete_boundary_parity.py`, `test_parity_order.py`). `-R` plans are scoped to the transferred prefix subtree |
| `--delete-delay` | Find deletions during, delete after | ✅ Parity | Implies `--delete`. **Protocol 2.24.0 implements rsync's delete-delay timing:** the sender records each directory's delete plan while scanning and the receiver commits those removals only after the whole transfer succeeds (per plan), so an extra created in the destination after its directory's plan survives while `--delete-after` re-scans and removes it, and a failed transfer removes nothing. The **reported** deleted count advances only on an actual removal. **Fixed (no-wire):** the `--max-delete` budget is now charged on ACTUAL removals (an unlink/rmdir that succeeded), not at plan/snapshot time, and a queued directory is re-scanned at commit and removed recursively (content created after the plan included), matching rsync: a snapshotted entry that fails or is skipped consumes no budget, so a later extra rsync would delete is still deleted. The deferred snapshot list keeps an independent hard cap (`DELETE_PLAN_SERVER_LIMIT`) so it cannot grow without bound now that the budget is no longer charged while scanning. A `--max-delete=2` partial delete reports exactly 2 and exits 25 in both tools, and the refilled-directory differential (late content removed, directory removed, budget shared) now matches rsync 3.4.1 on both sides (`test_delete_delay_budget_parity.py`, `test_delete_timing_parity.py`). Unit tests cover recursive removal, actual-removal charging, and the bounded deferred list. **Ordering parity (parity-2.29):** the sorted depth-first traversal plus the up-front plan set make the order in which extras are removed — and therefore the survivor set under a partial `--max-delete` — match rsync exactly (differential `test_parity_order.py::test_delete_delay_deletion_order_matches_rsync` and `::test_partial_max_delete_survivor_order_matches_rsync`) |
| `--delete-after` | Delete after transfer | ✅ Parity | Implies `--delete`. Selects the late whole-tree commit: the keep-set manifest closes the data stream and the receiver commits the bounded deletion only after the terminal `STATUS_FINISHED` proves the whole transfer (every data frame received and stored) succeeded. A failed or aborted transfer removes nothing. Since lockstep track 6 a plain `--delete` defaults to delete-during (rsync's `--del`); `--delete-after` — or the FastSync-only `--delete-commit` spelling, which selects the identical timing — is the explicit way to keep the old commit-style behavior |
| `--delete-excluded` | Also delete excluded files | ✅ Parity | `delete_excluded` config field. Under `--delete` FastSync protects (rsync's default) the destination mirror of paths the sender's source scan pruned by the user-selection rules — the `--filter`/`-F`/`-C` layer and the legacy `--exclude`/`--include` layer. The sender transmits those concrete pruned paths as **protected prefixes** in the delete-manifest frame (see the Phase-3 notes below); the walker never descends into or removes them. `--delete-excluded` opts back in: the sender sends an empty protected list, so the excluded destination mirrors become ordinary extras and are removed. **`--max-size`/`--min-size` pruned mirrors are a separate, always-on protection** (protocol 2.23.0, rsync parity): size-pruned source mirrors survive `--delete` even with `--delete-excluded`. Track 4a (protocol 2.28.0) additionally re-applies the received `protect`/`risk` rules on the receiver, so a destination-only entry matching an exclude rule is protected (or left at risk) exactly like rsync; the remaining sender-derived `--delete-excluded` behavior (an unqualified rule becomes sender-only, so its source mirror and matching destination-only extras are deleted) is unchanged |
| `--max-delete=NUM` | Max files to delete | ✅ Parity | `max_delete` config field (default -1 = no client limit; 0 = delete nothing). **Protocol 2.23.0 matches rsync's partial semantics:** the receiver deletes up to NUM entries (regular files, symlinks and empty directories; each directory removal counts as one) and then **stops deleting, skips the rest, and reports the run as partial**. The client prints a "deletions stopped due to `--max-delete` limit" message and exits **25** (rsync's `RERR_PARTIAL`), not a hard failure — the transfer itself succeeded. NUM only applies together with `--delete` (it is inert otherwise, matching rsync). A client NUM below the server hard bound `MAX_SERVER_DELETE_COUNT` (100000) replaces it; a NUM above it never raises that cap. Deleting an entire destination with no limit is still bounded by the server's 100000-entry ceiling. `--delete-missing-args` exact-path deletions and the ordinary extras walk draw from the same budget, matching rsync |
| `--ignore-errors` | Delete even with I/O errors | ✅ Parity | Sender-side, client-only config field. Matches rsync's semantics exactly: an unreadable source subdirectory is always skipped so the readable tree transfers (the transfer root itself stays fatal), and the run reports rsync's partial-transfer exit **23**. Deletion policy follows rsync: by default an I/O error suppresses deletion (`IO error encountered -- skipping file deletion`), while `--ignore-errors` lets the deletion commit. The decision applies to every timing (`--delete`, `--delete-before`, `--delete-during`, `--delete-delay`, `--delete-after`) in both the sequential and `--threads` send paths. Differential-tested against rsync 3.4.1 with both tools run as an unprivileged user (mode-000 source directory); the reference build's root-only gate still excludes the EACCES differential, but the setpriv differential test exercises it. The piece that stays FastSync-specific is documented under the recursive-empty-directory residual: FastSync never emits an unreadable (or empty) directory entry, so that mirror is an extra that a run with `--ignore-errors` removes, where rsync emits the directory and keeps its mirror |
| `--force` | Force deletion of non-empty dirs | ✅ Parity | `force_delete` receiver config field (crosses the wire). rsync's `--force` lets an incoming non-directory replace a destination directory; FastSync implements exactly that: when a regular file (or symlink) is written to a path that is currently a (possibly non-empty) destination directory, `--force` removes that directory tree first — confined to the receive root and symlink-safe (O_NOFOLLOW fd walk, symlinks removed by name, never followed) — so the install can place the file. **Protocol 2.23.0 honors `--force` on the `--delay-updates` publication path too**, not only the immediate-install path. Without `--force` such a write fails and the run aborts. Gated by the server `--allow-delete` policy (a client cannot use `--force` to remove a destination tree on a server that forbids deletion) |
| `-m`, `--prune-empty-dirs` | Prune empty dir chains | ✅ Parity | `-m`/`--prune-empty-dirs` (Phase 7 Wave A freed the rsync short `-m`; FastSync multithreading is now `-j`/`--threads`). A recursive transfer now recreates empty source directories by default (rsync parity); this flag suppresses that emission, so an empty directory (physically empty, or emptied by filtering) is not created and a true empty-directory chain is removed by `--delete`, matching rsync's `-m`. It also affects the `--dirs` explicit directory-entry generator: a plain `-d <empty-dir>` run omits the empty source directory's entry, so nothing is created at the destination (no `STATUS_MKDIR`, no `-i`/`--out-format` change line, and an existing empty mirror becomes an extra that `--delete` prunes). Explicitly `--files-from`-listed directories always pass through (documented `--files-from` behavior; `--files-from` runs never emit implicit empty directories). A directory that still holds an excluded-but-protected file survives, matching the `--delete-excluded` default |

**Deletion-timing implementation notes (Phase 3):** the delete flags above are
real. Two new config booleans (`delete_during`, `delete_delay`) join the already
serialized `delete_before`/`delete_after`, so the on-the-wire config layout
changed and `PROTOCOL_VERSION` was bumped **2.7.0 → 2.8.0** (peers must match).
The `STATUS_MANIFEST` frame is count-delimited and position-independent: the
receiver commits the deletion either when the manifest arrives (early modes:
`--delete-before`/`--delete-during`, which additionally acknowledge with
`STATUS_OK` before data flows) or after the terminal `STATUS_FINISHED` proves
the whole transfer succeeded (commit modes: `--delete-after`/`--delete-delay`;
plain `--delete` joined the per-directory plans in track 6). Timing is chosen purely from the config, so server policy
(`--allow-delete` off) still disables deletion without deadlocking the early
manifest ack. `--delete-delay` and `--delete-during` are each implemented as
the closest safe approximation their engine mode allows; the divergences are
noted in the rows above.

**Deletion-policy notes (Phase 3, delete-policy wave):** this wave made the
deletion family real — `--delete-excluded`, `--max-delete`, `--ignore-errors`,
`--force`, `--prune-empty-dirs` — and, to support them, the `STATUS_MANIFEST`
frame carries the keep-set paths followed by a list of **protected prefixes**
(destination-relative paths the source scan pruned by user-selection rules,
which the walker must never delete unless `--delete-excluded` opted out).
Two config booleans were added for the wave: `force_delete` (crosses the wire;
the receiver clears a directory that blocks an incoming file) and
`ignore_errors` (client-only; the sender's scan continues past an unreadable
directory). `max_delete`'s default became -1 ("no client limit"). These
wire/layout changes bumped `PROTOCOL_VERSION` **2.8.0 → 2.9.0** (peers must
match). All four wire additions — `force_delete`, `delete_excluded`,
`prune_empty_dirs`, `max_delete` — round-trip unchanged and are validated on
receive.

**Missing-args note (Phase 3, missing-args wave; extended in 2.23.0):**
`--ignore-missing-args` and `--delete-missing-args` are implemented as described
in the Safety & Security rows. Wire impact: the `STATUS_MANIFEST` frame carries
a list of destination-relative **exact-delete paths** (the missing entries'
mirrors), and the config frame gained a `delete_missing_args` boolean
(`ignore_missing_args` stays client-only, exactly like `ignore_errors`). These
wire/layout changes bumped `PROTOCOL_VERSION` **2.9.0 → 2.10.0** (peers must
match). The receiver validates the section identically to the keep-set (non-empty,
relative, traversal-free; the shared `MAX_MANIFEST_ENTRIES`/`MAX_MANIFEST_BYTES`
budget spans every section). On commit the receiver runs the exact-path deletions
FIRST (`manifest_delete_missing_args`: confined per-path unlink/rmdir, deep
removal only under `--force`/`--delete`, staging/basis protected, never blocked
by the protected-prefix list) and then the ordinary extras walk when `--delete`
is active (`manifest_delete_all`). A client may request the exact-path deletions
without `--delete`; the server's `--allow-delete` policy gates them exactly like
`--delete`, so an unauthorized server ignores the request while the missing
entries are still skipped.

**Delete scoping and partial limits (protocol 2.23.0).** The `STATUS_MANIFEST`
frame now carries **four sections** — keep-set, protected prefixes, exact-delete
(missing-args) paths, and the set of **synchronized directories**. The extras
walk is scoped to the synchronized directories, so a `--files-from` subset no
longer deletes untransmitted destination paths outside the listed directory
subtrees (a data-loss fix, matching rsync). `--max-size`/`--min-size` pruned
source mirrors are protected independently of `--delete-excluded`. Extraneous
destination symlinks are unlinked by name (never followed). The `--max-delete`
budget is **partial**: the walker deletes up to the effective bound (a client
`--max-delete=NUM` below the hard bound, else the hard
`MAX_SERVER_DELETE_COUNT` = 100000) and then stops, skips the rest, and reports
the run as partial so the client exits **25** (`RERR_PARTIAL`) exactly like
rsync — it is a successful transfer with an incomplete deletion, not a hard
failure. The exact-path missing-args removals and the extras walk share that one
budget. A directory that still holds entries the walker leaves in place (a
protected excluded file, a kept manifest entry, a symlink) is left behind rather
than failing the run — matching rsync's "cannot delete non-empty directory"
behaviour.

Manifest size: the sender's collections (streaming or early pre-scan) are
unbounded, but the receiver rejects a manifest whose **aggregate** count exceeds
`MAX_MANIFEST_ENTRIES` (1 048 576 entries across ALL sections) or whose aggregate
path bytes exceed `MAX_MANIFEST_BYTES` (16 MB across all sections) as a hard
protocol error. A heavily filtered source whose exclusion list grows large thus
fails the run cleanly on the receiver (STATUS_ERROR) instead of being silently
truncated. In the commit modes this only means the deletion is refused after the
data already arrived; in the early modes (`--delete-before`/`--delete-during`)
the manifest is the first frame, so an oversized manifest aborts the whole
transfer BEFORE any data is sent. Keep the source tree small enough for the
receiver's manifest caps when using the early timing.

Early-delete ACK wait: after committing a large deletion (up to
`MAX_SERVER_DELETE_COUNT` removals) the receiver's `STATUS_OK`/`STATUS_ERROR`
reply can legitimately take much longer than a normal round trip, so the sender
waits for that single ACK with an extended explicit deadline (1 hour) instead
of the default 60 s per-message receive window. A receiver that is genuinely
gone still aborts the wait via connection close/error; the extended bound only
protects against aborting after the deletion already committed on the receiver.

Flag-conflict policy: unlike rsync's last-one-wins behaviour, every deletion
timing flag implies `--delete`, and combining a timing flag with `--no-delete`
(in either argument order) — or more than one timing flag — is rejected as a
configuration error rather than silently resolved. Note the check is
order-independent because it runs over the fully parsed config. The
FastSync-only `--delete-commit` is a late-timing spelling (it maps onto
`--delete-after`), so it conflicts with any different timing flag exactly like
`--delete-after` does. The deletion
POLICY flags (`--delete-excluded`, `--max-delete`, `--ignore-errors`, `--force`)
do NOT imply `--delete`; without `--delete` they are inert (matching rsync).

**Append-resume notes (Phase 3, append wave):** `--append` and `--append-verify`
are real. Both are negotiated when an existing destination file is found to be
**shorter** than the source during the per-file `STATUS_CHECK`; the receiver
replies with a new `STATUS_APPEND` frame carrying the resume offset (the prefix
length it already holds) instead of `STATUS_NEXT`/`STATUS_DELTA_SIGNATURE`.
The sender transmits ONLY the tail. For `--append-verify` it first sends the
source's prefix xxHash64 in a `STATUS_APPEND_SIG` frame; the receiver compares
it to the retained prefix and answers `STATUS_APPEND_OK` (transfer the tail) or
`STATUS_NEXT` (prefix mismatch → the sender falls back to a byte-exact full
transfer). The tail arrives in a `STATUS_APPEND_DATA` frame (compression and
metadata still apply). The receiver then rebuilds the full file in memory
(prefix + tail) and routes it through the existing atomic store engine, so all
of `--inplace`, `--partial`/`--partial-dir`, `--delay-updates`, `--backup`,
`--existing`/`--ignore-existing`/`--update` and delete-manifest behaviour is
unchanged and the result is a byte-identical source copy (given a matching
prefix). These new frames changed the wire, so `PROTOCOL_VERSION` was bumped
**2.9.0 → 2.10.0** (peers must match; the pre-existing `append`/`append_verify`
config booleans already crossed the wire). CLI: both flags imply `--incremental`
(the handshake needs it); they are incompatible with `-s` (chunk serialization)
and `--whole-file` (both rejected up front, never a silent full transfer); when
both spellings are given `--append-verify` wins. The FastSync divergence from
rsync is intentional and safer: rsync appends in place, whereas FastSync
reconstructs the whole file and atomically installs it, so an interrupted or
failed resume never leaves a partial/corrupt file at the destination — this is
why plain `--append` works on the normal atomic path, not only with `--inplace`.

## 8. Metadata Preservation

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--preserve` | (FastSync alias, not an rsync flag) | ✅ Parity | **FastSync-only alias** for `-p` + `-t` (mode + mtime), long-form only. It is not rsync's `--preserve` (rsync has no such option); the short `-M` that used to spell it is now rsync's `--remote-option`. The wire metadata also carries uid/gid for `-o`/`-g`/`-a`, and ownership is applied via `-o`/`-g`, `-a`, or an explicit identity flag (`--numeric-ids`/`--usermap`/`--groupmap`/`--chown`/`--copy-as`) |
| `-p`, `--perms` | Preserve permissions | ✅ Parity | Real per-attribute flag (protocol 2.22.0): `preserve_perms` applies the source mode independently of times/owner/group. **Strict rsync parity when super-user activities are permitted (protocol 2.23.0): the source mode is copied exactly, including setuid/setgid/sticky and group/other-write bits.** **Audit-cycle fix:** when the connection forbids super-user activities (`--no-super`, a non-opted daemon module, or a privileged standalone listener without `--allow-super`), the setuid/setgid/sticky bits are masked from the applied mode (the other bits are unaffected); exact rsync semantics are preserved wherever super activities are permitted. Without `-p`, a new file gets `source_mode & ~umask` when metadata is present (else the historical fixed `0644`); new directories without `-p` still use FastSync's `0755` creation default, because directory metadata is only applied when a directory attribute is requested. **Audit-cycle fix:** the daemon no longer forces `umask(0)` (which made implied parent directories world-writable `0777`); it uses the conventional `022`, and `-p`/`-a` still restore the exact source mode via `fchmod`. `-A/--acls` implies `-p`; `--chmod` does **not** imply `-p` (rsync parity) and applies its own unsanitized changes to the new mode. `-X/--xattrs` does not imply `-p`. The SSH port moved to `--ssh-port`. rsync-parity short form |
| `-o`, `--owner` | Preserve owner | ✅ Parity | Real per-attribute flag (`preserve_owner`): preserve the source uid, resolved on the receiver by name against its own user database with a raw-numeric fallback (only numeric ids cross the wire). `--usermap`/`--chown=USER` imply it. Application follows the `--super`/`--no-super` policy; a non-opted daemon module applies no ownership (see the Daemon Mode notes) |
| `-g`, `--group` | Preserve group | ✅ Parity | Real per-attribute flag (`preserve_group`): preserve the source gid, resolved by name on the receiver with a raw-numeric fallback. `--groupmap`/`--chown=:GROUP` imply it. Same privilege/super-policy gating as `-o` |
| `-t`, `--times` | Preserve modification times | ✅ Parity | Real per-attribute flag (`preserve_times`): apply the source mtime independently of the other attributes. `-O/--omit-dir-times` suppresses directories only and `-J/--omit-link-times` suppresses symlinks only; `-U`/`-N` do not imply it. `--preserve`/`-a` imply it, and `--incremental`/`--delta` auto-enable it unless `--no-times`/`--no-preserve` |
| `-E`, `--executability` | Preserve executability | ✅ Parity | Preserves executable permission bits (implies metadata preservation) |
| `--chmod=CHMOD` | Affect file permissions | ✅ Parity | Faithful port of rsync 3.4.1's `parse_chmod`/`tweak_mode`: numeric octal and symbolic `ugo`/`rwx` changes, `D`/`F` directory/file selectors, `X` (execute only on directories or already-executable files), `s`/`t` setuid/setgid/sticky, and append semantics — repeated clauses and repeated `--chmod` options accumulate in order (joined with commas). The changes are applied to the new mode **without sanitization** (matching rsync), except that setuid/setgid/sticky are masked when the connection forbids super-user activities (audit-cycle fix, see `-p`), and `--chmod` does **not** imply `-p` (rsync parity). Applied to files and directories on the receiver |
| `-A`, `--acls` | Preserve ACLs | ✅ Parity | Implemented on Linux via the POSIX-ACL xattr representation: the sender captures the `system.posix_acl_access` / `system.posix_acl_default` xattrs and the receiver re-applies them fd-relative. A differential test with `setfacl` confirms the complete access and default ACL sets (including `mask`) are identical to rsync's on a directory. libacl is not required; a `fsetxattr` an unprivileged receiver may not perform is logged and skipped, never fatal. Only the `system.posix_acl_*` namespaces plus `user.*` are ever applied; privileged namespaces are never applied. Implies metadata transmission |
| `-X`, `--xattrs` | Preserve extended attributes | ❌ Divergent | Deliberately restricted to unprivileged `user.*` extended attributes plus the two POSIX ACL xattrs; `security.*` (SELinux, capabilities, ...) and `trusted.*` are **never** captured or applied — a client can never force a privileged attribute onto the destination, and the receiver independently re-validates every incoming name against the whitelist. This is a security-policy divergence from rsync, which can preserve the privileged namespaces with the needed privilege; implementing them would defeat FastSync's privilege-escalation guard. `user.*` capture/apply matches rsync in a differential test. Payloads are bounded on both ends. Incompatible with `-s`. **Also divergent: symlink xattrs/ACLs are not captured or applied** — `-X`/`-A` with `-l` carries only the link's owner/times/mode, not its xattrs (the capture uses path-following `listxattr`/`getxattr`, so the link's own xattrs are never read, and the receiver's symlink write path applies no xattr block). Closing this needs a dedicated symlink-xattr wire block and a `PROTOCOL_VERSION` bump |
| `-H`, `--hard-links` | Preserve hard links | ✅ Parity | Files on the source that share an inode (`st_dev`+`st_ino`, e.g. a `cp -al` tree) are re-created as hard links to one another on the destination, so duplicate links stay deduplicated and only the first member's data is sent (later members are transmitted as payload-less `STATUS_HARDLINK` frames). The receiver links each sibling to the first member's installed file with an atomic link + rename; on `link()` failure it falls back to a byte-identical local copy of the first member, never a partial/corrupt file. Requires the sequential scan for ordering (the first member is always emitted and installed before any sibling is linked). Works single-threaded and under `-j`/`--threads`, `--inplace`, `--delay-updates` (links staged and published by rename) and `--partial`. Crosses the wire (`preserve_hard_links` bool; `PROTOCOL_VERSION` bumped **2.11.0 → 2.12.0**, peers must match). Incompatible with `-s` (chunk serialization) and `--append`/`--append-verify`, rejected up front with a distinct error. See the Phase-4 hard-links notes below |
| `-D` | Same as --devices --specials | ✅ Parity | Implies `--devices --specials`. `-D` was unassigned in FastSync (verified: no collision), so it is free to imply both device-node and special-file preservation. As of protocol 2.23.0 `--specials` genuinely covers **both FIFOs and unix sockets**, so `-D` covers the full rsync set. See the `--devices`/`--specials` rows and the Phase-4 devices notes below |
| `--devices` | Preserve device files | ❌ Divergent | Recreates char/block device nodes with `mknodat` (type + rdev strictly validated, confined fd-relative below the receive root), but only when the receiver has `CAP_MKNOD`: a non-root receiver logs a warning and skips the entry instead of erroring, so a transfer with devices never aborts. Deliberate privilege-model divergence from rsync, which errors when it cannot create the node. `--specials` (FIFOs and unix sockets) is unprivileged and remains parity |
| `--specials` | Preserve special files | ✅ Parity | **FIFO and unix-socket recreation work** (protocol 2.23.0): FIFOs are recreated with `mkfifoat`, and sockets with `mknodat(..., S_IFSOCK)` — the latter is unprivileged on Linux because it materializes the socket *node*, not a live bound socket, so it is a real, assertable behavior under CI (it matches rsync, which also recreates a socket by `mknod`). Node creation is confined below the receive root (fd-relative parent; no `..`, no symlink follow) and type/rdev are validated strictly; a matching existing node is left in place and an unrelated entry is never replaced. Crosses the wire like `--devices` (the `STATUS_SPECIAL` frame). See the Phase-4 devices notes |
| `--copy-devices` | Copy device contents as file | ❌ Divergent | Copies a device/FIFO's reported `st_size` into an ordinary regular file and never reads an unbounded pseudo-device, so `--sendfile` cannot hang and the run always succeeds. Deliberate safe divergence from rsync's dd-like unbounded device read, which can block; the dangerous behavior will not be implemented |
| `--write-devices` | Write to devices as files | ❌ Divergent | Writes only into an existing char/block node under the confined receive root (`O_NOFOLLOW` + `O_NONBLOCK`); a missing, symlinked, FIFO-with-no-reader, non-device, or otherwise unusable destination is skipped with a warning rather than allowed or aborted. Deliberate confinement divergence from rsync's more permissive behavior |
| `-U`, `--atimes` | Preserve access times | ✅ Parity | Captures the source access time (from the scanner's pre-read stat, so it is not clobbered by reading the file for transfer) and transmits it over the wire; the receiver restores it together with the mtime via `futimens`/`utimensat`. Implies metadata transmission (the times travel inside the shared metadata payload), but does not enable ownership application (that stays opt-in via the identity flags). Wire: `atime` fields on the metadata frame + a `preserve_atimes` config boolean; `PROTOCOL_VERSION` bumped **2.11.0 → 2.12.0** |
| `-N`, `--crtimes` | Preserve create times | ❌ Divergent | Birth-times cannot be set by any portable filesystem call (`utimensat`/`futimens` only set atime/mtime), so this row is an explicit **Divergent** entry (Phase 7 Wave B). Capture + transmit stays: `statx(STATX_BTIME)` on Linux records the source birth time as a wire field; the receiver logs a debug note that it cannot be applied and continues — never failing the transfer and never pretending it worked. On platforms without `statx` it parses as a documented no-op (flag accepted; nothing is captured). Implies metadata transmission. Wire: new `crtime` fields + a `preserve_crtimes` config boolean; `PROTOCOL_VERSION` bumped **2.11.0 → 2.12.0** (see the Phase-4 metadata-time notes) |
| `-O`, `--omit-dir-times` | Omit dirs from --times | ✅ Parity | Real modifier now that FastSync preserves directory times. With metadata on, the scanner captures every traversed source directory's mtime (and atime under `-U`) and the sender transmits them in trailing `STATUS_DIR_TIMES` frame(s) **after all file data and the optional delete manifest** (chunked at the receiver's `MAX_MANIFEST_ENTRIES` per-frame cap); a dir-time entry only RECORDS metadata and never creates the directory (an empty source directory is created by the separate `STATUS_MKDIR` entry the scanner now emits, and `-m/--prune-empty-dirs` suppresses that; the trailing dir-time simply re-applies the metadata). The receiver defers applying them until its delete / `--delay-updates` publication phases have committed, so writing or removing a child never clobbers a parent directory's mtime (rsync applies directory times at the end for exactly this reason). When `-O` is set (the boolean crosses the wire) the receiver does not apply any of them; without `-O` an `-a`/`--preserve` transfer now restores directory times (reversing the old "never preserves dir times" divergence). Wire change: the terminal `STATUS_DIR_TIMES` frame; `PROTOCOL_VERSION` bumped **2.16.0 → 2.17.0** |
| `-J`, `--omit-link-times` | Omit symlinks from --times | ✅ Parity | Real modifier now that FastSync preserves symlink times. Symlink entries already carried their metadata on `STATUS_SYMLINK`; the receiver now applies it with **no-follow primitives only** (`utimensat(..., AT_SYMLINK_NOFOLLOW)`, plus best-effort `fchmodat(..., AT_SYMLINK_NOFOLLOW)` and policy-gated `fchownat(..., AT_SYMLINK_NOFOLLOW)`), so the link itself is stamped without ever dereferencing it, confined fd-relative below the authorized receive root. A symlink has no children, so the times are applied immediately at creation. When `-J` is set (the boolean crosses the wire) the receiver skips the timestamps (mode/ownership are unaffected); without `-J` an `-a`/`-l` transfer restores symlink mtimes. Wire change alongside `-O`: the shared `STATUS_DIR_TIMES` frame; `PROTOCOL_VERSION` bumped **2.16.0 → 2.17.0** |
| `--super` | Receiver attempts super-user activities | ❌ Divergent | Safe-subset privilege model. `--super` permits the receiver to attempt already-confined super-user activities (ownership application, char/block device-node creation, `--write-devices`); `--no-super` forbids them even for root; `auto` keeps the historical best-effort attempt. **FastSync never elevates** — no `setuid`/`seteuid`/`setgid` — and `--super` never bypasses the confinement floor, so it diverges from rsync's real elevation. A server `--no-super` veto forces it off for every connection; a privileged standalone listener defaults off without `--allow-super`; daemon modules opt in with `client owner = yes` |
| `--fake-super` | Store/recover privileged attrs via xattrs | ❌ Divergent | Records the resolved `uid:gid:mode:mtime_sec:mtime_nsec` in a reserved `user.fastsync.stat` xattr and immediately replays mode/times fd-relative, but **never performs a real `chown`** (the owner is recorded for a later privileged restore). The on-disk key and format are FastSync-native, not rsync's `user.rsync.%stat%`, so recordings are not interoperable with rsync — the same class as the native auth and batch formats. Implies metadata transmission; incompatible with `-s` |
| `--open-noatime` | Avoid changing access time when opening files | ✅ Parity | Sender-side policy: the sender opens source files with `O_NOATIME` (Linux) when reading them for transfer, so the open/read does NOT bump the source's on-disk access time. Degrades safely when `O_NOATIME` is unavailable (not defined) or refused (`EPERM`, since it needs `CAP_FOWNER` or file ownership): the code falls back to a normal open, so the data always transfers — only the atime-bump is skipped. It does not itself capture/preserve atime; it only avoids modifying it. **Client-only, never crosses the wire.** Exposed as `file_open_for_read()` and applied to both the buffered data path and the sendfile path |
| `--numeric-ids` | Do not map uid/gid by name | ✅ Parity | **A mapping modifier only:** when ownership is being applied it uses the transmitted numeric uid/gid directly, skipping the name lookup. It does **not** request ownership application on its own — combine it with `-o`/`-g`, `-a`, or an explicit map (`--chown`/`--usermap`/`--groupmap`) — and it does not need any metadata flag merely to parse. Ownership is only applied when metadata (hence the source uid/gid) is actually transmitted (see the Phase-4 identity notes) |
| `--usermap=STRING` | Map usernames | ✅ Parity | Opt-in ownership application. Comma-separated `FROM:TO` rules evaluated in order, first match wins. `FROM` accepts a source-resolved user name, a name **glob** (`*`/`?`/`[...]`, expanded sender-side at CLI-parse time against the sender's passwd/group database and collapsed into numeric `LOW-HIGH` ranges, bounded by `MAX_IDENTITY_MAP`), an `@N`/bare `N` numeric id, an inclusive `LOW-HIGH` id range, `*`, or an empty field (ids with no source name). `TO` accepts a receiver-resolved **name** (protocol 2.26.0 resolves it on the receiving side against the receiver's account database, matching rsync), an `@N`/bare `N` id, or `*` (the receiving process's euid). Rules travel as resolved numeric pairs plus an optional TO name; the receiver applies a matching rule, else falls back to `--chown`, `--numeric-ids`, then a best-effort name lookup, via fd-relative `fchown`. Malformed specs are clear errors. Implies metadata; only effective where the receiver can chown (otherwise a warning) |
| `--groupmap=STRING` | Map group names | ✅ Parity | Same rules and receiver-side `TO`-name resolution as `--usermap`, applied to the group (gid) side |
| `--chown=USER:GROUP` | Map owner and group | ✅ Parity | Opt-in ownership override. Forms `USER:GROUP`, `USER`, `:GROUP`; `*` means the current user/group as appropriate; `@N`/bare `N` ids; a name may escape `:` as `\:`. A name that resolves on the sender is sent as an id; an unresolvable name is carried as a receiver-resolved `TO` name (protocol 2.26.0), matching rsync's receiver-side resolution. Equivalent to a trailing `*:*` usermap+groupmap rule (an explicit map match wins). Conflicts with `--usermap`/`--groupmap` on the same side are a clear configuration error. Implies metadata; a non-root receiver warns and continues (rsync parity) |
| `--copy-as=USER[:GROUP]` | Perform the copy as another user/group | ❌ Divergent | Close-refusal safe subset. FastSync never switches process credentials (its receiver is multithreaded, so a real `setuid`/`setgid` would be unsafe); instead the receiver forces the ownership of every entry it writes to the client-resolved ids through the confined fd-relative identity path. A privileged (root) receiver is required: an unprivileged receiver refuses the whole transfer at the config handshake, before any data, rather than produce wrong ownership. Deliberate divergence from rsync's real identity switching; a daemon refuses it unless the module sets `client owner = yes` |

**Phase-4 metadata-time notes:** `-U/--atimes`, `-N/--crtimes`,
`-O/--omit-dir-times`, `-J/--omit-link-times`, and `--open-noatime` are new.
They change the wire: the per-file metadata frame grows `atime_valid` +
`atime_sec` + `atime_nsec` and `crtime_valid` + `crtime_sec` + `crtime_nsec`
(appended after the existing mode/uid/gid/mtime fields, preserving the exact
positions of every pre-existing field), and the config frame grows four
booleans — `preserve_atimes`, `preserve_crtimes`, `omit_dir_times`,
`omit_link_times` — that CROSS the wire so the receiver knows what to apply /
suppress. `--open-noatime` is **client-only** and is never serialized (it only
governs the sender's source reads). `PROTOCOL_VERSION` was bumped **2.11.0 →
2.12.0** (peers must match, exactly as prior phases did).

**Client-vs-wire split:** `-U` and `-N` affect both the sender (capture) and the
receiver (apply), so they and their metadata fields cross the wire;
`-O`/`-J` are receiver-side preferences and cross as config booleans;
`--open-noatime` is purely a client/sender open flag and stays off the wire
(mirroring the existing convention where `ignore_errors` is client-only while
`force_delete` crosses the wire).

**Phase-4 xattr/ACL notes (`-X/--xattrs`, `-A/--acls`, `--fake-super`):** these
are new in protocol 2.13.0 and add a bounded per-file xattr block to the
per-file metadata frame (count + each `name`/`value`, sent only when xattr
transport is enabled, i.e. with zero overhead on unaffected runs). The config
frame carries `preserve_xattrs`, `preserve_acls` (in the existing file-options
block) and a trailing `fake_super` boolean — all CROSS the wire so the receiver
knows the negotiated behavior; the derived `use_xattrs` flag is recomputed on
the receiver. `PROTOCOL_VERSION` was bumped **2.12.0 → 2.13.0** (peers must
match, exactly as prior phases did).

- **Security model (both `-X` and `-A`):** only `user.*` and the
  `system.posix_acl_access` / `system.posix_acl_default` namespaces are ever
  captured (sender) or applied (receiver). `security.*` (SELinux, capabilities,
  ...), `trusted.*`, and all other `system.*` attributes are never transmitted
  or applied, so a client can never compel the receiver to set a privileged
  xattr. The receiver re-validates each incoming name against this whitelist
  even though the sender already filtered, so a malicious/compromised sender's
  `security.capability` payload is rejected outright (a clean protocol error),
  never applied.
- **Bounds / memory safety:** per-name length ≤ 255 B, per-value ≤ 1 MiB,
  per-file count ≤ 256 names, per-file name+value total ≤ 4 MiB. Both the
  sender (during capture) and the receiver (during receive) enforce these; an
  oversized or malformed frame is rejected, never a large allocation.
- **Confined application:** xattrs are applied with `fsetxattr` on the exact
  just-written destination file fd (before the atomic rename), never on a
  caller-controlled path; this is the same confinement as mode/time restore.
  The `--link-dest` / `-H` hard-link copy fallback (a byte copy when `link()`
  is refused) also re-applies the incoming (or, for `-H`, the first member's)
  xattrs and the `--fake-super` stat, so attributes are preserved rather than
  silently dropped when the link fails.
- **Reserved fake-super key is receiver-only:** the `user.fastsync.stat` key is
  excluded from sender capture AND from receiver application, so it can only be
  written by the receiver's own `--fake-super` handling. A source file that
  already carries such a record is never forwarded on a plain `-X` run, so it
  cannot be spoofed to mislead a later privileged restore.
- **`-A` requires no libacl** — ACLs travel as the `system.posix_acl_*` xattrs.
  Applying an ACL is owner-privileged: `fsetxattr` failure (e.g. non-root,
  unsupported filesystem) is logged (collapsed to one line per file) and never
  fatal.
- **`--fake-super`**: see the row above; the reserved key is `user.fastsync.stat`
  with the documented `uid:gid:mode:mtime_sec:mtime_nsec` (mode octal) format.
  **Replay exists**: after each stored record the receiver immediately re-applies
  the recorded mode and times fd-relative (`fake_super_restore_fd`), but it
  deliberately never performs a real `chown` — `--fake-super` only *records*
  the resolved owner (the active `--chown`/`--usermap`/`--groupmap`/`--copy-as`
  mapping when one is in effect, otherwise the source's own id) for a later
  privileged restore. The recording format diverges from rsync's
  `user.rsync.%stat%`; no cross-tool conversion is attempted.
- **Chunk serialization (`-s`) incompatibility:** the per-file xattr block rides
  the streaming per-file frame, which `-s` replaces with a fixed buffer format,
  so `-X` / `-A` combined with `-s` is rejected up front on both ends (mirroring
  the existing `-H` + `-s` rejection) rather than silently dropping attributes.

**atime capture does not clobber the source atime:** the sender records the
access time from the **same pre-read stat the scanner already took** (inside
`file_metadata_create`), before any file data is read for transfer. So `-U`
alone captures the correct atime even without `--open-noatime`. `--open-noatime`
is orthogonal: it keeps the source's on-disk atime from being bumped by the read
that actually ships the data (only honoured where `O_NOATIME` works; it degrades
to a normal open otherwise, so the data always transfers).

**crtime handling:** `-N` captures the source birth time via `statx`/`STATX_BTIME`
(guarded `#ifdef STATX_BTIME` on Linux) and transmits it. On the receiver, **no
portable setter exists** (`utimensat` can only set atime/mtime), so the receiver
deliberately does **not** apply it: it logs a debug note and continues — it never
fails the transfer and never pretends the crtime was applied. This is the
explicit, documented unsupported-attribute handling. On platforms without
`statx` the flag is accepted but nothing is captured (a documented no-op).

**omit-dir-times / omit-link-times:** `-O` and `-J` are **real modifiers** as of
P7 Wave D (`🔄 → ✅ Implemented`). FastSync now preserves directory mtimes
(captured by the scanner, transmitted in trailing `STATUS_DIR_TIMES` frame(s),
applied only after all children and the delete/publication phases) and symlink
mtime/owner/mode (no-follow `utimensat`/`fchownat`/`fchmodat` at link creation).
`-O` makes the receiver skip the directory-time set; `-J` makes it skip the
symlink timestamps (ownership/mode application is unaffected and stays governed
by the identity opt-in). Both config booleans already crossed the wire. See the
`-O`/`-J` rows and the Wave D note below.

**-U/-N and metadata-bundle interaction:** because FastSync carries all metadata (mode, uid,
gid, mtime, and now atime/crtime) in one bounded payload that is only sent when
metadata transmission is on, `-U` and `-N` imply metadata transmission (the
times travel inside that payload). They do **not** enable ownership application,
which remains opt-in strictly through the identity flags (`--numeric-ids` /
`--usermap` / `--groupmap` / `--chown`).

**Phase-4 identity notes:** `--numeric-ids`, `--usermap`, `--groupmap`, and
`--chown` are real. They introduce a **controlled, opt-in, privilege-gated**
ownership-application path on the receiver: plain `-M`/`--preserve` still does
NOT apply client-supplied ownership (FastSync's deliberate conservative
default, byte-for-byte backward compatible); ownership is only attempted once a
client explicitly requests an ownership-affecting option. Application goes
through an fd-relative `fchown()` in the receiver's metadata-restore path (after
the file is fully written, before timestamps are set), so it is confined and
symlink-safe — never a path-based `chown`. When the receiver lacks permission
(typically non-root, e.g. the CI `nobody` user) `EPERM`/`EACCES` is logged as a
warning and the transfer CONTINUES with exit status success, matching rsync.
A no-op default means existing transfers are unaffected.

Resolution of the destination uid/gid on the receiver: a matching
`--usermap`/`--groupmap` rule wins; else the matching `--chown` side; else, with
`--numeric-ids`, the transmitted numeric id is used raw (no name lookup); else a
best-effort name lookup on the receiver's own account databases (skipped when
the transmitted id has no name present there). `--chown` enforces the receiver
side and is validated at parse time (malformed specs are clear errors, never a
silent no-op).

Wire/version: the config frame gained `numeric_ids`, `chown_uid_set`,
`chown_uid`, `chown_gid_set`, `chown_gid`, and the `usermap`/`groupmap` tables
(count-delimited lists of resolved int32 FROM/TO id pairs), so
`PROTOCOL_VERSION` was bumped **2.10.0 → 2.11.0** (peers must match). All new
fields cross `config_send`/`config_receive` with full symmetry and are validated
on receive (bounded map sizes below `MAX_IDENTITY_MAP`, ids `>=` the `-1`
sentinels).

Documented divergences from rsync: because FastSync transmits only numeric
uid/gid (not names) on the wire, name-based values (`--usermap`/`--groupmap`
names, `--chown` names) are resolved to numbers at CLI parse time against the
**client (sender) machine's** account databases; this reproduces rsync's
semantics on a shared-account source/destination and is documented for a
genuinely different destination. The interesting named-value subset is
supported (FROM name globs `*`/`?`/`[...]` expanded sender-side against the
passwd/group database and bounded by `MAX_IDENTITY_MAP`, `*` FROM wildcard,
`*` TO = current user, `@N`/bare-`N` numerics); a lone-`@` "use the FROM value
unchanged" rsync form is not implemented. Also
unlike rsync, plain `-M` never applies ownership and `--usermap`/`--groupmap`/
`--chown` each imply metadata preservation so the source uid/gid actually travel
(the flags only take effect where ownership is being preserved/applied).

**Phase-4 hard-links notes:** `-H`/`--hard-links` is real and introduces a
deduplicating wire path for files whose source entries share a filesystem inode.
On the sender, the scanner records each distinct `(st_dev, st_ino)` encounter and
assigns it a stable, run-local link-group id (`HardLinkTable`, mutex-guarded so a
multi-threaded scan could share one instance). The FIRST member of a group is
transferred normally and carries the data; each later (sibling) member is
transmitted as a payload-less `STATUS_HARDLINK` frame carrying its destination
path, the group id, and the first member's destination-relative wire path.
Ordering is guaranteed by forcing the sequential scanner whenever `-H` is on
(even under `-j`/`--threads`), so the first member is always emitted — and, on the receiver's
single write thread, installed — before any of its siblings; the receiver is
therefore always able to link to an already-present first member, including the
"first member already up-to-date/skipped" case (the sibling links to or copies
the existing file). Asymmetric existence policies are handled gracefully: under
`--existing`, if the first member's destination is absent (so it is skipped) but
a sibling's own destination already exists, that existing sibling is left in
place rather than the transfer aborting on the missing first member. The receiver
installs each sibling beneath its confined root
as an atomic hard link (temp link + rename); when `link()` fails (cross-device,
filesystem refuses links) it falls back to a byte-identical local copy of the
first member, never a partial/corrupt file. `--delay-updates` stages each sibling
as a hard link to the first member's STAGED file, so publication's renames
preserve the shared inode; `--inplace` and `--partial` are unaffected (a sibling
is a fresh link/copy). Because a hard link shares an inode, metadata is applied
exactly once on the first member and never re-written through the sibling (whose
members are byte-identical by construction), so all members agree.

Wire/version: `PROTOCOL_VERSION` was bumped **2.11.0 → 2.12.0** (peers must
match). The config frame already carried the `preserve_hard_links` boolean
(round-trips through `config_send`/`config_receive`); the only new wire element
is the `STATUS_HARDLINK` frame described above. Incompatibilities (rejected up
front with a distinct error on the client, and re-checked on receive): `-H` with
`-s` chunk serialization (the chunk wire has no per-file hard-link info) and `-H`
with `--append`/`--append-verify` (a payload-less sibling cannot be tail-resumed).

**Phase-4 devices notes:** `--devices`, `--specials`, `-D`, `--copy-devices`,
and `--write-devices` are new. They change the wire: the config frame grows three
booleans — `preserve_specials`, `copy_devices`, `write_devices` — that CROSS the
wire (`preserve_devices` already existed), and a new `STATUS_SPECIAL` frame (used
by `--devices`/`--specials`/`-D`) carries a special/device entry: the destination
path, the metadata frame (whose mode's S_IFMT bits carry the node kind, requiring
the flags to imply metadata transmission), and two int32 `rdev` major/minor
fields. The chunk-serialized wire (`-s`) grows a matching per-file special
marker + rdev so `--devices/--specials` also work under `-s`. `PROTOCOL_VERSION`
was bumped **2.12.0 → 2.13.0** (peers must match, exactly as prior phases did).

**Privilege gating (the crux):** making a device node requires `CAP_MKNOD` (root).
CI runs the integration suite as a NON-ROOT user (via setpriv), so `mknod` fails
with `EPERM`. The receiver treats this as a graceful, logged *skip of the entry*
returned as a success/skip outcome — the whole transfer NEVER aborts just because
the environment cannot create the node. `mkfifo` (FIFOs) is unprivileged, so
`--specials` FIFO creation is a real, assertable behavior under CI. **Sockets are
recreated too** (protocol 2.23.0) with `mknodat(..., S_IFSOCK)`: Linux allows an
unprivileged `mknod` of a socket node because no live bound socket is created,
so a source socket materializes as a socket-type filesystem entry exactly as
rsync does. The "device actually created" integration assertions are guarded to
run only as root. User-facing expectation: point `--devices` at devices and a
non-root receiver will faithfully skip them while transferring everything else;
`--specials` recreates FIFOs and socket nodes for any receiver.

**Confinement & validation:** a special/device node is created with
`mknodat`/`mkfifoat` on the parent directory opened fd-relative below the receive
root (`file_open_secure_parent`: `O_NOFOLLOW`, no `..` components, root-checked),
so a node can never be created outside the authorized destination root and never
through a symlinked parent. The transmitted type is derived ONLY from the
validated S_IFMT bits of the metadata mode (char/block/FIFO and socket honored;
regular/dir rejected as an invalid special), and the transmitted rdev is
validated both on the wire (`file_receive_special`, `chunk_deserialize`) and at
the creation site (`file_special_rdev_valid`): a negative, oversize, or
non-device-carrying rdev is rejected outright (receiver aborts the frame), and a
node is never replaced over an existing directory or unrelated entry (a matching
existing node is left in place). `--write-devices` is the deliberately restricted
danger path: it only ever opens an existing char/block node under the confined
root, and every failure mode (missing, non-device, write error, EPERM) is a
warning + skip, never a system-clobbering write or an abort.

**Documented divergences (honest subset):**
- A device entry the receiver cannot create (missing `CAP_MKNOD`) is *skipped*,
  not a transfer failure — rsync under the same conditions would error.
- `--copy-devices` copies the device's *reported size* (typically 0 for char
  devices/FIFOs) into a regular file and never reads an unbounded pseudo-device;
  this is the safe, non-hanging alternative to rsync's dd-like read.
- `--write-devices` requires the device to already exist at the destination and
  never creates it; unsupported/inaccessible targets are skipped, not written.
- Ownership is not applied to recreated nodes (identity `fchown` needs an fd and
  would require opening the node); permissions and mtime are applied at
  creation / via `utimensat`.

## 9. Symlink Handling

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-l`, `--links` | Copy symlinks as symlinks | ✅ Parity | A symlink is transmitted as a real symlink: its target string crosses the wire (`STATUS_SYMLINK` / chunk entry type) and the receiver creates it with `symlinkat` beneath the receive root, never following the target. **Targets are stored verbatim (protocol 2.23.0), matching rsync `-l`: an absolute target or one containing `..` is copied exactly, and the receiver no longer enforces a containment predicate by default.** `--safe-links` is the sender-side opt-in that drops unsafe targets before transmission; `--trust-sender` does **not** affect symlink targets (it only relaxes the receiver's path-list re-validation). The *placement* path is still hard-confined (`has_path_traversal`, O_NOFOLLOW fd walk), and the link's own mode/times are applied with no-follow primitives. See the Phase-4 symlink-trust notes and the residual-risk note below |
| `-L`, `--copy-links` | Transform symlink to referent | ✅ Parity | Sender-side: every symlink is replaced by its referent's content. A referent that cannot be read, including a broken symlink, makes the run exit 23 (`RERR_PARTIAL`) like rsync while the rest of the tree still transfers, in both the sequential and `--threads` paths (differential test). The transferred tree matches rsync |
| `--copy-unsafe-links` | Transform unsafe symlinks | ✅ Parity | Sender-side: only symlinks whose target is unsafe (absolute or escaping via `..`, matching rsync's `unsafe_symlink()` semantics) are dereferenced into their referent; safe links stay symlinks. A broken unsafe referent makes the run exit 23 like rsync (differential test), while a safe broken symlink is not dereferenced and exits 0 |
| `--safe-links` | Ignore symlinks outside tree | ✅ Parity | Sender-side: a symlink whose target is unsafe is not transmitted at all (skipped), matching rsync's `--safe-links`. Because FastSync applies this while scanning the source, the receiver does not need to repeat it (`safe_links` config field) |
| `--munge-links` | Munge symlinks for safety | ✅ Parity | The **receiver** munges: it prefixes each stored symlink target with rsync's `/rsyncd-munged/` marker (only when the negotiated `munge_links` policy is on, so a source link that genuinely begins with the marker round-trips verbatim). The **sender** un-munges a source target that already begins with the marker before transmitting, so a munged tree round-trips through the receiver's re-munging exactly like rsync. Matching rsync, the prefix is applied on the receiver and stripped on the sender; the wire result and the stored marker match rsync. See the Phase-4 symlink-trust notes |
| `-k`, `--copy-dirlinks` | Transform symlink to dir | ✅ Parity | A symlink whose referent is a directory is dereferenced and recursed as a real directory; a symlink to a regular file stays a symlink. Sender-side only. See the Phase-4 symlink-trust notes |
| `-K`, `--keep-dirlinks` | Treat symlinked dir as dir | ✅ Parity | On the receiver, an existing destination symlink-to-a-directory is used as that directory (followed) instead of being replaced; it is followed only when it resolves to a directory that stays beneath the receive root. See the Phase-4 symlink-trust notes |

**Phase-4 symlink-trust notes:** `-l/--links`, `-k/--copy-dirlinks`,
`-K/--keep-dirlinks`, and `--munge-links` form the "symlink trust boundaries"
row. Making all three new flags have an observable, security-sane effect
required transmitting symlink targets, so FastSync's `-l/--links` is now real:
a symlink-type entry carries its target on the wire (a new `STATUS_SYMLINK`
frame for the per-file path, and a new entry type `2` in the `-s` chunk
serializer) and the receiver creates it with `symlinkat` under an `O_NOFOLLOW`
parent walk, never following the target. Wire changes: `STATUS_SYMLINK`,
the chunk entry type `2`, a per-entry symlink-target string, and two new config
booleans that CROSS the wire — `munge_links` and `keep_dirlinks`; `PROTOCOL_VERSION`
was bumped **2.12.0 → 2.13.0** (peers must match, exactly as prior phases did).

**Per-flag semantics and divergences.**
- **`-l/--links`** copies a symlink as a symlink: the scanner `readlink`s the
  target, the sender transmits it, and the receiver `symlinkat`s it. **Targets
  are stored verbatim (protocol 2.23.0), matching rsync `-l`:** an absolute
  target or one containing `..` is copied exactly as-is. The receiver no longer
  enforces the strict containment predicate on the link *value*; target policy
  belongs to the sender (`--safe-links`/`--copy-unsafe-links`) exactly as in
  rsync. The link's *placement* path is still hard-confined
  (`has_path_traversal`, O_NOFOLLOW fd walk), and the link's own metadata is
  applied with no-follow primitives
  (`utimensat`/`fchownat`/`fchmodat` with `AT_SYMLINK_NOFOLLOW`), so `-J` is a
  real omit switch rather than a no-op. **Residual risk:** because `-l` stores
  targets verbatim and does not enforce containment, a destination later
  consumed by a link-following tool can follow a link outside the receive root.
  Use `--safe-links` when the source is not trusted; a destination that only
  ever uses `openat`-style no-follow access is unaffected.
- **`-k/--copy-dirlinks`** (sender): a symlink whose referent is a directory is
  dereferenced and recursed into as a real directory; a symlink to a regular
  file (or any non-directory) is kept as a symlink. This is rsync's `-k`. When
  `-L/--copy-links` or `--safe-links`/`--copy-unsafe-links` are active, their
  (dereference) semantics take precedence, so `-k` is subsumed exactly as in
  rsync.
- **`-K/--keep-dirlinks`** (receiver, crosses the wire): when a directory is to
  be created (on-demand parent creation for a child write) and the destination
  path is already an existing symlink that resolves to a directory *within* the
  receive root, that symlinked directory is used (followed) instead of being
  replaced by a real directory; new entries are written beneath it. The follow
  is confined: it only happens where `realpath` of the symlink resolves to a
  still-within-root real directory, so a malicious link pointing outside the
  root is never followed. Scope: `-K` acts on the write path (parent/`mkdir`
  creation); the delete walker still never follows symlinks (a documented
  divergence for `--delete` over an existing symlinked dir). Without `-K` the
  destination symlink is not followed (the O_NOFOLLOW walk fails the write),
  which is the safe default.
- **`--munge-links`** (receiver rewrite; crosses the wire so the receiver
  munges): every stored symlink target is prefixed with rsync's marker
  `SYMLINK_MUNGE_PREFIX` = `/rsyncd-munged/` by the **receiver**; the sender
  un-munges a source target that already begins with the marker before
  transmitting, so a munged tree round-trips verbatim. The marker is applied only
  when the negotiated `munge_links` policy is on — a plain `-l` run never
  prefixes, so a source symlink that genuinely begins with
  `/rsyncd-munged/` round-trips verbatim. This matches rsync's stored marker and
  its both-ends-negotiated model, with the prefix applied on the receiver. The link *value* is
  otherwise stored verbatim; the *placement* path still goes through
  `file_symlink_at_secure`'s confined fd walk (`has_path_traversal` on the
  destination path, no symlink follow). When no symlink is being transmitted
  (`-l`/`-k`/`-a` off) `--munge-links` has nothing to rewrite and is inert.
  `-K`/`--keep-dirlinks` policy is installed per connection at config-accept
  (stable for the whole transfer, never racy under `-j`/`--threads`), and only
  ever follows an in-root symlink-to-directory.

**Compatibility:** `-k`, `-K` and `--munge-links` are opt-in. Without them the
scanner's link handling, the wire frames, and the receiver's writes are unchanged
for every other option set. `--safe-links`/`--copy-unsafe-links` are applied
sender-side; `--trust-sender` no longer changes how symlink targets are stored
(it only skips the receiver's path-list re-validation). `-l/--links` stores
targets verbatim, matching rsync.

## 10. Sparse & Device

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-S`, `--sparse` | Sparse block handling | ✅ Parity | Phase 7 Wave B: real hole preservation with no wire change. The receiver's sparse-aware writer (`write_all_sparse`, next to `write_all` in `src/shared/file.c` and `src/shared/file_store.c`) walks the in-memory file image and emits any all-zero run ≥ 4096 bytes as a hole via `lseek(SEEK_CUR)` (the pre-size `ftruncate` guarantees the offset bookkeeping and logical size), `ftruncate(size)` after the last run pins the final size even with a hole tail. Wired into both the atomic temp+rename store and `--inplace` when `sparse` is set; the non-sparse path is byte-identical to before. **`--preallocate` wins over `--sparse`** (protocol 2.26.0: the allocation still runs when both are set, so the sparse writer's seeks do not re-hole the reserved blocks, matching rsync's observed `st_blocks`). Interplay note: under `--partial` a retained sparse temp already has the full logical size (trailing content is holes), so `--append`'s "shorter destination" resume does not re-run; the retained file is still valid and a normal re-transfer (or `-W`/delta) repairs it — documented so the combination is never surprising |
| `--preallocate` | Allocate dest files before writing | ✅ Parity | The receiver preallocates the destination file's full expected space before any data is written, so a transfer that would overflow disk fails fast at allocation time (a clean error, not a half-written file) and the file is laid out contiguously, avoiding fragmentation. Crosses the wire (the config frame carries a `preallocate` boolean; `PROTOCOL_VERSION` bumped **2.10.0 → 2.11.0**, peers must match) so the sender knows the receiver will preallocate and the receiver performs it. **Allocation approach (protocol 2.26.0):** `fallocate(2)` is tried first (what rsync uses); `posix_fallocate()` is the fallback and also reserves *real* disk blocks (true fail-fast on ENOSPC); plain `ftruncate()` is the final fallback when the filesystem reports the allocation is unsupported, still extending the logical size so the intent degrades gracefully. **Fallback/error semantics:** `EOPNOTSUPP`/`ENOSYS` → clean fallback to `ftruncate` (best-effort, preallocates the logical size and never fails a transfer on filesystems that lack `posix_fallocate`); a genuine allocation failure (`ENOSPC`/`EDQUOT`/`EFBIG`/…) aborts the file/receive with a distinct `preallocate failed ... transfer aborted` error — it does **not** fall back to a normal non-preallocated write, preserving the fail-fast purpose. **Size-known requirement:** preallocation only runs when the final size is already known up front (the normal regular-file case); unknown-length data is skipped (never failed). **Orthogonality:** applies uniformly across the atomic temp+rename store path, `--inplace`, `--partial`/`--partial-dir`, `--delay-updates` (the staged temp file is preallocated before data flows) and the `--link-dest` copy fallback; it neither implies nor conflicts with `-s`, `--append`, or delta. Protocol 2.26.0 matches rsync: `--preallocate` wins over `--sparse` — when both are set the allocation still runs (its reserved blocks survive the sparse writer's seeks), and a differential test's `st_blocks` agrees for every flag combination. See the Phase-4 preallocate notes below |

**Preallocate notes (Phase 4, preallocate wave):** `--preallocate` is implemented as a real receiver-side allocation of the destination file's space before data is written. It is a plain boolean config flag that crosses the wire (serialized in the config frame's selection-options block, mirroring `--inplace`/`--append`/`--force`), so the run requires matching ends: `PROTOCOL_VERSION` was bumped **2.10.0 → 2.11.0** (peers must match or the version check fails). The allocation is performed on the exact destination fd, immediately after it is opened, before any bytes are streamed; `posix_fallocate` (and the `ftruncate` fallback) leave the fd's file offset untouched, so the subsequent data write at offset 0 is unaffected and complete. Because FastSync writes each file's byte payload in one in-memory batch, the "full expected size" is exactly the known `data_size`, which is what gets preallocated. Unknown-length/streamed payloads are skipped rather than failed. A failed allocation logs a distinct `preallocate failed` error and aborts the file (the atomic temp is unlinked, the inplace target is left untrimmed) so the run fails cleanly and never silently degrades to a non-preallocated write — preserving rsync's fail-fast intent on a full disk.


## 11. Checksum & Comparison

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--checksum` | Skip based on checksum | ✅ Parity | `-c`/`--checksum` compares per-file whole-file content digests to skip unchanged files. **As of protocol 2.23.0 the short `-c` implies the checksum quick-check**, so a plain `-c` run verifies content rather than only affecting the `--incremental` handshake. The digest algorithm is `xxh128` by default (protocol 2.26.0's negotiated default) and is selectable via `--checksum-choice`/`--cc` (`xxh128`/`xxh3`/`xxh64`/`xxhash`/`md5`/`md4`/`sha1`/`none`/`auto`, plus rsync's two-name form) and `--checksum-seed=NUM` (see those rows) |
| `--checksum-choice=STR`, `--cc=STR` | Choose checksum algorithm | ✅ Parity | Real algorithm selection for the per-file whole-file digest used by the `--incremental`/`--checksum` handshake and basis-dir verification. **Protocol 2.26.0 accepts rsync 3.4.1's full set** — `xxh128` (the negotiated default), `xxh3`, `xxh64`, `xxhash`, `md5`, `md4`, `sha1`, `none`, `auto`, and the two-name `transfer,pre-transfer` form — with rsync's exit-4 rejection of an unknown name and of `none` on the transfer side when `--checksum` is on. `--cc=ALG` and space forms both parse. The algorithm id and seed cross the wire; the receiver hashes its old file with the same algorithm+seed and the per-file `STATUS_CHECK` handshake carries a bounded digest pinned to the negotiated length. `checksum_digest_file` now streams **every** supported algorithm (md4 via the self-contained RFC 1320 code, sha1/md5 via EVP, none as an empty digest), so the streaming path matches its contract, and `--out-format %C` uses the selected **transfer** half of a two-name choice and renders each algorithm byte-for-byte like rsync (xxh128 high-then-low, xxh64/xxh3 big-endian, md5/md4/sha1 standard hex, none a blank 2-char column) — differential-tested across all algorithms. **Track-3b finding — the block-checksum residual is not observable.** rsync applies the choice to the block checksum on its wire too, while FastSync selects only the whole-file comparison digest and keeps the delta BLOCK strong checksum fixed at xxHash32 (`DeltaBlockSig`, `delta_signature_create_seeded`). Because FastSync does not interoperate with rsync on the wire, only the compared surface matters, and a pre-seeded delta differential against rsync 3.4.1 (`--no-whole-file -B8192 --stats --out-format=%c|%C %n` vs `--incremental --delta`) shows the choice does not move it: across `xxh64`, `xxh128`, `xxh3`, `md5`, `md4`, `sha1` and both two-name orders the destination tree is byte-identical, `Matched data`/`Literal data`/`Total transferred file size` are unchanged (and equal to rsync's with the block size pinned), the `%c` block-checksum token is invariant (rsync `16 + 6·ceil(size/block)`, already documented under `--out-format`; FastSync its own basis-read counter), and the exit code is 0. The negotiated algorithm is visible only in `%C`, which applies it to the whole-file transfer digest and matches rsync byte-for-byte. A false block match would require the 4-byte adler32 AND the 4-byte xxHash32 to collide; at the 256 MiB maximum with the 1 KiB minimum block size the expected false matches are ≤2⁻¹⁸, and the choice cannot change this because FastSync's block strong sum is fixed. `auto` now consults `RSYNC_CHECKSUM_LIST` (rsync's whitespace-separated preference list; unknown names skipped, first supported wins, all-unknown is exit 4) before the compiled-in order; because both peers run the identical build this deterministic resolution needs no rsync peer probe, and an explicit `--cc` still wins. The list is differential-tested through `--out-format %C` (byte-identical digests to rsync for md5/sha1/xxh3) |
| `--compare-dest=DIR` | Compare dest files relative to DIR | ⚠️ Caveat | DIR is a receiver-side basis; protocol 2.26.0 uses an absolute path verbatim (rsync semantics) and resolves a relative path below the destination root (`..` components are rejected, `//` collapsed and trailing `/` dropped) — note rsync resolves a relative DIR against the destination directory while FastSync resolves it below the receive root and appends the mirrored source path, so the same relative spelling addresses a different tree (use an absolute DIR for exact parity). On the receiver's per-file check (implies `--incremental`) an exact match is rsync's metadata quick-check: same size and mtime (unless `--size-only`; `-I` disables matching), with NO content digest required by default (track 5a). A match suppresses the data transfer. The FastSync-only `--verify-basis` restores the stricter whole-file content equality. compare-dest never copies: it only skips a file the destination does **not** already hold (sparse destination, rsync parity), and is consulted before the normal delta/full paths. Repeatable; searched in command-line order, first match wins. Differential-tested against rsync 3.4.1 (`compare_dest`, and `test_verify_basis_restores_strict_content`). **Relative-DIR parity (parity-2.29):** a relative DIR now resolves against the destination directory with the file's transfer-relative name appended, exactly like rsync 3.4.1, instead of FastSync's source-mirrored wire path (the historical spelling stays as a fallback; differential `test_parity_basis_fuzzy.py`). Residual: a basis MISS above the 256 MiB whole-file payload bound is refused up front (FastSync's general whole-file limit, not basis-specific); rsync applies basis dirs to arbitrary sizes. Wire: a basis-count field plus the `verify_basis` bool are present on the config frame (protocol 2.9.0/2.28.0) |
| `--copy-dest=DIR` | Include copies of unchanged files | ⚠️ Caveat | Same basis rules as `--compare-dest`, but an exact match materializes a **local copy** of the DIR file into the destination (via the atomic temp+rename store path, so `--existing`/`--ignore-existing`/`--update`/`--backup`/`--delay-updates` all still apply) instead of transferring data. Track 5a re-applies the SOURCE attributes on the copy (rsync's "copy then fix attributes"): the sender transmits the source metadata with the basis check frame, so the copy's mode/uid/gid/mtime match the source rather than the basis inode (differential `copy_dest` compares modes). The copy streams the basis file through a bounded buffer, so a basis larger than the whole-file payload bound still materializes. Repeatable; command-line order = priority. Requires `--incremental` (implied); incompatible with `-s`. Wire: protocol 2.9.0 |
| `--link-dest=DIR` | Hardlink to files when unchanged | ⚠️ Caveat | Same basis rules as `--copy-dest`, but an exact match installs an atomic **hard link** to the DIR file (temp hard link + rename) so no data or disk space is used; where the link is impossible (basis on another filesystem, filesystem refuses links) it falls back cleanly to a byte-identical local copy (streamed from the basis, so an over-limit basis still works), never a corrupt/partial file. `--delay-updates` stages the link and publishes by rename, so the final entry stays a real hard link. Repeatable (searched in command-line order, first match wins). Differential-tested against rsync 3.4.1 (`link_dest`). Inherent shared-inode semantics (identical to rsync): a link keeps the basis inode's own mode/uid/gid and mtime — metadata is never written through the shared inode (that would mutate the basis file), so a later `--inplace` run that rewrites such a destination path **will mutate the basis snapshot** through the shared inode (use `--copy-dest` when the destination must stay independently writable); protocol 2.26.0 re-links an already up-to-date destination file to the basis; a `--remove-source-files` source satisfied by a basis dir is treated as skipped and therefore **retained** (never removed); basis dirs are excluded from `--delete`. **Relative-DIR parity (parity-2.29):** a relative DIR resolves against the destination directory with the transfer-relative name appended, exactly like rsync 3.4.1 (differential `test_parity_basis_fuzzy.py`). Residual: a basis MISS above the 256 MiB whole-file payload bound is refused (FastSync's general whole-file limit). Requires `--incremental` (implied); incompatible with `-s`. Wire: protocol 2.9.0 |
| `-y`, `--fuzzy`, `--no-fuzzy` | Find similar file for basis | ⚠️ Caveat | `-y/--fuzzy` is a pure bandwidth optimization on the existing receiver-driven delta path: when a file must be transferred and the destination holds no usable content at the exact path (file absent, or the destination file is outside the delta engine's size bounds), the receiver searches the SAME destination directory for an existing regular file whose basename is similar to the incoming name and uses it as the delta basis, so the sender transmits only the differences instead of the whole file. The output is always byte-exact regardless of which (or whether any) basis is chosen. Decision location: the receiver performs the candidate search inside `receive_incremental_check` and sends the normal `STATUS_DELTA_SIGNATURE`; the sender never learns the basis was a different file, so no new frame type or sender logic was needed — only the config frame grew a `fuzzy` boolean, so `PROTOCOL_VERSION` was bumped **2.8.0 → 2.9.0** (peers must match). Similarity heuristic (a deterministic port of rsync 3.4.1's matcher — `util1.c` `fuzzy_distance`/`find_filename_suffix` plus `generator.c find_fuzzy`'s exact size+mtime pass — documented precisely): candidates are the target's sibling entries in its destination directory, opened `O_NOFOLLOW`/`AT_SYMLINK_NOFOLLOW` under the confined root (symlinks never followed; nothing outside the destination root is ever read or hashed); dotfiles, directories, the target's own name, and the `.fastsync-stage`/temp scratch names are excluded; like the ordinary delta path, the block signature the receiver transmits is derived from on-disk content it may not otherwise send, so a negotiated `--fuzzy` run exposes the destination's sibling files (at block granularity) to the sender as a known-plaintext oracle — the same information class as the normal delta handshake over the file being replaced; the size gate is the delta engine's own bounds (both files ≥ 16 KiB, ≤ `--delta-max`, ratio ≤ 10×); rsync's fuzzy matcher is not tied to a delta size bound and empirically reuses a basis well outside FastSync's window (a 64 KiB source against a repeated-content sibling from 0.25× to 10000×, and files as small as 300 B), so candidate ELIGIBILITY — and hence the chosen basis — can differ even though the name heuristic is the same; protocol 2.26.0 uses rsync's weighted-Levenshtein name/suffix distance plus an exact size+mtime pass and reads a single best candidate; the tie-break (smallest size gap, then lexical name) is deterministic where rsync leaves equal distances to its file-list order; the directory scan is capped at 4096 entries so a pathological directory cannot stall a transfer. When fuzzy applies: only to files the receiver would otherwise send whole — the destination's own file is always preferred as the delta basis when it exists and fits the delta size bounds, so fuzzy does NOT replace an existing-but-different destination basis; FastSync's 10× delta size-ratio bound means an existing destination file that is too far away in size still lets the fuzzy search run. When no similar candidate exists the transfer falls back to the normal whole-file transfer. rsync-divergence note: the name matching is rsync's own rule; the residual is eligibility bounded by FastSync's delta engine, so no name-matcher port can widen it. Because FastSync's delta machinery is off by default (rsync's is on), `--fuzzy` implies `--incremental` + `--delta` (unless `--whole-file`/`-W` or an explicit `--no-delta` switched delta off, in which case fuzzy is inert — matching rsync where `--whole-file` makes fuzzy irrelevant). Unlike the basis-dir options, `--fuzzy` honors an explicit `--no-incremental` (it does not force the handshake back on); an explicit `--no-incremental` also suppresses the delta implication so no invalid `--delta requires --incremental` config results. `--no-fuzzy` negates it. All surrounding semantics are untouched: a fuzzy-reconstructed file is stored as a normal file, so `--remove-source-files`, itemize/`-i`, `--stats`, `--backup`, `--delay-updates`, `--existing`/`--ignore-existing`/`--update` behave exactly as for a whole-file transfer (the fuzzy delta does not skip the file). **Reclassified Caveat (track 5b):** the output is always byte-exact regardless of the basis, and the name rule is rsync's, **Eligibility parity (parity-2.29):** the fuzzy candidate search no longer inherits the ordinary delta engine's 16 KiB minimum or 10× size-ratio bound, so an oversized or sub-16-KiB sibling is now reused exactly as rsync reuses it — the chosen basis (and therefore `Matched data`/`Literal data`/`Total transferred file size`) matches rsync where the block size is pinned (differential `test_parity_basis_fuzzy.py`; the old boundary tests were flipped to assert both tools reuse the basis). Residual: the whole-basis buffer cap (`MAX_RECEIVE_WHOLE_FILE_SIZE`, 256 MiB) and the deterministic tie-break where rsync leaves equal distances to its file-list order. |

## 12. Compression

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-z`, `--compress` | Compress file data | ✅ Parity | Streaming compression. **Protocol 2.26.0 implements rsync 3.4.1's codec set** (`zstd` default, `lz4`, `zlib`, `zlibx`, `none`), selectable via `--compress-choice`/`--zc` and negotiated with `auto`. `-z` is the compression short form; `-c` is rsync's `--checksum`. `--skip-compress` applies rsync 3.4.1's default suffix list when no list is given. **Track 3a closes the codec caveats:** `zlibx` is no longer a divergence — FastSync's zlib stream already carries only the delta/token (literal) bytes, which is exactly rsync's zlibx semantics, so `--zc=zlib` and `--zc=zlibx` land the same tree/stdout/exit (differential `test_compress_codec_matches_rsync_bytes`) and the zlib/zlibx aliasing is only an implementation detail. Each codec now uses rsync's own default `--compress-level` (zstd 3, zlib/zlibx 6, lz4 ignored) and `auto` consults `RSYNC_COMPRESS_LIST` before the compiled-in order; the deterministic same-build resolution needs no peer probe. **Audit-cycle fix:** the decompressor's internal ceiling is now defined by the protocol whole-file bound (`MAX_RECEIVE_WHOLE_FILE_SIZE`, 256 MiB) instead of a separate 100 MiB constant, so `-z` on a 100–256 MiB regular file no longer fails with `Declared decompressed size exceeds 104857600 bytes` |
| `--compress-choice=STR`, `--zc=STR` | Choose compression algorithm | ✅ Parity | Protocol 2.26.0 accepts rsync 3.4.1's compiled-in choices — `zstd` (default), `lz4`, `zlib`, `zlibx`, `none`, `auto` — and rejects an unknown name with exit 4 like rsync. The negotiated codec id crosses the wire (`compression_algo`), so the receiver decodes with the sender's codec. `--zc` is the alias. `auto` now resolves through `RSYNC_COMPRESS_LIST` (whitespace-separated; unknown names skipped, first supported wins, all-unknown is exit 4) and then the compiled-in order, and an explicit `--zc` wins; the deterministic same-build resolution needs no peer probe. `zlib`/`zlibx` share FastSync's literal-only zlib path, which is rsync's zlibx behavior and is observably identical for both, so `zlibx` is not a divergence (the aliasing is an implementation detail) |
| `--compress-level=NUM`, `--zl=NUM` | Set compression level | ✅ Parity | Accepted range 1-22. When omitted, rsync 3.4.1's **per-codec default** applies: zstd 3 (`ZSTD_CLEVEL_DEFAULT`), zlib/zlibx 6 (`Z_DEFAULT_COMPRESSION` resolved), lz4 ignored (no tunable level; FastSync keeps a positive gate value and `lz4_compress` ignores it, so the bytes match rsync). An explicit level is clamped per codec like rsync's `init_compression_level()`: zstd 1-22, zlib/zlibx 1-9, lz4 ignored. Verified against `rsync --debug=NSTR1`, which reports the same effective level per codec |
| `--compress-threads=NUM` | Set compression threads | ✅ Parity | `compression_threads` config field (client-only; does not cross the wire). Sets the number of worker threads used by the zstd compression pool to NUM (1..64; 0/garbage/oversized rejected up front). Accepted in both `--compress-threads=NUM` and two-argument `--compress-threads NUM` forms. Composes with `-z`/compression; under the `-j`/`--threads` multithreaded pipeline it parallelizes compressed chunk encoding. See test_tcp.py `-z --compress-threads=2` and test_client_cli.c |
| `--skip-compress=LIST` | Skip compress for suffixes | ✅ Parity | Comma-separated (or `/`-separated, as in rsync) case-insensitive suffix list; a leading dot is optional; an empty list skips none. **When the option is omitted, rsync 3.4.1's built-in default suffix list applies** (`3g2 3gp 7z aac … zip zst`); an explicit list replaces that default entirely, matching rsync. A user-supplied list is a client-side compression choice; incompatible with FastSync chunk serialization (`-s`) |

## 13. Connectivity

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `-e`, `--rsh=COMMAND` | Remote shell to use | ✅ Parity | `-e`/`--rsh` (and `--rsh=COMMAND`) select the remote-shell program used to build the SSH child argv, overriding the default `ssh`. The command is whitespace-split into the leading argv words so rsync's `-e "ssh -p 2222"` works; the standard `-o` family, an optional `-p` port, `user@host` and the quoted remote command (`fastsync-server --stdio`) follow. Stored in the `rsh_command` config field. **Client-only, never crosses the wire** (it is a launch concern, not a handshake property) |
| `--rsync-path=PROGRAM` | rsync binary on remote | ✅ Parity | Alias for `--fastsync-server-path`: both write the `fastsync_server_path` config field used as the remote-side server program. The path is always quoted as one remote-shell word in the SSH argv. **Client-only: `fastsync_server_path` never crosses the wire** (it is a launch concern, not a handshake property), matching rsync, where `--rsync-path` likewise names the remote program locally. Kept separate from `--rsh`, which names the local connecting program |
| `--port=PORT`, `--port PORT` | Alternate daemon port | ✅ Parity | rsync's daemon-port flag is an alias for `--server-port`: both spellings (and `--server-port=PORT`) map to the client-side `server_port` config field. The client connects to a TCP/TLS server (incl. `host::module/path` daemon destinations) on that port, and the `fastsync-server --daemon` listener's port is taken from its config's `port` key (default 873) or overridden by `--dparam port=` / `-p` |
| `--sockopts=OPTIONS` | Custom TCP options | ✅ Parity | Comma-separated allowlist of `OPT=VAL` applied via `setsockopt` after `socket()` before `connect()`/`bind()`. Only `TCP_NODELAY`, `SO_KEEPALIVE`, `SO_REUSEADDR` (0/1) and `SO_RCVBUF`/`SO_SNDBUF` (byte count) are accepted; an unknown option name or a bad value is rejected up front, never silently ignored. A value is required for every option (`OPT=VAL`; a bare name is an error). Applied to the outgoing TCP and TLS client socket; absent by default. `SockOptEntry`/`sockopts` config fields. Local socket concern: never crosses the wire |
| `--blocking-io` | Use blocking I/O for remote shell | ✅ Parity | With `--blocking-io` the SSH-transport socketpair socket is left without `SO_RCVTIMEO`/`SO_SNDTIMEO`, so the transfer blocks naturally; by default it gets the same read/write timeout as the TCP transport (see `--timeout`). `blocking_io` config bool. **Client-only, never crosses the wire** |
| `--timeout=SEC`, `--contimeout=SEC` | Set I/O / connect timeouts | ✅ Parity | Protocol 2.23.0 matches rsync's defaults: **`--timeout` defaults to 0 (I/O deadlines disabled) and `--contimeout` to 60 s; `0` disables either.** A positive `--timeout` bounds both the socket (`SO_RCVTIMEO`/`SO_SNDTIMEO`) and the per-message protocol poll deadline on the client; the server floors its session deadline so a client `0` can never hold a session open forever. `--no-timeout`/`--no-contimeout` are the negations. Both are client-side deadlines and are not sent on the wire |
| `--outbuf=N\|L\|B` | Set output buffering | ✅ Parity | `N` (none/unbuffered) → `_IONBF`, `L` (line) → `_IOLBF`, `B` (block, the default) → `_IOFBF` via `setvbuf` on stdout and stderr. Garbage values are rejected. `outbuf` config field (`OutbufMode`). **Client-only, never crosses the wire** |
| `--address=ADDRESS` | Bind address for outgoing socket | ✅ Parity | Binds the outgoing client socket to a local source address before `connect()` (resolved with the same `-4`/`-6` family hints as the destination). Local socket concern: never crosses the wire |
| `-4`, `--ipv4` | Prefer IPv4 | ✅ Parity | Forces `AF_INET` in the `getaddrinfo` hints for client destination/source resolution and the server bind (see the Phase 5, Wave B note). Mutually exclusive with `-6` |
| `-6`, `--ipv6` | Prefer IPv6 | ✅ Parity | Forces `AF_INET6` in the `getaddrinfo` hints for client destination/source resolution and the server bind. Mutually exclusive with `-4` |
| `--remote-option=OPT`, `-M` | Send an option only to the remote side | ❌ Divergent | Each value is appended to the remote server invocation over SSH as an individually single-quote-escaped shell word in `ssh_build_remote_command()`. Values are validated (non-empty, no control characters) and shell metacharacters cannot break out of the quoting (`;`, `&`, `\|`, <code>`</code>, `$`, `(`, `)`, quotes are neutralized), so a value cannot inject an arbitrary remote command and a subsequent `--` on the client line cannot be turned into one. The short `-M` form (`-M OPT`, `-M=OPT`, and rsync-style attached `-MOPT`) is available, matching rsync; metadata mode moved to long-only `--preserve`. **Reclassified because the daemon/TCP case cannot be reproduced:** `-M` is only meaningful for the SSH transport (`user@host:path`); a daemon (`host::module/path`) or local TCP destination **rejects** it, whereas rsync forwards it to its own remote process on every transport. A differential test starts a real rsync daemon and shows `-M--totally-bogus` reaching the remote parser (`unknown option`) while a valid `-M--safe-links` is accepted. FastSync's daemon handshake is a fixed binary config frame with no per-connection argv channel; adding one would let a client set arbitrary server-side options (the same class of divergence as the native daemon config/auth), so the safe subset stays SSH-only |
| `--bwlimit=RATE` | Limit I/O bandwidth | ✅ Parity | A faithful port of rsync 3.4.1's `parse_size_arg(bwlimit_arg, 'K', "bwlimit", 512, -1, True)`: a bare value is KiB/s, `K`/`M`/`G`/`T`/`P` are binary suffixes, `KB`/`MB` are decimal, `KiB`/`MiB` are binary, decimals are accepted and quantized to whole KiB exactly like rsync's `(size + 512) / 1024`, `0` (or an empty value) means "no limit", and any other value below the 512-byte floor is rejected. The token bucket's burst capacity is ~100 ms of bandwidth, matching the point at which rsync's leaky bucket starts sleeping, so a throttled transfer paces like rsync (4 MiB at `--bwlimit=1024`/`2048` matches rsync within ~4%). Differential-tested: the accept/reject matrix and the wall-clock rate both match rsync 3.4.1. **Audit-cycle fix:** the plaintext-TCP `--sendfile` fast path now passes its writes through the same token bucket, so `--bwlimit` also paces it (previously the `sendfile(2)` path bypassed the limiter entirely); the TLS and plaintext transports therefore share identical throttling. The limit is a local I/O concern and is not negotiated on the wire |

## 14. Daemon Mode

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--daemon` | Run as rsync daemon | ❌ Divergent | Wave A: a real persistent listener. `fastsync-server --daemon --config FILE` (plus `--no-detach` to stay foreground; without it the listener detaches to the background after binding) reads a FastSync-native module config file and serves each connection confined to the requested module's `path` root (never a client-chosen root; every client-chosen-ownership/super-user request (`--numeric-ids`/`--chown`/`--usermap`/`--groupmap`/`--fake-super`/`--copy-as`/explicit `--super`) is refused unless the module opts in with `client owner = yes`, and the operator `--no-super` veto is honored). TCP/TLS via the existing `--tls` stack; plaintext still requires `--allow-unauthenticated` (same secure default as the standalone server). Client destinations use rsync's `host::module/path` form. Wire/protocol: the config frame gained a trailing daemon-module string and `PROTOCOL_VERSION` was bumped **2.14.0 → 2.15.0** (see the Daemon Mode notes below). Daemon mode is built in FastSync's own protocol/config grammar, not rsync's SMB/daemon option encoding |
| `--config=FILE` | Alternate rsyncd.conf file | ❌ Divergent | Wave A: selects the daemon config file. Default when omitted (in `--daemon` mode): `~/.config/fastsync/fastsyncd.conf` if it exists, else `/etc/fastsyncd.conf`. The grammar is FastSync-native (documented in the Daemon Mode notes below) and strictly rejects unknown keys so a typo can never silently change what a module serves; requires `--daemon` |
| `--dparam=OVERRIDE` | Override global daemon config | ❌ Divergent | Wave A: overrides one global scalar from the command line (`--dparam port=8734` and `--dparam=KEY=VALUE` both work). Limited to the global keys the grammar defines (`port`, `motd file`, `address`, `max connections`, `max connections per host`, `auth failure delay`, `auth lockout threshold`, `auth lockout duration`, `hosts allow`, `hosts deny`); keys are case-insensitive and unknown keys/invalid values are rejected. Requires `--daemon` |
| `--no-detach` | Don't detach from parent | ✅ Parity | Wave A: with `--daemon`, keeps the listener in the foreground (what integration tests use). Without it the daemonizes (fork/setsid, stdio redirected to /dev/null) after the listening socket is bound. Requires `--daemon` |
| `--password-file=FILE` | Read daemon password from file | ❌ Divergent | A7 daemon auth. Client: `--password-file` supplies `user:password` for a `host::module/path` destination (the username is taken from this file, so `user@host::module` stays rejected); the literal password is held client-side only for the SCRAM handshake and wiped at teardown. Server (`fastsync-server --daemon --password-file FILE`): the salted-PBKDF2 verifier store that modules with `auth users` are verified against. **Neither the password nor any replayable bearer value crosses the wire or is stored server-side** — the store holds a per-user salt plus derived keys, and the daemon proves the secret with a per-connection nonce challenge. The file must be private to its owner: both the client and server verify the exact inode they read (open-then-`fstat`, so the check cannot be raced) and refuse a `--password-file`/`--early-input` that is not owned by the current user or grants any group/other permission bit (mode 0600), mirroring the TLS private-key check. A process-substitution pipe (`--early-input <(vault ...)`) is still accepted when it satisfies those checks. **Hardening follow-up:** the file is opened with `O_NOFOLLOW`, so a symlinked credential path fails closed (`ELOOP`) instead of being followed before the owner/mode gate; literal fd-backed paths (`/dev/fd/<digits>`, `/proc/self/fd/<digits>`, which is what a bash process substitution passes) are exempt, so process substitution still works. A FIFO/process-substitution read now waits under a bounded ~3 s deadline for its writer, so a slow producer works while a connected-but-silent FIFO fails instead of hanging. See the Daemon Mode notes below for the file formats and the plaintext/TLS caveat |
| `--early-input=FILE` | Use FILE for daemon early exec | ❌ Divergent | Server-only (requires `--daemon`): a second credential-store file, same new-format grammar as `--password-file`, read before the listener accepts connections (a secrets-manager / process-substitution source). Its entries layer over `--password-file`: byte-identical verifiers dedupe, a conflicting verifier for the same user is a startup error. Opened with the same `O_NOFOLLOW` hardening as `--password-file` (a symlinked path fails closed with `ELOOP`; fd-backed `/dev/fd/N`/`/proc/self/fd/N` process-substitution paths are exempt) and a FIFO read is bound-waited (~3 s) so a slow producer works while a writer-less FIFO cannot hang. A daemon whose modules declare `auth users` must be given at least one of the two, or it refuses to start (fail closed) |
| `--hash-credentials=FILE`, `--iterations N` | Hash a plaintext credential file | ❌ Divergent | Server-only offline tool (A7): reads the `user:password` lines of FILE (same owner-only 0600 check) and prints one new-format store line per entry to stdout, then exits. `--iterations` sets the PBKDF2 work factor (default 600000, range 100000–10000000). Dependency-free and does not run a listener. Use its output as `--password-file` for `--daemon`. There is no auto-upgrade: a legacy store line is hard-rejected by the loader and must be regenerated |

**Daemon Mode notes (Wave A protocol 2.15.0; A7 auth protocol 2.19.0; MOTD no bump):** FastSync daemon mode is supported in FastSync's own protocol/config grammar, not rsync's SMB/daemon option encoding.

- **Config grammar** (`fastsyncd.conf`): line-based; an implicit global section first, then `[module]` sections. Keys are case-insensitive, values are trimmed and may be wrapped in one layer of double quotes (`path = "/srv/my dir"`). `#` and `;` at the start of a line (after leading whitespace) are full-line comments; inline comments and `\` continuations are not supported. Lines are bounded (4096 chars), and at most 256 `[module]` sections are accepted. Global keys: `port` (default 873), `motd file` (the daemon sends its bounded, escaped content to a client after the module gate/auth accepts, unless the client passes `--no-motd`), `address` (optional bind address), `max connections` (positive integer cap on concurrent connections, default 100; 0/negative/garbage is a parse error), `max connections per host` (concurrent-connection cap per source IP, default 0 = unlimited), `auth failure delay` (milliseconds to sleep after a failed authentication, default 500; 0 disables, capped at 5000), `auth lockout threshold` (failed authentications from one source before lockout, default 10; 0 disables), `auth lockout duration` (seconds a locked-out source is refused, default 300), `hosts allow` and `hosts deny` (comma- and/or whitespace-separated host access patterns — see the host access control note below). Module keys: `path` (required; the daemon-side authorized root for that module), `read only` (yes/no/true/false/1/0, default no), `client owner` (yes/no/true/false/1/0, default no; opts the module into client-chosen ownership — see below), `auth users` (comma list), `max connections` (optional per-module cap, 0 = unlimited; enforced across all connection children), `hosts allow`/`hosts deny` (per-module host access lists). **Unknown keys and malformed lines are parse-and-reject errors** (never silently ignored), so a typo cannot change what a module serves.
- **Host access control (`hosts allow`/`hosts deny`):** both keys accept a comma- and/or whitespace-separated list of patterns and may appear globally and/or per module (multiple config-file lines append; a `--dparam` override replaces). Supported patterns are `*` (match all), an IPv4 or IPv6 literal (`10.0.0.1`, `2001:db8::1`), and an IPv4/IPv6 CIDR (`10.0.0.0/8`, `2001:db8::/32`). Hostname patterns are **not** supported: because the peer is always a numeric address and no reverse DNS is performed, a hostname/glob pattern would silently never match, so it is rejected at load time (fail-closed) instead of being accepted as a dead rule. An IPv4 peer on a dual-stack IPv6 listener is normalized from its `::ffff:a.b.c.d` form so IPv4 patterns match it. rsync-like semantics: a matching `hosts deny` rejects; if any `hosts allow` entries exist, a peer matching none of them is rejected; deny takes precedence over allow. The daemon enforces the global list first, then the selected module's list, **before authentication** in `server_module_gate`, with an audit log line naming the peer, the module and the outcome. The numeric peer address is obtained with `getpeername`+`inet_ntop` (`utils_fd_peer_ip`, handling both address families); when it cannot be obtained a module with any ACL fails closed (refused), while an ACL-free module continues and logs at debug. A malformed pattern (e.g. an out-of-range CIDR prefix) is a parse error at load time.
- **Connection caps, shared registry and auth lockout:** the global `max connections` key (default 100) is plumbed into the listener (`transport_tcp.c`), which rejects a connection once the accept-loop parent's active-child count reaches it; the IPv4/IPv6 peer is logged for every accepted connection. Because the listener forks one child per connection, the per-module `max connections` cap, the global `max connections per host` cap, and the auth-failure counter live in a fixed-size registry carved from an anonymous shared mapping (`daemon_limits.c`, `mmap(MAP_SHARED|MAP_ANONYMOUS)`) created by the parent before the accept loop, so every forked child shares the same counters (C11 atomics only — never a pthread lock, which can deadlock in a forked child). The parent reserves a registry slot per accepted connection and the child records the selected module and source IP once known; the parent's `SIGCHLD` handler reclaims the slot when the child dies (including `SIGKILL`) and re-derives the per-module and per-source occupancy counts from the surviving REGISTERED slots, so a child killed mid-registration cannot leak a count. The per-source table has a bounded lifetime: an entry with no live connection is reclaimed after its lockout expires or it has been idle (300 s); if the table is genuinely full the per-source cap/lockout fails open for new sources (per-module cap and ACLs still apply) with a rate-limited warning. The per-module cap (0 = unlimited) is enforced after the module lookup and before auth; per-source identity reuses the normalized numeric peer address (`utils_fd_peer_ip`, IPv4-mapped IPv6 collapsed to IPv4), and a trusted loopback peer (127.0.0.0/8 / `::1`, `utils_fd_peer_is_local`) is exempt from the per-source cap and the auth lockout because all local clients share one address (the per-module/global caps still apply). Clients behind a shared NAT/proxy address likewise share one per-source budget and lockout counter. A failed authentication increments the shared per-source failure count and, once `auth lockout threshold` (default 10; 0 disables) is reached, the source is refused for `auth lockout duration` seconds (default 300) before any challenge is sent, even when the next attempt is handled by a different forked child; a successful authentication clears the counter. On a failed authentication the per-connection child still sleeps the global `auth failure delay` (default 500 ms, 0 disables, capped at 5000) via `nanosleep`, rate-limiting online guessing without delaying a success. A missing registry (allocation failure) degrades to the global cap and host ACLs rather than refusing to start.
- **Module selection & confinement:** the client requests a module with an rsync-style `host::module[/path]` destination. The module name crosses the wire as a trailing string on the config frame (bumping `PROTOCOL_VERSION` 2.14.0 → 2.15.0; the bump is required because the config-frame layout changed and the strict same-version handshake is what prevents a peer from desynchronizing on the new trailing field). The daemon looks the module up in ITS OWN config and uses the module's `path` as the authorized root through the exact same `configure_authorization` confinement the standalone server applies to `--destination-root` (`file_open_secure_parent`, `has_path_traversal`, `path_is_within`); the client never supplies the root, every client-chosen-ownership/super-user request is refused unless the module declares `client owner = yes` (the daemon's per-module opt-in, see below), and the operator `--no-super` veto forces super-user activities off for every daemon connection. The client's `/path` part is relative inside the module and is rejected if absolute or if it contains `..`. Unknown modules are refused before any data moves (the run fails cleanly at the config handshake). An absolute destination and a module request against a non-daemon server are also refused.
- **`client owner` (client-chosen-ownership opt-in):** by default a daemon module refuses every request that would let the client pick an owner or ask for super-user activities — `--numeric-ids`, `--chown`, `--usermap`/`--groupmap`, `--fake-super`, `--copy-as`, and an explicit `--super` — at the config handshake (before `STATUS_OK`), because a daemon has no per-module opt-in for client-chosen ownership and any anonymous client could otherwise force arbitrary owner ids inside the module root. A plain preserve-source request (`-a`/`-o`/`-g`) is **not** refused: the module forces super-user activities off for that connection, so no ownership is applied, and it logs a warning that the requested ownership will not be applied (the transfer itself still succeeds). `client owner = yes` opts a single module in, allowing those requests within that module's root (a root standalone TCP listener honors them for its single operator-authorized root only when started with `--allow-super`; the flag is rejected with `--stdio`, whose client-composed remote argv must never opt back into super mode). Without the opt-in the daemon also forces super-user **device** activity off for that connection — char/block device-node creation (`--devices`) and `--write-devices` — even under the default `AUTO` mode, so a non-opted module can never be made to `mknod` or write a raw device; those entries are skipped (not refused) so an ordinary `-a` push still succeeds without device nodes. The opt-in does **not** lift the privilege requirement: `--copy-as` still needs a root receiver, and the operator `--no-super` veto still forces super-user activities off for every connection. The daemon logs a prominent startup warning for each `client owner = yes` module so the operator's deliberate choice is visible.
- **`read only` safe default:** every network transfer FastSync currently supports is a push that writes under the module root, so a `read only` module refuses the connection (clear server log "module is read only"; the client exits non-zero, nothing is transferred). A future pull/list operation can be opened up when it exists; the knob is already stored.
- **Direction — remote source / pull is intentionally unsupported:** FastSync is push-only. The first positional argument is always a **local** source directory and the second is the destination; only the destination is parsed for remote syntax (`user@host:path` SSH, `host::module[/path]` daemon). A remote source such as `fastsync user@host:src ./local` is deliberately **not** implemented: rsync has no pull flag (direction is positional), so supporting a remote source is an optional feature rather than a compatibility requirement, and it would require a protocol role reversal (server as sender, client as receiver) across both transports. FastSync documents this as an intentional limitation rather than a missing rsync option. <a id="direction"></a>
- **`auth users` (A7 SCRAM-SHA-256 authentication):** a module that declares `auth users` requires the client to present credentials. The config frame carries ONLY the username; the daemon answers an auth-required module with `STATUS_AUTH_CHALLENGE` (PBKDF2 iteration count, 16-byte salt, 32-byte server nonce), the client answers with `STATUS_AUTH_RESPONSE` (fresh 32-byte client nonce + a 32-byte ClientProof), and the daemon accepts only when the proof verifies **and** the username is **on the module's `auth users` list** and has a store entry, replying `STATUS_AUTH_OK` with a 32-byte ServerSignature the client verifies before proceeding. Verification is constant-time over fixed 32-byte keys (the compare runs even for a miss), username membership uses a constant-time full-length scan, and an unknown/off-list user still receives a challenge and runs the same math against a dummy verifier: a deterministic per-username salt (`HMAC-SHA256(store dummy key, username)`), the store-wide uniform iteration count and dummy keys. Re-probing the same unknown username therefore yields an identical salt and iteration count while a different username yields a different salt, so there is no user-enumeration or timing oracle. The daemon logs the username but **never the password, proof or keys**. A module WITHOUT `auth users` stays open (legitimate rsync configuration); credentials sent to such a module are ignored. Read-only is orthogonal: even a correctly authenticated push to a `read only` module is still refused (all FastSync network transfers write). Fail-closed policy: a daemon whose config declares `auth users` on any module refuses to start unless a credential store was given (`--password-file` and/or `--early-input`); a missing or empty store is never silently treated as "open". A failed handshake (missing credentials, unknown/off-list user, wrong proof or malformed data) yields a single generic `STATUS_AUTH_FAILED` and the daemon closes before any data moves. The dummy key is persisted in an owner-only `<store_path>.dummykey` sidecar (auto-created on first load, mode 0600) so the dummy salt stays stable across daemon restarts, closing the restart-gated enumeration channel. The sidecar is secret material and must be protected like the credential store (owner-only 0600, included with the store in backups and rotation). It must be preserved across restarts for that guarantee; if it cannot be created (a process-substitution/FIFO store path such as `/dev/fd/N`, a read-only filesystem, a missing directory, or a create/write/fsync/link/fchmod failure), the daemon logs a warning and uses a transient per-run key, so unknown-user challenges change across restarts and the cross-restart guarantee does not hold for that deployment. One residual is accepted: the store iteration count is observable pre-auth by design, since the miss path must match a hit. **Transport policy (hardening A7-3/S1):** an auth-required module accepts credentials only when either (a) the connection is an encrypted, verified TLS connection whose client certificate matches `--client-cn`, or (b) the connection is plaintext from a loopback TCP peer **and** the operator explicitly passed `--allow-unauthenticated`. A remote plaintext peer, and a loopback plaintext peer without that flag, are refused at the config gate before any challenge is sent; `--allow-unauthenticated` never permits remote plaintext auth (remote peers still require verified TLS). Daemon modules are a `--daemon`-only feature — the SSH `--stdio` path never loads a daemon config and is not an auth transport for them. Because the loopback allowance trusts whichever peer the kernel reports as `127.0.0.1`, it assumes nothing relays remote connections to the daemon: a local TCP forwarder or TLS-terminating proxy in front of an auth-module listener makes remote clients appear as loopback and bypasses the mutual-TLS identity check, so do not front an auth-module listener with such a relay.
- **Credential store format:** server `--password-file`/`--early-input` files are line-based `user:$fastsync$1$pbkdf2-sha256$<iters>$<salt_b64>$<stored_key_b64>$<server_key_b64>`, one per line (standard base64; 16-byte salt, 32-byte keys; `iters` in `[100000, 10000000]`, default 600000). Every entry in the resulting store must agree on `iters` (a store whose entries disagree, or where a layered `--early-input` disagrees with `--password-file`, is rejected). Generate lines with `fastsync-server --hash-credentials FILE [--iterations N]`; the emitted lines are secret material, so redirect them to an owner-only (mode 0600) file (the tool warns on stderr if stdout is a group/other-accessible regular file). Blank lines and lines starting with `#`/`;` are comments; the parser is strict (a malformed line fails the whole load, so a typo can never let a different set of users in). **The legacy `user:SHA256HEX` form is hard-rejected** with an actionable "legacy" error; there is no auto-upgrade, so a replayable bearer digest can never be loaded by a 2.19.0 daemon. The client `--password-file` holds `user:password` on its first meaningful line (the literal password, used only for the handshake then burned); keep both files readable only by their owner (mode 0600). Per-username wire length is bounded (256 chars) and every decoded salt/key length is validated. Loading the store also maintains an owner-only `<store_path>.dummykey` sidecar (auto-created, mode 0600, exactly 32 bytes) holding the store-wide dummy key that shapes unknown-user challenges; persist it across daemon restarts so those challenges stay stable, and treat a sidecar with the wrong owner, a mode other than exactly 0600, the wrong size or the wrong type as a fatal load error (fail closed). If the sidecar cannot be created (e.g. a process-substitution store path such as `/dev/fd/N`, a read-only filesystem, a missing directory, or a create/write/fsync/link/fchmod failure), the daemon logs a warning and uses a transient per-run key, so the cross-restart stability guarantee does not hold there.
- **Plaintext caveat:** an auth-required module is refused, **before any challenge is sent**, unless the connection is encrypted and verified TLS whose client certificate matches the server's `--client-cn`, or it is plaintext from a loopback TCP peer **and** the operator passed `--allow-unauthenticated`. A remote plaintext peer, and a loopback plaintext peer without that flag, never receive a challenge, and `--allow-unauthenticated` never permits remote plaintext auth (remote peers still require verified TLS). On the loopback plaintext transport that remains permitted, a local sniffer could still read the challenge and response and mount an **offline dictionary attack** against a weak password, so use `--tls` for any real deployment. `--client-cn` matches the certificate CN only (not a subjectAltName), which is acceptable for a private CA. Clients sending daemon credentials with `--password-file` to a non-loopback daemon must use `--tls`; the client rejects such a destination before any network I/O. Unlike the old challenge-less exchange there is **no replay**: the proof is bound to the fresh per-connection server nonce, so a captured `STATUS_AUTH_RESPONSE` cannot be reused on another connection (an integration test proxies the daemon and proves this). TLS client-CN (`--client-cn`) is an independent transport identity check and composes with password auth; because `--tls` already mandates `--client-cn`, a TLS auth connection always verifies the client CN, so both checks necessarily apply together on such a connection.
- **Wire/protocol:** the config-frame auth block is now `[int present][str_redacted username]` (the old digest field is gone), and the frame stream gains the challenge/response (`STATUS_AUTH_CHALLENGE` → `STATUS_AUTH_RESPONSE` → `STATUS_AUTH_OK`/`STATUS_AUTH_FAILED`) between the config frame and the `STATUS_OK` ack. Both are wire-layout changes, so `PROTOCOL_VERSION` is bumped **2.18.0 → 2.19.0** (see the A7 note in `src/shared/config.h`); the strict same-version handshake keeps a 2.19 client and a 2.18 server from desynchronizing.
- **Client side:** `host::module/path` selects the TCP transport and connects to `--server-port`; `host:path` stays the SSH transport; plain paths stay local TCP. The daemon username comes from `--password-file` (first `user:password` line), and `--password-file` without a `host::module/path` destination is a client error (fail fast). A `user@host::module` form is rejected with a pointer to `--password-file`. The client's plaintext password is wiped from memory (`config_burn_auth`) at transfer teardown.
- **MOTD (Wave C):** a daemon configured with a global `motd file` sends that file's content as the first server→client string frame after the config-frame STATUS_OK ack (rsync sends the MOTD as the first thing from the server at the start of a daemon connection). Only the daemon listener path (`host::module`) gets a MOTD; the `--stdio` SSH path never sends or reads one. The server reads the file bounded to 4096 bytes and treats an absent/unreadable file as "no MOTD" (an empty frame, never an error). The exchange is server→client only and does **not** bump `PROTOCOL_VERSION`: every 2.15.0 daemon client reads the frame after the ack, so sender and receiver stay in lockstep (see the Wave C note in `src/shared/config.h`). `--no-motd` is the client-side suppression switch: the client still reads (consumes) the frame to keep the stream in sync but does not display it. The MOTD is printed to stdout with control bytes (ESC included) escaped octal-style while newlines/tabs are preserved, so a hostile server cannot inject terminal escape sequences.
- **Merge note:** the Wave A module bump (2.15.0) and the MOTD wave did not bump the version, but the A7 auth redesign is a genuine wire-layout change and owns the 2.18.0 → 2.19.0 bump (see the A7 note in `src/shared/config.h`).

## 15. Safety & Security

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| Path escape detection | Ensure files stay within root | ✅ Parity | `has_path_traversal()` + realpath |
| Symlink-safe delete | Skip symlinks in delete walk | ✅ Parity | `delete_extras_fd()` (`src/shared/utils.c`) and `manifest_delete_extras()` (`src/shared/file_receive.c`) |
| Protocol version check | Verify compatible versions | ✅ Parity | `config_receive()` |
| Max data/string/chunk sizes | Prevent OOM attacks | ✅ Parity | Per-message limits |
| Per-connection memory limit | Cap memory per connection | ✅ Parity | `MAX_CONNECTION_MEMORY` is **256 MiB per connection** (256 * 1024 * 1024 bytes), charged across protocol reservations and decompression/chunk allocations. This is a FastSync-internal bound with no direct rsync analogue |
| `--max-alloc=SIZE` | Limit a single memory allocation | ✅ Parity | Caps the largest single allocation; binary units, default 1G |
| `--trust-sender` | Trust remote sender's file list | ✅ Parity | Long-form-only, receiver-local policy that never crosses the wire. The receiver skips its redundant up-front re-validation of the incoming file list (empty/`..` path rejection), trusting the sender instead of double-checking (fewer checks, faster, potentially unsafe, matching rsync). Off by default. **It no longer affects symlink targets** (protocol 2.23.0): targets are stored verbatim under `-l` regardless of `--trust-sender`; the flag only relaxes the receiver's path-list checks. The low-level fd-relative confinement primitives (`file_open_secure_parent`, the O_NOFOLLOW parent walk, leaf/destination confinement) are deliberately KEPT even under `--trust-sender`, so a hostile sender still cannot write or link outside the authorized root (see Phase-5 notes below) |
| `--old-args` | Disable modern arg protection | ❌ Divergent | SSH-only; accepted for CLI compatibility but is now a **documented no-op**: FastSync always single-quote-escapes the remote server path and each `--remote-option` value (`ssh_build_remote_command`), so a metacharacter-bearing `--rsync-path` can never be interpreted by the remote shell. The flag no longer disables that quoting (the old raw-construction behavior was an injection foot-gun and is removed); the safety-relevant behavior is identical either way |
| `--ignore-missing-args` | Ignore missing source args | ✅ Parity | The flags apply to the `--files-from` entries (the single source root always exists; inert without `--files-from`). Without the flag a listed-but-missing entry is a hard pre-transfer error. With it each missing entry is skipped: nothing is sent for it, it never enters the keep-set, and the run succeeds for the rest (an all-missing list transfers nothing). Every skipped entry is logged and a per-run warning names the count. **An empty `--files-from` list is now a zero-transfer success with or without this flag (exit 0), matching rsync 3.4.1.** `--no-ignore-missing-args` is rejected exactly as rsync 3.4.1 rejects it, rather than being accepted as a negation |
| `--delete-missing-args` | Delete missing source args | ✅ Parity | Implies `--ignore-missing-args` (order-independent) and additionally removes each missing entry's destination mirror receiver-side. The mirror is computed exactly like a present sibling's wire path: the bare relative entry under `-R`, otherwise the full source-mirror path below the destination root. rsync parity, verified against the man page: it does **not** imply `--delete` generally and is "independent of any other type of delete processing" — unrelated destination extras are untouched unless `--delete` is also present. Composition with `--delete` + timing: the exact-path deletions commit with the manifest, early for `--delete-before`/`--delete-during`, else only after a fully-successful transfer (delete-after/commit). A non-empty directory mirror is removed only when `--force` or `--delete` is in effect (otherwise it is left with a warning and the run continues, like rsync); an absent mirror is a no-op. `--force` is deletion authority and is therefore gated by the server `--allow-delete` policy exactly like `--delete`/`--delete-missing-args`: without it the receiver clears the flag, so a client cannot use `--force` to recursively replace or remove a destination directory tree. An explicitly listed missing arg is a user request, not an excluded file: its deletion is never blocked by the filter-exclusion protection of excluded destination mirrors (a mirror sitting inside a filter-excluded directory is still removed). Safety/policy: gated by the server `--allow-delete` policy like `--delete`; the request paths cross the wire only in the delete-manifest frame and are confined by the same receiver validation as the keep-set (non-empty, relative, traversal-free, bounded by the per-section/per-frame manifest caps); the `--delay-updates` staging directory and basis snapshots are protected exactly as in the extras walker. Protocol 2.23.0 parity: the missing-args exact-path removals and the ordinary extras walk **draw from one shared `--max-delete` budget**, so a capped run stops part-way and exits 25 exactly like rsync. See the Phase-3 wire note below for the `PROTOCOL_VERSION` bump |

**Setuid/setgid/sticky bits under `-p` (security note).** As with upstream
rsync, `-p`/`--perms` reproduces the source's special bits as well as the rwx
bits: setuid, setgid, and sticky are applied whenever the receiver can apply
them (the receiving user owns the file and the mount permits it), and a refused
chmod is logged rather than silently masked (`tests/test_metadata.c:575`). This
is a deliberate change from earlier FastSync releases, which always masked
special bits. Deployments that do not trust the sender should rely on the
existing mitigations rather than on that masking: keep the daemon module default
`client owner = no`, run the daemon unprivileged, and use
`--munge-links`/`--safe-links` so a hostile source cannot weaponize preserved
modes or links.

## 16. Batch Operations

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--write-batch=FILE` | Write batched update to file | ❌ Divergent | Phase-6 residual-batch (client-only): runs the normal live transfer AND additionally emits a self-contained single-file batch of the whole source tree. The batch is a magic/format-version header followed by length-prefixed `chunk_serialize` blobs (full file images), replayable byte-identically by `--read-batch` on another machine with no source/server. `--write-batch` drives the single-threaded transfer path (the multithreaded path consumes the config before the separate batch scan pass). The FastSync container is deliberately not interoperable with rsync batch files. See the Phase-6 batch note below |
| `--only-write-batch=FILE` | Write batch without updating dest | ❌ Divergent | Phase-6 residual-batch: emits the self-contained batch FILE only — NO destination update, NO server connection. Requires a source (scans it and serializes the full tree to FILE). Same single-file format as `--write-batch`, so the file is re-appliable via `--read-batch=FILE DEST`. The FastSync container is deliberately not interoperable with rsync batch files. See the Phase-6 batch note below |
| `--read-batch=FILE` | Read batched update from file | ❌ Divergent | Phase-6 residual-batch: applies a previously written batch FILE locally to the destination. NO source and NO server — positional args are the destination only. Reads the magic/version header, then length-prefixed records, `chunk_deserialize`, and applies each via the confined `file_save_to_disk_full` path (same O_NOFOLLOW / `..`-rejection / root-confinement as the network receiver, so an attacker-controlled batch cannot escape the destination root). Malformed/truncated/oversized/traversal records are rejected cleanly. The FastSync container is deliberately not interoperable with rsync batch files. See the Phase-6 batch note below |

## 17. Advanced

| Flag | Rsync Description | FastSync Status | Notes |
|------|-------------------|-----------------|-------|
| `--stop-after=MINS` | Stop after N minutes | ✅ Parity | Client-only sender stop deadline (Phase 6): computing `--stop-after=MINS` (a positive minute count; 0/negative/garbage rejected) and `--stop-at=TIME` (`HH:MM`, `HH:MM:SS`, or `now+N[smhd]`; a past time stops immediately). The transfer stops ELEGANTLY at the next chunk boundary: everything already fully sent is kept and applied, the run returns 0, and --delete (late/delete-after timing) does NOT wipe the destination — when the scan is cut short the partial keep-set manifest is suppressed with a warning (the delete walk is skipped rather than acting on an incomplete keep-set, so unscanned source mirrors survive). `--delete-before`/`--delete-during` still run their complete pre-scan (which ignores the deadline). Local client-only fields: never serialized into the wire config frame, so no PROTOCOL_VERSION bump. `--stop-after` uses CLOCK_MONOTONIC; `--stop-at` uses the wall clock. Works single-threaded and under `-j`/`--threads` (multithreaded). Divergence: rsync computes `--stop-after` from the run start; FastSync likewise. When both are given, the earlier of the two deadlines wins (checked per iteration). See the Phase-6 stop notes below |
| `--stop-at=TIME` | Stop at specified time | ✅ Parity | Deadline transfer stop (client-only, never serialized). Protocol 2.26.0 accepts rsync's full date/time grammar (`2030-12-31T23:59`, `2030/12/31T23:59`, `2030-12-31`, `12-31`, `14:00`, `:59`, `1`) in addition to FastSync's `HH:MM[:SS]` and `now+N[smhd]`; a past time stops immediately. Everything already transferred is kept and an early stop suppresses the late `--delete` keep-set so unscanned source mirrors survive. Works single-threaded and under `-j`/`--threads` |
| `--fsync` | Fsync every written file before publication | ✅ Parity | |
| `--protocol=NUM` | Force older protocol version | ❌ Divergent | Forces the wire protocol version for this transfer. FastSync has exactly ONE wire format (`PROTOCOL_VERSION`, currently 2.28.0) with no downgrade/backward-compat code paths, so `--protocol=2.28.0` is accepted (it sets the version claim the client sends, which the server already requires to match exactly) and **every other value is rejected up front** with a clear error before any connection — it does not and cannot speak an older or virtual wire format. Divergence from rsync (which negotiates a range and downgrades to an integer 0..31): FastSync's honest contract is force-to-the-one-supported-value; a genuine downgrade would require a per-version compatibility layer that does not exist. Client-only; the server-side exact-match check is unchanged. `--protocol=2.27.0`/`2.26.0`/`2.25.0`/`2.24.0`/`2.23.0`/`2.22.0`/`2.21.0`/`2.20.0`/`2.19.0`/`2.18.0`/`2.17.0`/`2.16.0`/`2.15.0`/`216`/`31`/garbage are all rejected. See the Phase-6 protocol note below |
| `--iconv=CONVERT_SPEC` | Charset conversion | ✅ Parity | Charset conversion of FILE NAMES (not content) at the protocol boundary via iconv(3): `--iconv=LOCAL[,REMOTE]` — the sender converts each local filename LOCAL→REMOTE before transmitting, matching rsync's rule that the spec "stays the same whether you're pushing or pulling": on a PUSH the destination end's charset is the spec's REMOTE half, so the default receiver writes the wire bytes verbatim, and only a server started with its own `--iconv` (the daemon `charset` analog) declares a different destination charset and converts REMOTE→that LOCAL (rsync push parity, differential-tested with and without a server `--iconv`). The full CONVERT_SPEC is serialized into the config frame as a new trailing string field so the peer knows the wire charset; **PROTOCOL_VERSION bumped 2.15.0 → 2.16.0**. `LOCAL[,REMOTE]` parse: single charset ⇒ LOCAL==REMOTE (identity both ways); garbage rejected up front; protocol 2.26.0 additionally accepts `--iconv=.` (the locale's default charset for both directions), `--iconv=-` and `--no-iconv` (disable conversion). Validation probes BOTH directions (a spec that only opens one way is refused, as is a NUL-emitting target charset like utf-16/utf-32/ucs-2, since filenames cannot contain NUL). An unrepresentable name (EILSEQ/EINVAL) fails that path cleanly with a logged `--iconv: cannot convert file name ...` and is never written mangled/truncated. Conversion is applied at EVERY wire-path site (regular/MKDIR/hardlink path+target/symlink path+target/SPECIAL, the delete manifest, the incremental-check path, and the `-s`/`chunk_serialize` embedded blob path), on both client and server (`--iconv` is also a server/daemon option). Zero overhead when unset. See the Phase-6 iconv notes below |
| `--checksum-seed=NUM` | Set checksum seed | ✅ Parity | Sets the seed for FastSync's whole-file xxHash digest (full 64-bit seed) and for the delta path's per-block xxHash32 strong checksum (low 32 bits of the seed). **As of protocol 2.23.0 a seed of `0` — the default when the flag is unset — is randomized per transfer and the chosen seed is sent to the receiver**, exactly like rsync, so two runs against different content do not share a predictable seed; an explicit non-zero seed is used verbatim, so an explicit seed deterministically reproduces every computed digest on BOTH endpoints (the seed crosses in the config frame). `--checksum-choice=md5` has no seed and ignores it (documented). The value is a strict decimal 0..2⁶⁴-1 (blank, signed, or non-numeric values are rejected). Like rsync, a seed only matters where a digest is actually computed (`--checksum` or a basis-dir run, or a delta transfer); it does not by itself enable `--checksum`/`--delta` |
| `--secluded-args`, `-s` | Use protocol to send args | ❌ Divergent | Accepted for CLI compatibility (including the rsync short `-s`, Phase 7 Wave A) but a documented **no-op / divergence**. rsync's `-s` protects arguments from shell expansion by shipping them over the protocol; FastSync never passes remote arguments through a shell expansion boundary in the first place — its SSH transport builds the remote argv as **single-quote-escaped shell words** (`ssh_build_remote_command`), so the injection/leak that `-s` guards against does not exist and there is nothing to "seclude". Implementing a true arg-send protocol would mean replacing the argv-based SSH launch with an in-band argument channel, a large redesign of the transport that buys no security here. Chunk serialization remains the long-only `--chunk-serialization`. |
| `--protect-args` | Old name of --secluded-args | ❌ Divergent | Accepted for CLI compatibility as a documented no-op; the same rationale as `--secluded-args`/`-s` (FastSync's remote SSH argv is already built injection-safe, so there is no argument-leak to close) |
| `--no-OPTION` | Turn off implied option | ✅ Parity | Supported boolean FastSync options and archive-implied options; unsafe or value-taking options are rejected. |

---

## Implementation Difficulty Plan

**Phase 5 notes (remote-option wave):** `--remote-option=OPT` (long form only) and `--trust-sender` landed here.
- `--remote-option` is CLIENT-only and never serialized into the binary config frame. On the SSH transport the client forwards each value to the remote server by appending it to the remote command line in `ssh_build_remote_command()`, after ` --stdio`, as an individually single-quoted shell word (`'...'` with `'\''` for embedded quotes). Values are validated at CLI parse time (non-empty; no ASCII control characters) and rejected otherwise, and a non-conforming value is refused again in the command builder, so shell metacharacters (`;`, `&`, `|`, backticks, `$()`, quotes) can never break out of the quoting to inject an unrelated remote command — including after a client-side `--` separator, whose arguments are never forwarded anyway. Because the remote options affect the *remote server invocation*, not the transmitted config, the wire frame layout is unchanged, but `PROTOCOL_VERSION` was bumped **2.13.0 → 2.14.0** as the Phase-5 lockstep release marker (a 2.14 client against a 2.13 server fails the version check cleanly rather than the old server rejecting an unfamiliar forwarded argv later). Divergence: rsync's short `-M` form of `--remote-option` was intentionally NOT implemented at that time because `-M` was FastSync metadata mode; **Phase 7 Wave A later freed `-M` for `--remote-option` and moved metadata to long-only `--preserve`** (see the Sending Options table).
- `--trust-sender` is a receiver-local policy: it never crosses the wire (the sender's value is never serialized, so a wire peer can never enable it). On the receiving process it skips the up-front re-validation of the incoming file list (empty/`..` path rejection), trusting the sender's list instead of double-checking — fewer checks, faster, and potentially unsafe, matching rsync. It is OFF by default (`config.trust_sender`). Since protocol 2.23.0 it does **not** gate symlink-target handling: `-l` stores targets verbatim either way. As a deliberate safety floor, the low-level fd-relative confinement primitives are NOT disabled: `file_open_secure_parent()` (O_NOFOLLOW walk, `..` rejection, root containment) and leaf/destination confinement still hold, so even under `--trust-sender` a hostile sender cannot write or place a *path* outside the authorized root — the relaxation only removes the redundant list-layer double-checks, never the root-confinement guarantees for paths and placements.

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
| `--files-from=FILE`; `--from0`, `-0`; `--filter=RULE`, `-f`; `-F`; `--cvs-exclude`, `-C` | L | Build a complete filter/parser layer and integrate it with scanner pruning, manifests, and delete behavior. (Done: `-f` is bound to `--filter`; the old sendfile conflict is gone, since sendfile is long-only `--sendfile`.) |
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
| `--rsh=COMMAND`, `-e`; `--rsync-path=PROGRAM`; `--blocking-io`; `--outbuf=N\|L\|B` | M | ✅ Wave A implemented (see the Connectivity table above). SSH argv construction is generalized: `-e`/`--rsh` replaces the hardcoded `ssh` program (whitespace-split, so `-e "ssh -p 2222"` works), `--rsync-path` aliases the existing `fastsync_server_path`, `--blocking-io` drops the SSH socket timeouts, and `--outbuf` maps N/L/B onto `setvbuf`. All four are client-only launch concerns and never cross the wire. |
| `--address=ADDRESS`; `--ipv4`, `-4`; `--ipv6`, `-6`; `--sockopts=OPTIONS`; `--port=PORT` daemon semantics | M | Add explicit socket-family/bind configuration and validate it independently for TCP client and daemon modes. |

**Phase 5, Wave B (socket/bind) shipping note:** `--sockopts` adds a strict allowlisted `OPT=VAL` socket-option layer applied with correct per-option value types; `--address` binds the outgoing client socket to a local source address; `-4`/`-6` pin the address family via `getaddrinfo` hints on both the client connect and the server bind; and the server bind now honors `--address` plus `-4`/`-6` (falling back to the historical IPv4 `INADDR_ANY` when none are given). All of these are local socket concerns and none cross the wire config frame (only `--port` maps to `server_port`).
| `--remote-option=OPT`, `-M`; `--trust-sender` | L | Add authenticated remote-option/config negotiation and reject unsafe sender-controlled values. `-M` conflicts with FastSync metadata mode. |
| `--daemon`; `--config=FILE`; `--dparam=OVERRIDE`; `--no-detach`; `--password-file=FILE`; `--early-input=FILE`; `--no-motd` | XL | Implement a real daemon lifecycle, module configuration, authentication, privilege separation, and process management. |

**Phase 5, Wave A (rsh/ssh) shipping note:** the SSH transport no longer hardcodes `ssh`. `-e`/`--rsh=COMMAND` selects the remote-shell program (whitespace-split into the leading child argv words), `--rsync-path=PROGRAM` aliases `--fastsync-server-path`, `--blocking-io` removes the SSH-socketpair `SO_RCVTIMEO`/`SO_SNDTIMEO` timeouts (by default they now match the TCP transport so a wedged shell cannot hang forever), and `--outbuf=N|L|B` maps onto `setvbuf` (`_IONBF`/`_IOLBF`/`_IOFBF`, garbage rejected). All four are client-only launch concerns and never cross the wire.

**Phase 5, Wave C (remote-option/trust-sender) shipping note (PROTOCOL 2.13.0 → 2.14.0):** `--remote-option=OPT` (long form only; the short `-M` is intentionally left as FastSync metadata mode — documented divergence) appends each validated value to the remote server invocation over SSH as an individually single-quote-escaped shell word, so shell metacharacters cannot break out and a `--` can never be turned into injection; options never cross the binary config frame. `--trust-sender` is a receiver-local policy (never serialized, so a wire peer can't enable it): when requested on the server (via `--remote-option=--trust-sender`), it removes only the redundant receiver/save-layer path re-checking; the low-level floor (`file_open_secure_parent`'s `..` rejection, the O_NOFOLLOW parent walk, leaf/destination confinement) stays enforced. Off by default. The wire config-frame layout is unchanged; the bump reflects that a 2.14 sender composing remote options requires a 2.14 receiver to honor them.

### Phase 6: Batch, Encoding, and Protocol Interoperability

These are the hardest compatibility items because they require durable formats or behavior that must interoperate with rsync itself.

| Features | Effort | Implementation plan |
|----------|--------|--------------------|
| `--write-batch=FILE`; `--only-write-batch=FILE`; `--read-batch=FILE` | XL | ✅ Implemented (see the Batch Operations table and Phase-6 batch note below): a versioned self-contained single-file residual-batch format, persisted via the existing chunk codec, with replay, corruption, and partial-application safety tests |
| `--protocol=NUM` | XL | ✅ Implemented (see the Advanced table and Phase-6 protocol note below): protocol-version forcing without weakening current validation; FastSync's single lockstep wire format means only the current `PROTOCOL_VERSION` is accepted, and everything else is rejected up-front |
| `--iconv=CONVERT_SPEC` | L | ✅ Implemented (see the Advanced table and Phase-6 iconv notes below): filename charset conversion at the wire boundary with expansion/overflow safety and invalid-sequence test coverage |
| `--stop-after=MINS`; `--stop-at=TIME` | M | ✅ Implemented (see the Advanced table and Phase-6 stop notes below): deadline propagation and safe early stop with --delete safety |
| `--early-input=FILE`; `--password-file=FILE` | M | Securely read startup credentials/input with permission checks and no secret disclosure in logs. |

**Phase 6, Wave A (stop deadline) shipping note:** `--stop-after=MINS` and `--stop-at=TIME` are client-only sender stop deadlines. `--stop-after` takes a positive minute count (0/negative/garbage rejected); `--stop-at` takes `HH:MM`, `HH:MM:SS`, or `now+N[smhd]` (a past time stops immediately, a garbage spec is rejected at parse time). The deadline is computed once at the start of the transfer (CLOCK_MONOTONIC for `--stop-after`, wall clock via `time()` for `--stop-at`) and checked at every chunk boundary in both the single-threaded `send_files` loop and the multithreaded `send_chunks_multithreaded` path, and inside the scanner loops so a busy scan itself stops. When it fires, the transfer stops ELEGANTLY: the in-flight chunk completes, the existing completion tail runs (summary, `disconnect`), and the run returns 0 — exactly like rsync's clean early stop. Because the deadline is client-only and never crosses the wire config frame, no PROTOCOL_VERSION bump is required. The safety-critical interaction is with `--delete`: FastSync streams while scanning, so a deadline can cut the source scan short and yield a PARTIAL keep-set manifest; committing that would make the receiver delete destination mirrors of source files not yet scanned. So the sender tracks `scan_stopped_early` and, when it is true on the late/delete-after (`--delete`/`--delete-after`/`--delete-delay`) path, SUPPRESSES the keep-set manifest (logs a warning) so no deletion happens from an incomplete set — this is the safe direction (preserves data; the delete simply does not run). `--delete-before`/`--delete-during` are unaffected: their complete pre-scan runs before any data and ignores the deadline (a stop can be exceeded by that pre-scan). Under `-j`/`--threads` the stop is symmetric and the scanner thread's still-in-progress manifest appends can never race the tail because the tail does not read the manifest on the early-stop path.

**Phase 6, Wave B (iconv) shipping note (PROTOCOL 2.15.0 → 2.16.0):** `--iconv=LOCAL[,REMOTE]` converts file NAMES at the wire boundary (never content). The full CONVERT_SPEC is serialized into the config frame as a new trailing string field (empty→NULL canonicalized), so both ends share the same wire charset interpretation; this required the PROTOCOL bump because the frame is a strict ordered sequence and a peer that does not parse the new trailing field would desynchronize. Each end derives its charset and the wire charset: the sender opens LOCAL→REMOTE and converts every transmitted filename; on a push the receiver's destination charset is the spec's REMOTE half, so it writes the wire bytes verbatim, unless the server was started with its own `--iconv` naming a different LOCAL charset (then it opens REMOTE→that LOCAL). Conversion is applied at every wire-path site (regular/MKDIR/hardlink path+target/symlink path+target/SPECIAL, the delete manifest keep/protected/missing entries, the incremental-check path, and the embedded `-s`/chunk-blob path). A name it cannot convert (EILSEQ/EINVAL) is failed cleanly with a logged `--iconv: cannot convert file name ...` and is never written truncated/mangled. Validation probes both directions up front (both the sender local→remote and the receiver remote→destination, and, for a server/daemon with its own `--iconv`, the client-REMOTE→server-LOCAL pair) so an unusable spec is rejected before the connection rather than mid-transfer, and NUL-emitting target charsets (utf-16/utf-32/ucs-2) are refused because filenames cannot contain NUL. The wire charset always comes from the sender's REMOTE half; a server whose local charset differs from the client's REMOTE must declare it with its own `--iconv` (the daemon `charset` analog). Conversion is process-global and runs on a single thread per process (sender thread / receiver-loop thread), initialized before worker threads start and freed after they join.

**Phase 6, Wave C (protocol-version) shipping note (no PROTOCOL_VERSION change):** `--protocol=NUM` lets the client force the wire protocol version for a transfer. FastSync's protocol is a single lockstep format: the config frame is a strict ordered sequence and the server requires the client's version string to equal `PROTOCOL_VERSION` exactly (`config_receive_with_validate`, src/shared/config.c) — there are no older-format code paths and no downgrade/negotiation machinery, so a lower/higher/virtual version can never be spoken. The honest contract is therefore: the current `PROTOCOL_VERSION` (2.28.0 as of the parity 2.28.0 cycle) is accepted and stored into the client's `version` claim (which `config_send` already transmits), and every other value — `2.25.0`, `2.24.0`, `2.23.0`, `2.22.0`, `2.21.0`, `2.20.0`, `2.19.0`, `2.18.0`, `2.18`, `2.17.0`, `2.16.0`, `2.15.0`, `3.0.0`, rsync-integer spellings like `216`/`31`, garbage, empty — is rejected up front in `validate_config()` before any connection, with a clear error that FastSync supports only its current wire protocol and cannot speak an older or virtual one. Implementation is client-only: a server-side `--protocol` is intentionally not added because the server has no negotiation (it only enforces exact match), and it could only ever be the current version. This preserves (and slightly tightens) existing validation: the client now also refuses to launch with a version it cannot actually speak, rather than only the server rejecting it later. A genuine downgrade would require a per-version compatibility layer for every frame/feature added since (append 2.10, preallocate 2.11, hardlinks 2.12, devices/specials/symlink-trust/xattr 2.13, remote-option 2.14, daemon module/auth 2.15, iconv 2.16, dir/symlink times 2.17, privilege flags --super/--copy-as 2.18, SCRAM daemon auth 2.19, packed metadata 2.20, error-detail/dry-run 2.21, preserve-attribute split 2.22, rsync-parity wave 2.23) and is intentionally out of scope — documented divergences from rsync's integer-negotiated downgrade remain.

**Phase-1/2 selection-and-update status correction (docs):** `-I/--ignore-times`, `--size-only`, `-@/--modify-window`, `--existing`, `--ignore-existing`, `-u/--update`, `-W/--whole-file`, and `--compress-threads` were previously listed as not-implemented in this document but are in fact fully implemented and tested on `dev`. This pass corrects the matrix to match the code. The realistic model of these is that FastSync is a *sender-driven* whole-tree copy, so the size+mtime quick-check and all three receiver-policy skips (`--existing`, `--ignore-existing`, `-u`) are evaluated against the **destination** on the receiver side, and their booleans cross the wire in the config frame. `-I`/`--size-only`/`--modify-window` modify the `--incremental` per-file `STATUS_CHECK` handshake's match predicate (`-I` disables the mtime leg and forces transfer; `--size-only` drops only the mtime leg; `--modify-window` adds tolerance to `metadata_mtime_matches`); they require `--incremental` (or a basis dir) to have a handshake to affect, mirroring how they only matter where a quick-check exists in rsync. `--existing`/`--ignore-existing`/`-u` are receiver write-time policies (skipping the write / newer-destination guard) applied across the regular-file, `--delay-updates`-staged, hardlink-sibling, and special/device paths; `-u` implies `-M` metadata and uses a second-then-nanosecond strict `>` newer check; both correctly influence `--remove-source-files` (a skipped source is not removed). `-W/--whole-file` disables block-level delta (opt-in via `--delta`), folded into the wire `use_delta` so no protocol bump was needed, and makes `--fuzzy` inert; `--append`/`--append-verify` are rejected with `-W`. `--compress-threads=NUM` (1..64, client-only, never crosses the wire) sizes the zstd compression worker pool. No code was changed by this correction; the implementation had landed in earlier merge waves (feat/ignore-times, feat/ignore-existing via the newer `file_to_disk_secure_no_replace`/`linkat EEXIST` path, feat/size-only, feat/modify-window, feat/whole-file, feat/update, compression-threads).

**Phase 6, Wave D (batch) shipping note (no PROTOCOL_VERSION change):** FastSync batch mode is a **client-only, self-contained "residual batch"**: a single file `MAGIC "FSTRESBATCH" + format version 1 + metadata flag`, followed by length-prefixed `chunk_serialize` blobs that store full file images (regular files, dirs, symlinks, specials). It is NOT a raw capture of the live wire, because FastSync's protocol is per-file interactive (`STATUS_CHECK`/`STATUS_DELTA_SIGNATURE`/`STATUS_APPEND` handshake), so a raw sender-stream tee is not deterministically replayable against an arbitrary destination. Storing full residuals via the existing, fuzz-tested chunk codec makes `--read-batch` replay byte-identically by construction. `--write-batch=FILE` runs the normal live transfer AND emits the batch from a separate deterministic scan pass; `--only-write-batch=FILE` emits the batch only (no destination, no server); `--read-batch=FILE DEST` applies it locally (no source, no server; DEST is the only positional arg). Because batch is a local driver concern, it never crosses the wire: no new config-frame field and no `PROTOCOL_VERSION` bump (mirroring `--stop-after`/`--protocol`/`--compress-threads`). The READ side is hardened against untrusted/attacker-controlled batch files: magic+version validated before any record, per-record length bounds checked before allocation (64 MB cap), clean-EOF-after-prefix and truncated/oversized records rejected, and every applied path goes through the same confined `file_save_to_disk_full` machinery as the network receiver (O_NOFOLLOW fd-walk, `..`-rejection, root confinement — a malicious `../` or absolute/symlink path cannot escape the destination root; this was security-reviewed and valgrind/ASan-clean). Divergences from rsync: (1) the batch carries the FULL residual (complete file images) rather than rsync's update-only delta stream — always byte-correct but larger; (2) per-file data is capped at the chunk codec's ~64 MB (`BATCH_MAX_RECORD`), so very large files may be refused by the batch writer with a clean error (never a corrupt/truncated batch); (3) hard-links and xattr/ACL blocks are not represented by `chunk_serialize`, so `-H`/`-X`/`-A` are out of scope for batch; (4) there is no companion `.sh`/`.rsync_argvs` — the batch is invoked directly (`fastsync --read-batch=FILE DEST`, `--only-write-batch=FILE SOURCE`); (5) `--write-batch` drives the single-threaded transfer path. Integration/`-M` note: metadata is captured in the batch when `-M` is used and persisted in the header so it applies consistently regardless of the reading process's own `-M`.

### Phase 7: CLI-Namespace Parity, Filesystem/Output Completion, and Privilege (Final)

These are the last compatibility items and the closing phase toward rsync flag parity. Per the project decision: every rsync flag (short **and** long) that is *possible* gets real rsync-parity behavior; anything physically impossible becomes an explicit **Impossible/Divergence** status (accepted for CLI compatibility, safely inert, with coverage tests proving that); and the two privilege flags (`--super`, `--copy-as`) adopt the deliberately-scoped **safe-subset + clear-refusal** model rather than blind elevation. The remaining `⚠️ Partial`, `🔄 Compatibility No-op`, `🔀 Alt Arg`, and `❌ Not Implemented` rows in the Summary are this phase's scope. All Wave A renames are **client-side only** (the wire config fields `use_compression`/`use_metadata`/`use_sendfile`/`use_chunk_serialization` are unchanged), so they require **no `PROTOCOL_VERSION` bump**.

**Wave A — CLI namespace parity (rename colliding FastSync short flags) — ✅ implemented.** This freed the short letters rsync needs and made the three `🔀 Alt Arg` rows real. `-c`→`--checksum`, `-m`→`--prune-empty-dirs`, `-M`→`--remote-option`, `-f`→`--filter`, `-s`→`--secluded-args`, `-p`→`--perms`, `-T`→`--temp-dir`, `-a`/`--archive`→real `-rlptD`. FastSync's own flags moved to long-form-only or new shorts: `-j`/`--threads` (multithreading), `--preserve` (metadata), `--sendfile`, `--chunk-serialization`, `--timeout`, `--ssh-port`. The server's independent little CLI keeps `-p` as its port. All client-side, no wire change, no `PROTOCOL_VERSION` bump. Unit tests 37/37, full integration 400 passed, cppcheck and clang-format clean. Known Wave-A limitation: `--no-perms`/`--no-compress`-style negation of the newly-aliased shorts was not wired into the negatable set (only the long-form `--preserve`/`--compress`/`--no-links` negations existed), so `--archive --no-perms` was initially unsupported — a minor deviation from rsync. The preserve-attribute split wave below resolves the preservation side: `--no-perms`/`--no-times`/`--no-owner`/`--no-group` and `--no-preserve` now work, so `--archive --no-perms` is supported.

| FastSync flag today | rsync wants that name | Proposed rename |
|---------------------|----------------------|-----------------|
| `-c` / `--compress` | `-c` = `--checksum` | compression is already aliased as `-z`/`--compress` (rsync parity!) → drop the `-c` short, keep `--compress`/`-z` |
| `-m` / `--multithreading` | `-m` = `--prune-empty-dirs` | → `-j` / `--threads` |
| `-M` / `--preserve` | `-M` = `--remote-option` | → `--preserve` (long-only) |
| `-f` / `--sendfile` | `-f` = `--filter` | → `--sendfile` (long-only) |
| `-s` / `--chunk-serialization` | `-s` = `--secluded-args`/`--protect-args` | → `--chunk-serialization` (long-only) |
| `-p` (SSH port) | `-p` = `--perms` | → `--port` (long-only; `--server-port` already exists) |
| `-T` / `--timeout` | `-T` = `--temp-dir` | → `--timeout` (long-only) |
| `-a` / `--archive` (= `-c -m -M`) | `-a` = `-rlptD` | → becomes **real rsync `-a`** after the renames |

**Wave B — Output & filesystem completion (✅ implemented).** `-S`/`--sparse` (`⚠️→✅`): real hole preservation — a sparse-aware writer (`write_all_sparse`) skips all-zero runs ≥ 4096 bytes with `lseek(SEEK_CUR)` and `ftruncate`s the final size, wired into both the atomic temp+rename store and `--inplace` receiver-side with **no wire change** (the full file image is already in memory; the ftruncate presize is kept). `-P` (`⚠️→✅`): interrupted-write retention — on a save failure after data reached the temp fd, `--partial` now renames the already-written temp to the destination path (best-effort; falls through to the normal unlink on failure, never retains when `--partial` is off) so a later `--append`/`--append-verify` run can resume. `--block-size=SIZE` (`⚠️→✅`): promoted after verification — `--block-size` is now an alias for `--delta-block`, both set `config->delta_block_size`, which the delta engine already honored end-to-end (`delta_signature_create_seeded` + `delta_apply`); out-of-range values keep the default. `--fake-super` (`⚠️→✅`): added `fake_super_restore_fd` to parse and re-apply the recorded `user.fastsync.stat` record fd-relative (mode/time only — protocol 2.23.0: **never a real chown**; the resolved owner is recorded for a later privileged restore); a save under `--fake-super` now re-applies the recorded attrs instead of only recording them, with the recording format unchanged. `--stderr=client` (`⚠️→❌ Divergent`): FastSync has no rsync client-message channel, and `client` is rejected at CLI parse — the rejection is the documented behavior (unit-tested). `-N`/`--crtimes` (`⚠️→❌ Divergent`): birth-times cannot be set by any portable fs call (`utimensat` sets only atime/mtime); capture/transmit stays, setting is impossible, the flag is accepted and safely inert. Review-hardening (post-eval): fake-super replay applies the mode through the shared `metadata_mode_for_policy` helper (protocol 2.23.0: exactly the source mode under `-p`, with no masking); `--sparse` takes precedence over `--preallocate` (posix_fallocate skipped so holes survive) — **reversed by the parity-completion wave: `--preallocate` now wins, matching rsync**; `--partial` retention is disabled for `--no_replace` (ignore/existing) and only marks a write-attempt after the actual write begins; `--block-size=SIZE`/`--delta-block=SIZE` inline forms are accepted.

**Wave C — Devices & special files (finalize statuses + tests) (✅ implemented).** The four special-file rows are finalized with coverage tests. `--devices`, `--copy-devices`, and `--write-devices` are **✅ Implemented**, each with a documented, safety-driven divergence: device-node creation is privilege-gated, so a receiver without `CAP_MKNOD` skips that entry with a warning (a per-entry skip, never a transfer failure); `--copy-devices` copies a device/FIFO's reported size into an ordinary regular file (a size-bounded safe divergence from rsync's unbounded dd-like read); `--write-devices` writes only into an existing char/block node under the confined receive root and skips every unusable target rather than clobbering or aborting. `--specials` reclassified from **⛔ Impossible/Divergence** to **✅ Parity** in protocol 2.23.0: **FIFO recreation works** (unprivileged `mkfifo`) **and unix sockets are recreated** with `mknod(S_IFSOCK)`, which Linux permits unprivileged (the flag previously assumed sockets were impossible — see the `--specials` row). Tests assert FIFO recreation, socket recreation, the regular-file result of `--copy-devices`, the skipped/missing and non-device `--write-devices` targets, and (root-gated) real device-node creation; a root runner additionally drops the receiver to an unprivileged user to assert the `CAP_MKNOD` skip is graceful. (The parity-completion wave later reclassified `--devices`, `--copy-devices`, and `--write-devices` as explicit **❌ Divergent** rows, because their safe subsets are deliberately not rsync's behavior; the implementation itself is unchanged.)

**Wave D — Times superstructure & arg-protection no-ops (✅ implemented, `--secluded-args` ❌).** `-O`/`--omit-dir-times` and `-J`/`--omit-link-times` are now **real modifiers** (both `🔄 → ✅ Implemented`), reversing the old "never preserves directory/symlink times" divergence:

- **Directory times.** The recursive scanner captures every traversed source directory's metadata (mtime, plus atime under `-U`) into a per-transfer list — two paths are covered: the sequential `DirectoryScanner` captures each opened directory (including the transfer root), and the parallel scanner captures both the root in `parallel_scanner_create_with_options` and each worker's subdirectories in `open_next_directory` (appends are guarded by a mutex shared with the sender's pipeline context). The sender transmits them in trailing `STATUS_DIR_TIMES` frames (each: int count + count × (wire path, metadata) pairs) sent **after all file data and after the optional delete manifest**, just before `STATUS_FINISHED`. A tree larger than `MAX_MANIFEST_ENTRIES` (1 048 576) directories is chunked into repeated frames, each within the receiver's per-frame bound. A dir-time entry is RECORD-ONLY (`file->dir_time_only`): `file_save_to_disk_full` returns `FILE_SAVE_SKIPPED` without creating anything (the directory's creation, when it is empty, is now carried by a separate `STATUS_MKDIR` entry the scanner emits for every directory that produced no transferred child, and `-m/--prune-empty-dirs` suppresses that). The receiver accumulates received directory metadata in a `DirTimeList` and applies it only at the very end — after the entire stream, after the commit-style `--delete` deletion, and after `--delay-updates` publication — because creating or removing a child bumps the parent's mtime. Application is fd-relative/walk-confined (`file_open_secure_parent` + `utimensat(..., AT_SYMLINK_NOFOLLOW)`) and best-effort per entry: an absent path (an intentionally uncreated empty dir) is skipped QUIETLY and only a real existing directory is stamped. `-O` (config boolean, already on the wire) makes the receiver skip the whole set. The single-threaded sink applies in `receiver_send_success_frame`; the `-j`/`--threads` sink accumulates in `write_thread` and server.c applies after both threads join and the deletion commits.
- **Symlink times/owner/mode.** `STATUS_SYMLINK` already carried metadata; the receiver now applies it with no-follow primitives only: `utimensat(..., AT_SYMLINK_NOFOLLOW)`, best-effort `fchmodat(..., AT_SYMLINK_NOFOLLOW)` (honest no-op where unsupported, e.g. Linux), and policy-gated `fchownat(..., AT_SYMLINK_NOFOLLOW)` via a new `identity_apply_ownership_link` that shares the identity resolver with the fd path. `-J` suppresses only the timestamps; ownership stays governed by the identity opt-in (`--numeric-ids`/`--usermap`/`--groupmap`/`--chown`) exactly like regular files. A symlink has no children, so this is applied immediately at creation.
- **Wire:** the shared `STATUS_DIR_TIMES` frame (and metadata on `STATUS_MKDIR` for `--dirs` entries) is a frame-sequence change, so `PROTOCOL_VERSION` was bumped **2.16.0 → 2.17.0**; every version-sensitive test (`--protocol` accepted/rejected values) was updated. The config-frame layout itself is unchanged (the omit booleans already crossed). Non-metadata and `--no-preserve` transfers send no `STATUS_DIR_TIMES` frame and no directory metadata, keeping them byte-identical.

`--secluded-args` (`🔄 → ❌ Divergent`): a true arg-send protocol would replace the argv-based SSH launch with an in-band channel, and FastSync already builds the remote SSH argv injection-safe (single-quote-escaped shell words), so there is no argument-leak to close; the already-safe behavior is documented in the row and no transport change is made.

**Wave E (LAST) — Privilege: `--super`/`--no-super` and `--copy-as=USER[:GROUP]` (✅ implemented).** FastSync adopts a **safe-subset + clear-refusal** privilege model: it never blind-elevates and never calls `setuid`/`seteuid`/`setgid`. All privileged operations remain fd-relative and confined below the authorized receive root.

`--super`/`--no-super` set a receiver-side tri-state `Config->super_mode` (`SUPER_MODE_AUTO`/`ON`/`OFF`). `privilege_super_permitted()` / `privilege_super_mode_permitted()` (src/shared/identity.c) return true for `ON` and `AUTO` (AUTO preserves FastSync's historical best-effort attempt, where the kernel refuses an unprivileged call and the caller skips it) and false only for `OFF`. The gate covers every super-user activity FastSync performs: ownership application (`identity_apply_ownership`/`_link`), char/block device-node creation (`file_save_special_to_disk`), writes into an existing device (`--write-devices`), and the `--fake-super` owner replay. Unprivileged FIFO creation is deliberately unaffected. `--super` does **not** imply `--numeric-ids`: ownership is applied only when an explicit identity policy (`--usermap`/`--groupmap`/`--chown`/`--numeric-ids`/`--copy-as`) or a preserve-source request (`-o`/`-g`, or `-a`/`--archive`) is also given. `--no-super` suppresses those activities even for a root receiver. A non-root receiver given `--super` logs one warning at activation (`identity_set_active`); each confined attempt is then refused by the kernel and skipped, never aborting. The confinement floor is unchanged (`file_open_secure_parent`, `O_NOFOLLOW`, root/path checks). Operator control: the server CLI accepts `--no-super`, a veto that forces `OFF` for every connection, refuses any client `--copy-as`, and neutralizes an explicit `--super` (the connection is accepted but no super-user activity is attempted). A privileged (root) standalone TCP listener instead defaults to `OFF` and requires the server-only `--allow-super` opt-in to attempt any super-user activity (the flag is rejected with `--stdio`, whose client-composed remote argv must never defeat the default; use a forced command if the default must hold); a non-root server is unchanged. On a daemon, a module that has not opted in with `client owner = yes` additionally has super-user device activity forced off (see the Daemon Mode notes).

`--copy-as=USER[:GROUP]` is the safe subset. FastSync's receiver is multithreaded, so a real credential switch is unsafe; instead the receiver forces the ownership of **every entry it writes** — regular files, symlinks, directories (including implicitly-created parents), and special nodes — to the resolved target ids through the confined fd-relative identity path. USER is resolved on the client (name, `@N`/bare N, or `*` = client euid); when `:GROUP` is omitted the user's primary gid is used (falling back to `gid == uid` for a numeric id with no local passwd entry). It requires a privileged (root) receiver: an unprivileged receiver refuses the whole transfer at the config handshake, before `STATUS_OK`, so no data is ever written with the wrong ownership. A `--copy-as` chown failure on a capability-restricted root is logged at ERROR (never silently downgraded). `--copy-as` implies metadata (`--no-preserve` is rejected) and `--fake-super` cannot override it. Daemon policy: a `--daemon` receiver refuses **every** client-chosen-ownership / super-user request — `--numeric-ids`, `--chown`, `--usermap`/`--groupmap`, `--fake-super`, `--copy-as`, and explicit `--super` — unless the selected module opts in with `client owner = yes`; without that per-module opt-in any client could force arbitrary ownership inside the module root (a root standalone TCP listener, which serves one operator-authorized root, honors these requests only when started with `--allow-super`; the flag is rejected with `--stdio`). A `--copy-as` chown failure on a capability-restricted root marks the entry as failed rather than reporting success with the wrong owner.

**Wire:** two trailing config-frame blocks after the `--iconv` spec, in fixed order — `send_privilege_options`/`receive_privilege_options` (one `super_mode` int, validated `0..2`), then `send_copy_as_options`/`receive_copy_as_options` (presence int + two int32 ids, validated `>= 0`, with `copy_as_set ⇒ use_metadata`). `PROTOCOL_VERSION` bumped **2.17.0 → 2.18.0**. **Divergences from rsync:** rsync's `--super` elevates the receiver and `--copy-as` actually switches its credentials; FastSync never elevates and only permits/forwards confined attempts, and `--copy-as` forces ownership rather than switching identity.

**Honest status after the parity 2.29 cycle (protocol 2.28.0, no wire change), updated by the parity cycle 2.29 pass, the audit-cycle follow-ups, the triage cycle, and a later no-wire CLI parity fix.** ✅ Parity 118 / ⚠️ Caveat 13 / ❌ Divergent 26 = 157 rows. A no-wire CLI-parity pass accepted `--inc-recursive`/`--no-inc-recursive` as inert no-ops (❌ → ✅, since FastSync's full scan is rsync's `--no-inc-recursive` and the destination is identical) and narrowed the `--temp-dir` divergence by accepting an absolute path that canonicalizes inside the receive root (the row stays ❌ for out-of-root absolute paths). The 2.29 cycle closed the scanner-order, delete-timing, relative-basis, and fuzzy-eligibility residuals (moving `-n`/`--delete`/`--del`/`--delete-delay` to ✅) and improved the `--info`/`--stats`/`--debug` partial rows; the triage cycle moved `-F` and `-i`/`--itemize-changes` ✅ → ⚠️ for their documented residuals. The remaining ⚠️ rows are `--info`, `--debug`, `--msgs2stderr`, `--stats`, `--progress`, `-i`, `--delete-before`, `--filter`, `-F`, the three basis-dir options, and `-y/--fuzzy`. Earlier: **Honest status after the parity 2.28.0 cycle (protocol 2.28.0), updated by the rsync-parity-stats, rsync-parity-options, rsync-parity-fs, parity-review, no-wire parity-track-1/2b and wire parity-track-4a/5a passes.** ✅ Parity 116 / ⚠️ Caveat 14 / ❌ Divergent 27 = 157 rows. Earlier revisions of this document reported "143 ✅ / 0 divergence / 0 partial"; that conflated "parsed and tested" with "rsync parity", because many rows carried documented behavioral differences and some short options were not parsed at all. This reclassification makes every difference explicit. The completion wave closed 23 previously-caveated rows (9 that triage showed were already parity, plus 14 genuine fixes) and turned the 17 inherently non-rsync rows — native daemon config/auth, the FastSync batch container, the safe-subset device/privilege flags, `-X`'s privileged namespaces, `--fake-super`'s native xattr format, and the `--old-args` no-op — into explicit ❌ divergences. The stats pass flipped `--delete-delay` to ✅ (actual-removal accounting), but the parity-review pass moved it back to ⚠️ because FastSync charged the `--max-delete` budget at plan/snapshot time and left a refilled snapshotted directory in place, whereas rsync charges on actual removals and recursively removes a queued directory (including content created after its plan). The no-wire parity-track-1 pass fixed both (actual-removal charging plus recursive deferred removal with an independent deferred-list cap), narrowing the caveat to the partial-delete ordering. The stats pass also reclassified `--out-format` to ❌ (protocol-specific `%b`/delta-`%c`), and sharpened the `--stats`/`--progress`/`--checksum-choice` residuals. The options pass flipped `--bwlimit` and `--ignore-errors` to ✅ (rsync-exact size parsing and ~100 ms leaky-bucket throttling, and rsync's skip-unreadable-subdir plus IO-error-suppressed deletion with exit 23) and emits rsync-format `--info=name/flist/del/remove/nonreg/progress` lines (real-run `deleting`/`*deleting` carried over a new trailing `report_deletes` wire bool, `PROTOCOL_VERSION` 2.26.0 → 2.27.0), while reclassifying `-M` over daemon/TCP
and receiver-side `protect`/`risk` re-derivation to ❌ (no argv channel /
receiver filter engine); the wire parity-track-4a pass later added that
receiver filter engine, flipping `--filter=RULE` back to ✅ (see above; the
audit-cycle follow-ups later moved it to ⚠️ for the accepted-but-ignored merge
modifiers, see the audit-cycle note). The fs pass flips `-d/--dirs` and `--iconv` to ✅ — recursive transfers now recreate empty source directories (and replace a blocking destination non-directory with an incoming directory); `-R --no-implied-dirs --files-from` places a listed file under a missing implied parent with default attributes instead of refusing; and `--iconv` now reproduces rsync's push direction (destination charset = the spec's REMOTE half) — and reclassified six rows to ❌ after reproducing their exact residual with differential tests: `--temp-dir` (the receiver confines the scratch dir to the receive root, so an absolute temp dir is deliberately rejected although standalone rsync follows it), the three basis-dir options (FastSync xxHash-verifies a basis hit while rsync's `--size-only` quick check installs the wrong basis content), `--delay-updates` (fixed staging name wipes an unrelated destination entry of that name), and `--dry-run` (would-delete report over-reports). `--fuzzy` was also reclassified to ❌ (deterministic heuristic with a 10× size window, not rsync's matcher), but its residual is the candidate-selection heuristic itself: the final tree is byte-exact by design, so no destination differential can expose it and the row is pinned by the `TestFuzzy` threshold suite rather than a byte-level rsync differential. (Track 5b later showed the name heuristic is in fact rsync's own and moved the row ❌ → ⚠️, leaving only the narrower delta size window as the residual; see the track 5b paragraph above.) The remaining ⚠️ rows are the ones with a documented residual (see the row notes and the **Parity Completion Wave (protocol 2.26.0)** section below).

**Preserve-attribute split (protocol 2.21.0 → 2.22.0) — ✅ implemented.** FastSync splits the former single metadata bundle into four independent, rsync-compatible per-attribute flags — `-p/--perms`, `-t/--times`, `-o/--owner`, `-g/--group` — each with a negation (`--no-perms`/`--no-times`/`--no-owner`/`--no-group`, short `--no-p`/`--no-t`/`--no-o`/`--no-g`), plus `--no-preserve` clearing all four. `-a/--archive` is now full rsync `-rlptgoD` (owner and group included, though their application stays privilege-gated), `-A/--acls` implies `-p`, `-X/--xattrs` does not, `-E/--executability` sets only executability, and `-U`/`-N` do not imply `-t`. `--incremental`/`--delta` still auto-preserve perms+times unless the user explicitly negated them. Wire: the binary config frame gains four appended booleans (`preserve_perms`/`preserve_times`/`preserve_owner`/`preserve_group`) after `omit_link_times`, so `PROTOCOL_VERSION` is bumped **2.21.0 → 2.22.0**; the fixed-width `FileMetadata` layout is unchanged and the receiver gates the metadata frame on a derived `use_metadata`. Receiver behavior: each attribute is applied independently, directory modes are applied under `-p` (at the end of the transfer, alongside dir times), symlink mode under `-p`, and `-O/--omit-dir-times` suppresses directory times only. Documented divergences as of 2.22.0, **all but (d)/(e) removed by the rsync-parity wave (protocol 2.23.0)**: (a) the mode-masking divergence is **gone** — under `-p` the source mode is now copied exactly, including `S_IWGRP`/`S_IWOTH` and setuid/setgid/sticky; (b) a brand-new file without `-p` still gets `source_mode & ~umask` when metadata is present (else the historical fixed `0644`), and a new *directory* without `-p` still uses FastSync's `0755` default; (c) the `--chmod`-implies-`-p` divergence is **gone** — `--chmod` no longer implies `-p` (rsync parity); (d) `-o`/`-g` map by name on the receiver with a raw-numeric fallback (only numeric ids cross the wire); (e) a daemon module without `client owner = yes` does not refuse a plain `-a`/`-o`/`-g` — it forces super off, applies no ownership, and logs a warning, while explicit `--chown`/`--usermap`/`--groupmap`/`--numeric-ids`/`--copy-as`/`--super` are still refused.

## Rsync-Parity Wave (protocol 2.23.0)

This wave closed the remaining CLI, filesystem, ownership, deletion, and output
gaps against rsync 3.4.1. It is a wire change: `PROTOCOL_VERSION` moved
**2.22.0 → 2.23.0** because the delete manifest gained a synchronized-directory
section and the terminal status gained `STATUS_DELETE_LIMIT` (see the deletion
notes above). Everything below is implemented and covered by unit and
integration tests unless it is explicitly listed as a limitation.

### CLI parsing

- **Short options now parsed:** `-r` (`--recursive`), `-b` (`--backup`),
  `-L` (`--copy-links`), and `-B` (`--block-size`/`--delta-block`) are accepted
  as rsync spells them.
- **rsync short-option clustering:** a token is expanded before parsing, so
  `-av` → `-a -v`, `-aAX` → `-a -A -X`, `-rlpt` → `-r -l -p -t`, and so on.
  A value-taking short option consumes the remainder of its token
  (`-B1000` → `-B 1000`, `-essh` → `-e ssh`, `-MOPT` → `-M OPT`), with an
  optional leading `=` dropped (`-B=1000`); a value-taking option written alone
  takes the next argv entry, which is copied verbatim so a value that happens to
  start with `-` (e.g. `--filter "- *.tmp"`) is not mistaken for a cluster.
- **Inline/attached long values:** `--opt=value` is accepted uniformly, and each
  expanded token is mapped back to its original argv index so positional
  arguments stay correct.
- **`-c` implies the checksum quick-check.** `-c`/`--checksum` sets the
  incremental checksum comparison rather than doing nothing on its own; like
  rsync, `-c` does not imply `-t`.

### Checksums and compression

- **`--checksum-choice`/`--cc`** accepts the full rsync 3.4.1 set: `xxh64`
  (default), `xxhash`, `xxh3`, `xxh128`, `md5`, `md4`, `sha1`, `none`, the
  two-name `transfer,pre-transfer` form, and `auto` (which honors
  `RSYNC_CHECKSUM_LIST` before the compiled-in order). A genuinely unknown name
  is still rejected by name, matching rsync.
- **`--checksum-seed=0` is randomized per transfer** (the chosen seed is sent to
  the receiver), matching rsync; an explicit non-zero seed is used verbatim.
- **`--compress-choice`/`--zc`** accepts the full rsync 3.4.1 set: `zstd`
  (default), `lz4`, `zlib`, `zlibx`, `none`, and `auto` (which honors
  `RSYNC_COMPRESS_LIST` before the compiled-in order). A genuinely unknown name
  is still rejected by name, matching rsync.
- **`--skip-compress`** uses rsync 3.4.1's built-in default suffix list when no
  list is supplied; an explicit list replaces it.
- **`--no-whole-file`** is accepted as the rsync spelling that clears
  `-W`/`--whole-file`.

### Timeouts and limits

- **`--timeout` defaults to 0 (disabled) and `--contimeout` to 60 s; `0`
  disables either**, matching rsync.
- **`--max-alloc=0` means "no local allocation limit"** (rsync semantics). A
  standalone server still keeps its own ceiling for the peer it serves.

### Filesystem and deletion semantics

- **`--temp-dir` is confined to the receive root on the receiver:** a relative
  dir resolves below it, and an absolute path is accepted only when
  `realpath(3)` confirms it is inside the canonical receive root; an
  out-of-root absolute path or one containing `..` is rejected.
  An `EXDEV` install falls back to a non-atomic copy instead of aborting. (The
  confined receiver path cannot be mount-tested in the CI container — no
  `CAP_SYS_ADMIN` and unprivileged user namespaces are disabled — so the
  cross-filesystem fallback is exercised end-to-end through the unconfined local
  `--read-batch` apply against a `/dev/shm` scratch dir, in
  `tests/integration/test_temp_dir_exdev.py`.)
- **Deletion scoping:** the manifest carries the synchronized directories, so
  the extras walk only visits their subtrees; `--files-from` subsets no longer
  delete untransmitted paths outside the listed directories.
- **`--delete-excluded`** removes filter-excluded mirrors but never
  `--max-size`/`--min-size`-pruned mirrors (separate, always-on protection).
- **Destination symlinks** are unlinked by name, never followed; a directory
  still holding one survives.
- **`--max-delete=N` is partial:** delete up to N, skip the rest, exit **25**.
  `--delete-missing-args` removals draw from the same budget.
- **`--force` is honored during `--delay-updates` publication.**
- **`-x`/`--one-file-system` emits the mount-point directory entry** (an empty
  directory at the destination) without descending into it.
- **`--include`/`--exclude` are an ordered first-match rule list**, evaluated
  like `--filter`/`-F`/`-C` (first match wins), so an earlier rule can override a
  later one.

### Ownership and metadata

- **`--numeric-ids` is a mapping modifier only** — it changes *how* ids map, not
  *whether* ownership is applied; combine it with `-o`/`-g`, `-a`, or an
  explicit map.
- **`--usermap`/`--groupmap`** support names, FROM name **globs**
  (`*`/`?`/`[...]`, expanded sender-side against the passwd/group database and
  bounded by `MAX_IDENTITY_MAP`), `@N`/bare `N` ids, inclusive `LOW-HIGH` ranges,
  `*`, empty-`FROM` (unnamed ids), and receiver-resolved `TO` names.
- **`--chown` conflicts with `--usermap`/`--groupmap` on the same side** and is a
  clear configuration error (matching rsync) instead of an order-dependent
  winner.
- **`--fake-super` never real-chowns.** It records the *resolved* owner (the
  active mapping, else the source id) in `user.fastsync.stat` for a later
  privileged restore and replays only mode/times. Directory ownership and
  directory xattrs/ACLs are preserved alongside file entries.
- **`--chmod`** implements rsync's `D`/`F`/`X` selectors, `s`/`t`, append
  semantics, does not imply `-p`, and applies its changes without sanitization.

### Symlinks and special files

- **`-l`/`--links` stores symlink targets verbatim** (absolute and `..`-bearing
  targets included), matching rsync. `--safe-links` and `--copy-unsafe-links`
  match rsync and are applied sender-side; `--munge-links` (which now uses
  rsync's `/rsyncd-munged/` marker) matches rsync too but is applied
  **receiver-side** (the sender un-munges an already-marked source target).
- **`--specials` recreates unix sockets** with `mknodat(..., S_IFSOCK)`, so
  `-D`/`--devices --specials` now covers the full rsync node set.
- **`--copy-devices`** is implemented (see its caveat below).

### Output

- **`-i`/`--out-format`** print rsync-style change lines, including the
  transfer-root `./` and per-directory `cd...`/`.d..t...` lines; **`--list-only`**
  scans the source only and contacts no server; **`-h`** uses rsync's decimal
  units; **`--progress`** prints rsync-style per-file progress blocks;
  **`--stats`** prints the transfer-statistics block, whose receiver-only
  counters (`Matched data`, `Number of deleted files`) are populated from the
  receiver's `STATUS_STATS` report.
- **Server `--port`** is an alias of the `-p <port>` TCP listen port
  (`--dparam port=` overrides the daemon config).

### Known intentional divergences and limitations

These remain after the wave; they are the reasons a row above is ⚠️.

- **Symlink target containment is not enforced receiver-side by default.**
  Verbatim storage is rsync parity, but a destination later consumed by a
  link-following tool can follow a link outside the receive root. Use
  `--safe-links` when the source is untrusted. `--trust-sender` does **not**
  affect symlink targets.
- **`--temp-dir` out-of-root absolute and foreign-filesystem paths are rejected
  by the receiver** (an absolute path that canonicalizes inside the receive root
  is accepted; rsync's daemon also confines; standalone rsync differs).
- **`--copy-devices` reads a bounded `st_size`** rather than rsync's unbounded
  device read.
- **A broken symlink referent under `--copy-links`/`--copy-unsafe-links` exits 0**
  where rsync exits 23.
- **New directories without `-p` still use FastSync's `0755` creation default**
  rather than `source & ~umask`; directory metadata is only applied when a
  directory attribute is requested.
- **`--stats` byte totals** (`Total bytes sent`/`received`) are FastSync wire
  bytes framed differently from rsync's, so they are not numerically comparable;
  the remaining `--stats`/`--progress` divergences are the ones named in their
  rows (per-type deleted-file breakdown, root-line/ancestor suppression).
- **`--password-file`/`--early-input`/`--hash-credentials`/`--iterations` are
  FastSync-native** (SCRAM/PBKDF2), not rsync semantics; the batch format is not
  rsync-interoperable. Credential files are opened with `O_NOFOLLOW` (a symlinked
  path fails closed; fd-backed process-substitution paths are exempt) and a FIFO
  read is bound-waited (~3 s).
- **xattr/ACL namespace policy** permits only `user.*` and
  `system.posix_acl_*` when `-A` is negotiated (stricter than rsync).
- **`--stop-at` remains a FastSync-flexible parser** (client-only, not
  serialized); `--stop-after` matches rsync.
- **Push-only model and a non-rsync wire protocol** remain by design;
  `--protocol` accepts only the current version and `-s`/`--secluded-args` is an
  accepted no-op.

## Parity Completion Wave (protocol 2.26.0)

This wave closed the remaining rsync-parity gaps left by the rsync-parity wave
and reclassified the inherently non-rsync rows as **divergent**. It moved the
wire protocol three times (full rationale in `src/shared/config.h`):

- **2.23.0 → 2.24.0 (delete timing):** the sender streams one delete plan per
  source directory (`STATUS_DELETE_PLAN`) so `--delete-during`/`--delete-delay`
  reproduce rsync's per-directory deletion timing.
- **2.24.0 → 2.25.0 (wire stats):** the config frame gains `report_stats` and
  the receiver emits a `STATUS_STATS` frame carrying the receiver-only counters
  (matched data, deleted-file count) and, for `-n --delete`, the would-delete
  paths.
- **2.25.0 → 2.26.0 (codecs):** the config frame gains the negotiated
  `compression_algo` int, and the checksum codec accepts `md4`/`sha1`/`none`
  (default `xxh128`, negotiated with `auto`).

### Deletion timing (2.24.0)

- **`--delete-during`/`--del`** streams a per-directory plan as each directory
  is scanned, so its extras are removed before the next directory's data; a
  mid-transfer abort has already deleted the reached directories' extras.
- **`--delete-delay`** records each directory's plan while scanning and commits
  the removals only after the whole transfer succeeds, so an extra created
  mid-transfer after its directory's plan survives, while `--delete-after`'s
  fresh end scan removes it.
- Per-directory plans are scoped to `-R`'s transferred prefix and bounded by the
  shared manifest caps; `-d`/`--dirs` (no descent) falls back to the end commit.
- Empty in-scope source directories survive the per-directory delete. Dry-run
  never deletes; `-n --delete` prints the would-delete lines (see below).

### Receiver stats and output (2.25.0)

- **`STATUS_STATS`** is sent immediately before the terminal success status and
  carries `Matched data`, the deleted-file count, and the dry-run would-delete
  path list. The client reads it before the `--remove-source-files` acks so the
  counters are always populated, in both the sequential and `--threads` paths.
- **`--stats`** prints octets/rates/file counts from the sender plus the
  receiver counters above; the protocol-independent lines match rsync exactly.
- **`--progress`/`-P`** print rsync-style per-file blocks (the first frame is
  byte-identical) from the wire counters.
- **`--out-format`** gains `%b` (FastSync wire bytes), `%c` (block-sum bytes)
  and `%C` (whole-file digest). `%C` is protocol-independent and matches rsync
  for a whole-file transfer.
- **`-n --delete`** prints escaped `*deleting` lines from the receiver's
  would-delete list.

### Codec breadth and negotiation (2.26.0)

- **Compression:** `zstd` (default), `lz4`, `zlib`, `zlibx`, `none`, `auto`.
  The resolved codec id crosses the wire and the receiver validates it against
  its own set (rsync's "no common choice is an error").
- **Checksums:** `xxh128` (default), `xxh3`, `xxh64`/`xxhash`, `md5`, `md4`,
  `sha1`, `none`, `auto`, plus the two-name `transfer,pre-transfer` form.
  Unknown names and `none` on the transfer side under `--checksum` exit 4 like
  rsync.
- **Codec residuals:** the transfer checksum is not independently selectable
  (only the whole-file comparison digest is); `zlib`/`zlibx` share FastSync's
  literal-only zlib path (rsync's zlibx behavior, observably identical for both,
  so `zlibx` is not a divergence). Per-codec compression-level defaults and
  `RSYNC_COMPRESS_LIST`/`RSYNC_CHECKSUM_LIST` are implemented (track 3a).

### Selection, paths, and filters

- **General `-R`/`--relative`** implements the `/./` cut and prefix-scoped
  deletion; **`--no-implied-dirs`** stops implied-parent attribute application.
- **`-d`/`--dirs`** implements rsync's one-level listing for `dir`, `dir/` and
  `.`, with `STATUS_MKDIR` directory entries in the delete manifest.
- **Filter grammar:** `merge`/`.`, `dir-merge`/`:`, `hide`/`H`, `show`/`S`,
  `protect`/`P`, `risk`/`R`, `clear`/`!`, include/exclude and the `:`/`.`
  modifiers; `-f` is bound to `--filter`; a single `-F` transfers
  `.rsync-filter` and `-FF` excludes it. The xattr-name `x` modifier is **not
  implemented** and is rejected with a clear error everywhere. The merge-only
  `e`/`n`/`w` and `-` modifiers are accepted and consumed on `merge`/`dir-merge`
  rules (rejected elsewhere, matching rsync), but their semantics are **not
  implemented** (accepted-but-ignored).
- **Absolute basis directories** are used verbatim (rsync semantics) and
  **`--link-dest`** relinks an already up-to-date destination.

### Client quick wins and aliases

- `--iconv=.`/`-`/`--no-iconv`; a lone `-h` prints help; an empty
  `--files-from` succeeds (exit 0); a broken referent under `-L`/
  `--copy-unsafe-links` exits 23; the full `--info`/`--debug` vocabularies; and
  the aliases `--ignore-non-existing`, `--protect-args`, `--msgs2stderr`.
- Receiver-side `--chown`/`--usermap`/`--groupmap` TO-name resolution; a
  receiver-side `--ignore-existing` short-circuit before any payload; and
  `--preallocate` now wins over `--sparse` via `fallocate(2)`.

### Residuals and intentional divergences

These remain after the wave; the individual rows carry the precise wording.

- **`--stats`** now reproduces rsync's `(reg/dir/link/special)` breakdown on
  `Number of files`, the regular-transferred count and the size totals, but
  `Number of created files` is the transferred-regular count without a type
  breakdown and wire-byte totals differ; **`--progress`** now prints the leading
  `./` line and includes the root in `to-chk` (single-file output is
  byte-identical), but a multi-directory `to-chk` denominator and per-directory
  name lines still differ; **`--out-format`** `%C` matches for every algorithm,
  but `%b`/`%c` count FastSync wire bytes (protocol-specific, hence ❌).
- **`-n --delete`** ordering can differ from rsync's delete-during walk (the
  differential compares the sorted would-delete set).
- **Delete timing:** plain `--delete` now defaults to rsync's delete-during
  (lockstep track 6); the residual is the mid-transfer abort boundary, where
  rsync's generator removes all extras ahead of its throttled sender while
  FastSync removes only the reached directories (completed runs agree).
  `--delete-before` keeps its pre-scan snapshot race; and while
  base-rule `protect`/`risk` rules are now re-applied on the receiver (track 4a),
  per-directory merge (`.rsync-filter`) protection is still sender-derived, so a
  destination-only entry matching only a per-directory rule is not re-derived.
  `--ignore-errors` exits 23 but its EACCES differential is not
  exercised in CI.
- **`--delay-updates`** uses a fixed staging name with an advisory lock and
  deletes before publication; **`--temp-dir`** rejects out-of-root absolute and
  foreign paths (in-root absolute paths are accepted; deliberately confined, see
  the row); **`--remote-option`** is SSH-only.
  **`--iconv`** now matches rsync's push direction (destination charset = the
  spec's REMOTE half; a server `--iconv` overrides it).
- **Basis dirs** now use rsync's metadata quick-check by default (track 5a) and
  stream a hit of any size; the FastSync-only `--verify-basis` restores the
  stricter content equality. Remaining residuals: the relative-DIR resolution
  base and the over-limit basis-MISS refusal. **`--fuzzy`** uses rsync's
  name heuristic, but its candidate eligibility is bounded by the delta
  engine (both files ≥ 16 KiB, size ratio ≤ 10×), a narrower window than
  rsync's, so the selected basis — and the `--stats` bandwidth counters —
  can differ while the tree stays byte-exact.
- **`--inc-recursive`/`--no-inc-recursive`** are accepted as inert no-ops:
  FastSync always performs a single full recursive scan (equivalent to
  rsync's `--no-inc-recursive`), so the destination is identical either way.

### Intentional divergences (explicit ❌ rows)

Native daemon config/auth (`--daemon`, `--config`, `--dparam`,
`--password-file`, `--early-input`, `--hash-credentials`/`--iterations`), the
non-interoperable batch container (`--write-batch`/`--only-write-batch`/
`--read-batch`), `--fake-super`'s native xattr format, `-X`'s privileged
namespaces, `--devices`/`--copy-devices`/`--write-devices`'s safe subsets,
`--super`/`--copy-as`'s refusal to elevate or switch credentials, and the
`-s`/`--secluded-args`/`--protect-args`/`--old-args` accepted no-ops.

## Packed Metadata Frame (protocol 2.20.0)

A file's metadata used to cross the wire as up to 12 separate per-field framed
messages (a present flag followed by mode/uid/gid/mtime/atime/crtime writes),
which cost ~11 extra protocol frames per file on many-small-file trees. FastSync
now sends the metadata as ONE packed frame: a single `int32` present flag
(`0` = absent) followed, when present, by the fixed
`FILE_METADATA_WIRE_SIZE`-byte (68-byte) field record already emitted by the
shared `metadata_to_buf()`/`metadata_from_buf()` chunk codec. Absent metadata is
a lone `int32` zero. The encoded field layout is unchanged (only the framing
collapses), so chunk-serialized blobs remain byte-identical. Protocol data is an
unframed byte stream, so the packed encoding is byte-for-byte identical to the
old field-by-field writes; `PROTOCOL_VERSION` was bumped `2.19.0 → 2.20.0` as a
deliberate lockstep-release marker rather than because of a
desynchronization. The strict same-version handshake rejects any mismatch before
a byte of the frame is parsed.

### Recommended Delivery Order

1. Resolve short-option conflicts (`-m`, `-M`, `-T`, `-f`, `-s`) and define the compatibility contract.
2. Implement Phase 1 comparison, update, output, and alias features with unit and integration coverage.
3. Implement Phase 2 traversal/filtering and Phase 3 deletion semantics.
4. Implement metadata and link features that are safe on the supported platforms.
5. Treat daemon mode, special files, batch mode, and protocol-version compatibility as separate projects.

The existing priority list below is a feature shortlist, not an implementation schedule; this plan supersedes it for effort and sequencing.

---

## Recommendations: Top Features to Implement Next

Ranked by user demand, implementation complexity, and interoperability impact (_status reflects current `dev`_):

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| 1 | `--whole-file` / `-W` | Low | High — users expect opt-out of delta — **✅ implemented** |
| 2 | `--ignore-times` / `-I` | Low | Medium — useful for forcing re-transfer — **✅ implemented** |
| 3 | `--size-only` | Low | Medium — common migration scenario — **✅ implemented** |
| 4 | `--ignore-existing` | Low | Medium — common sync patterns — **✅ implemented** |
| 5 | `--existing` | Low | Medium — common sync patterns — **✅ implemented** |
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
| `-j` / `--threads[=N]` | Multithreaded pipeline (scanner/loader/sender); `N` (1–256) sizes the parallel scanner worker pool, bare `-j`/`--threads` uses the built-in default (renamed from `-m` in Phase 7 Wave A; `-m` is now rsync `--prune-empty-dirs`) |
| `--chunk-serialization` | Chunk serialization mode (long form only; `-s` is now rsync `--secluded-args`) |
| `--sendfile` | Zero-copy sendfile() syscall (TCP only) (long form only; `-f` is now rsync `--filter`) |
| `-z [level]` / `--compress` | zstd compression level (1-22) (`-c` is now rsync `--checksum`) |
| `--chunk-size` | Configurable chunk size |
| `--tls` | TLS encryption (mutual auth) |
| `--fastsync-server-path` | Path to fastsync-server binary |
| `--server-host` / `--server-port` | Direct TCP connection |
| `--verify-basis` | FastSync-only (long form, not in rsync): require a `--compare-dest`/`--copy-dest`/`--link-dest` basis hit to match the source by whole-file digest instead of trusting rsync's size+mtime (or `--size-only`) quick-check. Off by default (the default matches rsync). Crosses the wire (protocol 2.28.0) |
| `--delete-commit` | FastSync-only (long form, not in rsync): restore the late whole-tree delete commit — the keep-set manifest is committed only after the entire transfer succeeded. Identical timing to `--delete-after`, and implemented as the same `delete_after` wire bool (no new field); it exists because plain `--delete` now defaults to `--delete-during` (lockstep track 6). Implies `--delete` and conflicts with any different timing flag |
| Incremental sync | Skip unchanged files (size+mtime) |
| Delta transfer | Block-level delta for changed files |
