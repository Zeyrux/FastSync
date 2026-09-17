# FastSync — Session Handoff (2026-09-17)

## Current status
- **Release `v2.21.0`** tagged (`919a729`, "Release v2.21.0"); full CI green
  (run 552: lint, build-and-test, ASan, UBSan, fuzz-build, coverage, valgrind).
  `dev` has the release commit plus later doc-only merges (a README refresh and
  this handoff).
- **Release PR #284 (`dev` -> `main`)** open, CI green (run 553).
  `main` is protected: it needs review/approval to merge.
  https://gitea.tap-tap.win/TapTap/FastSync/pulls/284
- **`PROTOCOL_VERSION` = `"2.26.0"`** (`src/shared/config.h`); CMake
  `project(FastFileTransfer VERSION 2.26.0)`.
- Working tree clean; no wave worktrees remain.

## What landed this session
1. **Wave 8 (refactors):** Config X-macro wire table; single-owner `authorized_root`;
   daemon per-module/per-host caps + cross-process auth lockout (`daemon_limits.[ch]`);
   `Data` charge returns to its owning `ProtocolSession`.
2. **Wave 9 (protocol 2.21.0):** optional `STATUS_ERROR_DETAIL` rejection reasons;
   server-contacting `--dry-run` (`STATUS_DRY_RUN_TRANSFER`, receiver mutates nothing).
3. **Security wave:** ran 5 parallel audits (wire parsing; daemon/transport/TLS/auth;
   receiver confinement; client/CLI/SSH; crypto/memory/limits). Fixed all HIGH and the
   confirmed MEDIUMs:
   - SSH `-o ProxyCommand=…` argument injection (RCE) — reject leading `-`, insert `--`.
   - Truncated zstd frame infinite CPU loop (remote DoS).
   - FIFO receiver opens lacked `O_NONBLOCK` (indefinite hang).
   - `--inplace` could write a FIFO/device (bypass of `--write-devices` gate).
   - `--force` not gated by server `--allow-delete`.
   - Privileged standalone server defaulted super activities on; added `--allow-super`
     (never honored with `--stdio`).
   - `--dry-run` content/hash oracle on `read only`/basis files removed.
   - Empty `hosts allow`/`deny`/`auth users` now rejected.
   - TLS: AEAD-only 1.2 + server preference, TOCTOU-safe key load, IP-SAN verify,
     CN-truncation guard. Glob backtracking bounded; line reads bounded; ACL xattrs
     gated on `--acls`; decompression/chunk memory charged; pre-auth `basis_count`
     NULL-deref fixed.
4. **Tooling:** benchmark accuracy (data mix, verification, percentiles, `tc`,
   `build-bench/`, `--warm` mode); `shell.nix` full toolchain and no build-on-entry;
   docs state push-only / remote-source unsupported.
5. **Preserve-attribute split (protocol 2.22.0)** landed on `feat/preserve-attr-split`: per-attribute `-p/-t/-o/-g` + `--no-*` negations, `-a` = `-rlptgoD`, and the 2.21.0 → 2.22.0 wire bump.
6. **Rsync-parity wave (protocol 2.23.0)** on `feat/rsync-parity`: rsync short options/clustering/attached values (`-r`/`-b`/`-L`/`-B`, `-av`, `-aAX`, `-B1000`, `-essh`, `-MOPT`), `-c` checksum quick-check, `--checksum-choice`/`--compress-choice` validation and seed randomization, rsync timeout/max-alloc defaults, temp-dir confinement + `EXDEV` fallback, ownership/mapping parity (numeric-ids modifier, map ranges/`*`/empty-FROM, `--chown`+map conflicts, fake-super resolved-owner record), verbatim symlink storage with rsync `--safe-links`/`--munge-links`, socket recreation under `--specials`, `--chmod` 3.4.1 semantics, and delete scoping + `--max-delete` partial/exit-25. Wire: appended delete-manifest synchronized-directory section and `STATUS_DELETE_LIMIT`.
7. **Parity-completion wave (protocol 2.24.0 → 2.26.0)** on `feat/parity-completion`: per-directory delete plans (`STATUS_DELETE_PLAN`) for `--delete-during`/`--delete-delay`; receiver `STATUS_STATS` counters feeding `--stats`/`--progress` and `--out-format %b/%c/%C`, plus `-n --delete` lines; `lz4`/`zlib`/`zlibx` compression and `md4`/`sha1`/`none` checksums with `auto` negotiation (default `xxh128`/`zstd`); general `-R`/`--no-implied-dirs`/`-d`; the full filter grammar (`merge`/`dir-merge`/`hide`/`show`/`protect`/`risk`/`clear` + modifiers) and corrected `-F`/`-FF`; receiver-side `--chown`/map TO-name resolution; absolute basis dirs + `--link-dest` relink; receiver-side `--ignore-existing` short-circuit; `--preallocate` over `--sparse` via `fallocate(2)`; `--iconv=.`/`-`/`--no-iconv`; lone `-h` help; aliases `--ignore-non-existing`/`--protect-args`/`--msgs2stderr`; and the full `--info`/`--debug` vocabulary. `RSYNC_COMPAT.md` reclassifies the matrix to 109 ✅ / 25 ⚠️ / 23 ❌.

## Next steps
1. **Merge PR #284** (`dev` -> `main`) once reviewed (protected branch).
2. **Deferred security items** (documented, not implemented):
   - Pre-auth config/daemon-auth handshake has no aggregate wall-clock deadline
     (per-message timeout only) — slowloris holds connection slots.
   - Per-source registry fails open when the shared table is full (per-module/global
     caps and host ACLs still apply); consider fail-closed or larger/evicting table.
   - SCRAM-like daemon auth has no TLS channel binding (and is not RFC 5802).
   - `cleanup()` signal handler calls non-async-signal-safe teardown; daemon `umask(0)`.
   - Wire protocol assumes homogeneous word size/endianness (lengths are native
     `size_t`) — document or move to fixed-width framing.
3. **Out of scope / intentional:** pull (remote source) mode is **not** planned —
   FastSync is push-only; see `RSYNC_COMPAT.md#direction`.

## Key facts / commands
- CI image: `gitea.tap-tap.win/taptap/fastsync-ci:v11` (alias `fastsync-ci:local`).
- Build/test: `cmake -B build -S . -DSTRICT_WARNINGS=ON && cmake --build build -j$(nproc) && ./build/tests`
  then `python3 -m pytest tests/integration/ -n 4 --dist=load -m "not setpriv"`.
- Dev shell: `nix-shell` (provides clang-format, cppcheck, pytest-xdist, openssh,
  rsync, iproute2, valgrind, lcov; does not build on entry).
- Gitea API token: supplied out-of-band via the `TOKEN` environment variable; it is
  intentionally **not** recorded in this file.
- CI polling: `GET /api/v1/repos/TapTap/FastSync/actions/runs?limit=N`, match `head_sha`,
  then `/actions/runs/<id>/jobs`.
