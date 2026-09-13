# Changelog

All notable changes to FastSync are documented here. Versions match
`PROTOCOL_VERSION` (printed by `fastsync --version`); the client and server must
run the same version because the handshake is strict.

## [Unreleased]

### Security

- Enforce the daemon's per-module `max connections` cap and add a global
  `max connections per host` cap plus a cross-process `auth lockout`
  (`auth lockout threshold` / `auth lockout duration`). Because the listener
  forks one child per connection, the counters live in an anonymous shared
  mapping created before the accept loop and reclaimed by the parent's
  `SIGCHLD` handler, so the per-module, per-source and auth-failure state is
  shared across every child (including after `SIGKILL`). The per-source table
  now has a bounded lifetime (expired-lockout/idle entries are reclaimed, with a
  rate-limited warning when it is genuinely full), and the occupancy counters are
  re-derived from the shared slot table on every child exit so a child killed
  mid-registration cannot leak a count. Trusted loopback peers are exempt from the
  per-host cap and the auth lockout (they share one address); clients behind a
  shared NAT/proxy still share a single per-host budget and lockout, which is
  documented.

## [2.21.0] - 2026-09-13

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

### Changed

- `receive_incremental_check()` (the per-file `STATUS_CHECK` fast path) is split
  into small static helpers with a short linear orchestrator. Pure refactor: the
  wire byte stream and all cleanup are unchanged.

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
