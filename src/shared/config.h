#ifndef CONFIG_H
#define CONFIG_H

#include "array_list.h"
#include "checksum.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

typedef enum { TRANSPORT_TCP, TRANSPORT_SSH } TransportType;

/* --outbuf stdout/stderr buffering style (client-only launch concern, never
 * crosses the wire).  OUTBUF_BLOCK is the default, matching the stdio default
 * (fully buffered when output is not a terminal). */
typedef enum {
  OUTBUF_BLOCK = 0, /* _IOFBF */
  OUTBUF_LINE,      /* _IOLBF */
  OUTBUF_NONE       /* _IONBF */
} OutbufMode;

/* Receiver-side staging state for --delay-updates.  Forward-declared here so
   Config can carry it; the concrete type lives in delay_updates.h. */
typedef struct DelayUpdatesContext DelayUpdatesContext;

/* Alternate basis-directory modes (--compare-dest / --copy-dest /
 * --link-dest).  Each flag adds one entry to the ordered Config->basis_dirs
 * list; the receiver consults entries in command-line order and stops at the
 * first exact match, mirroring rsync's basis-dir priority rules. */
typedef enum {
  BASIS_DEST_NONE = 0,
  BASIS_DEST_COMPARE, /* compare only: never copies, never materializes */
  BASIS_DEST_COPY,    /* local copy of the matched basis file */
  BASIS_DEST_LINK     /* hard link to the matched basis file */
} BasisDestType;

typedef struct BasisDest {
  BasisDestType type;
  char* path; /* relative to the destination root (receiver-confined) */
} BasisDest;

/* One resolved FROM:TO identity-mapping rule (--usermap / --groupmap).  Both
 * fields are numeric ids.  IDENTITY_MATCH_ANY (-1) in `from` is rsync's '*'
 * wildcard (matches any transmitted id); IDENTITY_CURRENT (-1) in `to` makes
 * the receiver resolve the receiving process's own current euid/egid at apply
 * time.  Names are resolved to numbers at parse time on the client (see
 * identity.h for the exact subset). */
typedef struct {
  int32_t from;
  int32_t to;
} IdentityMap;

/* --sockopts=OPTIONS allowlist.  Only these option names are accepted; anything
 * else is rejected (never silently ignored).  TCP_NODELAY, SO_KEEPALIVE and
 * SO_REUSEADDR are boolean options (value 0/1); SO_RCVBUF and SO_SNDBUF take a
 * non-negative byte count.  All are applied as int-sized setsockopt values. */
typedef enum {
  SOCKOPT_TCP_NODELAY = 0,
  SOCKOPT_SO_KEEPALIVE,
  SOCKOPT_SO_RCVBUF,
  SOCKOPT_SO_SNDBUF,
  SOCKOPT_SO_REUSEADDR,
  SOCKOPT_COUNT
} SockOptId;

typedef struct {
  SockOptId id; /* allowlist index */
  int value;    /* 0/1 for booleans, byte count for SO_RCVBUF/SO_SNDBUF */
} SockOptEntry;

/* --super / --no-super tri-state (Config->super_mode).  AUTO (default) and ON
 * both permit a confined super-user attempt (AUTO preserves FastSync's
 * historical best-effort behavior; an unprivileged attempt is refused by the
 * kernel and skipped per entry); OFF forbids the attempt even for root.  See
 * privilege_super_mode_permitted() in identity.h. */
typedef enum SuperMode { SUPER_MODE_AUTO = 0, SUPER_MODE_ON = 1, SUPER_MODE_OFF = 2 } SuperMode;

typedef struct Config {
  char* version;
  char* send_directory;
  char* receive_root_directory;
  bool save_to_disk;
  bool use_multithreading;
  bool use_chunk_serialization;
  bool use_compression;
  bool use_sendfile;
  bool use_metadata;
  bool use_executability;
  bool metadata_explicitly_disabled;
  bool show_progress;
  bool dry_run;
  bool remove_source_files;
  bool use_delete;
  int compression_level;
  int compression_threads;
  unsigned long long chunk_size;
  int ssh_port;
  TransportType transport;
  char* ssh_destination;
  /* Daemon module selection (Wave A, protocol 2.15.0).  Client-composed from a
   * host::module/path destination; NULL or "" means "no module" (the ordinary
   * standalone-server path).  Crosses the wire as a trailing config-frame
   * string so the daemon can look the module up in its own config and confine
   * the connection to the module's root (never a client-chosen root). */
  char* module;
  /* Daemon password authentication (A7 remediation, protocol 2.19.0).
   * Client-composed from a --password-file whose first meaningful line is
   * `user:password`: the client sends ONLY the username in the config frame
   * (auth_user); the literal password is kept in auth_password CLIENT-SIDE for
   * the duration of the SCRAM challenge/response and is NEVER serialized.  Both
   * are NULL when the client has no credentials to present; a module WITHOUT
   * `auth users` stays open and the server ignores any credentials that do
   * arrive (the client sends them opportunistically and the server decides). */
  char* auth_user;
  char* auth_password;
  /* Client-only path of --password-file (never crosses the wire; it is read to
   * populate auth_user/auth_password before connecting). */
  char* password_file;
  char* fastsync_server_path;
  /* --iconv=CONVERT_SPEC (protocol 2.16.0, rsync compatibility): convert the
   * charset of FILE NAMES at the wire boundary.  CONVERT_SPEC is
   * "LOCAL[,REMOTE]": LOCAL is the charset of our own file names, REMOTE is
   * the remote side's charset and defaults to LOCAL.  The sender converts
   * every path LOCAL->REMOTE before transmitting it; the receiver converts
   * every received path back REMOTE->LOCAL before creating/writing it.  The
   * FULL SPEC crosses the wire as a trailing config-frame string so each end
   * derives its own LOCAL and the wire (REMOTE) charset symmetrically.  NULL
   * (or "") means no conversion: identity with zero overhead.  See charset.c
   * and the PROTOCOL_VERSION note below. */
  char* iconv_spec;
  char** exclude_patterns;
  int exclude_count;
  char** include_patterns;
  int include_count;
  unsigned long long max_size;
  unsigned long long min_size;
  unsigned long long max_alloc;
  bool use_incremental;
  bool ignore_times;
  bool size_only;
  bool use_delta;
  bool whole_file;
  /* -y/--fuzzy: when a file must be transferred and the destination holds no
   * usable file at the exact path, the receiver may reuse a SIMILAR-named
   * existing regular file in the same destination directory as the delta
   * basis so the sender transmits only the differences.  Crosses the wire
   * (the receiver performs the candidate search); the CLI implies
   * --incremental + --delta because the similar-basis only matters on the
   * receiver-driven delta path.  Off by default. */
  bool fuzzy;
  int modify_window;
  uint32_t delta_block_size;
  unsigned long long delta_max_file_size;
  bool use_tls;
  char* server_host;
  int server_port;
  char* tls_cert;
  char* tls_key;
  char* tls_ca;
  /* --timeout: per-message I/O deadline in seconds.  0 (the default/unset
   * sentinel) leaves the transport's built-in 30 s socket timeout and the
   * protocol's built-in 60 s per-message deadline in place; a positive value
   * overrides both.  See protocol_session_set_io_timeout. */
  int timeout;
  /* --contimeout: connect()/accept timeout, transport layer only. */
  int contimeout;
  bool quiet;
  bool backup;
  char* backup_dir;
  bool stats;
  int max_depth;
  FILE* log_file;
  int queue_size;
  bool follow_symlinks;
  bool partial;

  // Issue #120: Symlink handling
  bool copy_links;
  bool safe_links;
  bool copy_unsafe_links;
  /* Phase 4 symlink-trust.  -k/--copy-dirlinks and --munge-links are
   * CLIENT/sender-side only (they decide how the SENDER scans and rewrites
   * symlinks; the receiver never reads them), so they never cross the wire.
   * -K/--keep-dirlinks is a RECEIVER-side policy (follow an in-root destination
   * symlink-to-directory as a directory) and CROSSES the wire along with
   * --munge-links (so the receiver knows to unmunge). */
  bool copy_dirlinks; /* client-only, sender-side (-k) */
  bool munge_links;   /* crosses the wire */
  bool keep_dirlinks; /* crosses the wire (-K) */

  // Issue #121: Extended metadata preservation
  bool preserve_hard_links;
  bool preserve_acls;
  bool preserve_xattrs;
  bool preserve_devices;
  bool preserve_sparse;
  /* Phase 4 special/devices: preserve special files (FIFOs, sockets) and device
   * nodes on the destination by recreating them (mknod/mkfifo) instead of
   * transferring content.  preserve_specials mirrors rsync --specials (the
   * special-file half of -D); preserve_devices mirrors --devices (the device
   * half of -D); both CROSS the wire so the receiver knows a special/device
   * entry must be recreated rather than written as a regular file. */
  bool preserve_specials;
  /* --copy-devices: copy the CONTENT of a source device as an ordinary regular
   * file on the destination (rsync's non-privileged safe mode), instead of
   * recreating the device node.  CROSSES the wire (receiver treats the entry as
   * a regular file, which is the default, so this is belt-and-braces). */
  bool copy_devices;
  /* --write-devices: write the received data directly INTO an existing device
   * node on the destination instead of creating a regular file.  Dangeroud;
   * see RSYNC_COMPAT.md for the tight gating.  CROSSES the wire. */
  bool write_devices;

  // Issue #122: Output/logging options
  bool itemize_changes;
  char* out_format;
  char* log_file_format;
  int info_level;
  int debug_level;
  bool list_only;
  bool human_readable;
  bool eight_bit_output;

  // Issue #127: Transfer modes
  bool existing;
  bool ignore_existing;
  bool update;
  bool inplace;
  bool delay_updates;
  bool use_fsync;
  bool append;
  bool append_verify;
  /* --preallocate: allocates the destination file's full expected space up
   * front (before any data is written) so a transfer that would overflow disk
   * fails fast at allocation time and the file is laid out contiguously,
   * avoiding fragmentation.  Receiver-side, crosses the wire. */
  bool preallocate;

  // Issue #128: Extended delete options
  /* --delete-excluded: also delete destination entries that were excluded on
   * the source.  Default (off) matches rsync: excluded paths are protected from
   * deletion.  Crosses the wire (the sender encodes the choice by whether it
   * transmits a protected-prefix list with the keep-set manifest). */
  bool delete_excluded;
  bool delete_after;
  /* --max-delete=NUM: the receiver refuses to delete more than NUM entries per
   * run (all-or-nothing: when the extras would exceed NUM nothing is removed and
   * the transfer fails with a distinct error).  -1 == no client limit (the
   * server hard bound MAX_SERVER_DELETE_COUNT still applies). */
  int max_delete;
  /* --ignore-errors (client-only, never serialized): a sender-side source I/O
   * error (an unreadable directory during the scan) normally aborts the run so
   * no deletion happens; with --ignore-errors the scan continues and the
   * (partial) keep-set is still transmitted so the deletion runs. */
  bool ignore_errors;
  /* --force (receiver-side): a regular file may replace a destination
   * directory by removing that (possibly non-empty, symlink-safe) directory
   * tree first, instead of failing the write.  Crosses the wire. */
  bool force_delete;
  /* --ignore-missing-args (client-only, never serialized): a --files-from
   * entry that does not exist under the source is silently skipped instead of
   * failing the run.  Sender-side only: nothing is sent for it and it never
   * enters the keep-set.  Implied by --delete-missing-args. */
  bool ignore_missing_args;
  /* --delete-missing-args: implies --ignore-missing-args; additionally each
   * missing entry's destination mirror (computed like a present entry's wire
   * path) is deleted receiver-side.  Crosses the wire and is gated by the
   * server's --allow-delete policy like --delete.  rsync-parity: independent
   * of ordinary --delete processing (it does not imply --delete); a non-empty
   * directory mirror is only removed with --force or --delete in effect, and
   * the missing-args deletions are not counted toward --max-delete. */
  bool delete_missing_args;

  // Issue #129: Advanced file selection. These fields are CLIENT-ONLY: they are
  // never serialized to the wire (the receiver must not learn them).
  ArrayList* filters;   /* --filter=RULE rule strings, in order */
  char* files_from;     /* --files-from path (may be NULL) */
  void* files_from_set; /* parsed FileListSet* allow-set, or NULL */
  bool from0;           /* -0/--from0: NUL-delimited *-from files */
  bool cvs_exclude;     /* -C/--cvs-exclude: standard CVS ignore set */
  bool per_dir_filter;  /* -F: apply per-directory .rsync-filter files */
  bool prune_empty_dirs;
  bool one_file_system; /* -x/--one-file-system: do not cross filesystem boundaries */
  /* -R/--relative: crosses the wire; with --files-from listed entries keep
   * their bare relative destination path (no source-root mirror prefix). */
  bool relative;
  /* --no-implied-dirs: client-only.  With -R + --files-from, refuse to place a
   * listed file whose ancestor directory is not itself explicitly listed. */
  bool no_implied_dirs;
  /* -d/--dirs: client-only.  Transfer the directory entries named by the
   * source argument / --files-from list without recursing into contents. */
  bool dirs;
  /* --mkpath: crosses the wire.  Tells the server to create the destination
   * root directory (and missing leading components below its authorized root)
   * at connection start instead of requiring it to already exist. */
  bool mkpath;

  // Issue #130: Remote shell/connection options
  /* -e/--rsh: the remote-shell program used to establish the SSH transport.
   * NULL means the default "ssh".  Client-only launch concern: NEVER crosses
   * the wire (it is not meaningful to the daemon/server handshake). */
  char* rsh_command;
  /* --blocking-io: leave the SSH transport socket without
   * SO_RCVTIMEO/SO_SNDTIMEO so it blocks naturally instead of timing out.
   * Client-only launch concern: NEVER crosses the wire. */
  bool blocking_io;
  /* --outbuf mode (OutbufMode): stdout/stderr buffering.  Client-only launch
   * concern: NEVER crosses the wire. */
  int outbuf;
  bool old_args;
  char* temp_dir;
  /* --remote-option=OPT (Phase 5, long form only): one or more extra command-line
   * options to append to the REMOTE server invocation over SSH.  CLIENT-ONLY:
   * they are composed into the remote command line by ssh_build_remote_command()
   * (each valid word is shell-escaped with the same quoting boundary as the
   * server path), and are NEVER serialized into the binary config frame.  They
   * do NOT cross the wire and are never parsed on the receiver process. */
  char** remote_options;
  int remote_option_count;
  /* Alternate basis directories, ordered by command-line appearance.  Each
   * entry's type selects compare/copy/link behavior on an exact match.  These
   * cross the wire so the receiver can consult them; they are interpreted
   * relative to the destination root and confined there. */
  BasisDest* basis_dirs;
  int basis_count;

  // PR #174: Partial transfer resumption
  char* partial_dir;

  // PR #178: Backup versioning
  char* suffix;

  // PR #179: Delete policies
  bool delete_before;

  /* rsync deletion-timing family (real from Phase 3).  At most one of
     delete_before / delete_during / delete_delay / delete_after may be set, and
     only together with use_delete (the CLI implies --delete for each of them).
     delete_before and delete_during select the EARLY engine mode: the keep-set
     manifest is transmitted before any file data and extras are removed then,
     acknowledged, before the first data byte.  delete_delay and delete_after
     select the LATE commit mode: extras are removed only after the whole
     transfer has succeeded (plain --delete keeps this mode).  The exact
     semantics and the divergences from rsync are documented in RSYNC_COMPAT.md
     and in config_delete_timing_early() below. */
  bool delete_during;
  bool delete_delay;

  // PR #181: IPv6 and bind address
  char* address;
  char* bind_address;
  bool ipv6;
  bool ipv4;
  /* --sockopts=OPTIONS (Phase 5, Wave B): strict allowlist of TCP/socket
   * options applied via setsockopt after socket() and before connect()/bind().
   * These are LOCAL socket concerns: they never cross the wire config frame.
   * .address is the outgoing/source bind address (--address); .bind_address is
   * reserved for daemon-side binding and is not wired yet. */
  SockOptEntry* sockopts;
  int sockopt_count;

  // PR #182: Daemon/server mode
  bool daemon;
  char* daemon_config;
  bool server_mode;
  /* --no-motd (Wave C): CLIENT-ONLY, never crosses the wire.  Suppresses
   * DISPLAY of the daemon's MOTD; the daemon still sends the MOTD frame, so
   * the client reads and discards it to keep the stream in sync.  rsync's
   * --no-motd is likewise a client-side display switch.  Default false (the
   * MOTD is shown when a daemon offers one). */
  bool no_motd;

  // PR #183: Checksum comparison
  bool checksum;

  // PR #184: Compression algorithm negotiation
  char* compress_choice;
  char* chmod_spec;

  /* --checksum-choice / --cc and --checksum-seed.  checksum_algo is the id of
   * the whole-file content-digest algorithm used by the per-file --incremental
   * handshake (sender computes it, receiver compares it to skip unchanged
   * files) and by the basis-dir content verification.  checksum_seed is passed
   * to xxHash64 (and to the delta block strong hash, low 32 bits); md5 has no
   * seed so it is ignored there.  Both cross the wire: the receiver MUST hash
   * the on-disk old file with the same algorithm and seed to reach a matching
   * digest.  Defaults (XXH64 / seed 0) reproduce the pre-existing behavior
   * byte-for-byte. */
  int checksum_algo;      /* ChecksumAlgo, default CHECKSUM_ALGO_XXH64 */
  uint64_t checksum_seed; /* default 0 */

  char** skip_compress_suffixes;
  int skip_compress_count;
  bool skip_compress_set;

  // Issue #131: Identity mapping.  These configure whether and how the receiver
  // applies ownership when it is actually preserved/applied.  ALL of them cross
  // the wire (protocol 2.11.0) so the receiver resolves and applies ownership
  // with the exact policy the client requested.  Plain -M/--preserve still does
  // NOT apply ownership (FastSync's deliberate conservative default); it is
  // only attempted when at least one of these is set (see identity.h).
  /* --numeric-ids: no name lookup, use the transmitted numeric ids raw. */
  bool numeric_ids;
  /* --chown USER (owner) override; IDENTITY_CURRENT = the receiver's euid. */
  bool chown_uid_set;
  int32_t chown_uid;
  /* --chown :GROUP (group) override; IDENTITY_CURRENT = the receiver's egid. */
  bool chown_gid_set;
  int32_t chown_gid;
  /* --usermap / --groupmap entries, in order (first match wins). */
  IdentityMap* usermap;
  int usermap_count;
  IdentityMap* groupmap;
  int groupmap_count;

  /* --super / --no-super (P7 Wave E, protocol 2.18.0): receiver-side privilege
   * policy for super-user activities confined below the authorized receive
   * root.  SUPER_MODE_AUTO (default) preserves the pre-existing best-effort
   * behavior: the confined super-user operation is ALWAYS attempted and an
   * unprivileged attempt is refused by the kernel and skipped per entry.
   * SUPER_MODE_ON (--super) explicitly REQUESTS those activities (char/block
   * device-node creation, --write-devices); it does NOT imply --numeric-ids and
   * never enables ownership application on its own.  SUPER_MODE_OFF
   * (--no-super) FORBIDS them even when running as root.  FastSync NEVER
   * elevates privileges (no setuid/seteuid/setgid) and never bypasses the
   * fd-relative confinement (file_open_secure_parent, O_NOFOLLOW, root checks);
   * --super only permits an attempt that is already confined.  Crosses the wire
   * as a trailing int so the receiver can enforce the policy.  See
   * privilege_super_permitted() and identity_ownership_requested() in
   * identity.h. */
  SuperMode super_mode;

  // Receiver-side runtime staging registry for --delay-updates.  Never sent
  // over the wire and never set on the sender side.
  DelayUpdatesContext* delay_context;

  // Phase 4: metadata time preservation.  -U/--atimes and -N/--crtimes capture
  // and transmit the source access / birth time (both sender and receiver
  // effect, so they CROSS the wire).  --omit-dir-times/-O and
  // --omit-link-times/-J are receiver-side prefs (CROSS the wire).  Their
  // exact capture/transmit/apply semantics are documented in RSYNC_COMPAT.md.
  /* -U/--atimes: preserve source access times on the destination. */
  bool preserve_atimes;
  /* -N/--crtimes: capture+transmit source birth time; see RSYNC_COMPAT for the
   * receiver not-applied divergence. */
  bool preserve_crtimes;
  /* -O/--omit-dir-times: do not apply mtimes to directories. */
  bool omit_dir_times;
  /* -J/--omit-link-times: do not apply times to symlinks. */
  bool omit_link_times;
  /* --open-noatime: CLIENT-ONLY (never crosses the wire).  The sender opens
   * source files with O_NOATIME so reading for transfer does not bump the
   * source access time. */
  bool open_noatime;

  // Phase 4: xattr / ACL / fake-super preservation.
  /* -X/--xattrs and -A/--acls toggle the sender's capture and the receiver's
   * application of per-file extended attributes (xattrs).  Both cross the wire:
   * the sender only transmits the bounded, whitelisted attribute set it
   * captures and the receiver re-validates namespaces/sizes before applying
   * fd-relative.  With neither set (the default) no xattr block is sent, so the
   * wire is byte-identical to prior protocol versions for unaffected runs. */
  /* true when preserve_xattrs || preserve_acls; the sender/receiver gate the
   * xattr wire block on this single flag. */
  bool use_xattrs;
  /* --fake-super: receiver-only.  When set, each written file additionally gets
   * a reserved user.fastsync.stat xattr recording the source uid/gid/mode/mtime
   * so a later privileged restore could re-apply them.  Crosses the wire. */
  bool fake_super;
  /* --copy-as=USER[:GROUP] (P7 Wave E, protocol 2.18.0).  Safe-subset
   * implementation, a documented divergence from rsync's real identity switch:
   * the receiver does NOT change its process credentials (FastSync's receiver
   * is multithreaded, so a setuid/seteuid drop would be unsafe).  Instead the
   * receiver FORCES the ownership of every entry it writes to copy_as_uid /
   * copy_as_gid through the existing confined, fd-relative identity path
   * (fchown/fchownat), which REQUIRES receiver privilege (root); an
   * unprivileged receiver REFUSES the whole transfer up front at the config
   * handshake (never a silent wrong-ownership result).  All three fields CROSS
   * the wire as a trailing config-frame block so the receiver learns the
   * requested ids; see the PROTOCOL_VERSION note below. */
  bool copy_as_set;
  int32_t copy_as_uid;
  int32_t copy_as_gid;

  // Phase 5: --trust-sender
  /* Long-form-only, receiver-local policy.  rsync's --trust-sender tells the
   * receiving side to trust that the sender already produced a sane file list,
   * relaxing the receiver's own up-front re-validation of every incoming path.
   * In FastSync the receiver normally double-checks each transmitted file-list
   * entry (empty / ".." path-traversal rejection) and refuses to materialize a
   * symlink whose target could escape the receive root.  When trust_sender is
   * set, those redundant list-level re-checks are SKIPPED: the receiving side
   * trusts the sender's list instead of re-validating it (fewer checks, faster,
   * potentially unsafe, matching rsync).  It is a LOCAL receiver policy and is
   * NEVER serialized into the config frame (it exists only on the process that
   * actually receives the file list).  Even under trust_sender the low-level
   * fd-relative confinement primitives (file_open_secure_parent, the O_NOFOLLOW
   * parent walk, leaf/destination confinement) are deliberately KEPT as a hard
   * floor, so a hostile sender still cannot write or link outside the
   * authorized root (see the phase-5 notes in RSYNC_COMPAT.md).  Off by
   * default; only relaxes validation when explicitly requested. */
  bool trust_sender;

  // Phase 6: --stop-after / --stop-at
  /* Client-only sender-side transfer stop deadlines.  --stop-after=MINS stops
   * the transfer after a number of elapsed minutes (checked against
   * CLOCK_MONOTONIC so clock changes do not skew it); --stop-at=TIME stops at
   * an absolute wall-clock time (HH:MM, HH:MM:SS, or now+N[smhd]).  At the
   * deadline the run stops elegantly at the next chunk/file boundary and the
   * completion tail still runs (exit 0).  Both are LOCAL to the sending
   * process and are NEVER serialized into the config frame. */
  int stop_after_mins; /* --stop-after=MINS minutes; 0 when unset */
  time_t stop_at;      /* --stop-at=... absolute wall-clock deadline */
  bool stop_at_set;    /* true when --stop-at was given */

  // Phase 6: --write-batch / --only-write-batch / --read-batch
  /* Client-only residual-batch paths.  A residual batch is a self-contained
   * single-file record of the whole source tree (full file images using the
   * chunk codec), independent of any live server.  --write-batch=FILE runs the
   * normal live transfer AND additionally emits the batch FILE;
   * --only-write-batch=FILE emits FILE only (no destination, no server);
   * --read-batch=FILE applies FILE to the destination (no source, no server).
   * All three are LOCAL to the driving process and are NEVER serialized into
   * the config frame (the batch paths bypass the transport entirely). */
  char* write_batch;      /* --write-batch=FILE path, or NULL */
  char* only_write_batch; /* --only-write-batch=FILE path, or NULL */
  char* read_batch;       /* --read-batch=FILE path, or NULL */
} Config;

/* Phase 5 (remote-option wave): 2.13.0 -> 2.14.0.
 *
 * WHY the bump, grounded in the wire: the binary config-frame layout is
 * UNCHANGED by this wave (neither --remote-option nor --trust-sender adds a
 * serialized field; see the field comments above).  --remote-option is
 * forwarded to the remote server over the SSH remote-command line
 * (ssh_build_remote_command) and --trust-sender is a purely local receiver
 * policy, so there is no new frame byte to negotiate.  The bump is still the
 * correct release marker for Phase 5 because the client-to-server INVOCATION
 * surface changed: a client that composes remote-options expects a server that
 * knows how to honor them, and the only safe way to express "this feature set
 * is one coordinated release" is the strict same-version handshake FastSync
 * already performs for every release.  A 2.14 client against a 2.13 server
 * fails the version check cleanly up front (rather than the remote server
 * rejecting an unfamiliar forwarded argv at a confusing later point), which is
 * exactly what the lockstep convention of this project requires. */
/* Daemon Wave A: 2.14.0 -> 2.15.0.
 *
 * WHY the bump, grounded in the wire: this wave really does add a serialized
 * field to the binary config frame.  The client sends its requested daemon
 * module name (Config->module) as a new trailing string on the frame (sent
 * after the Phase-4 xattr block and before the STATUS_OK/STATUS_ERROR ack, in
 * config_send/config_receive), and the daemon reads it to select which module
 * root confines the connection.  Any config-frame layout change must bump the
 * protocol version because a peer that does not parse the new trailing bytes
 * would desynchronize on the frame boundary; the strict same-version handshake
 * (config_receive rejects a mismatched version before parsing anything else)
 * is what keeps a 2.15 client and a 2.14 server from ever reaching that state.
 *
 * NOTE: daemon module-selection bump owned by Wave A (2.15.0); later daemon
 * waves (auth, motd) must not bump PROTOCOL_VERSION.  Wave B (auth) added the
 * credential fields (auth_user + password digest) as further trailing
 * config-frame strings AFTER the Wave A module string, with a presence int
 * prefix.  This is not a new frame version: sender and receiver of a 2.15.0
 * build always read and write the same full layout (the strict same-version
 * handshake rejects any other version before a byte of the frame is parsed),
 * so a peer can never desynchronize on the added tail.  The 2.15.0 release
 * ships Wave A + Wave B together; the bump stays owned by Wave A.
 *
 * Wave C (MOTD) adds NO config-frame field and no version bump either.  On the
 * daemon listener path only, the server sends one MOTD string frame AFTER the
 * config-frame STATUS_OK (server.c handler), and every 2.15.0 daemon client
 * reads that frame right after the ack (client_send.c) -- symmetric
 * server->client in every build, so the strict same-version handshake keeps the
 * two peers in lockstep and nothing can desynchronize.  The --stdio SSH path
 * sends/reads no MOTD at all.
 *
 * --iconv Wave (P6): 2.15.0 -> 2.16.0.
 *
 * WHY the bump, grounded in the wire: the --iconv feature adds a serialized
 * field to the binary config frame.  The client sends the full CONVERT_SPEC
 * (Config->iconv_spec) as a new trailing string AFTER the Wave A/B daemon-auth
 * block (in config_send/config_receive), so the receiver knows the wire charset
 * (the REMOTE half) before the first file name arrives.  Any config-frame
 * layout change must bump the protocol version: a peer that does not parse the
 * new trailing bytes would desynchronize on the frame boundary, and the strict
 * same-version handshake (config_receive rejects a mismatched version before
 * parsing anything else) is what keeps a 2.16 client and a 2.15 server from
 * ever reaching that state.
 *
 * Times Wave (P7 Wave D): 2.16.0 -> 2.17.0.
 *
 * WHY the bump, grounded in the wire: this wave makes -O/--omit-dir-times and
 * -J/--omit-link-times REAL by adding directory and symlink time preservation.
 * The config-frame LAYOUT is unchanged (the omit flags already crossed the
 * wire), but the FRAME STREAM gains a new terminal frame: after all file data
 * and the optional delete manifest, the sender transmits STATUS_DIR_TIMES
 * frame(s) (each a count followed by (path, metadata) pairs, chunked so no
 * frame exceeds the receiver's MAX_MANIFEST_ENTRIES bound) carrying every
 * source directory's captured times, so the receiver can apply them AFTER all of a
 * directory's children have been written (writing a child bumps the parent's
 * mtime).  Symlink entries already carry their metadata on the STATUS_SYMLINK
 * frame; the receiver now applies it (utimensat/lchown with
 * AT_SYMLINK_NOFOLLOW) unless -J is set.  Any change to the frame sequence must
 * bump the protocol version: a 2.16 peer that does not know STATUS_DIR_TIMES
 * would desynchronize on the unknown frame, and the strict same-version
 * handshake (config_receive rejects a mismatched version before parsing
 * anything else) is what keeps a 2.17 client and a 2.16 server from ever
 * reaching that state.
 *
 * Privilege Wave (P7 Wave E): 2.17.0 -> 2.18.0.
 *
 * WHY the bump, grounded in the wire: this wave adds the receiver-side
 * privilege flags --super/--no-super and --copy-as=USER[:GROUP].  The
 * config-frame layout gains two new trailing blocks AFTER the --iconv
 * CONVERT_SPEC string, in this fixed order: (1) send_privilege_options /
 * receive_privilege_options send one int (Config->super_mode, 0..2), then
 * (2) send_copy_as_options / receive_copy_as_options send a presence int and,
 * when set, the target uid and gid (both int32).  The receiver uses
 * super_mode to decide whether it may attempt super-user activities
 * (ownership application, char/block device-node creation) already confined
 * below the authorized receive root, and the copy-as ids to force the
 * ownership of every entry it writes (the safe-subset --copy-as model).  The
 * receiver REQUIRES privilege for copy-as: an unprivileged receiver refuses
 * the transfer at the config handshake (server_module_gate) instead of silently
 * ignoring the flag.  Any config-frame layout change must bump the protocol
 * version: a peer that does not parse the new trailing bytes would
 * desynchronize on the frame boundary, and the strict same-version handshake
 * (config_receive rejects a mismatched version before parsing anything else) is
 * what keeps a 2.18 client and a 2.17 server from ever reaching that state.
 * --super never elevates privileges; it only permits a confined attempt, and
 * --copy-as never switches process credentials (see RSYNC_COMPAT.md).
 *
 * A7 Auth Wave: 2.18.0 -> 2.19.0.
 *
 * WHY the bump, grounded in the wire: the daemon auth block on the config frame
 * loses the hard-wired password digest (it becomes `[int present][str_redacted
 * username]`), and the frame stream gains the SCRAM challenge/response
 * (STATUS_AUTH_CHALLENGE -> STATUS_AUTH_RESPONSE -> STATUS_AUTH_OK) between the
 * config frame and the STATUS_OK ack.  A 2.18 peer would desynchronize on both
 * the shorter auth block and the new status frames, so the strict same-version
 * handshake (config_receive rejects a mismatched version before parsing
 * anything else) is what keeps a 2.19 client and a 2.18 server from ever
 * reaching that state.  SECURITY: a 2.19 store holds a salted PBKDF2 verifier
 * and cannot verify (and refuses to load) a legacy unsalted-SHA-256 store line,
 * so an old bearer digest can never be replayed against a 2.19 daemon.
 *
 * Packed Metadata Wave: 2.19.0 -> 2.20.0.
 *
 * WHY the bump: metadata_send()/metadata_receive() no longer emit/consume the
 * metadata as up to 12 separate per-field writes.  A file's metadata now
 * crosses the wire as ONE packed frame: a single int32 present flag (0 =
 * absent, 1 = present) followed, when present, by the fixed
 * FILE_METADATA_WIRE_SIZE-byte (68-byte) field record produced by
 * metadata_to_buf().  Protocol data is an unframed byte stream, so the packed
 * encoding is byte-for-byte identical to the old field-by-field writes (same
 * fields, same order, same widths); the change only removes per-field syscalls.
 * The bump is therefore a deliberate lockstep-release marker, not a
 * desynchronization fix — the strict same-version handshake still rejects a
 * mixed 2.19/2.20 deployment.  The chunk codec, which already used the packed
 * metadata_to_buf()/metadata_from_buf() form, is unchanged. */
#define PROTOCOL_VERSION "2.20.0"
#define DEFAULT_CHUNK_SIZE (10 * 1024 * 1024)
/* Upper bound on total basis-dir entries (rsync caps --link-dest at 20). */
#define MAX_BASIS_DIRS 64

/* Upper bound on the number of --skip-compress suffixes accepted from the wire.
 * Each suffix is an independent wire string (up to MAX_STRING_SIZE = 64 KiB), so
 * without this a hostile pre-auth client could otherwise retain
 * skip_count * MAX_STRING_SIZE bytes on the server before authentication; 256
 * covers any realistic suffix list while keeping the worst case small. */
#define MAX_SKIP_COMPRESS_SUFFIXES 256

/* Aggregate ceiling on the bytes retained by ALL strings in one received config
 * frame (version, send/receive roots, backup/temp/partial/suffix, compression
 * choice, chmod spec, skip-compress suffixes, basis paths, module, auth user,
 * iconv spec, ...).  The config frame is parsed BEFORE authentication and every
 * one of these strings lives for the whole connection, so this cumulative
 * (never released) budget bounds the pre-auth memory a single connection can
 * pin.  MAX_SKIP_COMPRESS_SUFFIXES / MAX_BASIS_DIRS bound the individual
 * repeatable counts; this budget bounds their product and any single oversized
 * field. */
#define MAX_CONFIG_STRING_BYTES (1ULL * 1024 * 1024)

/* Identity-mapping sentinels and bounds (see identity.h for semantics).
 * IDENTITY_MATCH_ANY is a usermap/groupmap FROM '*' (matches any id);
 * IDENTITY_CURRENT is a chown / map TO '*' (resolve to the receiver's current
 * euid/egid at apply time). */
#define IDENTITY_MATCH_ANY (-1)
#define IDENTITY_CURRENT (-1)
#define MAX_IDENTITY_MAP 128

Config* config_create(void);
void config_delete(Config* config);

/* Wipe the client-side plaintext auth password (and username) from a Config
 * before it is freed or handed off.  Safe on a NULL/empty Config and idempotent
 * (it clears the pointers after burning).  config_delete calls this
 * automatically; a caller that drops a Config earlier may call it explicitly. */
void config_burn_auth(Config* config);

bool config_send(int file_descriptor, const Config* config);
Config* config_receive(int file_descriptor);
bool config_is_remote_dest(const char* s);
void config_parse_ssh_dest(Config* config);

/* A ConfigValidateFunc may return this sentinel to tell
 * config_receive_with_validate that the callback ALREADY sent a terminal status
 * frame (e.g. STATUS_AUTH_FAILED, then closed) and the frame must be abandoned
 * without an additional STATUS_ERROR.  A normal rejection returns a message
 * string (logged, then STATUS_ERROR); NULL accepts. */
#define CONFIG_VALIDATE_ALREADY_TERMINATED ((const char*)-1)

/* Server-side config-frame gate (daemon module selection, Wave A).  A server
 * that needs to make an accept/reject decision about a received Config BEFORE
 * it sends the STATUS_OK ack (so a rejected connection is refused cleanly with
 * no data transferred) passes a callback here; it runs after the frame parses
 * and validates but before the STATUS_OK/STATUS_ERROR ack.  Return NULL to
 * accept the connection; return a non-NULL message to reject it (the message
 * is logged server-side and STATUS_ERROR is sent in place of STATUS_OK), or the
 * CONFIG_VALIDATE_ALREADY_TERMINATED sentinel when the callback already sent
 * its own terminal status.  The callback runs in the connection's own process,
 * so it may set up per-module process state (e.g. the authorized root) and
 * drive the daemon auth handshake.  context is an opaque caller pointer. */
typedef const char* (*ConfigValidateFunc)(const Config* config, void* context);
Config* config_receive_with_validate(int file_descriptor, ConfigValidateFunc validate,
                                     void* context);

/* Daemon-destination (host::module[/path]) helpers, Wave A.  config_is_remote_dest
 * recognizes the ordinary rsync-style single-colon host:path form used by the
 * SSH transport; config_is_daemon_dest recognizes the double-colon form that
 * selects a daemon module over TCP.  config_parse_transport_dest is the single
 * entry point main() uses: it parses a :: destination as a daemon TCP
 * destination (host -> server_host, module -> config->module, path ->
 * receive_root_directory) and otherwise falls back to the existing SSH
 * host:path handling. */
bool config_is_daemon_dest(const char* s);
/* Returns 1 when the destination was daemon syntax and was parsed, 0 when it
 * is not daemon syntax (nothing changed), -1 on an invalid daemon destination
 * (a message is logged and config is left untouched). */
int config_parse_daemon_dest(Config* config);
/* Returns 1/0/-1 mirroring config_parse_daemon_dest when the destination is
 * daemon syntax; otherwise runs the existing SSH host:path parse and returns
 * 0. */
int config_parse_transport_dest(Config* config);

/* True when the negotiated delete timing performs the extra-file deletion
 * BEFORE the transfer data (--delete-before / --delete-during).  The flag is
 * a pure function of the config and is used identically on the sender (to pick
 * the manifest-first frame order) and the receiver (to delete when the early
 * manifest arrives).  When false the deletion is committed only after the whole
 * transfer succeeded (--delete / --delete-after / --delete-delay). */
bool config_delete_timing_early(const Config* config);
/* Delete-timing sanity: with deletion enabled at most one timing flag may be
 * set (none = the default delete-after commit timing); without deletion no
 * timing flag may be set (each timing flag implies --delete). */
bool config_has_valid_delete_timing(const Config* config);

/* Single source of truth for the cross-field ("combination") invariants a
 * Config must satisfy.  Returns NULL when `config` is consistent, or a static,
 * human-readable error string (no trailing period) describing the FIRST
 * violation found.  No I/O, no logging and no printing, so it is safe to call
 * from every trust boundary; the iconv rule does invoke charset_spec_valid
 * (which parses via str_dup/iconv_open), so it is not allocation-free.  The client calls
 * it from validate_config() for up-front UX and the server calls it from
 * validate_received_config() so the receiver enforces exactly the same
 * invariants it relies on (the server is the trust boundary). */
const char* config_invariants_error(const Config* config);
/* True when at least one --compare-dest/--copy-dest/--link-dest was set. */
bool config_has_basis(const Config* config);
/* Append one basis-dir entry. Returns 0 on success, -1 on allocation failure. */
int config_basis_append(Config* config, BasisDestType type, const char* path);
/* Validate a client-provided basis-dir path (relative, confined, non-empty). */
bool config_basis_path_valid(const char* path);

/* Parse and validate a --sockopts=OPTIONS comma-separated "OPT=VAL" list into a
 * malloc'd array of at most *out_count entries.  Returns 0 on success (the
 * caller takes ownership of *out), or -1 on the first invalid option name or
 * value.  Pure/static-analysis friendly: performs no socket calls, so it is
 * directly unit-testable. */
int config_sockopts_parse(const char* spec, SockOptEntry** out, int* out_count);

#endif
