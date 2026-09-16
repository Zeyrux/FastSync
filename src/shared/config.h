#ifndef CONFIG_H
#define CONFIG_H

#include "array_list.h"
#include "checksum.h"
#include "compression.h"
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

/* One FROM:TO identity-mapping rule (--usermap / --groupmap).  `from`/`from_hi`
 * describe the sender-side FROM matcher (a single id when from_hi == from, an
 * inclusive LOW-HIGH range, IDENTITY_MATCH_ANY for rsync's '*', or
 * IDENTITY_MATCH_UNNAMED for rsync's empty FROM).  `to` is the receiver-side TO
 * numeric id (IDENTITY_CURRENT = the receiving process's own euid/egid) UNLESS
 * `to_name` is non-NULL, in which case the receiver resolves the name against
 * its own account database at apply time (rsync resolves TO names on the
 * receiver) and `to` is ignored.  FROM names/ranges/globs are resolved on the
 * client (the sender) exactly as rsync matches them against sender names. */
typedef struct {
  int32_t from;
  int32_t from_hi;
  int32_t to;
  char* to_name;
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

/* ===========================================================================
 * Config wire-field table (single source of truth for protocol 2.26.0).
 *
 * Every field below crosses the wire.  The table is the ONLY place a
 * serialized field is named: config.h expands CONFIG_WIRE_FIELDS() to declare
 * the struct member, config_set_defaults() expands it to assign the default,
 * and config_send_wire_block()/config_receive_with_validate() expand the
 * per-segment lists to emit/consume the frame in exactly this order.  Do NOT
 * reorder entries and do NOT change a field's segment/KIND without a
 * PROTOCOL_VERSION bump: the resulting byte stream is pinned by
 * test_config_wire_golden().
 *
 * Entry layout: X(MEMBER, CTYPE, DEFAULT, KIND)
 *   MEMBER   struct member name (public; never rename)
 *   CTYPE    C type of the member
 *   DEFAULT  default-value expression used by config_set_defaults()
 *   KIND     wire codec, dispatched to CONFIG_SEND_<KIND>/CONFIG_RECV_<KIND>
 *            in config.c (strings receive through a ConfigStringBudget).
 *
 * Fields with genuinely custom logic keep dedicated helpers but are still
 * declared here exactly once: the protocol-version handshake (HEADER), the
 * daemon SCRAM auth username (STR_REDACTED_AUTH), the daemon module name
 * (STR_MODULE), repeated count+array blocks (BLOCK_*), --copy-as presence
 * (COPY_AS_*), and the derived --delta / use_xattrs bits (DERIVED_DELTA,
 * BOOL_XATTR_DERIVE).
 *
 * SCOPE: this table covers ONLY the serialized wire frame.  The client CLI
 * option tables in client_cli.c (OPTION_TABLE / NEGATABLE_OPTIONS) are still
 * hand-maintained and are deliberately NOT generated from this table: the CLI
 * surface carries client-only fields and flag/alias/negation semantics that
 * have no wire representation.  Do not assume the two are folded together.
 * =========================================================================== */
#define CONFIG_WIRE_HEADER_FIELDS(X) X(version, char*, str_dup(PROTOCOL_VERSION), STR)

/* dry_run (--dry-run) is CLIENT-INTENT that now CROSSES the wire (protocol
 * 2.21.0): the receiver needs it to answer what WOULD transfer/skip without
 * touching disk.  The client-only launch behavior (no server contact for a
 * local destination) is decided separately in client_send.c before the frame
 * is ever sent. */
#define CONFIG_WIRE_CORE_FIELDS(X)                                                                 \
  X(eight_bit_output, bool, false, BOOL_8BIT)                                                      \
  X(max_alloc, unsigned long long, DEFAULT_MAX_ALLOC, RAW_MAXALLOC)                                \
  X(send_directory, char*, NULL, STR)                                                              \
  X(receive_root_directory, char*, NULL, STR)                                                      \
  X(save_to_disk, bool, false, BOOL)                                                               \
  X(use_multithreading, bool, false, BOOL)                                                         \
  X(use_chunk_serialization, bool, false, BOOL)                                                    \
  X(use_compression, bool, false, BOOL)                                                            \
  X(use_metadata, bool, false, BOOL)                                                               \
  X(use_executability, bool, false, BOOL)                                                          \
  X(compression_level, int, 5, INT)                                                                \
  X(chunk_size, unsigned long long, DEFAULT_CHUNK_SIZE, RAW)                                       \
  X(use_sendfile, bool, false, BOOL)                                                               \
  X(dry_run, bool, false, BOOL)

#define CONFIG_WIRE_DELTA_FIELDS(X)                                                                \
  X(use_delete, bool, false, BOOL)                                                                 \
  X(use_incremental, bool, false, BOOL)                                                            \
  X(size_only, bool, false, BOOL)                                                                  \
  X(ignore_times, bool, false, BOOL)                                                               \
  X(use_delta, bool, false, DERIVED_DELTA)                                                         \
  X(delta_block_size, uint32_t, DELTA_BLOCK_SIZE_DEFAULT, RAW)                                     \
  X(delta_max_file_size, unsigned long long, DELTA_MAX_FILE_SIZE, RAW)

#define CONFIG_WIRE_FILE_OPTIONS_FIELDS(X)                                                         \
  X(backup, bool, false, BOOL)                                                                     \
  X(backup_dir, char*, NULL, STR_OPT)                                                              \
  X(remove_source_files, bool, false, BOOL)                                                        \
  X(follow_symlinks, bool, false, BOOL)                                                            \
  X(copy_links, bool, false, BOOL)                                                                 \
  X(safe_links, bool, false, BOOL)                                                                 \
  X(copy_unsafe_links, bool, false, BOOL)                                                          \
  X(preserve_hard_links, bool, false, BOOL)                                                        \
  X(preserve_acls, bool, false, BOOL)                                                              \
  X(preserve_xattrs, bool, false, BOOL)                                                            \
  X(preserve_devices, bool, false, BOOL)                                                           \
  X(preserve_sparse, bool, false, BOOL)                                                            \
  X(preserve_specials, bool, false, BOOL)                                                          \
  X(copy_devices, bool, false, BOOL)                                                               \
  X(write_devices, bool, false, BOOL)

#define CONFIG_WIRE_SELECTION_FIELDS(X)                                                            \
  X(ignore_existing, bool, false, BOOL)                                                            \
  X(existing, bool, false, BOOL)                                                                   \
  X(update, bool, false, BOOL)                                                                     \
  X(inplace, bool, false, BOOL)                                                                    \
  X(delay_updates, bool, false, BOOL)                                                              \
  X(append, bool, false, BOOL)                                                                     \
  X(use_fsync, bool, false, BOOL)                                                                  \
  X(append_verify, bool, false, BOOL)                                                              \
  X(delete_excluded, bool, false, BOOL)                                                            \
  X(force_delete, bool, false, BOOL)                                                               \
  X(delete_missing_args, bool, false, BOOL)                                                        \
  X(delete_after, bool, false, BOOL)                                                               \
  X(preallocate, bool, false, BOOL)                                                                \
  X(max_delete, int, -1, RAW)                                                                      \
  X(relative, bool, false, BOOL)                                                                   \
  X(prune_empty_dirs, bool, false, BOOL)                                                           \
  X(mkpath, bool, false, BOOL)                                                                     \
  X(delete_during, bool, false, BOOL)                                                              \
  X(delete_delay, bool, false, BOOL)

#define CONFIG_WIRE_RESUME_FIELDS(X)                                                               \
  X(temp_dir, char*, NULL, STR_OPT)                                                                \
  X(partial, bool, false, BOOL)                                                                    \
  X(partial_dir, char*, NULL, STR_OPT)                                                             \
  X(suffix, char*, NULL, STR_OPT)                                                                  \
  X(delete_before, bool, false, BOOL)                                                              \
  X(checksum, bool, false, BOOL)                                                                   \
  X(modify_window, int, 0, RAW)                                                                    \
  X(compress_choice, char*, NULL, STR_KEEP)                                                        \
  X(chmod_spec, char*, NULL, STR_KEEP)                                                             \
  X(skip_compress_set, bool, false, BOOL)                                                          \
  X(skip_compress_count, int, 0, INT_SKIPCOUNT)                                                    \
  X(skip_compress_suffixes, char**, NULL, BLOCK_SKIP_SUFFIXES)

#define CONFIG_WIRE_BASIS_FIELDS(X)                                                                \
  X(basis_count, int, 0, INT_BASISCOUNT)                                                           \
  X(basis_dirs, BasisDest*, NULL, BLOCK_BASIS)

#define CONFIG_WIRE_FUZZY_FIELDS(X) X(fuzzy, bool, false, BOOL)

#define CONFIG_WIRE_CHECKSUM_FIELDS(X)                                                             \
  X(checksum_algo, int, CHECKSUM_ALGO_DEFAULT, INT_CHECKSUM_ALGO)                                  \
  X(checksum_seed, uint64_t, 0, RAW)

#define CONFIG_WIRE_IDENTITY_FIELDS(X)                                                             \
  X(numeric_ids, bool, false, BOOL)                                                                \
  X(chown_uid_set, bool, false, BOOL)                                                              \
  X(chown_uid, int32_t, 0, INT_IDENTITY)                                                           \
  X(chown_gid_set, bool, false, BOOL)                                                              \
  X(chown_gid, int32_t, 0, INT_IDENTITY)                                                           \
  X(usermap_count, int, 0, INT_IDMAPCOUNT)                                                         \
  X(usermap, IdentityMap*, NULL, BLOCK_IDMAP)                                                      \
  X(groupmap_count, int, 0, INT_IDMAPCOUNT)                                                        \
  X(groupmap, IdentityMap*, NULL, BLOCK_IDMAP)

#define CONFIG_WIRE_METADATA_TIMES_FIELDS(X)                                                       \
  X(preserve_atimes, bool, false, BOOL)                                                            \
  X(preserve_crtimes, bool, false, BOOL)                                                           \
  X(omit_dir_times, bool, false, BOOL)                                                             \
  X(omit_link_times, bool, false, BOOL)                                                            \
  X(preserve_perms, bool, false, BOOL)                                                             \
  X(preserve_times, bool, false, BOOL)                                                             \
  X(preserve_owner, bool, false, BOOL)                                                             \
  X(preserve_group, bool, false, BOOL)

#define CONFIG_WIRE_SYMLINK_TRUST_FIELDS(X)                                                        \
  X(munge_links, bool, false, BOOL)                                                                \
  X(keep_dirlinks, bool, false, BOOL)

#define CONFIG_WIRE_XATTR_FIELDS(X) X(fake_super, bool, false, BOOL_XATTR_DERIVE)

#define CONFIG_WIRE_MODULE_FIELDS(X) X(module, char*, NULL, STR_MODULE)

#define CONFIG_WIRE_DAEMON_AUTH_FIELDS(X) X(auth_user, char*, NULL, STR_REDACTED_AUTH)

#define CONFIG_WIRE_ICONV_FIELDS(X) X(iconv_spec, char*, NULL, STR_OPT)

#define CONFIG_WIRE_PRIVILEGE_FIELDS(X) X(super_mode, SuperMode, SUPER_MODE_AUTO, SUPERMODE)

#define CONFIG_WIRE_COPY_AS_FIELDS(X)                                                              \
  X(copy_as_set, bool, false, COPY_AS_PRESENCE)                                                    \
  X(copy_as_uid, int32_t, 0, COPY_AS_ID)                                                           \
  X(copy_as_gid, int32_t, 0, COPY_AS_ID)

/* Output-parity wave (protocol 2.23.0).  report_dest_info tells the receiver to
 * answer every per-file STATUS_CHECK with a STATUS_DEST_INFO snapshot of the
 * pre-transfer destination entry (see protocol.h).  It is set by the client
 * only when -i/--itemize-changes or --out-format asks for per-file change
 * output; the transfer decision itself is unchanged. */
#define CONFIG_WIRE_OUTPUT_FIELDS(X) X(report_dest_info, bool, false, BOOL)

/* Codec-negotiation wave (protocol 2.26.0).  compression_algo is the concrete
 * codec the client selected for this transfer (a CompressionAlgo id) and is the
 * value the receiver validates and installs.  It is the resolved result of
 * --compress-choice / the "auto" negotiation so both peers agree exactly.
 *
 * Negotiation model: FastSync enforces a strict same-version handshake, so both
 * peers carry the identical compiled-in codec set.  The client resolves the
 * effective algorithm deterministically and serializes it here; "auto" picks
 * the first entry of the rsync 3.4.1 preference order
 * (compression: zstd lz4 zlibx zlib none; checksum: xxh128 xxh3 xxh64 md5 md4
 * sha1 none), and an explicit request wins.  The receiver rejects (before
 * STATUS_OK) any algorithm outside its own supported set, which is rsync's
 * "no common choice is an error" behavior.  The same resolver runs on both
 * sides (compression_negotiate_default / checksum_negotiate_default), so the
 * fallback is consistent.
 *
 * The field is appended after the output block so every pre-2.26 field keeps
 * its wire position. */
#define CONFIG_WIRE_CODEC_FIELDS(X)                                                                \
  X(compression_algo, int, COMPRESSION_ALGO_ZSTD, INT_COMPRESSION_ALGO)

/* All serialized fields, in exact wire order.  Concatenating the per-segment
 * lists here is what keeps the declaration order = the wire order. */
#define CONFIG_WIRE_FIELDS(X)                                                                      \
  CONFIG_WIRE_HEADER_FIELDS(X)                                                                     \
  CONFIG_WIRE_CORE_FIELDS(X)                                                                       \
  CONFIG_WIRE_DELTA_FIELDS(X)                                                                      \
  CONFIG_WIRE_FILE_OPTIONS_FIELDS(X)                                                               \
  CONFIG_WIRE_SELECTION_FIELDS(X)                                                                  \
  CONFIG_WIRE_RESUME_FIELDS(X)                                                                     \
  CONFIG_WIRE_BASIS_FIELDS(X)                                                                      \
  CONFIG_WIRE_FUZZY_FIELDS(X)                                                                      \
  CONFIG_WIRE_CHECKSUM_FIELDS(X)                                                                   \
  CONFIG_WIRE_IDENTITY_FIELDS(X)                                                                   \
  CONFIG_WIRE_METADATA_TIMES_FIELDS(X)                                                             \
  CONFIG_WIRE_SYMLINK_TRUST_FIELDS(X)                                                              \
  CONFIG_WIRE_XATTR_FIELDS(X)                                                                      \
  CONFIG_WIRE_MODULE_FIELDS(X)                                                                     \
  CONFIG_WIRE_DAEMON_AUTH_FIELDS(X)                                                                \
  CONFIG_WIRE_ICONV_FIELDS(X)                                                                      \
  CONFIG_WIRE_PRIVILEGE_FIELDS(X)                                                                  \
  CONFIG_WIRE_COPY_AS_FIELDS(X)                                                                    \
  CONFIG_WIRE_OUTPUT_FIELDS(X)                                                                     \
  CONFIG_WIRE_CODEC_FIELDS(X)

typedef struct Config {
  /* -j/--threads=N: number of parallel scanner worker threads for the -m
   * pipeline.  0 (the default, also set by bare -j/--threads) means "use the
   * scanner's built-in default" (4).  CLIENT-ONLY: it is a local scheduling
   * concern and is NEVER serialized into the wire config frame. */
  int scanner_threads;
  bool metadata_explicitly_disabled;
  /* CLIENT-ONLY (never serialized; not in CONFIG_WIRE_FIELDS).  Set when the
   * user explicitly turned an attribute off with --no-perms / --no-times (long
   * or short form).  --incremental/--delta historically auto-enabled mode and
   * mtime preservation; these flags let cli_finalize_config restore that
   * behavior while still honoring the explicit per-attribute negation.  A
   * later -p/-t re-enables the attribute directly, so the flag only prevents
   * the incremental/delta implication, never a POSITIVE request. */
  bool preserve_perms_explicit_off;
  bool preserve_times_explicit_off;
  bool show_progress;
  int compression_threads;
  int ssh_port;
  TransportType transport;
  char* ssh_destination;
  char* auth_password;
  /* Client-only path of --password-file (never crosses the wire; it is read to
   * populate auth_user/auth_password before connecting). */
  char* password_file;
  char* fastsync_server_path;
  char** exclude_patterns;
  int exclude_count;
  char** include_patterns;
  int include_count;
  unsigned long long max_size;
  unsigned long long min_size;
  bool whole_file;
  bool use_tls;
  char* server_host;
  int server_port;
  /* True when --server-port/--port was explicitly given.  CLIENT-ONLY (never
   * serialized): --dry-run uses it to decide whether a real server handshake
   * was requested, so a plain local destination (no explicit port) keeps the
   * existing client-side dry-run behavior instead of dialing the default
   * 127.0.0.1:8080. */
  bool server_port_set;
  /* True when --server-host was explicitly given.  CLIENT-ONLY (never
   * serialized), and distinct from the "127.0.0.1" default: --dry-run uses it
   * to route an explicit remote target to the server so it reports receiver
   * state exactly like a real run, instead of silently running the client-side
   * manifest. */
  bool server_host_set;
  char* tls_cert;
  char* tls_key;
  char* tls_ca;
  /* --timeout: per-message I/O deadline in seconds.  0 (rsync's default)
   * disables the deadline entirely on the client's own socket and protocol
   * layers; a positive value sets it.  A server session never inherits the
   * disabled value: it applies the SERVER_IO_TIMEOUT_SEC floor (see
   * protocol_server_io_timeout_sec and tcp_set_timeouts). */
  int timeout;
  /* --contimeout: connect()/accept timeout in seconds (rsync's default 60);
   * 0 disables it.  Transport layer only. */
  int contimeout;
  bool quiet;
  bool stats;
  int max_depth;
  FILE* log_file;

  /* Phase 4 symlink-trust.  -k/--copy-dirlinks and --munge-links are
   * CLIENT/sender-side only (they decide how the SENDER scans and rewrites
   * symlinks; the receiver never reads them), so they never cross the wire.
   * -K/--keep-dirlinks is a RECEIVER-side policy (follow an in-root destination
   * symlink-to-directory as a directory) and CROSSES the wire along with
   * --munge-links (so the receiver knows to unmunge). */
  bool copy_dirlinks; /* client-only, sender-side (-k) */

  // Issue #122: Output/logging options
  bool itemize_changes;
  char* out_format;
  char* log_file_format;
  int info_level;
  int debug_level;
  bool list_only;
  bool human_readable;

  /* --ignore-errors (client-only, never serialized): a sender-side source I/O
   * error (an unreadable directory during the scan) normally aborts the run so
   * no deletion happens; with --ignore-errors the scan continues and the
   * (partial) keep-set is still transmitted so the deletion runs. */
  bool ignore_errors;
  /* --ignore-missing-args (client-only, never serialized): a --files-from
   * entry that does not exist under the source is silently skipped instead of
   * failing the run.  Sender-side only: nothing is sent for it and it never
   * enters the keep-set.  Implied by --delete-missing-args. */
  bool ignore_missing_args;

  /* Codec-negotiation CLI state (all client-only, never serialized).  The
   * effective pre-transfer checksum is Config->checksum_algo (serialized);
   * checksum_transfer_algo is the rsync "transfer" half of a two-name
   * --checksum-choice form (validated and used only to mirror rsync's
   * whole-file forcing, since FastSync's per-block strong hash is fixed).
   * cli_exit_code carries a parser-requested process exit status (rsync uses 4
   * for an unsupported checksum/compress algorithm) so main() can mirror it. */
  int checksum_transfer_algo;
  int cli_exit_code;

  // Issue #129: Advanced file selection. These fields are CLIENT-ONLY: they are
  // never serialized to the wire (the receiver must not learn them).
  ArrayList* filters;   /* --filter=RULE rule strings, in order */
  char* files_from;     /* --files-from path (may be NULL) */
  void* files_from_set; /* parsed FileListSet* allow-set, or NULL */
  bool from0;           /* -0/--from0: NUL-delimited *-from files */
  bool cvs_exclude;     /* -C/--cvs-exclude: standard CVS ignore set */
  bool per_dir_filter;  /* -F: apply per-directory .rsync-filter files */
  bool one_file_system; /* -x/--one-file-system: do not cross filesystem boundaries */
  /* --no-implied-dirs: client-only.  With -R + --files-from, refuse to place a
   * listed file whose ancestor directory is not itself explicitly listed. */
  bool no_implied_dirs;
  /* -d/--dirs: client-only.  Transfer the directory entries named by the
   * source argument / --files-from list without recursing into contents. */
  bool dirs;

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
  /* --remote-option=OPT (Phase 5, long form only): one or more extra command-line
   * options to append to the REMOTE server invocation over SSH.  CLIENT-ONLY:
   * they are composed into the remote command line by ssh_build_remote_command()
   * (each valid word is shell-escaped with the same quoting boundary as the
   * server path), and are NEVER serialized into the binary config frame.  They
   * do NOT cross the wire and are never parsed on the receiver process. */
  char** remote_options;
  int remote_option_count;

  // PR #181: IPv6 and bind address
  char* address;
  bool ipv6;
  bool ipv4;
  /* --sockopts=OPTIONS (Phase 5, Wave B): strict allowlist of TCP/socket
   * options applied via setsockopt after socket() and before connect()/bind().
   * These are LOCAL socket concerns: they never cross the wire config frame.
   * .address is the outgoing/source bind address (--address). */
  SockOptEntry* sockopts;
  int sockopt_count;

  // PR #182: Daemon/server mode
  bool daemon;
  /* --no-motd (Wave C): CLIENT-ONLY, never crosses the wire.  Suppresses
   * DISPLAY of the daemon's MOTD; the daemon still sends the MOTD frame, so
   * the client reads and discards it to keep the stream in sync.  rsync's
   * --no-motd is likewise a client-side display switch.  Default false (the
   * MOTD is shown when a daemon offers one). */
  bool no_motd;

  // Receiver-side runtime staging registry for --delay-updates.  Never sent
  // over the wire and never set on the sender side.
  DelayUpdatesContext* delay_context;

  /* --open-noatime: CLIENT-ONLY (never crosses the wire).  The sender opens
   * source files with O_NOATIME so reading for transfer does not bump the
   * source access time. */
  bool open_noatime;

  /* true when preserve_xattrs || preserve_acls; the sender/receiver gate the
   * xattr wire block on this single flag. */
  bool use_xattrs;

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

  /* ===================================================================
   * Serialized wire fields.  Their members, defaults and send/receive
   * sequence are generated from the CONFIG_WIRE_*_FIELDS table above (the
   * single source of truth); they are declared here in exact wire order.
   * The per-field notes were moved here from their original positions and
   * are listed in wire order.
   * =================================================================== */
  /* copy_links */
  // Issue #120: Symlink handling
  /* preserve_hard_links */
  // Issue #121: Extended metadata preservation
  /* preserve_specials */
  /* Phase 4 special/devices: preserve special files (FIFOs, sockets) and device
   * nodes on the destination by recreating them (mknod/mkfifo) instead of
   * transferring content.  preserve_specials mirrors rsync --specials (the
   * special-file half of -D); preserve_devices mirrors --devices (the device
   * half of -D); both CROSS the wire so the receiver knows a special/device
   * entry must be recreated rather than written as a regular file. */
  /* copy_devices */
  /* --copy-devices: copy the CONTENT of a source device as an ordinary regular
   * file on the destination (rsync's non-privileged safe mode), instead of
   * recreating the device node.  CROSSES the wire (receiver treats the entry as
   * a regular file, which is the default, so this is belt-and-braces). */
  /* write_devices */
  /* --write-devices: write the received data directly INTO an existing device
   * node on the destination instead of creating a regular file.  Dangeroud;
   * see RSYNC_COMPAT.md for the tight gating.  CROSSES the wire. */
  /* existing */
  // Issue #127: Transfer modes
  /* delete_excluded */
  /* --delete-excluded: also delete destination entries that were excluded on
   * the source.  Default (off) matches rsync: excluded paths are protected from
   * deletion.  Crosses the wire (the sender encodes the choice by whether it
   * transmits a protected-prefix list with the keep-set manifest). */
  /* force_delete */
  /* --force (receiver-side): a regular file may replace a destination
   * directory by removing that (possibly non-empty, symlink-safe) directory
   * tree first, instead of failing the write.  Crosses the wire. */
  /* delete_missing_args */
  /* --delete-missing-args: implies --ignore-missing-args; additionally each
   * missing entry's destination mirror (computed like a present entry's wire
   * path) is deleted receiver-side.  Crosses the wire and is gated by the
   * server's --allow-delete policy like --delete.  rsync-parity: independent
   * of ordinary --delete processing (it does not imply --delete); a non-empty
   * directory mirror is only removed with --force or --delete in effect, and
   * the missing-args deletions are not counted toward --max-delete. */
  /* preallocate */
  /* --preallocate: allocates the destination file's full expected space up
   * front (before any data is written) so a transfer that would overflow disk
   * fails fast at allocation time and the file is laid out contiguously,
   * avoiding fragmentation.  Receiver-side, crosses the wire. */
  /* max_delete */
  /* --max-delete=NUM: the receiver refuses to delete more than NUM entries per
   * run (all-or-nothing: when the extras would exceed NUM nothing is removed and
   * the transfer fails with a distinct error).  -1 == no client limit (the
   * server hard bound MAX_SERVER_DELETE_COUNT still applies). */
  /* relative */
  /* -R/--relative: crosses the wire; with --files-from listed entries keep
   * their bare relative destination path (no source-root mirror prefix). */
  /* mkpath */
  /* --mkpath: crosses the wire.  Tells the server to create the destination
   * root directory (and missing leading components below its authorized root)
   * at connection start instead of requiring it to already exist. */
  /* delete_during */
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
  /* partial_dir */
  // PR #174: Partial transfer resumption
  /* suffix */
  // PR #178: Backup versioning
  /* delete_before */
  // PR #179: Delete policies
  /* checksum */
  // PR #183: Checksum comparison
  /* compress_choice */
  // PR #184: Compression algorithm negotiation
  /* basis_dirs */
  /* Alternate basis directories, ordered by command-line appearance.  Each
   * entry's type selects compare/copy/link behavior on an exact match.  These
   * cross the wire so the receiver can consult them; they are interpreted
   * relative to the destination root and confined there. */
  /* fuzzy */
  /* -y/--fuzzy: when a file must be transferred and the destination holds no
   * usable file at the exact path, the receiver may reuse a SIMILAR-named
   * existing regular file in the same destination directory as the delta
   * basis so the sender transmits only the differences.  Crosses the wire
   * (the receiver performs the candidate search); the CLI implies
   * --incremental + --delta because the similar-basis only matters on the
   * receiver-driven delta path.  Off by default. */
  /* checksum_algo / checksum_seed */
  /* --checksum-choice / --cc and --checksum-seed.  checksum_algo is the id of
   * the whole-file content-digest algorithm used by the per-file --incremental
   * handshake (sender computes it, receiver compares it to skip unchanged
   * files) and by the basis-dir content verification.  checksum_seed is passed
   * to xxHash64 (and to the delta block strong hash, low 32 bits); md5 has no
   * seed so it is ignored there.  Both cross the wire: the receiver MUST hash
   * the on-disk old file with the same algorithm and seed to reach a matching
   * digest. */
  /* munge_links / keep_dirlinks */
  /* Phase 4 symlink-trust: both cross the wire (the receiver unmunges symlink
   * targets and, with -K, follows an in-root destination symlink-to-directory);
   * -k/--copy-dirlinks is sender-only and is never serialized. */
  /* numeric_ids */
  /* --numeric-ids: a mapping MODIFIER only -- no name lookup, use the
   * transmitted numeric ids raw.  It does NOT by itself request ownership. */
  /* chown_uid_set */
  /* --chown USER (owner) override; IDENTITY_CURRENT = the receiver's euid. */
  /* chown_gid_set */
  /* --chown :GROUP (group) override; IDENTITY_CURRENT = the receiver's egid. */
  /* usermap */
  /* --usermap / --groupmap entries, in order (first match wins).  Each entry's
   * from/from_hi are a single id, an inclusive range, IDENTITY_MATCH_ANY ('*'),
   * or IDENTITY_MATCH_UNNAMED (empty FROM); to_name carries a receiver-resolved
   * TO name (rsync resolves TO names on the receiving side). */
  /* preserve_atimes */
  /* -U/--atimes: preserve source access times on the destination. */
  /* preserve_crtimes */
  /* -N/--crtimes: capture+transmit source birth time; see RSYNC_COMPAT for the
   * receiver not-applied divergence. */
  /* omit_dir_times */
  /* -O/--omit-dir-times: do not apply mtimes to directories. */
  /* omit_link_times */
  /* -J/--omit-link-times: do not apply times to symlinks. */
  /* preserve_perms */
  /* -p/--perms: preserve the source permission bits (mode).  One of the four
   * per-attribute preservation flags split out of the former single
   * use_metadata bundle; --chmod and -A/--acls also imply it. */
  /* preserve_times */
  /* -t/--times: preserve source modification times.  Split out of the former
   * use_metadata bundle; --preserve and -a/--archive imply it. */
  /* preserve_owner */
  /* -o/--owner: preserve the source owner (uid).  Split out of the former
   * use_metadata bundle; --usermap/--chown (and, when a uid is requested,
   * --copy-as) imply it.  Owner application still requires receiver privilege
   * and is gated separately by the identity flags. */
  /* preserve_group */
  /* -g/--group: preserve the source group (gid).  Split out of the former
   * use_metadata bundle; --groupmap/--chown (and, when a gid is requested,
   * --copy-as) imply it. */
  /* fake_super */
  /* --fake-super: receiver-only.  When set, each written file additionally gets
   * a reserved user.fastsync.stat xattr recording the RESOLVED uid/gid (the
   * source's own when no ownership request is active, else the --chown/--usermap
   * result) plus mode/mtime so a later privileged restore could re-apply them.
   * It NEVER real-chowns: the point is to record the source ownership on an
   * unprivileged receiver.  Crosses the wire. */
  /* module */
  /* Daemon module selection (Wave A, protocol 2.15.0).  Client-composed from a
   * host::module/path destination; NULL or "" means "no module" (the ordinary
   * standalone-server path).  Crosses the wire as a trailing config-frame
   * string so the daemon can look the module up in its own config and confine
   * the connection to the module's root (never a client-chosen root). */
  /* auth_user */
  /* Daemon password authentication (A7 remediation, protocol 2.19.0).
   * Client-composed from a --password-file whose first meaningful line is
   * `user:password`: the client sends ONLY the username in the config frame
   * (auth_user); the literal password is kept in auth_password CLIENT-SIDE for
   * the duration of the SCRAM challenge/response and is NEVER serialized.  Both
   * are NULL when the client has no credentials to present; a module WITHOUT
   * `auth users` stays open and the server ignores any credentials that do
   * arrive (the client sends them opportunistically and the server decides). */
  /* iconv_spec */
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
  /* super_mode */
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
   * privilege_super_permitted() and identity_explicit_ownership_requested() in
   * identity.h. */
  /* copy_as_set */
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

#define CONFIG_STRUCT_MEMBER(name, ctype, def, kind) ctype name;
  CONFIG_WIRE_FIELDS(CONFIG_STRUCT_MEMBER)
#undef CONFIG_STRUCT_MEMBER
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
 * metadata_to_buf()/metadata_from_buf() form, is unchanged.
 *
 * Error-Detail + Server-contacting Dry-run Wave: 2.20.0 -> 2.21.0.
 *
 * WHY the bump, grounded in the wire: this release combines two changes on the
 * same lockstep version.
 *
 * (1) Error detail: a server may now answer a rejected operation with
 * STATUS_ERROR_DETAIL followed by a bounded (<= MAX_ERROR_DETAIL_BYTES)
 * length-prefixed string instead of a bare STATUS_ERROR (see protocol.h).  The
 * config-frame LAYOUT is unchanged, but the FRAME STREAM gains a new framed
 * body after a status, so a 2.20 peer that does not consume it would
 * desynchronize on the following exchange.  receive_status() transparently maps
 * STATUS_ERROR_DETAIL back to STATUS_ERROR for every existing call site and
 * captures the reason into a thread-local buffer consulted via
 * protocol_last_error().
 *
 * (2) --dry-run: --dry-run now contacts the receiver and reports exactly what
 * WOULD change.  The binary config frame gains one serialized bool
 * (Config->dry_run) appended to CONFIG_WIRE_CORE_FIELDS after use_sendfile, and
 * the frame stream gains one terminal status (STATUS_DRY_RUN_TRANSFER) sent in
 * reply to a per-file STATUS_CHECK when the file is not already up to date.
 * The receiver performs the normal read-only incremental decision but no
 * mutation; the sender then skips the data.
 *
 * Any config-frame layout or frame-sequence change must bump the protocol
 * version: a 2.20 peer would desynchronize on the extra trailing byte, the
 * unknown status, or the unconsumed detail body, and the strict same-version
 * handshake (config_receive rejects a mismatched version before parsing
 * anything else) is what keeps a 2.21 client and a 2.20 server from ever
 * reaching that state.
 *
 * Preserve-Attribute Split Wave: 2.21.0 -> 2.22.0.
 *
 * WHY the bump, grounded in the wire: this wave splits the former single
 * use_metadata bundle into four independent rsync-compatible preservation
 * attributes (preserve_perms / preserve_times / preserve_owner /
 * preserve_group) so -p/-t/-o/-g (and their --no-* negations) become real
 * drop-in flags.  The binary config frame gains four serialized bools appended
 * to CONFIG_WIRE_METADATA_TIMES_FIELDS after omit_link_times, in this fixed
 * order: preserve_perms, preserve_times, preserve_owner, preserve_group.  Any
 * config-frame layout change must bump the protocol version: a peer that does
 * not parse the new trailing bytes would desynchronize on the frame boundary,
 * and the strict same-version handshake (config_receive rejects a mismatched
 * version before parsing anything else) is what keeps a 2.22 client and a 2.21
 * server from ever reaching that state.  The fixed-width FileMetadata layout is
 * UNCHANGED: the receiver still gates attribute application on use_metadata,
 * which is now DERIVED from these attributes by config_derived_use_metadata().
 *
 * Rsync-Parity Wave: 2.22.0 -> 2.23.0.
 *
 * WHY the bump, grounded in the wire.  Several independent changes land in this
 * protocol version:
 *
 * (1) Ownership parity (#286/#294): each --usermap/--groupmap wire entry grows
 * from two int32s to [from][from_hi][to][to_name]; `from_hi` carries an
 * inclusive LOW-HIGH range (== from for a single/any/unnamed matcher) and the
 * trailing string carries a TO NAME for the receiver to resolve (rsync resolves
 * TO names on the receiving side).  The STATUS_MKDIR and STATUS_DIR_TIMES frames
 * also gain a bounded per-entry xattr block when -X/-A is negotiated, so
 * directory xattrs/ACLs (including default ACLs) are preserved like regular-file
 * xattrs.
 *
 * (2) Delete semantics (#290): the delete-manifest frame gains a fourth trailing
 * section -- a synchronized-directory count followed by that many
 * destination-relative directory paths (the receive root is ".").  The receiver
 * confines its extras walk to these directories, so `--files-from` with
 * `--delete` only removes inside listed directory subtrees (rsync parity)
 * instead of deleting every untransmitted path under the receive root.  The
 * frame stream also gains STATUS_DELETE_LIMIT, the terminal success status sent
 * instead of STATUS_OK when a --max-delete commit removes up to the bound and
 * skips the rest (the sender then exits 25 like rsync).
 *
 * Any config-frame layout or frame-sequence change must bump the protocol
 * version: a 2.22 peer would desynchronize on the new entry bytes, the extra
 * trailing section or the unknown status, and the strict same-version handshake
 * (config_receive rejects a mismatched version before parsing anything else) is
 * what keeps a 2.23 client and a 2.22 server from ever reaching that state.
 *
 * (3) Output parity (#291/#292): -i/--itemize-changes and --out-format must
 * compare the source against the PRE-TRANSFER destination entry (new vs
 * modified, and which of size/time/perms/owner/group differ), but FastSync's
 * push sender never sees the destination.  The receiver therefore answers a
 * per-file STATUS_CHECK with a new STATUS_DEST_INFO frame (a fixed-width
 * snapshot of the old entry) before its ordinary verdict when the config frame
 * carries the new report_dest_info bool appended after the --copy-as block.
 * This is both a config-frame layout change (one trailing bool) and a frame
 * sequence change (the new status).
 *
 * Codec-Breadth + Negotiation Wave: 2.23.0 -> 2.26.0.
 *
 * WHY the bump, grounded in the wire: the config frame gains one trailing int,
 * compression_algo (a CompressionAlgo id), appended after the output block.
 * It is the negotiated/effective compression codec and is what the receiver's
 * self-describing decompressor validates against its own supported set.  The
 * checksum_algo wire value now also accepts md4/sha1/none, and its default
 * changes to the rsync 3.4.1 auto-negotiated xxh128.  Any config-frame layout
 * change must bump the protocol version: a peer that does not parse the new
 * trailing int would desynchronize on the frame boundary, and the strict
 * same-version handshake (config_receive rejects a mismatched version before
 * parsing anything else) is what keeps a 2.26 client and an older server from
 * ever reaching that state.  (2.24/2.25 are reserved for the other waves
 * landing alongside this one; this busy-work bump keeps 2.26.0 for codecs.) */
#define PROTOCOL_VERSION "2.26.0"
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
 * IDENTITY_MATCH_UNNAMED is a FROM with an empty token (rsync's "ids with no
 * name on the sender"); IDENTITY_CURRENT is a chown / map TO '*' (resolve to
 * the receiver's current euid/egid at apply time). */
#define IDENTITY_MATCH_ANY (-1)
#define IDENTITY_MATCH_UNNAMED (-2)
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
/* Emit the config frame BODY (every serialized field, in wire order) without
 * the trailing STATUS_OK handshake.  config_send() is this plus the handshake;
 * the wire-compatibility golden test uses it to hash the exact byte stream. */
bool config_send_wire_block(int file_descriptor, const Config* config);
Config* config_receive(int file_descriptor);
bool config_is_remote_dest(const char* s);
/* Parse a single-colon host:path SSH destination (0 = not an SSH destination or
 * parsed successfully, -1 = rejected, e.g. a user@host beginning with '-'; the
 * reason is logged). */
int config_parse_ssh_dest(Config* config);

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
/* Single source of truth for the DERIVED transport bit (use_metadata): true
 * when any configured preservation/ownership option requires the metadata
 * frame to travel.  Returns false when no such option is set (a bare run).
 * This is a pure predicate over the config; the client lowers it into
 * Config->use_metadata at the end of parsing so every implication (devices,
 * executability, identity maps, incremental/delta, ...) is centralized here
 * rather than scattered as direct writes. */
bool config_derived_use_metadata(const Config* config);
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
