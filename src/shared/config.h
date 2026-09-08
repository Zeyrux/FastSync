#ifndef CONFIG_H
#define CONFIG_H

#include "array_list.h"
#include "checksum.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum { TRANSPORT_TCP, TRANSPORT_SSH } TransportType;

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
  char* fastsync_server_path;
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
  int timeout;
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

  // Issue #121: Extended metadata preservation
  bool preserve_hard_links;
  bool preserve_acls;
  bool preserve_xattrs;
  bool preserve_devices;
  bool preserve_sparse;

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
  char* rsh_command;
  char* rsync_path;
  bool old_args;
  char* temp_dir;
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

  // PR #182: Daemon/server mode
  bool daemon;
  char* daemon_config;
  bool server_mode;

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

  // Receiver-side runtime staging registry for --delay-updates.  Never sent
  // over the wire and never set on the sender side.
  DelayUpdatesContext* delay_context;
} Config;

#define PROTOCOL_VERSION "2.12.0"
#define DEFAULT_CHUNK_SIZE (10 * 1024 * 1024)
/* Upper bound on total basis-dir entries (rsync caps --link-dest at 20). */
#define MAX_BASIS_DIRS 64

/* Identity-mapping sentinels and bounds (see identity.h for semantics).
 * IDENTITY_MATCH_ANY is a usermap/groupmap FROM '*' (matches any id);
 * IDENTITY_CURRENT is a chown / map TO '*' (resolve to the receiver's current
 * euid/egid at apply time). */
#define IDENTITY_MATCH_ANY (-1)
#define IDENTITY_CURRENT (-1)
#define MAX_IDENTITY_MAP 128

Config* config_create(void);
void config_delete(Config* config);
bool config_send(int file_descriptor, const Config* config);
Config* config_receive(int file_descriptor);
bool config_is_remote_dest(const char* s);
void config_parse_ssh_dest(Config* config);

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
/* True when at least one --compare-dest/--copy-dest/--link-dest was set. */
bool config_has_basis(const Config* config);
/* Append one basis-dir entry. Returns 0 on success, -1 on allocation failure. */
int config_basis_append(Config* config, BasisDestType type, const char* path);
/* Validate a client-provided basis-dir path (relative, confined, non-empty). */
bool config_basis_path_valid(const char* path);

#endif
