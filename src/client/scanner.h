#ifndef SCANNER_H
#define SCANNER_H

#include "chunk.h"
#include "file_list.h"
#include "filter.h"
#include "hardlink.h"
#include "protocol.h"
#include "queue.h"
#include "stop_condition.h"
#include <dirent.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <threads.h>

/* Upper bound on the configurable parallel scanner worker count (--threads=N):
 * keeps one transfer from spawning an unbounded pool on a very large machine. */
#define MAX_SCANNER_THREADS 256

typedef struct {
  bool use_metadata;
  /* Phase 4 metadata capture: -U/--atimes and -N/--crtimes tell the scanner to
   * capture the source access / birth time into each entry's FileMetadata. */
  bool preserve_atimes;
  bool preserve_crtimes;
  /* Phase 4 xattrs: when preserve_xattrs || preserve_acls is set the scanner
   * captures each regular file's whitelisted xattr set onto the File. */
  bool preserve_xattrs;
  bool preserve_acls;
  unsigned long long chunk_size;
  char** exclude_patterns;
  int exclude_count;
  char** include_patterns;
  int include_count;
  unsigned long long max_size;
  unsigned long long min_size;
  int max_depth;
  int num_threads;
  bool follow_symlinks;
  bool copy_links;
  bool safe_links;
  bool copy_unsafe_links;
  /* Phase 4 symlink-trust sender options: -k/--copy-dirlinks (dereference a
   * symlink to a directory as a directory, keeping symlinks-to-files as
   * symlinks) and --munge-links (rewrite each transmitted symlink target with a
   * marker; escaping targets are never transmitted).  Both are client/sender
   * side only and never serialized to the wire (keep_dirlinks is the
   * receiver-side counterpart). */
  bool copy_dirlinks;
  bool munge_links;
  bool checksum;
  bool one_file_system;
  /* Phase 4 special/devices: whether device nodes (--devices) and special files
   * (--specials) are preserved via recreation, and whether --copy-devices
   * copies a device's content as an ordinary regular file. */
  bool preserve_devices;
  bool preserve_specials;
  bool copy_devices;
  /* Phase 2 (files-from / filter layer). All pointers are shared read-only
   * across scanner instances and worker threads; ownership stays with the
   * caller (client_send). */
  const FileListSet* file_list;       /* --files-from allow-set, or NULL */
  const FilterRuleList* base_filters; /* command-line + -C rules, or NULL */
  bool per_dir_filters;               /* -F: read .rsync-filter per directory */
  /* --delete-excluded: per-directory plain rules become sender-only, so they no
     longer protect the receiver from deletion. */
  bool delete_excluded;
  /* -FF: also exclude the per-directory filter files themselves from the
     transfer (single -F transfers them). */
  bool exclude_per_dir_filter_files;
  bool dirs;     /* -d/--dirs: transfer dir entries, no recursion */
  bool relative; /* -R/--relative (dest rel paths, with --files-from) */
  /* -R/--relative outside --files-from: the destination-relative path prefix
   * reconstructed from the source spec (rsync's '/./' cut point), or NULL when
   * -R is off or --files-from is in use (the bare-relative path then comes from
   * the listed entry).  Borrowed read-only; owned by client_send. */
  const char* relative_prefix;
  /* --list-only: emit an is_dir File for every traversed directory (the listing
   * includes directory entries, matching rsync).  Client-only; never set on a
   * real transfer, which relies on implicit parent creation. */
  bool list_dirs;
  /* --prune-empty-dirs (long only): in --dirs mode an empty source directory's
     explicit entry is omitted from the transfer file list (so nothing is
     created at the destination and it can be pruned by --delete); explicitly
     --files-from-listed directories always pass through.  Recursive transfers
     never emit empty directories, so the flag has no additional effect there. */
  bool prune_empty_dirs;
  /* Delete-excluded protection sink (optional): when non-NULL the scanner
   * appends the destination-relative path of every entry it prunes because a
   * USER SELECTION rule excluded it (--filter/-C/per-dir rules and the legacy
   * --exclude/--include layer).  The sender turns this list into the manifest's
   * protected prefixes so `--delete` leaves the destination mirror of excluded
   * source paths alone (rsync's default), and drops it when --delete-excluded
   * opts back into deleting them.  NOT recorded for --files-from subset pruning
   * (whose delete semantics derive from the synchronized-directory set) or for
   * -R/--files-from relative wire paths.  When `excluded_mutex` is non-NULL it
   * is taken around every append (the parallel scanner shares one list across
   * its worker threads). */
  ArrayList* excluded_paths;
  mtx_t* excluded_mutex;
  /* Size-prune protection sink (optional): when non-NULL the scanner appends
   * the destination-relative path of every entry it skipped because of
   * --max-size/--min-size.  rsync never deletes a size-skipped source mirror,
   * even under --delete-excluded, so the sender always transmits this list as
   * protected prefixes (unlike excluded_paths, which --delete-excluded drops).
   * Guarded by `excluded_mutex` like excluded_paths. */
  ArrayList* size_skipped_paths;
  /* Synchronized-directory sink (optional): when non-NULL the scanner appends
   * the destination-relative path of every directory it is about to traverse
   * that lies inside a --files-from listed directory (or of every traversed
   * directory when there is no list).  The sender sends this set with the delete
   * manifest so the receiver confines its extras walk to synchronized
   * directories, exactly like rsync; the receive root is the "." sentinel.
   * Guarded by `excluded_mutex`. */
  ArrayList* synced_dirs;
  /* Delete-plan directory sink (optional): when non-NULL the scanner appends
   * the destination-relative path of every directory it traverses (except the
   * receive root).  The per-directory --delete-during/--delete-delay plan
   * builder uses this to keep an empty in-scope source directory (rsync keeps
   * it) and to emit its plan after the data stream, when no file frame would
   * otherwise trigger it.  Guarded by `excluded_mutex`. */
  ArrayList* plan_dirs;
  /* --ignore-errors: an unreadable directory during the scan is recorded as an
   * I/O error and skipped instead of aborting the scan.  Client-only. */
  bool ignore_io_errors;
  /* --ignore-missing-args (implied by --delete-missing-args): an explicitly
   * --files-from-listed entry that does not exist under the source is skipped
   * instead of failing (the --dirs generator is the only scanner path that
   * observes a listed-but-missing entry). */
  bool ignore_missing_args;
  /* --hard-links (-H): shared, mutable (mutex-guarded) link-group detection
   * table, NULL when -H is off.  Owned by the caller (client_send), shared
   * read-only here; the parallel scanner passes it unchanged to every worker so
   * one table detects every group across all subdirectories. */
  HardLinkTable* hardlinks;
  /* Phase 6: optional sender stop deadline.  When non-NULL the scanner checks
   * it at natural loop boundaries and stops emitting chunks once reached
   * (without marking the scan as failed), so a busy scan itself stops early.
   * Client-only, never serialized to the wire. */
  const StopCondition* stop_condition;
  /* P7 Wave D (protocol 2.17.0): directory-time capture sink.  When
   * `capture_dir_times` is true the recursive scan appends one is_dir File
   * (with metadata, no payload) per source directory it traverses to
   * `dir_entries`, so the sender can transmit trailing STATUS_DIR_TIMES
   * frame(s) and the receiver can apply directory mtimes AFTER all children
   * are written.  `dir_entries_mutex` (optional) guards the list
   * for the parallel scanner's shared worker threads; the caller owns both.
   * The --dirs generator does not use this (its directory entries carry their
   * metadata inline through STATUS_MKDIR). */
  bool capture_dir_times;
  ArrayList* dir_entries;
  mtx_t* dir_entries_mutex;
  /* --no-implied-dirs with -R + --files-from: a directory that is only an
   * implied parent of a listed entry (not itself listed, nor below a listed
   * directory) must not carry source metadata; it is created with default
   * attributes at the destination, matching rsync. */
  bool no_implied_dirs;
} ScannerOptions;

/* Internal per-scanner filter state. FilterNode chains represent the ordered
 * per-directory .rsync-filter rules that apply below a directory. */
typedef struct FilterNode FilterNode;

typedef struct {
  /* Scan inputs, copied once at create time.  Everything that is also a
     ScannerOptions field lives here (with the normalized chunk_size); only
     scanner-owned bookkeeping stays as direct members below. */
  ScannerOptions options;
  Queue* directories;
  DIR* current_dir;
  char* current_path;
  int current_depth;
  dev_t root_dev;
  bool failed;
  /* Recursive scan: whether the open directory yielded any transferred or
     descended entry.  When it did not, closing it emits a directory entry so
     the empty source directory is recreated at the destination (rsync
     parity). */
  bool current_dir_produced;
  /* Phase 2 (files-from / filter layer). */
  char* root_path;          /* transfer root (fs path) for rel computation */
  char* current_rel;        /* rel path of the open directory ("" == root) */
  bool at_seed_dir;         /* next open is the seed directory */
  FilterNode* seed_node;    /* inherited context of the seed dir, or NULL */
  FilterNode* current_node; /* filter context of the open directory */
  ArrayList* filter_nodes;  /* owned FilterNode arena (may be NULL) */
  /* --dirs / -R state for the directory-entry generator (options.dirs replaces
     the recursive scan). */
  bool relative_mode; /* file_list && relative: send bare relative wire paths */
  bool dirs_root_emitted;
  int list_index;
  ArrayList* dirs_batch; /* owned when non-NULL */
  unsigned long long dirs_batch_size;
  /* A directory could not be opened (I/O error, e.g. EACCES).  With
     --ignore-errors the scan continues past it and the caller decides what to
     do; `failed` is reserved for fatal errors that always abort the scan. */
  bool io_error;
} DirectoryScanner;

typedef struct {
  Queue* result_queue;
  mtx_t result_mutex;
  cnd_t result_not_empty;
  cnd_t result_not_full;
  int num_threads;
  int expected_threads;
  int created_threads;
  thrd_t* threads;
  bool done;
  bool failed;
  /* A worker skipped an unreadable directory under --ignore-errors (non-fatal). */
  bool io_error;
  atomic_bool cancelled;
  int completed;
  Chunk* initial_chunk;
  ProtocolSession* allocation_session;
  FilterNode* root_filter_node; /* root .rsync-filter context (owned by ps) */
} ParallelScanner;

DirectoryScanner* directory_scanner_create(const char* root_directory, bool use_metadata,
                                           unsigned long long chunk_size, char** exclude_patterns,
                                           int exclude_count, char** include_patterns,
                                           int include_count, unsigned long long max_size,
                                           unsigned long long min_size, int max_depth,
                                           bool follow_symlinks, bool copy_links, bool safe_links,
                                           bool copy_unsafe_links, bool checksum);
DirectoryScanner* directory_scanner_create_with_options(const char* root_directory,
                                                        const ScannerOptions* options);
Chunk* directory_scanner_next(DirectoryScanner* scanner);
bool directory_scanner_failed(const DirectoryScanner* scanner);
void directory_scanner_destroy(DirectoryScanner* scanner);

/* --one-file-system (-x) decision: a directory entry may be descended into
 * only when the option is disabled or the entry lives on the same device as
 * the transfer root. Exposed so tests can exercise the rule directly. */
bool scanner_same_filesystem(bool one_file_system, dev_t root_device, dev_t entry_device);

/* Relative path of an on-disk path below `root` ("" == the root itself, NULL
 * when `fs_path` is not under `root`). Handles trailing slashes and a root of
 * "/". Exposed so tests can exercise the mapping directly. */
char* scanner_path_relative(const char* root, const char* fs_path);

/* -R/--relative destination-relative prefix reconstructed from a source spec:
 * the path after rsync's first '.' path component (the '/./' cut point), with
 * leading/trailing slashes removed, or the whole spec (normalized) when there
 * is no cut.  Returns "" for the receive root, or NULL when `spec` is NULL or
 * allocation fails.  Exposed so tests can exercise the mapping directly. */
char* scanner_relative_prefix(const char* spec);

ParallelScanner* parallel_scanner_create_with_options(const char* root_directory,
                                                      const ScannerOptions* options,
                                                      ProtocolSession* allocation_session);
Chunk* parallel_scanner_next(ParallelScanner* scanner);
bool parallel_scanner_failed(const ParallelScanner* scanner);
bool parallel_scanner_had_io_error(const ParallelScanner* scanner);
void parallel_scanner_destroy(ParallelScanner* scanner);

/* True when a directory could not be opened during the scan (an I/O error,
   recorded even when --ignore-errors keeps the scan going past it). */
bool directory_scanner_had_io_error(const DirectoryScanner* scanner);

#endif
