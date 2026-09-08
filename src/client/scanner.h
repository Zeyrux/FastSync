#ifndef SCANNER_H
#define SCANNER_H

#include "chunk.h"
#include "file_list.h"
#include "filter.h"
#include "hardlink.h"
#include "protocol.h"
#include "queue.h"
#include <dirent.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <threads.h>

typedef struct {
  bool use_metadata;
  /* Phase 4 metadata capture: -U/--atimes and -N/--crtimes tell the scanner to
   * capture the source access / birth time into each entry's FileMetadata. */
  bool preserve_atimes;
  bool preserve_crtimes;
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
  bool dirs;                          /* -d/--dirs: transfer dir entries, no recursion */
  bool relative;                      /* -R/--relative (dest rel paths, with --files-from) */
  /* --prune-empty-dirs (long only): in --dirs mode an empty source directory's
     explicit entry is omitted from the transfer file list (so nothing is
     created at the destination and it can be pruned by --delete); explicitly
     --files-from-listed directories always pass through.  Recursive transfers
     never emit empty directories, so the flag has no additional effect there. */
  bool prune_empty_dirs;
  /* Delete-excluded protection sink (optional): when non-NULL the scanner
   * appends the destination-relative path of every entry it prunes because a
   * USER SELECTION rule excluded it (--filter/-C/per-dir rules, the legacy
   * --exclude/--include layer, and --max-size/--min-size).  The sender turns
   * this list into the manifest's protected prefixes so `--delete` leaves the
   * destination mirror of excluded source paths alone (rsync's default), and
   * empties it when --delete-excluded opts back into deleting them.  NOT
   * recorded for --files-from subset pruning (whose delete semantics stay
   * keep-set-only) or for -R/--files-from relative wire paths.  When
   * `excluded_mutex` is non-NULL it is taken around every append (the parallel
   * scanner shares one list across its worker threads). */
  ArrayList* excluded_paths;
  mtx_t* excluded_mutex;
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
} ScannerOptions;

/* Internal per-scanner filter state. FilterNode chains represent the ordered
 * per-directory .rsync-filter rules that apply below a directory. */
typedef struct FilterNode FilterNode;

typedef struct {
  Queue* directories;
  DIR* current_dir;
  char* current_path;
  bool use_metadata;
  bool preserve_atimes;
  bool preserve_crtimes;
  unsigned long long chunk_size;
  char** exclude_patterns;
  int exclude_count;
  char** include_patterns;
  int include_count;
  unsigned long long max_size;
  unsigned long long min_size;
  int max_depth;
  int current_depth;
  bool follow_symlinks;
  bool copy_links;
  bool safe_links;
  bool copy_unsafe_links;
  bool checksum;
  bool one_file_system;
  dev_t root_dev;
  bool failed;
  /* Phase 4 special/devices (see ScannerOptions). */
  bool preserve_devices;
  bool preserve_specials;
  bool copy_devices;
  /* Phase 2 (files-from / filter layer). */
  char* root_path;          /* transfer root (fs path) for rel computation */
  char* current_rel;        /* rel path of the open directory ("" == root) */
  bool at_seed_dir;         /* next open is the seed directory */
  FilterNode* seed_node;    /* inherited context of the seed dir, or NULL */
  FilterNode* current_node; /* filter context of the open directory */
  ArrayList* filter_nodes;  /* owned FilterNode arena (may be NULL) */
  const FileListSet* file_list;
  const FilterRuleList* base_filters;
  bool per_dir_filters;
  /* --dirs / -R state for the directory-entry generator (dirs_mode replaces
     the recursive scan). */
  bool dirs_mode;
  bool relative_mode; /* file_list && relative: send bare relative wire paths */
  bool prune_empty_dirs;
  bool dirs_root_emitted;
  int list_index;
  ArrayList* dirs_batch; /* owned when non-NULL */
  unsigned long long dirs_batch_size;
  /* Excluded-path sink (see ScannerOptions). `excluded_mutex` is shared across
     parallel worker threads. */
  ArrayList* excluded_paths;
  mtx_t* excluded_mutex;
  /* --ignore-errors: continue past unreadable directories (records io_error). */
  bool ignore_io_errors;
  /* --ignore-missing-args: --dirs listed-but-missing entries are skipped, not
     fatal (see ScannerOptions.ignore_missing_args). */
  bool ignore_missing_args;
  /* A directory could not be opened (I/O error, e.g. EACCES).  With
     --ignore-errors the scan continues past it and the caller decides what to
     do; `failed` is reserved for fatal errors that always abort the scan. */
  bool io_error;
  /* --hard-links (-H): shared link-group detection table (see ScannerOptions).
     NULL when -H is off. */
  HardLinkTable* hardlinks;
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
