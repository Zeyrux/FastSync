#ifndef FILE_RECEIVE_H
#define FILE_RECEIVE_H

#include "config.h"
#include "file_types.h"
#include "utils.h"
#include <stdbool.h>

/* Server-side file receive/save path. */

/* Cumulative caps for the deferred directory-time accumulator.  The sender may
 * legitimately split a large tree across repeated STATUS_DIR_TIMES frames, so a
 * per-frame bound is not enough: the receiver must bound the TOTAL it retains
 * against a hostile sender.  Mirror the delete-manifest limits
 * (MAX_MANIFEST_ENTRIES / MAX_MANIFEST_BYTES): the entry count bounds the
 * metadata array and the byte budget bounds the concatenated path strings. */
#define MAX_DIR_TIME_ENTRIES (1024 * 1024)
#define MAX_DIR_TIME_BYTES (16ULL * 1024 * 1024)

File* file_receive(const Config* config, int file_descriptor);
File* file_receive_directory(int file_descriptor, const Config* config);
File* file_receive_dir_time(int file_descriptor, const Config* config);
File* file_receive_hardlink(int file_descriptor);
File* file_receive_symlink(int file_descriptor, const Config* config);
File* file_receive_special(int file_descriptor);
bool file_special_rdev_valid(int32_t major, int32_t minor, mode_t mode);
File* receive_incremental_check(int fd, const Config* config, bool* skipped);
/* Extended variant used by the receiver.  `would_transfer` (may be NULL) is set
 * true only on the server-contacting --dry-run path when the file is not up to
 * date: the receiver has already sent STATUS_DRY_RUN_TRANSFER and returns NULL
 * without storing anything.  On that path `*skipped` is true for an up-to-date
 * (STATUS_OK) file and both flags are false for a genuine error. */
File* receive_incremental_check_ex(int fd, const Config* config, bool* skipped,
                                   bool* would_transfer);

/* P7 Wave D directory-time accumulator.  The receiver collects the metadata of
 * every directory it creates/receives (STATUS_MKDIR with metadata and/or the
 * trailing STATUS_DIR_TIMES frame(s)) and applies the times only at the END of the
 * transfer, after all children have been written and after the delete /
 * --delay-updates phases have committed (writing or removing a child bumps the
 * parent's mtime).  -O/--omit-dir-times skips the application entirely.  The
 * list owns deep copies of the paths and metadata; freed on every path. */
typedef struct {
  char** paths;           /* owned, destination-relative wire paths */
  FileMetadata* entries;  /* owned, parallel to paths */
  FileXattrList** xattrs; /* owned, parallel to paths; NULL when none */
  size_t count;
  size_t capacity;
  size_t bytes; /* cumulative strlen of every retained path */
} DirTimeList;

/* Capture gate shared by the sender-side and receiver-side sinks: directory
 * metadata is accumulated only when a directory attribute is requested
 * (-p/--perms for directory modes, or -t/--times for directory mtimes with
 * -O/--omit-dir-times not suppressing them) and metadata rides the wire.  Kept
 * here, next to the accumulator it guards, so both call sites express the same
 * condition. */
bool dir_metadata_should_capture(const Config* config);

void dir_time_list_init(DirTimeList* list);
void dir_time_list_free(DirTimeList* list);
/* Deep-copy one directory's path + metadata (and, when non-NULL, its captured
 * xattr/ACL block) into the list.  Returns false on allocation failure OR when
 * the cumulative entry/byte caps would be exceeded (the caller fails the
 * transfer). */
bool dir_time_list_add(DirTimeList* list, const char* wire_path, const FileMetadata* metadata,
                       const FileXattrList* xattrs);
/* Apply every accumulated directory's metadata beneath `root_directory`,
 * confined fd-relative: ownership through the negotiated identity policy,
 * times (mtime, plus atime when -U captured one under -t), the mode (through
 * --chmod when configured, under -p), and the captured xattrs/ACLs (under
 * -X/-A).  Best-effort per entry: an absent directory (an empty/pruned source
 * dir that was deliberately not created) or a non-directory at the path is
 * skipped QUIETLY, an unreachable one with a warning, and never fatal. */
void dir_metadata_list_apply(const DirTimeList* list, const char* root_directory,
                             const Config* config);

/* A received delete-manifest frame: the keep-set (`keeps`, destination-relative
   paths the sender transferred/keeps) plus `protected`, destination-relative
   prefixes the sender asks the receiver never to delete (paths excluded on the
   source, protected at any depth).  When --delete-excluded is given the sender
   transmits an empty protected list so excluded destination mirrors are treated
   as ordinary extras.  With --delete-missing-args a third section (`missing`)
   carries the destination mirrors of explicitly-listed source entries that do
   not exist: each is an exact deletion request, independent of the ordinary
   extras walk (never blocked by the protected prefixes) and processed when the
   manifest is committed. */
typedef struct DeleteManifest {
  ArrayList* keeps;
  ArrayList* protected;
  ArrayList* missing;
  /* Destination-relative paths of the directories the sender synchronized for
     this run.  The extras walker only removes entries directly inside one of
     these (the receive root is the "." sentinel); `--files-from` runs therefore
     leave untransmitted directories and the unlisted parts of listed ones
     alone, matching rsync's "delete only in synchronized directories". */
  ArrayList* dirs;
} DeleteManifest;

void delete_manifest_free(DeleteManifest* manifest);
/* Read a delete-manifest frame (protocol 2.23.0): keep count + keeps, then
   protected count + protected prefixes, then missing count + missing paths,
   then synchronized-directory count + directory paths (self-delimiting; the
   leading STATUS_MANIFEST code has been consumed).  Returns an owned
   DeleteManifest, or NULL after signalling STATUS_ERROR on a malformed frame. */
DeleteManifest* receive_manifest_entries(int fd);
/* Remove destination entries under config->receive_root_directory that are not
   in `manifest` (bounded, all-or-nothing walk; staging-dir, basis-dir and
   protected-prefix skips).  `--max-delete` and `--force` are honored here.  The
   caller decides WHEN to run it based on the negotiated delete timing.  Returns
   false (and the transfer fails) when the deletion cannot be committed. */
bool manifest_delete_extras(const Config* config, DeleteManifest* manifest);
/* --delete-missing-args exact-path deletions: remove each destination mirror
   in `manifest->missing` (never blocked by the protected prefixes, staging dir
   and basis dirs excluded).  A regular file/symlink is unlinked; an empty
   directory is removed; a NON-empty directory is removed recursively only when
   --delete or --force is in effect, otherwise it is left with a warning (rsync
   parity).  A missing path is a no-op.  Returns false only on a genuine
   confinement or I/O error (the run then fails); tolerated per-path cases are
   reported and skipped. */
bool manifest_delete_missing_args(const Config* config, DeleteManifest* manifest);
/* Budgeted form of manifest_delete_missing_args for the per-directory delete
   session: each removed mirror draws from `max_delete` (SIZE_MAX = unlimited)
   and the tallies are accumulated into `*deleted`/`*skipped`.  `*limit_hit` is set
   when the budget stopped the pass with entries left over.  Returns false only
   on a genuine deletion error. */
bool manifest_delete_missing_args_limited(const Config* config, DeleteManifest* manifest,
                                          size_t max_delete, size_t* deleted, size_t* skipped,
                                          bool* limit_hit);
/* Observer-aware form of manifest_delete_missing_args_limited: `observer` (may
   be NULL) is invoked for every destination-relative path truly removed. */
bool manifest_delete_missing_args_limited_observed(const Config* config, DeleteManifest* manifest,
                                                   size_t max_delete, size_t* deleted,
                                                   size_t* skipped, bool* limit_hit,
                                                   DeletePathObserver observer,
                                                   void* observer_context);
/* Outcome of committing a delete manifest.  LIMIT_REACHED reports rsync's
   partial --max-delete result: the budget allowed some deletions and the rest
   were skipped (the run still stores all file data but the client exits 25). */
typedef enum {
  DELETE_COMMIT_OK = 0,
  DELETE_COMMIT_LIMIT_REACHED,
  DELETE_COMMIT_ERROR
} DeleteCommitResult;

/* Run every deletion family the manifest carries: the --delete-missing-args
   exact-path deletions first (user requests are not blocked by exclusion
   protection), then the ordinary extras walk when --delete is active.  Both
   share one --max-delete budget.  Returns DELETE_COMMIT_OK when nothing was to
   do or everything committed, DELETE_COMMIT_LIMIT_REACHED when the budget
   stopped part of the work, or DELETE_COMMIT_ERROR on a genuine failure. */
DeleteCommitResult manifest_delete_all(const Config* config, DeleteManifest* manifest);
/* Like manifest_delete_all, but reports how many destination entries the commit
   removed (for the end-of-transfer wire stats).  `deleted` may be NULL. */
DeleteCommitResult manifest_delete_all_counted(const Config* config, DeleteManifest* manifest,
                                               size_t* deleted);
/* Observer-aware form of manifest_delete_all_counted: `observer` (may be NULL)
   is invoked for every destination-relative path truly removed. */
DeleteCommitResult manifest_delete_all_observed(const Config* config, DeleteManifest* manifest,
                                                size_t* deleted, DeletePathObserver observer,
                                                void* observer_context);

/* -n/--dry-run --delete would-delete reporting: walk the destination exactly as
   the delete pass would and append (strdup'd) destination-relative paths that
   WOULD be removed to `out`, without touching disk.  Uses the same staging-dir,
   basis-dir and protected-prefix skips as the real commit.  Returns true on a
   clean walk; `*count_out` receives the number of paths appended. */
bool manifest_would_delete_list(const Config* config, DeleteManifest* manifest, ArrayList* out,
                                size_t* count_out);
/* Convert one basis-directory path to the receive-root-relative protection
   prefix the delete walker uses (NULL when it lies outside the root).  Exposed
   for unit tests of the root-of-"/" and normalization edge cases. */
char* file_receive_basis_delete_relative(const Config* config, const char* path);

/* Outcome of a single file_save_to_disk operation.  The receiver needs to
   distinguish "written" from "skipped" so --remove-source-files can be told
   which sources were actually stored. */
typedef enum { FILE_SAVE_ERROR = 0, FILE_SAVE_WRITTEN = 1, FILE_SAVE_SKIPPED = 2 } FileSaveResult;

FileSaveResult file_save_to_disk_full(const char* root_directory, const File* file,
                                      const Config* config);
/* Protocol 2.28.0 variant: also reports through `created` (when non-NULL)
 * whether the destination entry did not exist before this save, and through
 * `created_dirs` how many parent directories the confined walk created, so the
 * receiver can build rsync's `Number of created files` breakdown.  The plain
 * file_save_to_disk_full() is this with both out-params NULL. */
FileSaveResult file_save_to_disk_full_ex(const char* root_directory, const File* file,
                                         const Config* config, bool* created,
                                         unsigned* created_dirs);
bool file_save_to_disk(const char* root_directory, const File* file, const Config* config);

/* Protocol 2.28.0 receiver counter accumulator: fold one successfully saved
 * entry into `stats`, adding its receiver-observed literal bytes and, when
 * `created`, the matching created-by-type counter (regular file / symlink /
 * special) plus `created_dirs` implicitly-created parent directories.
 * Non-first hardlink siblings contribute no literal bytes. */
void receiver_stats_note_saved(ReceiverStats* stats, const File* file, bool created,
                               unsigned created_dirs);

#endif
