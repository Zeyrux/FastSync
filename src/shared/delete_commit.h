#ifndef DELETE_COMMIT_H
#define DELETE_COMMIT_H

#include "array_list.h"
#include "config.h"
#include "utils.h"
#include <stdbool.h>

/* Delete-commit module: delete-manifest receive plus the budgeted extras and
 * --delete-missing-args walkers.  These declarations are re-exported by the
 * file_receive.h facade. */

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

#endif
