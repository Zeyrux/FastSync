#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "array_list.h"
#include "charset.h"
#include "chmod.h"
#include "chunk.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delay_updates.h"
#include "delete_commit.h"
#include "delta.h"
#include "file.h"
#include "format.h"
#include "identity.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"
#include "xattr.h"

#define MAX_SERVER_DELETE_COUNT 100000U
/* Retained cost of one delete-manifest entry beyond its path bytes: the
   ArrayList pointer slot plus an approximate malloc header/rounding for the
   heap copy.  Charged against MAX_MANIFEST_BYTES so a frame full of tiny paths
   cannot retain far more than the byte budget (B5). */
#define MANIFEST_ENTRY_OVERHEAD (sizeof(char*) + 16)

/* Read a delete-manifest frame (the STATUS_MANIFEST leading code has already
   been consumed): a keep-set entry count followed by that many
   destination-relative paths, then a protected-prefix count followed by that
   many destination-relative prefixes, then a missing-args count followed by that
   many destination-relative delete paths, then (protocol 2.23.0) a
   synchronized-directory count followed by that many destination-relative
   directory paths (the receive root is the "." sentinel).  The frame is
   self-delimiting (the counts are authoritative), so the caller decides what to
   do next and continues reading the following STATUS_* frame.  Every section is
   validated identically: an entry must be non-empty, relative and traversal-free
   and the aggregate length across ALL sections is capped by MAX_MANIFEST_BYTES
   (so the missing-args deletion requests are confined like the rest of the
   manifest).  Returns an owned DeleteManifest, or NULL after sending STATUS_ERROR
   when the frame is malformed (bad count, empty/absolute path, path traversal,
   or an aggregate size beyond MAX_MANIFEST_BYTES). */
static bool receive_manifest_section(int fd, ArrayList* list, size_t* manifest_bytes,
                                     size_t* manifest_entries) {
  int count;
  if (!receive_int(fd, &count)) {
    send_status(fd, STATUS_ERROR);
    return false;
  }
  if (count < 0 || count > MAX_MANIFEST_ENTRIES ||
      (size_t)count > MAX_MANIFEST_ENTRIES - *manifest_entries) {
    send_status(fd, STATUS_ERROR);
    return false;
  }
  for (int i = 0; i < count; i++) {
    char* s = receive_wire_str(fd);
    size_t entry_size = s ? strlen(s) + MANIFEST_ENTRY_OVERHEAD : 0;
    if (!s || s[0] == '\0' || s[0] == '/' || has_path_traversal(s) ||
        entry_size > MAX_MANIFEST_BYTES - *manifest_bytes ||
        (*manifest_bytes += entry_size) > MAX_MANIFEST_BYTES || !array_list_add(list, s)) {
      free(s);
      send_status(fd, STATUS_ERROR);
      return false;
    }
  }
  *manifest_entries += (size_t)count;
  return true;
}

DeleteManifest* receive_manifest_entries(int fd) {
  DeleteManifest* manifest = calloc(1, sizeof(DeleteManifest));
  if (!manifest) {
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  manifest->keeps = array_list_create(free);
  manifest->protected = array_list_create(free);
  manifest->missing = array_list_create(free);
  manifest->dirs = array_list_create(free);
  if (!manifest->keeps || !manifest->protected || !manifest->missing || !manifest->dirs) {
    delete_manifest_free(manifest);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  size_t manifest_bytes = 0;
  size_t manifest_entries = 0;
  if (!receive_manifest_section(fd, manifest->keeps, &manifest_bytes, &manifest_entries) ||
      !receive_manifest_section(fd, manifest->protected, &manifest_bytes, &manifest_entries) ||
      !receive_manifest_section(fd, manifest->missing, &manifest_bytes, &manifest_entries) ||
      !receive_manifest_section(fd, manifest->dirs, &manifest_bytes, &manifest_entries)) {
    delete_manifest_free(manifest);
    return NULL;
  }
  return manifest;
}

void delete_manifest_free(DeleteManifest* manifest) {
  if (!manifest)
    return;
  array_list_delete(manifest->keeps);
  array_list_delete(manifest->protected);
  array_list_delete(manifest->missing);
  array_list_delete(manifest->dirs);
  free(manifest);
}

/* Shared --max-delete budget for one receiver-side deletion commit.  Both the
   --delete-missing-args exact-path removals and the ordinary extras walk draw
   from the same tally, matching rsync (whose --max-delete counts every deleted
   file or directory).  `max_delete` is SIZE_MAX for an unlimited budget. */
typedef struct {
  size_t max_delete;
  size_t deleted;
  size_t skipped;
  bool limit_hit;
} DeleteBudgetState;

/* Remove every destination entry under the receive root that is not in the
   keep-set, bounded by the shared budget (a smaller client --max-delete=NUM
   replaces the server hard bound; rsync deletes up to the bound and skips the
   rest).  With --delay-updates the not-yet-published staging directory is a
   direct child of the receive root and must not be treated as a set of extras;
   the manifest's protected prefixes (paths excluded on the source), the
   size-pruned prefixes (--max-size/--min-size, always protected) and the
   alternate basis directories are never destination content and are skipped at
   any depth.  Returns true unless a traversal/unlink error aborted the walk;
   the budget's limit_hit/skipped fields report a cap-stopped run. */
static bool delete_extras_budgeted_observed(const Config* config, const DeleteManifest* manifest,
                                            DeleteBudgetState* budget, DeletePathObserver observer,
                                            void* observer_context) {
  if (!config || !manifest || !manifest->keeps)
    return false;
  fprintf(stderr, "Deleting files not in manifest...\n");
  /* Protected entries: the --delay-updates staging name (only as a DIRECT child
     of the receive root), the alternate basis directories and the sender-side
     protected prefixes (filter-excluded and size-pruned source mirrors), all at
     any depth.  See delete_skips_build(). */
  DeleteSkipSet skips;
  if (!delete_skips_build(config, manifest->protected, NULL, true, &skips))
    return false;
  /* Clamp rather than subtract: an accounting bug where deleted already exceeds
     max_delete must never underflow into an effectively unlimited budget. */
  size_t remaining;
  if (budget->max_delete == SIZE_MAX)
    remaining = SIZE_MAX;
  else if (budget->deleted >= budget->max_delete)
    remaining = 0;
  else
    remaining = budget->max_delete - budget->deleted;
  size_t deleted = 0;
  size_t skipped = 0;
  DeleteWalkResult result = delete_extras_limited_observed(
      config->receive_root_directory, manifest->keeps, manifest->dirs, remaining, skips.entries,
      skips.count, config->protect_rules, &deleted, &skipped, observer, observer_context);
  delete_skips_free(&skips);
  budget->deleted += deleted;
  budget->skipped += skipped;
  if (result == DELETE_WALK_LIMIT_REACHED) {
    budget->limit_hit = true;
    return true;
  }
  if (result != DELETE_WALK_OK) {
    log_message(LOG_LEVEL_ERROR, "deletion failed while removing extraneous files");
    return false;
  }
  return true;
}

static bool delete_extras_budgeted(const Config* config, const DeleteManifest* manifest,
                                   DeleteBudgetState* budget) {
  return delete_extras_budgeted_observed(config, manifest, budget, NULL, NULL);
}

/* Prefixes every observed path with a fixed subtree root, so a nested walk
   (a recursively removed missing-arg directory) reports receive-root-relative
   names like the rest of the delete output. */
typedef struct {
  DeletePathObserver inner;
  void* inner_context;
  const char* prefix;
} PrefixedDeleteObserver;

static void prefixed_delete_observer(void* context, const char* rel, DeleteEntryType type) {
  PrefixedDeleteObserver* prefixed = context;
  if (!prefixed->inner || !rel)
    return;
  char* joined = path_cat((char*)prefixed->prefix, rel);
  if (joined) {
    prefixed->inner(prefixed->inner_context, joined, type);
    free(joined);
  }
}

/* --delete-missing-args exact-path deletions: each destination mirror in
   manifest->missing is an explicit user request, so it is removed even when the
   ordinary extras walk (with its protected prefixes) would leave it alone.  The
   --delay-updates staging directory and basis snapshots are receiver artifacts
   and stay protected exactly as in the extras walker.  A regular file or
   symlink is unlinked, an empty directory removed, and a NON-empty directory is
   removed recursively only when --delete or --force is in effect (rsync parity:
   the man page says a non-empty directory mirror is only deleted with --force
   or --delete); otherwise it is left with a warning and the run continues.  A
   mirror that does not exist is a no-op.  Each removal draws from the shared
   --max-delete budget: once it is exhausted the remaining requests are skipped
   and counted.  Returns false only on a genuine error (a confinement failure on
   a validated path or an I/O error), which fails the run. */
static bool delete_missing_args_budgeted_observed(const Config* config,
                                                  const DeleteManifest* manifest,
                                                  DeleteBudgetState* budget,
                                                  DeletePathObserver observer,
                                                  void* observer_context) {
  if (!config || !manifest)
    return false;
  if (!manifest->missing || manifest->missing->size == 0)
    return true;
  fprintf(stderr, "Deleting destination mirrors of missing source arguments...\n");
  /* The staging directory and basis snapshots stay protected exactly as in the
     extras walker (the missing-args path overrides the ordinary protected
     prefixes, so those are not passed here). */
  DeleteSkipSet skips;
  if (!delete_skips_build(config, NULL, NULL, true, &skips))
    return false;
  bool ok = true;
  for (int i = 0; i < manifest->missing->size; i++) {
    const char* rel = (const char*)manifest->missing->items[i];
    if (!rel || *rel == '\0' || *rel == '/' || has_path_traversal(rel)) {
      /* Defensive only: receive_manifest_entries already validated every
         section identically, so a controlled peer never reaches this branch. */
      log_message(LOG_LEVEL_ERROR, "invalid missing-args delete path");
      ok = false;
      continue;
    }
    bool at_root = strchr(rel, '/') == NULL;
    if (path_under_skip_prefix(rel, at_root, skips.entries, skips.count)) {
      char* escaped = output_escape(rel, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING,
                  "missing-args path '%s' is protected (staging directory or basis snapshot); "
                  "not deleting",
                  escaped ? escaped : "<allocation failed>");
      free(escaped);
      continue;
    }
    char* full = path_cat(config->receive_root_directory, rel);
    if (!full) {
      ok = false;
      continue;
    }
    char* leaf = NULL;
    int parent_fd = file_open_secure_parent(full, &leaf, false);
    if (parent_fd < 0) {
      /* The mirror's parent directory may itself not exist on the destination
         (a deeper missing entry whose leading directories were never created).
         That is a no-op -- there is nothing to delete -- matching
         file_remove_tree_secure's absent-path handling; only a genuine I/O
         error (EACCES, a symlink loop, ...) fails the run. */
      bool absent = errno == ENOENT || errno == ENOTDIR;
      free(full);
      free(leaf);
      if (!absent)
        ok = false;
      continue;
    }
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) {
      /* Already absent: nothing to delete (a no-op, not a deletion). */
      if (errno != ENOENT)
        ok = false;
      close(parent_fd);
      free(leaf);
      free(full);
      continue;
    }
    /* An entry that exists is one deletion: skip it (and count it) when the
       shared --max-delete budget is already exhausted. */
    if (budget->deleted >= budget->max_delete) {
      budget->limit_hit = true;
      budget->skipped++;
      close(parent_fd);
      free(leaf);
      free(full);
      continue;
    }
    bool removed = false;
    if (S_ISDIR(st.st_mode)) {
      if (unlinkat(parent_fd, leaf, AT_REMOVEDIR) == 0) {
        removed = true;
      } else if (errno == ENOTEMPTY || errno == EEXIST) {
        close(parent_fd);
        parent_fd = -1;
        free(leaf);
        leaf = NULL;
        if (config->use_delete || config->force_delete) {
          /* Remove the contents entry-by-entry through the budgeted extras
             walker so every deleted file/dir counts toward --max-delete (rsync
             parity); the now-empty directory itself costs one more.  A run that
             hits the cap leaves the remaining entries in place. */
          ArrayList* no_keeps = array_list_create(free);
          /* Never let an accounting slip (deleted > max_delete) underflow the
             remaining budget into SIZE_MAX, which would grant unlimited
             deletions. */
          size_t remaining =
              budget->deleted >= budget->max_delete ? 0 : budget->max_delete - budget->deleted;
          size_t contents_deleted = 0;
          size_t contents_skipped = 0;
          PrefixedDeleteObserver nested = {observer, observer_context, rel};
          DeleteWalkResult walk =
              no_keeps ? delete_extras_limited_observed(full, no_keeps, NULL, remaining, NULL, 0,
                                                        NULL, &contents_deleted, &contents_skipped,
                                                        observer ? prefixed_delete_observer : NULL,
                                                        observer ? &nested : NULL)
                       : DELETE_WALK_ERROR;
          if (no_keeps)
            array_list_delete(no_keeps);
          budget->deleted += contents_deleted;
          budget->skipped += contents_skipped;
          if (walk == DELETE_WALK_LIMIT_REACHED) {
            budget->limit_hit = true;
          } else if (walk != DELETE_WALK_OK) {
            ok = false;
          } else if (budget->deleted >= budget->max_delete) {
            budget->limit_hit = true;
            budget->skipped++;
          } else if (file_remove_tree_secure(full)) {
            /* The shared `if (removed)` tail charges this directory exactly
               once; counting it here too would consume two budget units. */
            removed = true;
          } else {
            ok = false;
          }
        } else {
          char* escaped = output_escape(rel, log_get_8_bit_output());
          log_message(LOG_LEVEL_WARNING,
                      "missing-args destination '%s' is a non-empty directory; use --force or "
                      "--delete to remove it",
                      escaped ? escaped : "<allocation failed>");
          free(escaped);
        }
      } else if (errno != ENOENT) {
        ok = false;
      }
    } else {
      if (unlinkat(parent_fd, leaf, 0) == 0) {
        removed = true;
      } else if (errno != ENOENT) {
        ok = false;
      }
    }
    if (removed) {
      budget->deleted++;
      if (observer)
        observer(observer_context, rel, delete_entry_type_of_mode(st.st_mode));
      char* escaped = output_escape(rel, log_get_8_bit_output());
      fprintf(stderr, "  Deleted: %s\n", escaped ? escaped : "<allocation failed>");
      free(escaped);
    }
    if (parent_fd >= 0)
      close(parent_fd);
    free(leaf);
    free(full);
    if (!ok)
      break;
  }
  delete_skips_free(&skips);
  return ok;
}

/* Public wrappers used outside the commit path (and by unit tests): no
   --max-delete budget. */
bool manifest_would_delete_list(const Config* config, const DeleteManifest* manifest,
                                ArrayList* out, size_t* count_out) {
  if (count_out)
    *count_out = 0;
  if (!config || !manifest || !manifest->keeps || !out)
    return false;
  DeleteSkipSet skips;
  if (!delete_skips_build(config, manifest->protected, NULL, true, &skips))
    return false;
  bool ok = delete_extras_list(config->receive_root_directory, manifest->keeps, manifest->dirs,
                               skips.entries, skips.count, config->protect_rules, out, count_out);
  delete_skips_free(&skips);
  return ok;
}

bool manifest_delete_extras(const Config* config, const DeleteManifest* manifest) {
  DeleteBudgetState budget = {
      .max_delete = SIZE_MAX, .deleted = 0, .skipped = 0, .limit_hit = false};
  return delete_extras_budgeted(config, manifest, &budget);
}

bool manifest_delete_missing_args(const Config* config, const DeleteManifest* manifest) {
  DeleteBudgetState budget = {
      .max_delete = SIZE_MAX, .deleted = 0, .skipped = 0, .limit_hit = false};
  return delete_missing_args_budgeted_observed(config, manifest, &budget, NULL, NULL);
}

bool manifest_delete_missing_args_limited(const Config* config, const DeleteManifest* manifest,
                                          size_t max_delete, size_t* deleted, size_t* skipped,
                                          bool* limit_hit) {
  return manifest_delete_missing_args_limited_observed(config, manifest, max_delete, deleted,
                                                       skipped, limit_hit, NULL, NULL);
}

bool manifest_delete_missing_args_limited_observed(
    const Config* config, const DeleteManifest* manifest, size_t max_delete, size_t* deleted,
    size_t* skipped, bool* limit_hit, DeletePathObserver observer, void* observer_context) {
  DeleteBudgetState budget = {
      .max_delete = max_delete, .deleted = 0, .skipped = 0, .limit_hit = false};
  bool ok =
      delete_missing_args_budgeted_observed(config, manifest, &budget, observer, observer_context);
  if (deleted)
    *deleted = budget.deleted;
  if (skipped)
    *skipped = budget.skipped;
  if (limit_hit)
    *limit_hit = budget.limit_hit;
  return ok;
}

/* Commit every deletion family the manifest carries.  The --delete-missing-args
   exact-path deletions run FIRST: they are explicit user requests and must not
   be blocked by the extras walker's filter-exclusion protection (a protected
   leftover inside a missing-argument directory must not make that user-requested
   removal fail).  The ordinary extras walk then runs when --delete is active.
   Both draw from one --max-delete budget; the result reports a cap-stopped
   (partial) commit distinctly so the client can exit 25 like rsync. */
DeleteCommitResult manifest_delete_all(const Config* config, const DeleteManifest* manifest) {
  return manifest_delete_all_counted(config, manifest, NULL);
}

DeleteCommitResult manifest_delete_all_counted(const Config* config, const DeleteManifest* manifest,
                                               size_t* deleted) {
  return manifest_delete_all_observed(config, manifest, deleted, NULL, NULL);
}

DeleteCommitResult manifest_delete_all_observed(const Config* config,
                                                const DeleteManifest* manifest, size_t* deleted,
                                                DeletePathObserver observer,
                                                void* observer_context) {
  if (deleted)
    *deleted = 0;
  if (!config || !manifest)
    return DELETE_COMMIT_ERROR;
  /* Central no-mutation guard: a dry-run never deletes.  No manifest is sent on
     the dry-run path, but a hostile/buggy peer could; treat it as a no-op so
     the receiver can never remove anything. */
  if (config->dry_run)
    return DELETE_COMMIT_OK;
  /* A client --max-delete=NUM smaller than the server's hard bound replaces it
     for this run; both still bound the commit. */
  bool user_limited =
      config->max_delete >= 0 && (size_t)config->max_delete < MAX_SERVER_DELETE_COUNT;
  DeleteBudgetState budget = {.max_delete = user_limited ? (size_t)config->max_delete
                                                         : MAX_SERVER_DELETE_COUNT,
                              .deleted = 0,
                              .skipped = 0,
                              .limit_hit = false};
  if (config->delete_missing_args &&
      !delete_missing_args_budgeted_observed(config, manifest, &budget, observer, observer_context))
    return DELETE_COMMIT_ERROR;
  if (config->use_delete &&
      !delete_extras_budgeted_observed(config, manifest, &budget, observer, observer_context))
    return DELETE_COMMIT_ERROR;
  if (deleted)
    *deleted = budget.deleted;
  if (budget.limit_hit) {
    if (user_limited) {
      log_message(LOG_LEVEL_ERROR, "Deletions stopped due to --max-delete limit (%zu skipped)",
                  budget.skipped);
    } else {
      log_message(LOG_LEVEL_ERROR,
                  "Deletions stopped due to the server deletion limit of %u (%zu skipped)",
                  (unsigned)MAX_SERVER_DELETE_COUNT, budget.skipped);
    }
    return DELETE_COMMIT_LIMIT_REACHED;
  }
  return DELETE_COMMIT_OK;
}
