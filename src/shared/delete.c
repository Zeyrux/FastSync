#include "delete.h"

#include "delay_updates.h"
#include "filter.h"
#include "log.h"
#include "utils.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Build the keep-set index from the exact manifest entries only.  A lookup of
   `rel` succeeds iff `rel` is a kept entry, a kept directory, or an ancestor
   directory of kept content (the old is_dir_in_manifest predicate); the sorted
   view answers "is an ancestor of kept content" without materializing any
   per-component prefix copy, so the index is O(manifest size) memory. */
static bool build_keep_index(const ArrayList* manifest, PathIndex* index) {
  if (!manifest || manifest->size <= 0)
    return path_index_build(index, NULL, 0);
  return path_index_build(index, (const char* const*)manifest->items, (size_t)manifest->size);
}

static bool keep_is_dir(const PathIndex* index, const char* rel_path) {
  return path_index_contains(index, rel_path) || path_index_has_descendant(index, rel_path);
}

static bool keep_is_file(const PathIndex* index, const char* rel_path) {
  return path_index_contains(index, rel_path);
}

/* rsync's receiver-side verdict for one candidate extra: the per-directory
 * chain first (deepest directory before ancestors), then the command-line base
 * rules.  Either rule set may be absent. */
FilterAction delete_protect_verdict(const DeleteProtectRules* protect, const char* rel_path,
                                    const char* leaf, bool is_dir) {
  if (!protect)
    return FILTER_ACTION_NONE;
  /* rsync protects its own --backup files from the delete pass: a name ending
     in the backup suffix is never an extra.  Checked before the filter rules so
     an explicit exclude cannot be bypassed (the suffix is always a shield). */
  if (protect->backup_suffix && protect->backup_suffix[0] != '\0') {
    size_t name_len = strlen(leaf);
    size_t suffix_len = strlen(protect->backup_suffix);
    if (name_len > suffix_len &&
        strcmp(leaf + (name_len - suffix_len), protect->backup_suffix) == 0)
      return FILTER_ACTION_PROTECT;
  }
  FilterAction action = filter_dir_rules_apply_side(protect->dir_rules, rel_path, leaf, is_dir);
  if (action != FILTER_ACTION_NONE)
    return action;
  return filter_rules_apply_side(protect->base_rules, rel_path, leaf, is_dir, FILTER_SIDE_RECEIVER);
}

const char* delete_backup_suffix(const Config* config) {
  if (!config || !config->backup || config->ignore_existing)
    return NULL;
  const char* suffix = config->suffix ? config->suffix : "~";
  if (!suffix[0] || strchr(suffix, '/'))
    return NULL;
  return suffix;
}

/* Classify a removed entry from its st_mode for the per-type delete counters. */
DeleteEntryType delete_entry_type_of_mode(mode_t mode) {
  if (S_ISDIR(mode))
    return DELETE_ENTRY_DIR;
  if (S_ISLNK(mode))
    return DELETE_ENTRY_LINK;
  if (S_ISREG(mode))
    return DELETE_ENTRY_REG;
  return DELETE_ENTRY_SPECIAL;
}

/* True when child_rel is, or lies below, a protected entry.  A prefix "a"
   therefore protects "a" and "a/b/c" but not "ab".  Entries with top_level_only
   set only protect DIRECT children of the receive root (at_root); nested
   directories that share such a name stay ordinary destination content. */
bool path_under_skip_prefix(const char* child_rel, bool at_root, const DeleteSkipEntry* skips,
                            int skip_count) {
  for (int i = 0; i < skip_count; i++) {
    if (skips[i].top_level_only && !at_root)
      continue;
    size_t prefix_len = strlen(skips[i].prefix);
    if (strncmp(child_rel, skips[i].prefix, prefix_len) == 0 &&
        (child_rel[prefix_len] == '\0' || child_rel[prefix_len] == '/'))
      return true;
  }
  return false;
}

/* Per-run deletion budget and tallies.  `max_delete` is the cap on the number
   of entries the walker may remove (SIZE_MAX = unlimited); once it is reached
   the remaining extras are counted in `skipped` and left in place, matching
   rsync's partial --max-delete behavior. */
typedef struct {
  size_t max_delete;
  size_t deleted;
  size_t skipped;
  bool limit_hit;
} DeleteBudget;

/* True when direct children of the directory named by `rel` may be removed.
   With no synchronization info (dirs == NULL) the whole tree is deletable; when
   a dirs index is supplied only its exact entries are (the receive root is the
   "." sentinel). */
static bool is_synced_dir(const PathIndex* dirs, const char* rel) {
  if (!dirs)
    return true;
  return path_index_contains(dirs, rel[0] == '\0' ? "." : rel);
}

/* Unsigned byte-wise string compare, matching rsync's u_strcmp (a signed
   strcmp would order bytes >= 0x80 differently). */
static int delete_name_cmp(const char* a, const char* b) {
  const unsigned char* pa = (const unsigned char*)a;
  const unsigned char* pb = (const unsigned char*)b;
  while (*pa != '\0' && *pa == *pb) {
    pa++;
    pb++;
  }
  return (int)*pa - (int)*pb;
}

bool delete_dir_entries_collect(int dirfd, DeleteDirEntry** out, size_t* count,
                                bool* operation_ok) {
  *out = NULL;
  *count = 0;
  if (operation_ok)
    *operation_ok = true;
  int scanfd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (scanfd < 0)
    return false;
  DIR* dir = fdopendir(scanfd);
  if (!dir) {
    close(scanfd);
    return false;
  }
  DeleteDirEntry* entries = NULL;
  size_t used = 0;
  size_t capacity = 0;
  bool ok = true;
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    struct stat st;
    if (fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno != ENOENT && operation_ok)
        *operation_ok = false;
      continue;
    }
    if (used == capacity) {
      size_t next = capacity == 0 ? 16 : capacity * 2;
      DeleteDirEntry* grown = realloc(entries, next * sizeof(*grown));
      if (!grown) {
        ok = false;
        break;
      }
      entries = grown;
      capacity = next;
    }
    entries[used].name = str_dup(entry->d_name);
    if (!entries[used].name) {
      ok = false;
      break;
    }
    entries[used].is_dir = S_ISDIR(st.st_mode);
    entries[used].mode = st.st_mode;
    used++;
  }
  closedir(dir);
  if (!ok) {
    delete_dir_entries_free(entries, used);
    return false;
  }
  *out = entries;
  *count = used;
  return true;
}

void delete_dir_entries_free(DeleteDirEntry* entries, size_t count) {
  if (!entries)
    return;
  for (size_t i = 0; i < count; i++)
    free(entries[i].name);
  free(entries);
}

/* rsync's extraneous-entry order: subdirectories before files, each group in
   descending name order. */
int delete_dir_entry_cmp_desc(const void* a, const void* b) {
  const DeleteDirEntry* ea = a;
  const DeleteDirEntry* eb = b;
  if (ea->is_dir != eb->is_dir)
    return ea->is_dir ? -1 : 1;
  return -delete_name_cmp(ea->name, eb->name);
}

/* rsync's kept-subdirectory order: plain ascending name. */
int delete_dir_entry_cmp_asc(const void* a, const void* b) {
  const DeleteDirEntry* ea = a;
  const DeleteDirEntry* eb = b;
  return delete_name_cmp(ea->name, eb->name);
}

/* How the shared classification/descent walk disposes of an extra it has
   identified.  LIST records the destination-relative path without touching disk
   (the -n/--dry-run would-delete enumeration); DELETE unlinks/rmdirs it, charges
   the shared --max-delete budget and notifies the observer.  Both modes classify
   and traverse identically, so the dry-run enumeration and the real deletion
   cannot drift. */
typedef enum { DELETE_WALK_MODE_DELETE, DELETE_WALK_MODE_LIST } DeleteWalkMode;

typedef struct {
  DeleteWalkMode mode;
  DeleteBudget* budget;        /* DELETE mode */
  ArrayList* out;              /* LIST mode: receives strdup'd relative paths */
  size_t* recorded;            /* LIST mode */
  DeletePathObserver observer; /* DELETE mode */
  void* observer_context;      /* DELETE mode */
} DeleteWalkState;

/* The per-walk invariants threaded unchanged through every recursive descent:
   the keep/synchronized-dir indexes, the destination mode and the protection
   rules.  Bundling them keeps the recursive helpers below to a handful of
   positional arguments. */
typedef struct {
  const PathIndex* keep;
  const PathIndex* dirs;
  DeleteWalkState* state;
  const DeleteSkipEntry* skips;
  int skip_count;
  const DeleteProtectRules* protect;
} DeleteWalkContext;

/* Duplicate `path` with rsync's trailing-slash convention, used to report a
   removed (or would-be-removed) directory.  Returns NULL on allocation
   failure. */
static char* with_trailing_slash(const char* path) {
  size_t len = strlen(path);
  char* copy = malloc(len + 2);
  if (!copy)
    return NULL;
  memcpy(copy, path, len);
  copy[len] = '/';
  copy[len + 1] = '\0';
  return copy;
}

/* Forward declaration: the ordered passes below recurse through the driver. */
static bool delete_walk_fd(int dirfd, const char* rel_path, const DeleteWalkContext* ctx,
                           bool parent_deletable, bool* all_removed);

/* Descend into the child directory `name` of `dirfd`, walking it as part of the
   current operation.  Returns false on a genuine open/walk failure; on success
   *child_all_removed reports whether the child removed everything it held (so
   the caller may rmdir it). */
static bool delete_walk_child(int dirfd, const char* name, const char* child_rel,
                              const DeleteWalkContext* ctx, bool deletable,
                              bool* child_all_removed) {
  *child_all_removed = false;
  int childfd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (childfd < 0)
    return errno == ENOENT;
  bool ok = delete_walk_fd(childfd, child_rel, ctx, deletable, child_all_removed);
  close(childfd);
  return ok;
}

/* Classify every entry up front (the verdict does not depend on processing
   order) so the ordered passes below can act on it.  Sets shielded[]/is_extra[]
   and reports through *local_survives whether anything in this directory stays
   in place.  Returns false on a path-construction failure. */
static bool delete_walk_classify(const char* rel_path, const DeleteDirEntry* entries, size_t count,
                                 const DeleteWalkContext* ctx, bool deletable, bool at_root,
                                 bool* shielded, bool* is_extra, bool* local_survives) {
  bool ok = true;
  for (size_t i = 0; i < count; i++) {
    char* child_rel = path_cat((char*)rel_path, entries[i].name);
    if (!child_rel) {
      ok = false;
      continue;
    }
    /* A --delay-updates run keeps its staging directory as a direct child of
       the receive root, and basis-dir snapshots live below it too.  Their
       contents are not manifest entries, so descending into them would delete
       every staged / basis file as an "extra".  Only the staging name (a
       top-level-only prefix) and the basis prefixes are protected: a nested
       destination directory that happens to be called .fastsync-stage is
       ordinary content. */
    if (path_under_skip_prefix(child_rel, at_root, ctx->skips, ctx->skip_count)) {
      shielded[i] = true;
      *local_survives = true;
    } else if (delete_protect_verdict(ctx->protect, child_rel, entries[i].name,
                                      entries[i].is_dir) == FILTER_ACTION_PROTECT) {
      /* A first-match protect rule shields the extra; for a directory the whole
         subtree is shielded (rsync prunes an excluded directory), so do not
         descend. */
      shielded[i] = true;
      *local_survives = true;
    } else if (entries[i].is_dir) {
      bool child_synced = ctx->dirs && path_index_contains(ctx->dirs, child_rel);
      is_extra[i] = deletable && !child_synced && !keep_is_dir(ctx->keep, child_rel);
      if (!is_extra[i])
        *local_survives = true;
    } else {
      is_extra[i] = deletable && !keep_is_file(ctx->keep, child_rel);
      if (!is_extra[i])
        *local_survives = true;
    }
    free(child_rel);
  }
  return ok;
}

/* Pass 1: extraneous subdirectories, descending.  Recurses into each and, when
   the child removed everything it held, records or removes it and charges the
   budget. */
static bool delete_walk_extra_dirs(int dirfd, const char* rel_path, const DeleteDirEntry* entries,
                                   size_t dir_count, const DeleteWalkContext* ctx, bool deletable,
                                   const bool* is_extra, bool* local_survives) {
  bool ok = true;
  for (size_t i = 0; i < dir_count; i++) {
    if (!is_extra[i])
      continue;
    char* child_rel = path_cat((char*)rel_path, entries[i].name);
    if (!child_rel) {
      ok = false;
      continue;
    }
    bool child_all_removed = false;
    if (!delete_walk_child(dirfd, entries[i].name, child_rel, ctx, deletable, &child_all_removed))
      ok = false;
    if (child_all_removed && deletable) {
      if (ctx->state->mode == DELETE_WALK_MODE_LIST) {
        /* Record the directory with rsync's trailing slash. */
        char* copy = with_trailing_slash(child_rel);
        if (!copy) {
          ok = false;
        } else if (!array_list_add(ctx->state->out, copy)) {
          free(copy);
          ok = false;
        } else {
          (*ctx->state->recorded)++;
        }
      } else if (ctx->state->budget->deleted >= ctx->state->budget->max_delete) {
        ctx->state->budget->limit_hit = true;
        ctx->state->budget->skipped++;
        *local_survives = true;
      } else if (unlinkat(dirfd, entries[i].name, AT_REMOVEDIR) != 0) {
        /* ENOENT: already gone (fine).  ENOTEMPTY/EEXIST: the directory still
           holds entries the walker leaves in place (a protected excluded
           prefix, a kept file the manifest protects, a symlink); rsync leaves
           such a directory behind, so this is not an error.  Only genuine I/O
           failures abort the deletion. */
        if (errno != ENOENT && errno != ENOTEMPTY && errno != EEXIST)
          ok = false;
        *local_survives = true;
      } else {
        ctx->state->budget->deleted++;
        /* rsync reports a removed directory with a trailing slash. */
        if (ctx->state->observer) {
          char* with_slash = with_trailing_slash(child_rel);
          if (with_slash) {
            ctx->state->observer(ctx->state->observer_context, with_slash, DELETE_ENTRY_DIR);
            free(with_slash);
          } else {
            ctx->state->observer(ctx->state->observer_context, child_rel, DELETE_ENTRY_DIR);
          }
        }
      }
    } else {
      *local_survives = true;
    }
    free(child_rel);
  }
  return ok;
}

/* Pass 2: extraneous files, descending. */
static bool delete_walk_extra_files(int dirfd, const char* rel_path, const DeleteDirEntry* entries,
                                    size_t dir_count, size_t count, const DeleteWalkContext* ctx,
                                    const bool* is_extra, bool* local_survives) {
  bool ok = true;
  for (size_t i = dir_count; i < count; i++) {
    if (!is_extra[i])
      continue;
    if (ctx->state->mode == DELETE_WALK_MODE_LIST) {
      char* child_rel = path_cat((char*)rel_path, entries[i].name);
      if (!child_rel) {
        ok = false;
        continue;
      }
      char* copy = str_dup(child_rel);
      if (!copy || !array_list_add(ctx->state->out, copy)) {
        free(copy);
        ok = false;
      } else {
        (*ctx->state->recorded)++;
      }
      free(child_rel);
    } else if (ctx->state->budget->deleted >= ctx->state->budget->max_delete) {
      ctx->state->budget->limit_hit = true;
      ctx->state->budget->skipped++;
      *local_survives = true;
    } else if (unlinkat(dirfd, entries[i].name, 0) != 0) {
      if (errno != ENOENT)
        ok = false;
      *local_survives = true;
    } else {
      ctx->state->budget->deleted++;
      char* child_rel = path_cat((char*)rel_path, entries[i].name);
      if (child_rel) {
        if (ctx->state->observer)
          ctx->state->observer(ctx->state->observer_context, child_rel,
                               delete_entry_type_of_mode(entries[i].mode));
        char* escaped_path = output_escape(child_rel, log_get_8_bit_output());
        fprintf(stderr, "  Deleted: %s\n", escaped_path ? escaped_path : "<allocation failed>");
        free(escaped_path);
      }
      free(child_rel);
    }
  }
  return ok;
}

/* Pass 3: kept subdirectories, ascending (rsync descends into these only after
   the parent's own extras have been handled). */
static bool delete_walk_kept_dirs(int dirfd, const char* rel_path, const DeleteDirEntry* entries,
                                  size_t dir_count, const DeleteWalkContext* ctx, bool deletable,
                                  const bool* is_extra, const bool* shielded,
                                  bool* local_survives) {
  bool ok = true;
  for (size_t i = dir_count; i-- > 0;) {
    if (is_extra[i] || shielded[i])
      continue;
    char* child_rel = path_cat((char*)rel_path, entries[i].name);
    if (!child_rel) {
      ok = false;
      continue;
    }
    bool child_all_removed = false;
    if (!delete_walk_child(dirfd, entries[i].name, child_rel, ctx, deletable, &child_all_removed))
      ok = false;
    /* A kept/synchronized directory is never removed. */
    *local_survives = true;
    free(child_rel);
  }
  return ok;
}

/* Remove the extras directly inside the directory open on `dirfd` (DELETE mode)
   or record the paths that WOULD be removed (LIST mode), recursing into every
   child directory so kept content below a synchronized prefix is reached.
   `all_removed` reports whether every child entry was removed (so the caller may
   rmdir this directory).  A child directory is never removed when it is itself a
   synchronized directory or holds kept content; with a dirs index supplied,
   direct children of a non-synchronized directory are never extras at all (they
   are left in place but still descended into).  Symlinks are unlinked like any
   other non-directory extra (never followed).

   Entries are processed in rsync's order (extraneous subdirectories in
   descending name order, then extraneous files, then kept subdirectories in
   ascending order) rather than readdir() order, so `--max-delete` leaves the
   same survivors and the `--info=del`/dry-run line order matches rsync. */
static bool delete_walk_fd(int dirfd, const char* rel_path, const DeleteWalkContext* ctx,
                           bool parent_deletable, bool* all_removed) {
  DeleteDirEntry* entries = NULL;
  size_t count = 0;
  bool collect_ok = true;
  if (!delete_dir_entries_collect(dirfd, &entries, &count, &collect_ok))
    return false;
  bool operation_ok = collect_ok;
  bool local_survives = false;
  bool* shielded = calloc(count ? count : 1, sizeof(bool));
  bool* is_extra = calloc(count ? count : 1, sizeof(bool));
  if (!shielded || !is_extra) {
    free(shielded);
    free(is_extra);
    delete_dir_entries_free(entries, count);
    return false;
  }
  /* A directory is deletable when it or ANY ancestor is synchronized; the
     `parent_deletable` flag carries that down the recursion so dest-only
     directories below a synchronized root are removed wholesale. */
  bool deletable = parent_deletable || is_synced_dir(ctx->dirs, rel_path);
  bool at_root = rel_path[0] == '\0';

  /* Reproduce rsync's traversal order: extraneous subdirectories in descending
     name order, then extraneous files in descending name order, and kept
     subdirectories only afterwards (ascending).  Sorting up front also fixes the
     identity of the survivors under a partial --max-delete. */
  if (count > 1)
    qsort(entries, count, sizeof(*entries), delete_dir_entry_cmp_desc);
  size_t dir_count = 0;
  while (dir_count < count && entries[dir_count].is_dir)
    dir_count++;

  if (!delete_walk_classify(rel_path, entries, count, ctx, deletable, at_root, shielded, is_extra,
                            &local_survives))
    operation_ok = false;
  if (!delete_walk_extra_dirs(dirfd, rel_path, entries, dir_count, ctx, deletable, is_extra,
                              &local_survives))
    operation_ok = false;
  if (!delete_walk_extra_files(dirfd, rel_path, entries, dir_count, count, ctx, is_extra,
                               &local_survives))
    operation_ok = false;
  if (!delete_walk_kept_dirs(dirfd, rel_path, entries, dir_count, ctx, deletable, is_extra,
                             shielded, &local_survives))
    operation_ok = false;

  free(shielded);
  free(is_extra);
  delete_dir_entries_free(entries, count);
  *all_removed = !local_survives;
  return operation_ok;
}

/* Open the receive root following the same authorized-root confinement the
   walker uses, or dest_root directly when no authorized root is installed. */
static int open_destination_root(const char* dest_root) {
  int root_fd = utils_get_authorized_root_fd();
  if (root_fd >= 0) {
    if (utils_get_authorized_root_path())
      return utils_open_authorized_destination(dest_root);
    if (dest_root == NULL)
      return dup(root_fd);
    return -1;
  }
  return open(dest_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

bool delete_extras_list(const char* dest_root, const ArrayList* manifest,
                        const ArrayList* synced_dirs, const DeleteSkipEntry* skips, int skip_count,
                        const DeleteProtectRules* protect, ArrayList* out, size_t* count_out) {
  if (count_out)
    *count_out = 0;
  if (!manifest || !out)
    return false;
  PathIndex keep;
  if (!build_keep_index(manifest, &keep))
    return false;
  PathIndex dirs;
  bool have_dirs = synced_dirs != NULL;
  if (have_dirs &&
      !path_index_build(&dirs, (const char* const*)synced_dirs->items, (size_t)synced_dirs->size)) {
    path_index_free(&keep);
    return false;
  }
  int rootfd = open_destination_root(dest_root);
  if (rootfd < 0) {
    path_index_free(&keep);
    if (have_dirs)
      path_index_free(&dirs);
    return false;
  }
  bool all_removed = false;
  size_t recorded = 0;
  DeleteWalkState state = {.mode = DELETE_WALK_MODE_LIST,
                           .budget = NULL,
                           .out = out,
                           .recorded = &recorded,
                           .observer = NULL,
                           .observer_context = NULL};
  DeleteWalkContext ctx = {.keep = &keep,
                           .dirs = have_dirs ? &dirs : NULL,
                           .state = &state,
                           .skips = skips,
                           .skip_count = skip_count,
                           .protect = protect};
  bool ok = delete_walk_fd(rootfd, "", &ctx, false, &all_removed);
  if (close(rootfd) != 0)
    ok = false;
  path_index_free(&keep);
  if (have_dirs)
    path_index_free(&dirs);
  if (count_out)
    *count_out = recorded;
  return ok;
}

DeleteWalkResult delete_extras_limited_observed(const char* dest_root, const ArrayList* manifest,
                                                const ArrayList* synced_dirs, size_t max_delete,
                                                const DeleteSkipEntry* skips, int skip_count,
                                                const DeleteProtectRules* protect,
                                                size_t* deleted_out, size_t* skipped_out,
                                                DeletePathObserver observer,
                                                void* observer_context) {
  if (deleted_out)
    *deleted_out = 0;
  if (skipped_out)
    *skipped_out = 0;
  if (!manifest)
    return DELETE_WALK_ERROR;
  /* Index the keep-set (and the synchronized-dir set, when supplied) once so
     membership is answered in O(path length) instead of scanning every entry
     for every destination entry. */
  PathIndex keep;
  if (!build_keep_index(manifest, &keep))
    return DELETE_WALK_ERROR;
  PathIndex dirs;
  bool have_dirs = synced_dirs != NULL;
  if (have_dirs &&
      !path_index_build(&dirs, (const char* const*)synced_dirs->items, (size_t)synced_dirs->size)) {
    path_index_free(&keep);
    return DELETE_WALK_ERROR;
  }
  int rootfd = open_destination_root(dest_root);
  if (rootfd < 0) {
    path_index_free(&keep);
    if (have_dirs)
      path_index_free(&dirs);
    return DELETE_WALK_ERROR;
  }
  DeleteBudget budget = {.max_delete = max_delete, .deleted = 0, .skipped = 0, .limit_hit = false};
  bool all_removed = false;
  DeleteWalkState state = {.mode = DELETE_WALK_MODE_DELETE,
                           .budget = &budget,
                           .out = NULL,
                           .recorded = NULL,
                           .observer = observer,
                           .observer_context = observer_context};
  DeleteWalkContext ctx = {.keep = &keep,
                           .dirs = have_dirs ? &dirs : NULL,
                           .state = &state,
                           .skips = skips,
                           .skip_count = skip_count,
                           .protect = protect};
  bool ok = delete_walk_fd(rootfd, "", &ctx, false, &all_removed);
  if (close(rootfd) != 0)
    ok = false;
  path_index_free(&keep);
  if (have_dirs)
    path_index_free(&dirs);
  if (deleted_out)
    *deleted_out = budget.deleted;
  if (skipped_out)
    *skipped_out = budget.skipped;
  if (!ok)
    return DELETE_WALK_ERROR;
  return budget.limit_hit ? DELETE_WALK_LIMIT_REACHED : DELETE_WALK_OK;
}

DeleteWalkResult delete_extras_limited(const char* dest_root, const ArrayList* manifest,
                                       const ArrayList* synced_dirs, size_t max_delete,
                                       const DeleteSkipEntry* skips, int skip_count,
                                       const DeleteProtectRules* protect, size_t* deleted_out,
                                       size_t* skipped_out) {
  return delete_extras_limited_observed(dest_root, manifest, synced_dirs, max_delete, skips,
                                        skip_count, protect, deleted_out, skipped_out, NULL, NULL);
}

bool delete_extras(const char* dest_root, const ArrayList* manifest) {
  return delete_extras_limited(dest_root, manifest, NULL, SIZE_MAX, NULL, 0, NULL, NULL, NULL) ==
         DELETE_WALK_OK;
}

/* Build the delete-walk protection prefix for one basis directory.  The walker
   compares paths relative to the receive root, so a relative entry is already
   in the right form; an absolute entry that lies below the root is converted to
   its root-relative form, and one outside the root returns NULL (the walk
   cannot reach it, and it is not protected data beneath the root).  Exposed so
   tests can exercise the root-of-"/" child mapping directly. */
char* delete_basis_relative(const Config* config, const char* path) {
  if (!path)
    return NULL;
  if (path[0] != '/')
    return str_dup(path);
  const char* root = config->receive_root_directory;
  if (!root || root[0] != '/')
    return NULL;
  size_t root_len = strlen(root);
  while (root_len > 1 && root[root_len - 1] == '/')
    root_len--;
  if (strncmp(path, root, root_len) != 0)
    return NULL;
  if (root_len == 1) {
    /* `root` is "/" (the only single-character absolute root): every absolute
       path is below it, and the child relative form is everything after the
       leading '/'. */
    if (path[1] == '\0')
      return NULL; /* identical to the root, not a child */
    return str_dup(path + 1);
  }
  if (path[root_len] != '/')
    return NULL; /* identical or a sibling sharing a name prefix */
  return str_dup(path + root_len + 1);
}

bool delete_skips_build(const Config* config, const ArrayList* protected_paths,
                        const ArrayList* size_skipped, bool basis_root_relative,
                        DeleteSkipSet* out) {
  if (!out)
    return false;
  out->entries = NULL;
  out->owned_prefixes = NULL;
  out->count = 0;
  out->owned_count = 0;
  if (!config)
    return false;
  int protected_count = protected_paths ? protected_paths->size : 0;
  int size_skipped_count = size_skipped ? size_skipped->size : 0;
  int count =
      (config->delay_updates ? 1 : 0) + config->basis_count + protected_count + size_skipped_count;
  if (count == 0)
    return true;
  out->entries = calloc((size_t)count, sizeof(DeleteSkipEntry));
  if (!out->entries)
    return false;
  if (basis_root_relative && config->basis_count > 0) {
    out->owned_prefixes = calloc((size_t)config->basis_count, sizeof(char*));
    if (!out->owned_prefixes) {
      free(out->entries);
      out->entries = NULL;
      return false;
    }
    out->owned_count = config->basis_count;
  }
  int idx = 0;
  if (config->delay_updates) {
    /* Protect this transfer's actual (per-run unique) staging directory.  The
       runtime name is only known to the receiver-side context; fall back to the
       reserved prefix for a context that was never created (e.g. a dry run). */
    const char* staging_name = (config->delay_context && config->delay_context->staging_name)
                                   ? config->delay_context->staging_name
                                   : DELAY_UPDATES_STAGING_DIR;
    out->entries[idx].prefix = staging_name;
    out->entries[idx].top_level_only = true;
    idx++;
  }
  for (int i = 0; i < config->basis_count; i++) {
    const char* prefix = config->basis_dirs[i].path;
    if (basis_root_relative) {
      /* An absolute basis outside the receive root is unreachable by this walk,
         so it contributes no protection prefix (and no slot). */
      char* relative = delete_basis_relative(config, config->basis_dirs[i].path);
      if (!relative)
        continue;
      out->owned_prefixes[i] = relative;
      prefix = relative;
    }
    out->entries[idx].prefix = prefix;
    out->entries[idx].top_level_only = false;
    idx++;
  }
  for (int i = 0; i < protected_count; i++) {
    out->entries[idx].prefix = (const char*)protected_paths->items[i];
    out->entries[idx].top_level_only = false;
    idx++;
  }
  for (int i = 0; i < size_skipped_count; i++) {
    out->entries[idx].prefix = (const char*)size_skipped->items[i];
    out->entries[idx].top_level_only = false;
    idx++;
  }
  out->count = idx;
  return true;
}

void delete_skips_free(DeleteSkipSet* set) {
  if (!set)
    return;
  if (set->owned_prefixes) {
    for (int i = 0; i < set->owned_count; i++)
      free(set->owned_prefixes[i]);
  }
  free(set->owned_prefixes);
  free(set->entries);
  set->entries = NULL;
  set->owned_prefixes = NULL;
  set->count = 0;
  set->owned_count = 0;
}
