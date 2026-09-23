#ifndef DELETE_H
#define DELETE_H

#include "array_list.h"
#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

/* Delete engine.
 *
 * This module owns destination-relative delete traversal: the ordered directory
 * walker that reproduces rsync's extraneous-entry order, the skip-prefix
 * protection set shared by every delete pass, and the read-only enumeration
 * that mirrors the walker for -n/--dry-run.  The budgeted manifest commit
 * (delete_commit.c) and the per-directory delete plans (delete_plan.c) are
 * built on the primitives exported here. */

/* Result of a bounded extra-file deletion run. */
typedef enum {
  /* Every extra entry was removed (or there were none). */
  DELETE_WALK_OK = 0,
  /* The numeric cap for this run was reached before every extra was removed.
     The walker removed exactly the entries the cap allowed and skipped (without
     removing) the rest, matching rsync's partial --max-delete behavior. */
  DELETE_WALK_LIMIT_REACHED,
  /* A traversal or unlink failure aborted the deletion (partial removal is
     possible, mirroring the delete pass). */
  DELETE_WALK_ERROR
} DeleteWalkResult;

/* One protected entry for the delete walker.  When top_level_only is true the
   prefix is skipped only as a DIRECT child of dest_root (the --delay-updates
   staging directory, which must not hide genuine extras inside a nested
   destination directory that happens to share the staging name); otherwise the
   prefix is skipped at any depth (the --compare-dest/--copy-dest/--link-dest
   basis trees, and the sender-side protected filter-excluded prefixes, which
   are never destination content). */
typedef struct {
  const char* prefix;
  bool top_level_only;
} DeleteSkipEntry;

/* A built skip-prefix set.  `entries`/`count` are what path_under_skip_prefix()
   consumes.  `owned_prefixes` holds any prefix strings the builder had to
   allocate (root-relative basis-dir conversions); it is NULL when every prefix
   is borrowed from the config or the caller's lists.  Release with
   delete_skips_free(). */
typedef struct {
  DeleteSkipEntry* entries;
  char** owned_prefixes;
  int count;
  int owned_count;
} DeleteSkipSet;

/* True when child_rel is, or lies below, one of the protected entries (a prefix
   "a" protects "a" and "a/b/c" but not "ab"; top_level_only entries protect
   only DIRECT children of the destination root, i.e. child_rel has no '/'). */
bool path_under_skip_prefix(const char* child_rel, bool at_root, const DeleteSkipEntry* skips,
                            int skip_count);

/* One destination-directory entry collected up front so the delete walkers can
   reproduce rsync's traversal order instead of readdir() order.  rsync processes
   a directory's extraneous subdirectories first (descending name, depth-first),
   then its extraneous files (descending name), and only afterwards descends into
   its kept subdirectories (ascending name). */
typedef struct {
  char* name;
  bool is_dir;
  /* The entry's full st_mode from the AT_SYMLINK_NOFOLLOW stat, so a delete
     observer can classify a removed non-directory as reg/link/special. */
  mode_t mode;
} DeleteDirEntry;
/* Collect the entries of the directory open on `dirfd` (excluding "." and ".."),
   stat'ing each with AT_SYMLINK_NOFOLLOW.  On success *out is a malloc'd array of
   *count entries whose names the caller frees with delete_dir_entries_free().
   Returns false on an allocation/readdir failure; a vanished entry (ENOENT) is
   skipped, any other stat failure is reported through *operation_ok while the
   walk continues. */
bool delete_dir_entries_collect(int dirfd, DeleteDirEntry** out, size_t* count, bool* operation_ok);
void delete_dir_entries_free(DeleteDirEntry* entries, size_t count);
/* Sort comparators: `_desc` orders subdirectories before files and each group by
   descending name (rsync's extraneous-entry order); `_asc` orders plain ascending
   name (rsync's kept-subdirectory order). */
int delete_dir_entry_cmp_desc(const void* a, const void* b);
int delete_dir_entry_cmp_asc(const void* a, const void* b);

/* Remove files/dirs/symlinks under dest_root that are not listed in manifest
   without ever descending into a protected prefix (see DeleteSkipEntry).  When
   `synced_dirs` is non-NULL, extras are only removed directly inside a directory
   whose destination-relative path is an exact entry in that list (the receive
   root is the "." sentinel); directories outside the synchronized set are still
   descended into so kept content below a listed directory is preserved, but
   nothing in them is removed.  A NULL `synced_dirs` keeps the legacy behavior of
   treating the whole destination tree as deletable.  `max_delete` caps the
   number of removed entries (SIZE_MAX = unlimited): the walker removes up to the
   cap and returns DELETE_WALK_LIMIT_REACHED when more extras remained.
   `deleted_out`/`skipped_out` optionally receive the number of entries removed
   and the number skipped because of the cap. */
DeleteWalkResult delete_extras_limited(const char* dest_root, const ArrayList* manifest,
                                       const ArrayList* synced_dirs, size_t max_delete,
                                       const DeleteSkipEntry* skips, int skip_count,
                                       const FilterRuleList* protect_rules, size_t* deleted_out,
                                       size_t* skipped_out);

/* Entry kind of a removed path, reported to the delete observer so the receiver
   can build rsync's `--stats` `Number of deleted files` per-type breakdown.  The
   four categories are a strict partition of every removed entry. */
typedef enum {
  DELETE_ENTRY_REG = 0,
  DELETE_ENTRY_DIR,
  DELETE_ENTRY_LINK,
  DELETE_ENTRY_SPECIAL
} DeleteEntryType;

/* Optional per-deletion observer: called for each destination-relative path
   actually removed (a file, symlink, or directory) with its entry kind, in
   removal order, so the receiver can stream rsync's `--info=del`/`--info=remove`
   lines and tally the per-type `--stats` counters. */
typedef void (*DeletePathObserver)(void* context, const char* rel_path, DeleteEntryType type);

/* Classify a removed entry from its st_mode for the per-type delete counters. */
DeleteEntryType delete_entry_type_of_mode(mode_t mode);

/* `delete_extras_limited_observed` is delete_extras_limited with an optional
 * observer; the observer is invoked only for entries truly removed.  When
 * `protect_rules` is non-NULL its receiver-side verdict is evaluated for every
 * candidate extra: a first-match PROTECT leaves the entry (and, for a
 * directory, its whole subtree) in place, while RISK/NONE fall through to the
 * ordinary skip-prefix/keep-set logic. */
DeleteWalkResult delete_extras_limited_observed(const char* dest_root, const ArrayList* manifest,
                                                const ArrayList* synced_dirs, size_t max_delete,
                                                const DeleteSkipEntry* skips, int skip_count,
                                                const FilterRuleList* protect_rules,
                                                size_t* deleted_out, size_t* skipped_out,
                                                DeletePathObserver observer,
                                                void* observer_context);
/* Read-only companion to delete_extras_limited: walk the destination exactly as
   the delete pass would and APPEND (strdup'd) destination-relative paths that
   WOULD be removed, without touching disk.  Used for -n/--dry-run --delete
   would-delete reporting.  Returns true on a clean walk; the caller owns the
   strings appended to `out` and receives their count in *count_out. */
bool delete_extras_list(const char* dest_root, const ArrayList* manifest,
                        const ArrayList* synced_dirs, const DeleteSkipEntry* skips, int skip_count,
                        const FilterRuleList* protect_rules, ArrayList* out, size_t* count_out);
bool delete_extras(const char* dest_root, const ArrayList* manifest);

/* Build the delete walk's skip-prefix set from the config's --delay-updates
   staging directory, its --compare-dest/--copy-dest/--link-dest basis dirs, and
   the caller-supplied protection lists, in that order.  `protected_paths` and
   `size_skipped` are borrowed (may be NULL); every entry in them is protected at
   any depth.  The staging directory is protected only as a DIRECT child of the
   receive root.  `basis_root_relative` selects how a basis path becomes a
   prefix: true converts an absolute path under the receive root to its
   root-relative form (the whole-tree commit walk; an unreachable path
   contributes no slot), false keeps the configured path verbatim (the
   per-directory plan walk).  On success the caller releases `*out` with
   delete_skips_free(); returns false on allocation failure. */
bool delete_skips_build(const Config* config, const ArrayList* protected_paths,
                        const ArrayList* size_skipped, bool basis_root_relative,
                        DeleteSkipSet* out);
void delete_skips_free(DeleteSkipSet* set);

/* Convert one basis-directory path to the receive-root-relative protection
   prefix the delete walker uses (NULL when it lies outside the root).  Exposed
   for unit tests of the root-of-"/" and normalization edge cases. */
char* delete_basis_relative(const Config* config, const char* path);

#endif
