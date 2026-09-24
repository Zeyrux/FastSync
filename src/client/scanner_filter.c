#include "log.h"
#include "scanner.h"
#include "scanner_internal.h"
#include "array_list.h"
#include "chunk.h"
#include "file.h"
#include "queue.h"
#include "utils.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <threads.h>
#include <unistd.h>
#include <limits.h>

#include "xattr.h"

/* A chain node: `own` holds the .rsync-filter rules of one directory, `parent`
 * the context that directory inherited (nearest ancestor with a filter file).
 * The chain for a directory's contents runs from that directory's own node up
 * to the root; the command-line base rules are evaluated after the whole
 * chain. */
struct FilterNode {
  FilterNode* parent;
  FilterRuleList* own;
};

void filter_node_destroy(void* item) {
  if (item) {
    FilterNode* node = (FilterNode*)item;
    if (node->own)
      filter_rule_list_free(node->own);
    free(node);
  }
}

FilterNode* filter_node_alloc(FilterNode* parent, FilterRuleList* own) {
  FilterNode* node = malloc(sizeof(FilterNode));
  if (!node)
    return NULL;
  node->parent = parent;
  node->own = own;
  return node;
}

/* Evaluate a rule chain for one entry.  rsync precedence, highest first: the
 * innermost (current) directory's .rsync-filter rules, then each ancestor's,
 * then the root's, and finally the command-line base rules (--filter/-C).  The
 * sender-side verdict decides whether the entry is hidden from the transfer;
 * the receiver-side verdict decides whether its destination mirror is protected
 * from --delete.  Each side takes the FIRST matching rule independently. */
typedef struct {
  bool hide;    /* sender-side exclude matched */
  bool protect; /* receiver-side exclude matched */
} FilterOutcome;

static void chain_rules_outcome(const FilterRuleList* base, const FilterNode* node, const char* rel,
                                const char* leaf, bool is_dir, FilterOutcome* out) {
  memset(out, 0, sizeof(*out));
  bool sender_decided = false;
  bool receiver_decided = false;
  const FilterNode* n = node;
  while (!sender_decided || !receiver_decided) {
    const FilterRuleList* list = n ? n->own : base;
    if (list) {
      if (!sender_decided) {
        FilterAction action = filter_rules_apply_side(list, rel, leaf, is_dir, FILTER_SIDE_SENDER);
        if (action != FILTER_ACTION_NONE) {
          out->hide = action == FILTER_ACTION_EXCLUDE;
          sender_decided = true;
        }
      }
      if (!receiver_decided) {
        FilterAction action =
            filter_rules_apply_side(list, rel, leaf, is_dir, FILTER_SIDE_RECEIVER);
        if (action != FILTER_ACTION_NONE) {
          out->protect = action == FILTER_ACTION_PROTECT;
          receiver_decided = true;
        }
      }
    }
    if (!n)
      break;
    n = n->parent;
  }
}

static bool entry_allowed(const FilterRuleList* base, const FilterNode* node, const char* rel,
                          const char* leaf, bool is_dir, bool exclude_filter_files,
                          bool* protect_out) {
  /* -FF: per-directory .rsync-filter files are never transferred (single -F
     transfers them, matching rsync). */
  if (exclude_filter_files && !is_dir && strcmp(leaf, ".rsync-filter") == 0) {
    if (protect_out)
      *protect_out = false;
    return false;
  }
  FilterOutcome outcome;
  chain_rules_outcome(base, node, rel, leaf, is_dir, &outcome);
  if (protect_out)
    *protect_out = outcome.protect;
  return !outcome.hide;
}

void dir_entry_destroy(void* item) {
  if (item) {
    DirEntry* de = (DirEntry*)item;
    free(de->path);
    free(de);
  }
}

DirEntry* dir_entry_create(const char* path, int depth, FilterNode* context) {
  DirEntry* de = malloc(sizeof(DirEntry));
  if (!de)
    return NULL;
  de->path = str_dup(path);
  if (!de->path) {
    free(de);
    return NULL;
  }
  de->depth = depth;
  de->context = context;
  return de;
}

/* Apply rsync's symlink-resolution precedence to one S_ISLNK entry:
 *   --copy-links  dereferences every symlink;
 *   --copy-unsafe-links  dereferences only targets unsafe_symlink() flags;
 *   -k/--copy-dirlinks  dereferences only a symlink whose referent is a dir;
 *   --safe-links  (receiver-side in rsync; modelled here) ignores an unsafe
 *                 target that would otherwise be carried; with --munge-links
 *                 every stored target becomes absolute, so --safe-links then
 *                 ignores every symlink, exactly as rsync documents;
 *   -l/--links  carries the link.
 * `link_rel` is the symlink's transfer-relative path (incl. name) and is used
 * only for the lexical unsafe test.  `target` receives the raw link value. */
LinkAction scanner_link_action(const ScannerOptions* options, const char* path,
                               const char* link_rel, char* target, size_t target_size) {
  if (!options->follow_symlinks && !options->copy_links && !options->safe_links &&
      !options->copy_unsafe_links && !options->copy_dirlinks)
    return LINK_ACTION_SKIP;
  ssize_t length = readlink(path, target, target_size - 1);
  if (length < 0)
    return LINK_ACTION_SKIP;
  target[length] = '\0';

  bool unsafe = file_symlink_unsafe(target, link_rel);
  if (options->copy_links || (options->copy_unsafe_links && unsafe))
    return LINK_ACTION_DEREF;
  if (options->copy_dirlinks) {
    struct stat ref;
    if (stat(path, &ref) == 0 && S_ISDIR(ref.st_mode))
      return LINK_ACTION_DEREF;
  }
  if (options->safe_links && (unsafe || options->munge_links))
    return LINK_ACTION_SKIP_PROTECTED;
  if (!options->follow_symlinks || target[0] == '\0')
    return LINK_ACTION_SKIP;
  return LINK_ACTION_CARRY;
}

/* --one-file-system (-x) decision. Only directories can carry a different
 * device than their parent (mount points), so this is checked when a child
 * directory is about to be descended into. */
bool scanner_same_filesystem(int one_file_system, dev_t root_device, dev_t entry_device) {
  return one_file_system <= 0 || entry_device == root_device;
}

/* Build a payload-less directory File carrying the captured metadata (when
 * requested).  Used by -x mount-point emission and --list-only directory
 * entries.  Returns NULL on allocation failure. */
File* scanner_build_dir_file(const char* path, const struct stat* stats,
                             const ScannerOptions* options) {
  File* dir = file_create(path);
  if (dir == NULL)
    return NULL;
  dir->is_dir = true;
  if (options->use_metadata) {
    dir->metadata =
        file_metadata_create(dir->path, stats, options->preserve_atimes, options->preserve_crtimes);
    if (!dir->metadata) {
      file_destroy(dir);
      return NULL;
    }
  }
  return dir;
}

/* Relative path of an on-disk path below `root`. The transfer root may be
 * given with a trailing slash; the returned rel path never has one and is ""
 * for the root itself. A root of "/" is handled (its children start at "/").
 * Exposed so tests can exercise the mapping directly. */
char* scanner_path_relative(const char* root, const char* fs_path) {
  size_t root_len = strlen(root);
  while (root_len > 1 && root[root_len - 1] == '/')
    root_len--;
  if (strncmp(root, fs_path, root_len) != 0)
    return NULL;
  if (root_len == 1 && root[0] == '/') {
    if (fs_path[1] == '\0')
      return str_dup("");
    return str_dup(fs_path + 1);
  }
  if (fs_path[root_len] == '\0')
    return str_dup("");
  if (fs_path[root_len] != '/')
    return NULL;
  return str_dup(fs_path + root_len + 1);
}

/* -R/--relative destination-relative prefix reconstructed from a source spec:
 * everything after the first '.' path component (rsync's '/./' cut point),
 * with leading/trailing slashes removed; or the whole spec (normalized) when
 * there is no cut.  Returns "" for the receive root.  Exposed for tests. */
char* scanner_relative_prefix(const char* spec) {
  if (!spec || spec[0] == '\0')
    return NULL;
  const char* after = spec;
  if (spec[0] == '.' && spec[1] == '/') {
    after = spec + 2;
  } else {
    const char* cut = strstr(spec, "/./");
    if (cut)
      after = cut + 3;
  }
  size_t cap = strlen(spec) + 1;
  char* out = malloc(cap);
  if (!out)
    return NULL;
  size_t len = 0;
  for (const char* s = after; *s;) {
    while (*s == '/')
      s++;
    const char* comp = s;
    while (*s && *s != '/')
      s++;
    size_t clen = (size_t)(s - comp);
    if (clen == 0 || (clen == 1 && comp[0] == '.'))
      continue;
    if (len)
      out[len++] = '/';
    memcpy(out + len, comp, clen);
    len += clen;
  }
  out[len] = '\0';
  return out;
}

/* Relative path of a child entry below the current directory. */
char* child_rel_path(const char* parent_rel, const char* name) {
  if (!parent_rel || parent_rel[0] == '\0')
    return str_dup(name);
  return path_cat(parent_rel, name);
}

/* Destination-relative wire path for an entry under an -R prefix. */
char* scanner_prefix_send_path(const char* prefix, const char* rel) {
  if (prefix[0] == '\0')
    return str_dup(rel);
  if (rel[0] == '\0')
    return str_dup(prefix);
  return path_cat(prefix, rel);
}

/* Apply the --files-from allow-set and the filter layer to one entry.  On
 * return `*protect_out` is true when a receiver-side rule protects the entry's
 * destination mirror from deletion. */
bool entry_passes_selection(const FileListSet* file_list, const FilterRuleList* base,
                            const FilterNode* node, const char* rel, const char* leaf, bool is_dir,
                            bool per_dir_filters, bool exclude_filter_files, bool* protect_out) {
  if (protect_out)
    *protect_out = false;
  if (file_list && !file_list_affects(file_list, rel))
    return false;
  if (base || per_dir_filters)
    return entry_allowed(base, node, rel, leaf, is_dir, exclude_filter_files, protect_out);
  return true;
}

/* Best-effort capture of the file's whitelisted xattrs (-X/-A).  A failure to
 * read xattrs is non-fatal: the file is transferred without them.  A symlink
 * entry reads the LINK's own xattrs (never the referent's) with the no-follow
 * variant; on Linux the VFS refuses xattrs on symlinks, so that yields NULL. */
void scanner_capture_xattrs_opts(const ScannerOptions* options, File* file) {
  if (!options || !file || !(options->preserve_xattrs || options->preserve_acls))
    return;
  file->xattrs = file->is_symlink ? xattr_capture_path_nofollow(file->path, options->preserve_acls)
                                  : xattr_capture_path(file->path, options->preserve_acls);
}

void scanner_capture_xattrs(const DirectoryScanner* scanner, File* file) {
  if (!scanner)
    return;
  scanner_capture_xattrs_opts(&scanner->options, file);
}

/* Apply --hard-links (-H) detection to one regular File.  On a sibling (a
 * later member of an already-seen source inode) the File keeps the group id
 * and the first member's wire path but carries NO data payload (size 0); the
 * first member is left untouched (data present, link_first).  Returns false on
 * allocation failure (the caller marks the scan failed); the File stays usable
 * either way. */
bool scanner_assign_hardlink(HardLinkTable* table, File* file, const struct stat* stats) {
  if (!table || !file || !stats)
    return true;
  int gid;
  bool is_first;
  char* first_path = NULL;
  if (!hardlink_table_assign(table, file_wire_path(file), stats->st_dev, stats->st_ino, &gid,
                             &is_first, &first_path))
    return false;
  file->link_group = gid;
  file->link_first = is_first;
  if (!is_first) {
    file->hardlink_target = first_path;
    file->data->size = 0;
  } else {
    free(first_path);
  }
  return true;
}

/* Phase 4 special/devices decision for one non-regular entry, matching rsync:
   - a char/block device is RECREATED as a node under -D/--devices, unless
     --copy-devices asks for its content to be copied into a regular file;
   - a FIFO/socket is RECREATED under --specials;
   - when the matching flag is absent the entry is SKIPPED ("skipping
     non-regular file"), exactly like rsync's default, instead of being
     silently copied as a zero-length regular file;
   - anything else (regular/directory) is left to the normal data path. */
ScannerSpecial scanner_prepare_special(bool preserve_devices, bool preserve_specials,
                                       bool copy_devices, File* file, const struct stat* stats) {
  if (!file || !stats)
    return SCANNER_SPECIAL_REGULAR;
  bool is_device = S_ISCHR(stats->st_mode) || S_ISBLK(stats->st_mode);
  bool is_fifo = S_ISFIFO(stats->st_mode);
  bool is_socket = S_ISSOCK(stats->st_mode);
  if (!is_device && !is_fifo && !is_socket)
    return SCANNER_SPECIAL_REGULAR;
  if (is_device && copy_devices)
    return SCANNER_SPECIAL_REGULAR; /* copy device content as a regular file */
  bool preserve = is_device ? preserve_devices : preserve_specials;
  if (!preserve)
    return SCANNER_SPECIAL_SKIP;
  file->is_special = true;
  file->data->size = 0;
  file->data->data = NULL;
  if (is_device) {
    file->rdev_major = (int32_t)major(stats->st_rdev);
    file->rdev_minor = (int32_t)minor(stats->st_rdev);
  }
  return SCANNER_SPECIAL_RECREATE;
}

/* Append `rel` to the caller's exclusion sink, taking `mtx` when shared across
   parallel worker threads.  Returns false on allocation failure (list left
   unchanged). */
bool excluded_sink_append(ArrayList* list, mtx_t* mtx, const char* rel) {
  if (!list)
    return true;
  char* dup = str_dup(rel);
  if (!dup)
    return false;
  if (mtx)
    mtx_lock(mtx);
  bool ok = array_list_add(list, dup);
  if (mtx)
    mtx_unlock(mtx);
  if (!ok)
    free(dup);
  return ok;
}

/* Record one pruned filesystem path in a delete-protection sink.  The stored
   form is the entry's wire/destination-relative path (a single leading '/'
   removed, exactly how manifest keep entries are stored), so the receiver's
   walker prefixes match the destination layout.  An allocation failure is a
   fatal scan error. */
static void scanner_record_protected(DirectoryScanner* scanner, const char* fs_path,
                                     ArrayList* sink) {
  if (!sink || !fs_path)
    return;
  const char* rel = *fs_path == '/' ? fs_path + 1 : fs_path;
  if (!excluded_sink_append(sink, scanner->options.excluded_mutex, rel))
    scanner->failed = true;
}

/* rsync's `--info=nonreg` line for a non-regular entry that is not being
 * preserved: `skipping non-regular file "NAME"`.  The name is the path relative
 * to the transfer root, so it matches rsync's displayed name. */
void scanner_note_nonreg(const ScannerOptions* options, const char* fs_path) {
  if (!options || !options->note_nonreg || !fs_path)
    return;
  const char* rel = utils_strip_transfer_root(fs_path, options->send_directory);
  char* escaped = output_escape(rel, options->eight_bit_output);
  printf("skipping non-regular file \"%s\"\n", escaped ? escaped : rel);
  free(escaped);
  fflush(stdout);
}

/* Construct one non-directory File from an inspected entry.  Shared by the
 * sequential and parallel scanners so entry construction has a single
 * implementation: data size (or carried symlink), -R wire path, special/devices
 * classification, hardlink group, metadata and xattr capture all happen here in
 * the same order for both.  See the declaration for the ownership contract. */
ScannerBuildStatus scanner_build_file_entry(const ScannerOptions* options, ScannerEntry* inspected,
                                            const char* rel, File** out_file, bool* failed) {
  *out_file = NULL;
  if (failed)
    *failed = false;
  File* file = file_create(inspected->path);
  if (!file) {
    /* The File never existed, so drop the not-yet-transferred symlink target
       here; the caller's entry teardown would otherwise double-free it. */
    free(inspected->link_target);
    inspected->link_target = NULL;
    return SCANNER_BUILD_FAIL_CONTINUE;
  }
  if (inspected->is_symlink) {
    file->is_symlink = true;
    file->symlink_target = inspected->link_target;
    inspected->link_target = NULL;
  } else {
    file->data->size = inspected->stats.st_size;
  }
  /* -R + --files-from uses the bare transfer-relative path; -R without
     --files-from prefixes it.  Plain scans keep the source path. */
  bool relative_mode = options->relative && options->file_list != NULL;
  if (relative_mode) {
    file->send_path = str_dup(rel);
  } else if (options->relative_prefix) {
    file->send_path = scanner_prefix_send_path(options->relative_prefix, rel);
  }
  if ((relative_mode || options->relative_prefix) && !file->send_path) {
    file_destroy(file);
    return SCANNER_BUILD_FAIL_BREAK;
  }
  /* --devices/--specials: a device/FIFO/socket entry marked for preservation
     becomes a node to recreate (is_special, no data, rdev captured); an
     unrequested non-regular entry is skipped (rsync default). */
  ScannerSpecial special =
      scanner_prepare_special(options->preserve_devices, options->preserve_specials,
                              options->copy_devices, file, &inspected->stats);
  if (special == SCANNER_SPECIAL_SKIP) {
    scanner_note_nonreg(options, file->path);
    file_destroy(file);
    return SCANNER_BUILD_SKIP;
  }
  if (options->hardlinks && S_ISREG(inspected->stats.st_mode) &&
      !scanner_assign_hardlink(options->hardlinks, file, &inspected->stats)) {
    /* Allocation failure is non-fatal to this entry (it is still emitted) but
       marks the scan failed, matching the historical inlined behaviour. */
    if (failed)
      *failed = true;
  }
  if (options->use_metadata) {
    file->metadata = file_metadata_create(file->path, &inspected->stats, options->preserve_atimes,
                                          options->preserve_crtimes);
    if (!file->metadata) {
      file_destroy(file);
      return SCANNER_BUILD_FAIL_BREAK;
    }
  }
  /* A hardlink sibling carries no data, so it carries no xattrs. */
  if (!(file->link_group != 0 && !file->link_first))
    scanner_capture_xattrs_opts(options, file);
  *out_file = file;
  return SCANNER_BUILD_OK;
}

/* rsync 3.4.1's `--info=mount` line, emitted when `-xx` drops a mount-point
 * directory: `[sender] skipping mount-point dir NAME` (the client is the
 * sender).  Plain `-x` keeps the empty directory and prints nothing, matching
 * rsync. */
void scanner_note_mount(const ScannerOptions* options, const char* fs_path) {
  if (!options || !options->note_mount || !fs_path)
    return;
  const char* rel = utils_strip_transfer_root(fs_path, options->send_directory);
  char* escaped = output_escape(rel, options->eight_bit_output);
  printf("[sender] skipping mount-point dir %s\n", escaped ? escaped : rel);
  free(escaped);
  fflush(stdout);
}

/* --debug=filter: a selection/filter decision dropped an entry. */
void scanner_note_filter(const ScannerOptions* options, const char* name) {
  if (!options || !log_debug_enabled(LOG_DEBUG_FILTER) || !name)
    return;
  log_debug_message(LOG_DEBUG_FILTER, "filter: excluded %s", name);
}

/* Account for a directory that will not be represented by an inline directory
 * entry.  Paired with scanner_dir_count_uncount for empty directories that are
 * emitted inline, so every traversed directory is counted exactly once. */
void scanner_dir_count_count(const ScannerOptions* options) {
  if (options && options->dir_count)
    atomic_fetch_add(options->dir_count, 1);
}

void scanner_dir_count_uncount(const ScannerOptions* options) {
  if (options && options->dir_count)
    atomic_fetch_sub(options->dir_count, 1);
}

/* A user-selection exclusion (--filter/-C/per-dir or --exclude/--include). */
void scanner_record_excluded(DirectoryScanner* scanner, const char* fs_path) {
  scanner_record_protected(scanner, fs_path, scanner->options.excluded_paths);
}

/* A --max-size/--min-size prune (always protected, even under --delete-excluded). */
void scanner_record_size_skipped(DirectoryScanner* scanner, const char* fs_path) {
  scanner_record_protected(scanner, fs_path, scanner->options.size_skipped_paths);
}

/* The destination-relative coordinate the receiver's delete walkers match
   against for an entry at `fs_path` (with `rel` its path relative to the
   transfer root, "" for the root): `relative_prefix + rel` under -R+--relative,
   the bare relative path under -R+--files-from, else the source path with a
   leading '/' removed, with "." for the receive root.  Shared by the
   synchronized-directory sink and the mirrored per-directory rule owners so
   both live in the same coordinate system.  Returns an owned string, or NULL on
   allocation failure. */
char* scanner_dest_rel_path(const ScannerOptions* options, const char* fs_path, const char* rel,
                            bool relative_mode) {
  char* prefixed = NULL;
  const char* dest;
  if (relative_mode) {
    dest = rel;
  } else if (options->relative_prefix) {
    prefixed = scanner_prefix_send_path(options->relative_prefix, rel);
    if (!prefixed)
      return NULL;
    dest = prefixed;
  } else {
    dest = fs_path;
  }
  if (dest[0] == '/')
    dest++;
  if (dest[0] == '\0')
    dest = ".";
  char* out = str_dup(dest);
  free(prefixed);
  return out;
}

/* Record a directory the scan synchronized.  `fs_path` is its absolute path and
   `rel` its path relative to the transfer root ("" for the root); the stored
   form matches the wire layout (see scanner_dest_rel_path).  Returns false on
   allocation failure. */
bool scanner_record_synced_dir(const ScannerOptions* options, const char* fs_path, const char* rel,
                               bool relative_mode) {
  if (!options->synced_dirs && !options->plan_dirs)
    return true;
  if (!file_list_dir_in_scope(options->file_list, rel))
    return true;
  char* dest = scanner_dest_rel_path(options, fs_path, rel, relative_mode);
  if (!dest)
    return false;
  bool ok = true;
  if (options->synced_dirs)
    ok = excluded_sink_append(options->synced_dirs, options->excluded_mutex, dest);
  /* The delete-plan keep set needs an entry for every traversed source
     directory, including empty ones, so its destination mirror is kept rather
     than deleted as an extra; the receive root (".") is implicit. */
  if (ok && options->plan_dirs && strcmp(dest, ".") != 0)
    ok = excluded_sink_append(options->plan_dirs, options->excluded_mutex, dest);
  free(dest);
  return ok;
}

/* Read every per-directory filter file that applies to `dir_path` (its
 * .rsync-filter when -F is active, plus each registered "dir-merge NAME") into a
 * fresh list.  Returns NULL on allocation/parse failure (message in `err`);
 * returns an empty list (and *any_exists=false) when no file exists. */
FilterRuleList* read_dir_filters(const ScannerOptions* options, const char* dir_path,
                                 const char* rel, bool relative_mode, bool* any_exists, char* err,
                                 size_t err_size) {
  if (err && err_size > 0)
    err[0] = '\0';
  const FilterRuleList* base = options->base_filters;
  bool have_names = options->per_dir_filters || (base && base->dir_merge_count > 0);
  if (any_exists)
    *any_exists = false;
  if (!have_names)
    return NULL;
  FilterRuleList* own = filter_rule_list_create();
  if (!own) {
    snprintf(err, err_size, "memory allocation failed");
    return NULL;
  }
  FilterParseOptions opts = {.delete_excluded = options->delete_excluded, .cvs_exclude = false};
  bool exists = false;
  if (options->per_dir_filters) {
    if (!filter_file_append(own, dir_path, ".rsync-filter", rel, &opts, &exists, err, err_size))
      goto fail;
    if (exists && any_exists)
      *any_exists = true;
  }
  if (base) {
    for (int i = 0; i < base->dir_merge_count; i++) {
      if (!filter_dir_merge_append(own, dir_path, &base->dir_merges[i], rel, &opts, &exists, err,
                                   err_size))
        goto fail;
      if (exists && any_exists)
        *any_exists = true;
    }
  }
  /* Mirror the directory's rules into the delete-carrier sink so the receiver
   * can reconstruct its per-directory protect/risk set.  The mirrored rules
   * carry the destination-relative owner coordinate (not the transfer-root-
   * relative one the sender's own evaluation uses) so the receiver's delete
   * walkers, which match against receive-root-relative paths, find them. */
  if (options->per_dir_rules && own->count > 0) {
    char* owner = scanner_dest_rel_path(options, dir_path, rel, relative_mode);
    if (!owner)
      goto fail;
    mtx_t* mtx = options->excluded_mutex;
    if (mtx)
      mtx_lock(mtx);
    for (int i = 0; i < own->count; i++) {
      FilterRule* copy = filter_rule_clone(own->items[i]);
      if (!copy || !filter_rule_set_owner(copy, owner) ||
          !filter_rule_list_add(options->per_dir_rules, copy)) {
        filter_rule_free(copy);
        if (mtx)
          mtx_unlock(mtx);
        free(owner);
        goto fail;
      }
    }
    if (mtx)
      mtx_unlock(mtx);
    free(owner);
  }
  return own;
fail:
  filter_rule_list_free(own);
  return NULL;
}

/* Merge the open directory's own per-directory filter files (the default
 * .rsync-filter when -F is active, plus every "dir-merge NAME" registered on the
 * base rule list) into the inherited context, returning the context used for
 * this directory's entries. On a parse error the scanner is marked failed.
 * Returns 0 on success, -1 on failure. */
int open_directory_filter_context(DirectoryScanner* scanner, const FilterNode* inherited) {
  char err[256];
  bool any_exists = false;
  FilterRuleList* own = read_dir_filters(&scanner->options, scanner->current_path,
                                         scanner->current_rel ? scanner->current_rel : "",
                                         scanner->relative_mode, &any_exists, err, sizeof(err));
  if (!own) {
    /* read_dir_filters() leaves `err` set on a parse/allocation failure even
       when an earlier merge file in the same directory existed (any_exists true);
       key off the error text rather than any_exists so an invalid per-directory
       filter file can never be silently ignored. */
    if (err[0] == '\0') {
      scanner->current_node = (FilterNode*)inherited;
      return 0;
    }
    char* escaped_path = output_escape(scanner->current_path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "invalid per-directory filter in %s: %s",
                escaped_path ? escaped_path : "<allocation failed>", err);
    free(escaped_path);
    scanner->failed = true;
    return -1;
  }
  if (any_exists && (own->count > 0 || own->dir_merge_count > 0)) {
    FilterNode* node = filter_node_alloc((FilterNode*)inherited, own);
    if (!node || !array_list_add(scanner->filter_nodes, node)) {
      filter_node_destroy(node);
      scanner->failed = true;
      return -1;
    }
    scanner->current_node = node;
  } else {
    filter_rule_list_free(own);
    scanner->current_node = (FilterNode*)inherited;
  }
  return 0;
}

/* Inspect symlinks, resolve the entry type, and apply file filters once for both scanners.
 * `link_rel` is the entry's path relative to the transfer root (including its
 * name), used for the lexical rsync unsafe-symlink test. */
int scanner_inspect_entry(const ScannerOptions* options, const char* containing_dir,
                          const char* link_rel, const char* name, ScannerEntry* entry) {
  entry->excluded = false;
  entry->size_excluded = false;
  entry->referent_error = false;
  entry->is_symlink = false;
  entry->link_target = NULL;
  entry->path = path_cat(containing_dir, name);
  if (!entry->path)
    return -1;

  struct stat link_stats;
  if (lstat(entry->path, &link_stats) != 0) {
    free(entry->path);
    return 0;
  }
  if (!S_ISLNK(link_stats.st_mode))
    goto regular;

  char link_target[4096];
  switch (scanner_link_action(options, entry->path, link_rel, link_target, sizeof(link_target))) {
  case LINK_ACTION_SKIP:
    goto skip;
  case LINK_ACTION_SKIP_PROTECTED:
    /* --safe-links ignored the link, but rsync still counts it as present in
       the transfer, so its destination mirror survives --delete.  Record it as
       an excluded path (the same delete-protection channel as a filter prune). */
    entry->excluded = true;
    goto skip;
  case LINK_ACTION_DEREF:
    if (stat(entry->path, &entry->stats) != 0) {
      /* rsync reports "symlink has no referent" and continues with a partial
         transfer (exit 23); record the error so the run exits 23 too. */
      char* escaped = output_escape(entry->path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING, "symlink has no referent: %s",
                  escaped ? escaped : "<allocation failed>");
      free(escaped);
      entry->referent_error = true;
      goto skip;
    }
    entry->is_directory = S_ISDIR(entry->stats.st_mode);
    if (entry->is_directory)
      return 1;
    goto apply_filters;
  case LINK_ACTION_CARRY:
    break;
  }

  /* Carry the link as a symlink.  --munge-links is applied by the RECEIVER (it
     prefixes every stored target with /rsyncd-munged/); when the SOURCE already
     holds a munged value the sender strips it so the receiver re-munges a clean
     target, round-tripping a munged tree exactly like rsync. */
  entry->is_symlink = true;
  entry->stats = link_stats;
  entry->is_directory = false;
  entry->link_target = str_dup(link_target);
  if (!entry->link_target)
    goto skip;
  if (options->munge_links)
    file_symlink_unmunge(entry->link_target);
  goto apply_filters;

regular:
  /* Not a symlink: the lstat() above already described this entry, and lstat
     and stat are identical for every non-symlink, so reuse that result instead
     of issuing a redundant stat() on the scanner hot path.  stat() is still
     used on the dereference paths above/below for actual symlinks (copy-links,
     safe/copy-unsafe links, and -k symlinks-to-directories). */
  entry->stats = link_stats;
  entry->is_directory = S_ISDIR(link_stats.st_mode);
  if (entry->is_directory)
    return 1;

apply_filters:
  for (int i = 0; i < options->exclude_count; i++)
    if (glob_match(options->exclude_patterns[i], name)) {
      entry->excluded = true;
      goto skip;
    }
  if (options->include_count > 0) {
    bool included = false;
    for (int i = 0; i < options->include_count; i++)
      if (glob_match(options->include_patterns[i], name))
        included = true;
    if (!included) {
      entry->excluded = true;
      goto skip;
    }
  }
  if ((options->max_size > 0 && (unsigned long long)entry->stats.st_size > options->max_size) ||
      (options->min_size > 0 && (unsigned long long)entry->stats.st_size < options->min_size)) {
    entry->excluded = true;
    entry->size_excluded = true;
    goto skip;
  }
  return 1;

skip:
  free(entry->path);
  entry->path = NULL;
  free(entry->link_target);
  entry->link_target = NULL;
  return 0;
}
