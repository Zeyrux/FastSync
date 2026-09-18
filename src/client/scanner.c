#include "log.h"
#include "scanner.h"
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

typedef struct {
  char* path;
  int depth;
  FilterNode* context; /* inherited per-directory filter context */
} DirEntry;

/* A chain node: `own` holds the .rsync-filter rules of one directory, `parent`
 * the context that directory inherited (nearest ancestor with a filter file).
 * The chain for a directory's contents runs from that directory's own node up
 * to the root; the command-line base rules are evaluated after the whole
 * chain. */
struct FilterNode {
  FilterNode* parent;
  FilterRuleList* own;
};

static void filter_node_destroy(void* item) {
  if (item) {
    FilterNode* node = (FilterNode*)item;
    if (node->own)
      filter_rule_list_free(node->own);
    free(node);
  }
}

static FilterNode* filter_node_alloc(FilterNode* parent, FilterRuleList* own) {
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

static void dir_entry_destroy(void* item) {
  if (item) {
    DirEntry* de = (DirEntry*)item;
    free(de->path);
    free(de);
  }
}

static DirEntry* dir_entry_create(const char* path, int depth, FilterNode* context) {
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

/* How rsync's readlink_stat()/generator resolves one source symlink. */
typedef enum {
  LINK_ACTION_SKIP,           /* not transferred (no link option) */
  LINK_ACTION_SKIP_PROTECTED, /* ignored as unsafe by --safe-links; rsync keeps
                                 it in the transfer, so its destination mirror
                                 must be protected from --delete */
  LINK_ACTION_DEREF,          /* follow the referent (--copy-links, an unsafe
                                 target under --copy-unsafe-links, or -k dir) */
  LINK_ACTION_CARRY,          /* transmit the link itself (-l) */
} LinkAction;

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
static LinkAction scanner_link_action(const ScannerOptions* options, const char* path,
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

typedef struct {
  char* path;
  struct stat stats;
  bool is_directory;
  /* True when the entry should be carried through as a SYMLINK (is_symlink)
     rather than a dereferenced file/directory.  When true, `link_target` holds
     the owned target string to transmit (sender-munged under --munge-links);
     ownership transfers to the File built from this entry. */
  bool is_symlink;
  char* link_target;
  /* True when the entry was pruned by a user selection rule (--filter/-C/per-dir
     rules or the --exclude/--include layer) rather than skipped for another
     reason (unreadable, symlink policy, not applicable). */
  bool excluded;
  /* True when the entry was skipped specifically by --max-size/--min-size.
     Size pruning protects the destination mirror even under --delete-excluded,
     so it is recorded into a separate sink from `excluded`. */
  bool size_excluded;
  /* True when a symlink selected for dereferencing (-L/--copy-links or an
     unsafe target under --copy-unsafe-links) had no usable referent (a broken
     link or a stat() failure).  rsync still reports this as a partial transfer
     (exit 23) even though the entry is skipped, so the scanner records it as a
     non-fatal I/O error. */
  bool referent_error;
} ScannerEntry;

/* --one-file-system (-x) decision. Only directories can carry a different
 * device than their parent (mount points), so this is checked when a child
 * directory is about to be descended into. */
bool scanner_same_filesystem(bool one_file_system, dev_t root_device, dev_t entry_device) {
  return !one_file_system || entry_device == root_device;
}

/* Build a payload-less directory File carrying the captured metadata (when
 * requested).  Used by -x mount-point emission and --list-only directory
 * entries.  Returns NULL on allocation failure. */
static File* scanner_build_dir_file(const char* path, const struct stat* stats,
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
static char* child_rel_path(const char* parent_rel, const char* name) {
  if (!parent_rel || parent_rel[0] == '\0')
    return str_dup(name);
  return path_cat(parent_rel, name);
}

/* Destination-relative wire path for an entry under an -R prefix. */
static char* scanner_prefix_send_path(const char* prefix, const char* rel) {
  if (prefix[0] == '\0')
    return str_dup(rel);
  if (rel[0] == '\0')
    return str_dup(prefix);
  return path_cat(prefix, rel);
}

/* Apply the --files-from allow-set and the filter layer to one entry.  On
 * return `*protect_out` is true when a receiver-side rule protects the entry's
 * destination mirror from deletion. */
static bool entry_passes_selection(const FileListSet* file_list, const FilterRuleList* base,
                                   const FilterNode* node, const char* rel, const char* leaf,
                                   bool is_dir, bool per_dir_filters, bool exclude_filter_files,
                                   bool* protect_out) {
  if (protect_out)
    *protect_out = false;
  if (file_list && !file_list_affects(file_list, rel))
    return false;
  if (base || per_dir_filters)
    return entry_allowed(base, node, rel, leaf, is_dir, exclude_filter_files, protect_out);
  return true;
}

/* Best-effort capture of the file's whitelisted xattrs (-X/-A).  A failure to
 * read xattrs is non-fatal: the file is transferred without them. */
static void scanner_capture_xattrs(const DirectoryScanner* scanner, File* file) {
  if (!scanner || !file || !(scanner->options.preserve_xattrs || scanner->options.preserve_acls))
    return;
  file->xattrs = xattr_capture_path(file->path, scanner->options.preserve_acls);
}

/* Apply --hard-links (-H) detection to one regular File.  On a sibling (a
 * later member of an already-seen source inode) the File keeps the group id
 * and the first member's wire path but carries NO data payload (size 0); the
 * first member is left untouched (data present, link_first).  Allocation
 * failure is fatal: the scanner is marked failed. */
static void scanner_assign_hardlink(DirectoryScanner* scanner, HardLinkTable* table, File* file,
                                    const struct stat* stats) {
  if (!table || !file || !stats)
    return;
  int gid;
  bool is_first;
  char* first_path = NULL;
  if (!hardlink_table_assign(table, file_wire_path(file), stats->st_dev, stats->st_ino, &gid,
                             &is_first, &first_path)) {
    if (scanner)
      scanner->failed = true;
    return;
  }
  file->link_group = gid;
  file->link_first = is_first;
  if (!is_first) {
    file->hardlink_target = first_path;
    file->data->size = 0;
  } else {
    free(first_path);
  }
}

/* Phase 4 special/devices decision for one non-regular entry, matching rsync:
   - a char/block device is RECREATED as a node under -D/--devices, unless
     --copy-devices asks for its content to be copied into a regular file;
   - a FIFO/socket is RECREATED under --specials;
   - when the matching flag is absent the entry is SKIPPED ("skipping
     non-regular file"), exactly like rsync's default, instead of being
     silently copied as a zero-length regular file;
   - anything else (regular/directory) is left to the normal data path. */
typedef enum {
  SCANNER_SPECIAL_REGULAR,  /* ordinary file: transfer content */
  SCANNER_SPECIAL_RECREATE, /* is_special node to recreate on the receiver */
  SCANNER_SPECIAL_SKIP,     /* non-regular entry not requested: skip */
} ScannerSpecial;

static ScannerSpecial scanner_prepare_special(bool preserve_devices, bool preserve_specials,
                                              bool copy_devices, File* file,
                                              const struct stat* stats) {
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
static bool excluded_sink_append(ArrayList* list, mtx_t* mtx, const char* rel) {
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

/* A user-selection exclusion (--filter/-C/per-dir or --exclude/--include). */
static void scanner_record_excluded(DirectoryScanner* scanner, const char* fs_path) {
  scanner_record_protected(scanner, fs_path, scanner->options.excluded_paths);
}

/* A --max-size/--min-size prune (always protected, even under --delete-excluded). */
static void scanner_record_size_skipped(DirectoryScanner* scanner, const char* fs_path) {
  scanner_record_protected(scanner, fs_path, scanner->options.size_skipped_paths);
}

/* Record a directory the scan synchronized.  `fs_path` is its absolute path and
   `rel` its path relative to the transfer root ("" for the root); the stored
   form matches the wire layout (the bare relative path in -R+--files-from, else
   the source path with a leading '/' removed, with "." for the receive root).
   Returns false on allocation failure. */
static bool scanner_record_synced_dir(const ScannerOptions* options, const char* fs_path,
                                      const char* rel, bool relative_mode) {
  if (!options->synced_dirs && !options->plan_dirs)
    return true;
  if (!file_list_dir_in_scope(options->file_list, rel))
    return true;
  char* prefixed = NULL;
  const char* dest;
  if (relative_mode) {
    dest = rel;
  } else if (options->relative_prefix) {
    prefixed = scanner_prefix_send_path(options->relative_prefix, rel);
    if (!prefixed)
      return false;
    dest = prefixed;
  } else {
    dest = fs_path;
  }
  if (dest[0] == '/')
    dest++;
  if (dest[0] == '\0')
    dest = ".";
  bool ok = true;
  if (options->synced_dirs)
    ok = excluded_sink_append(options->synced_dirs, options->excluded_mutex, dest);
  /* The delete-plan keep set needs an entry for every traversed source
     directory, including empty ones, so its destination mirror is kept rather
     than deleted as an extra; the receive root (".") is implicit. */
  if (ok && options->plan_dirs && strcmp(dest, ".") != 0)
    ok = excluded_sink_append(options->plan_dirs, options->excluded_mutex, dest);
  free(prefixed);
  return ok;
}

/* Read every per-directory filter file that applies to `dir_path` (its
 * .rsync-filter when -F is active, plus each registered "dir-merge NAME") into a
 * fresh list.  Returns NULL on allocation/parse failure (message in `err`);
 * returns an empty list (and *any_exists=false) when no file exists. */
static FilterRuleList* read_dir_filters(const ScannerOptions* options, const char* dir_path,
                                        const char* rel, bool* any_exists, char* err,
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
      if (!filter_file_append(own, dir_path, base->dir_merge_names[i], rel, &opts, &exists, err,
                              err_size))
        goto fail;
      if (exists && any_exists)
        *any_exists = true;
    }
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
static int open_directory_filter_context(DirectoryScanner* scanner, const FilterNode* inherited) {
  char err[256];
  bool any_exists = false;
  FilterRuleList* own = read_dir_filters(&scanner->options, scanner->current_path,
                                         scanner->current_rel ? scanner->current_rel : "",
                                         &any_exists, err, sizeof(err));
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
static int scanner_inspect_entry(const ScannerOptions* options, const char* containing_dir,
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

DirectoryScanner* directory_scanner_create_with_options(const char* root_directory,
                                                        const ScannerOptions* options) {
  if (!root_directory || !options)
    return NULL;
  DirectoryScanner* scanner = calloc(1, sizeof(DirectoryScanner));
  if (scanner == NULL)
    return NULL;
  /* One copy of the scan inputs; normalize chunk_size as the old field-by-field
     copy did. */
  scanner->options = *options;
  if (scanner->options.chunk_size == 0)
    scanner->options.chunk_size = DESIRED_CHUNK_SIZE;
  scanner->directories = queue_create(100, dir_entry_destroy);
  if (!scanner->directories) {
    free(scanner);
    return NULL;
  }
  scanner->current_dir = NULL;
  scanner->current_path = NULL;
  scanner->current_depth = 0;
  scanner->failed = false;
  scanner->root_path = str_dup(root_directory);
  if (!scanner->root_path) {
    queue_destroy(scanner->directories);
    free(scanner);
    return NULL;
  }
  scanner->current_rel = NULL;
  scanner->at_seed_dir = true;
  scanner->seed_node = NULL;
  scanner->current_node = NULL;
  scanner->io_error = false;
  scanner->relative_mode = options->relative && options->file_list != NULL;
  scanner->dirs_root_emitted = false;
  scanner->list_index = 0;
  scanner->dirs_batch = NULL;
  scanner->dirs_batch_size = 0;
  scanner->filter_nodes = NULL;
  if (scanner->options.base_filters || scanner->options.per_dir_filters) {
    scanner->filter_nodes = array_list_create(filter_node_destroy);
    if (!scanner->filter_nodes) {
      free(scanner->root_path);
      queue_destroy(scanner->directories);
      free(scanner);
      return NULL;
    }
  }
  if (scanner->options.one_file_system) {
    struct stat root_stats;
    if (stat(root_directory, &root_stats) != 0) {
      log_perror("Could not stat source directory");
      free(scanner->root_path);
      queue_destroy(scanner->directories);
      array_list_delete(scanner->filter_nodes);
      free(scanner);
      return NULL;
    }
    scanner->root_dev = root_stats.st_dev;
  }
  DirEntry* root = dir_entry_create(root_directory, 0, NULL);
  if (!root) {
    free(scanner->root_path);
    queue_destroy(scanner->directories);
    array_list_delete(scanner->filter_nodes);
    free(scanner);
    return NULL;
  }
  if (!queue_enqueue(scanner->directories, root)) {
    dir_entry_destroy(root);
    free(scanner->root_path);
    queue_destroy(scanner->directories);
    array_list_delete(scanner->filter_nodes);
    free(scanner);
    return NULL;
  }
  return scanner;
}

DirectoryScanner* directory_scanner_create(const char* root_directory, bool use_metadata,
                                           unsigned long long chunk_size, char** exclude_patterns,
                                           int exclude_count, char** include_patterns,
                                           int include_count, unsigned long long max_size,
                                           unsigned long long min_size, int max_depth,
                                           bool follow_symlinks, bool copy_links, bool safe_links,
                                           bool copy_unsafe_links, bool checksum) {
  ScannerOptions options = {
      .use_metadata = use_metadata,
      .chunk_size = chunk_size,
      .exclude_patterns = exclude_patterns,
      .exclude_count = exclude_count,
      .include_patterns = include_patterns,
      .include_count = include_count,
      .max_size = max_size,
      .min_size = min_size,
      .max_depth = max_depth,
      .num_threads = 0,
      .follow_symlinks = follow_symlinks,
      .copy_links = copy_links,
      .safe_links = safe_links,
      .copy_unsafe_links = copy_unsafe_links,
      .checksum = checksum,
      .one_file_system = false,
      .file_list = NULL,
      .base_filters = NULL,
      .per_dir_filters = false,
      .dirs = false,
      .relative = false,
  };
  return directory_scanner_create_with_options(root_directory, &options);
}

void directory_scanner_destroy(DirectoryScanner* scanner) {
  if (scanner == NULL)
    return;
  if (scanner->current_dir) {
    closedir(scanner->current_dir);
    scanner->current_dir = NULL;
  }
  free(scanner->current_path);
  free(scanner->current_rel);
  free(scanner->root_path);
  array_list_delete(scanner->filter_nodes);
  array_list_delete(scanner->dirs_batch);
  queue_destroy(scanner->directories);
  free(scanner);
}

static Chunk* chunk_data_to_chunk(ArrayList* chunk_data) {
  void** chunk_items = array_list_to_array(chunk_data);
  if (!chunk_items) {
    array_list_delete(chunk_data);
    return NULL;
  }
  Chunk* chunk = chunk_create((File**)chunk_items, chunk_data->size);
  free(chunk_items);
  if (!chunk) {
    array_list_delete(chunk_data);
    return NULL;
  }
  chunk_data->item_destroyer = NULL;
  array_list_delete(chunk_data);
  return chunk;
}

/* P7 Wave D: append one traversed source directory's captured metadata to the
 * shared pending-directory-time list.  The File carries no payload; only the
 * wire path (absolute fs path normally, the bare relative path under
 * -R + --files-from) and its metadata are used, and the sender transmits them
 * in trailing STATUS_DIR_TIMES frame(s).  `mutex` (optional) serializes the
 * append for the parallel scanner's shared workers.  An unstattable or
 * non-directory path is silently skipped (the transfer is unaffected); an
 * allocation failure is fatal and reported to the caller. */
static bool scanner_capture_dir_time(ArrayList* dir_entries, mtx_t* mutex, const char* root_path,
                                     const char* fs_path, bool relative_mode,
                                     const char* relative_prefix, bool preserve_atimes,
                                     bool preserve_crtimes, bool preserve_xattrs,
                                     bool preserve_acls, bool no_implied_dirs,
                                     const FileListSet* file_list) {
  if (!dir_entries || !root_path || !fs_path)
    return true;
  struct stat st;
  if (stat(fs_path, &st) != 0 || !S_ISDIR(st.st_mode))
    return true;
  char* rel = scanner_path_relative(root_path, fs_path);
  if (!rel)
    return true;
  /* --no-implied-dirs: an implied parent directory (not listed, and not under
     a listed directory) keeps the destination's own/default attributes, so its
     source metadata is not transmitted. */
  if (no_implied_dirs && file_list && !file_list_dir_in_scope(file_list, rel)) {
    free(rel);
    return true;
  }
  if (relative_mode && rel[0] == '\0') {
    /* -R + --files-from: the transfer root itself has no bare relative wire
       path (matches the -R scan, which never emits the root). */
    free(rel);
    return true;
  }
  char* prefixed = NULL;
  if (relative_prefix) {
    prefixed = scanner_prefix_send_path(relative_prefix, rel);
    if (!prefixed) {
      free(rel);
      return false;
    }
    if (prefixed[0] == '\0') {
      /* -R with a cut at the receive root: the root itself has no wire path. */
      free(prefixed);
      free(rel);
      return true;
    }
  }
  File* file = file_create(fs_path);
  if (!file) {
    free(prefixed);
    free(rel);
    return false;
  }
  file->is_dir = true;
  file->metadata = file_metadata_create(fs_path, &st, preserve_atimes, preserve_crtimes);
  if (!file->metadata) {
    free(prefixed);
    free(rel);
    file_destroy(file);
    return false;
  }
  /* Directory xattrs/ACLs (-X/-A): captured here so the deferred
     STATUS_DIR_TIMES frame can carry them and the receiver can re-apply them
     fd-relative (a regular file's per-file block never covered directories). */
  if (preserve_xattrs || preserve_acls)
    file->xattrs = xattr_capture_path(fs_path, preserve_acls);
  if (relative_mode) {
    file->send_path = rel;
    rel = NULL;
  } else if (prefixed) {
    file->send_path = prefixed;
    prefixed = NULL;
  }
  free(prefixed);
  free(rel);
  bool added;
  if (mutex) {
    mtx_lock(mutex);
    added = array_list_add(dir_entries, file);
    mtx_unlock(mutex);
  } else {
    added = array_list_add(dir_entries, file);
  }
  if (!added) {
    file_destroy(file);
    return false;
  }
  return true;
}

/* Recursive scan: emit a payload-less directory entry for the directory that
 * just finished scanning.  rsync creates every source directory at the
 * destination; FastSync otherwise creates one only implicitly through a
 * transferred child, so a directory emptied on the transfer side (physically
 * empty, or all of its entries filtered out) would never appear.  The transfer
 * root is skipped (it maps to the receive root, which already exists), as are
 * --files-from (only listed items and their implied parents transfer),
 * --list-only (directory lines are emitted by the caller) and
 * -m/--prune-empty-dirs.  Returns false on allocation failure. */
static bool scanner_emit_empty_dir(DirectoryScanner* scanner, ArrayList* chunk_data) {
  if (!scanner->current_path || !scanner->current_rel || scanner->current_rel[0] == '\0')
    return true;
  struct stat st;
  if (stat(scanner->current_path, &st) != 0 || !S_ISDIR(st.st_mode))
    return true;
  File* dir = scanner_build_dir_file(scanner->current_path, &st, &scanner->options);
  if (!dir)
    return false;
  if (scanner->relative_mode) {
    dir->send_path = str_dup(scanner->current_rel);
  } else if (scanner->options.relative_prefix) {
    dir->send_path =
        scanner_prefix_send_path(scanner->options.relative_prefix, scanner->current_rel);
  }
  if ((scanner->relative_mode || scanner->options.relative_prefix) && !dir->send_path) {
    file_destroy(dir);
    return false;
  }
  if (scanner->options.preserve_xattrs || scanner->options.preserve_acls)
    dir->xattrs = xattr_capture_path(scanner->current_path, scanner->options.preserve_acls);
  if (!array_list_add(chunk_data, dir)) {
    file_destroy(dir);
    return false;
  }
  return true;
}

/* Open the next queued directory and set up its filter context.  Returns 1 when
   a directory is open, 0 when the queue is exhausted, and -1 on a fatal error.
   A directory that cannot be opened is an I/O error: it is recorded on the
   scanner and, when --ignore-errors is active, skipped so the rest of the tree
   is still scanned (the caller decides whether to treat the recorded error as
   fatal). */
static int open_next_directory(DirectoryScanner* scanner) {
  if (scanner->current_dir) {
    closedir(scanner->current_dir);
    scanner->current_dir = NULL;
  }
  free(scanner->current_path);
  scanner->current_path = NULL;

  while (!queue_is_empty(scanner->directories)) {
    DirEntry* de = (DirEntry*)queue_dequeue(scanner->directories);
    scanner->current_path = de->path;
    scanner->current_depth = de->depth;
    /* The seed directory inherits the scanner's configured context (the root
     * .rsync-filter context in parallel mode); other dirs inherit the context of
     * the directory that enqueued them. */
    const FilterNode* inherited = scanner->at_seed_dir ? scanner->seed_node : de->context;
    scanner->at_seed_dir = false;
    scanner->current_dir_produced = false;
    free(de);

    free(scanner->current_rel);
    scanner->current_rel = scanner_path_relative(scanner->root_path, scanner->current_path);
    if (!scanner->current_rel) {
      log_message(LOG_LEVEL_ERROR, "Could not compute relative path under %s", scanner->root_path);
      scanner->failed = true;
      free(scanner->current_path);
      scanner->current_path = NULL;
      return -1;
    }

    scanner->current_dir = opendir(scanner->current_path);
    if (scanner->current_dir == NULL) {
      scanner->io_error = true;
      log_perror("Could not open directory");
      /* The transfer ROOT (a sequential scanner's seed directory) must be
         readable even under --ignore-errors: an unreadable root would produce
         an empty scan whose keep-set would delete the whole destination.  Only
         subdirectories discovered during an otherwise-successful root scan are
         skippable.  (The parallel scanner never reaches this for the root: its
         root open failure aborts scanner creation; worker seeds are assigned
         subdirectories with a non-empty relative path and stay skippable.) */
      bool is_root_seed = scanner->current_rel != NULL && scanner->current_rel[0] == '\0' &&
                          scanner->current_depth == 0;
      free(scanner->current_rel);
      scanner->current_rel = NULL;
      free(scanner->current_path);
      scanner->current_path = NULL;
      if (!scanner->options.ignore_io_errors || is_root_seed) {
        scanner->failed = true;
        return -1;
      }
      /* --ignore-errors: record the I/O error and keep scanning the rest. */
      continue;
    }
    if (open_directory_filter_context(scanner, inherited) != 0) {
      closedir(scanner->current_dir);
      scanner->current_dir = NULL;
      free(scanner->current_path);
      scanner->current_path = NULL;
      return -1;
    }
    /* A successfully opened directory is synchronized for --delete: record it
       so the receiver confines its extras walk to these (and the root sentinel
       ".") instead of the whole receive root. */
    if (!scanner_record_synced_dir(&scanner->options, scanner->current_path, scanner->current_rel,
                                   scanner->relative_mode)) {
      closedir(scanner->current_dir);
      scanner->current_dir = NULL;
      free(scanner->current_path);
      scanner->current_path = NULL;
      scanner->failed = true;
      return -1;
    }
    if (scanner->options.capture_dir_times &&
        !scanner_capture_dir_time(
            scanner->options.dir_entries, scanner->options.dir_entries_mutex, scanner->root_path,
            scanner->current_path, scanner->relative_mode, scanner->options.relative_prefix,
            scanner->options.preserve_atimes, scanner->options.preserve_crtimes,
            scanner->options.preserve_xattrs, scanner->options.preserve_acls,
            scanner->options.no_implied_dirs, scanner->options.file_list)) {
      closedir(scanner->current_dir);
      scanner->current_dir = NULL;
      free(scanner->current_path);
      scanner->current_path = NULL;
      scanner->failed = true;
      return -1;
    }
    return 1;
  }
  return 0;
}

/* ---- --dirs mode ----
   With -d the scanner transfers directory entries and never recurses into
   contents.  A plain `-d <dir>` sends only the source-root directory mirror
   (created empty at the destination); `-d dir/`, `-d dir/.` and `-d .` list
   the directory's immediate contents instead (files plus empty directory
   entries), matching rsync.  With -d + --files-from exactly the listed items
   are sent: listed directories become empty directory entries and listed
   regular files are transferred as files; nothing else is scanned, so no
   descent into a listed directory can happen. */

/* Directory entries carry no payload, so the dirs generator also bounds every
   chunk by element count; chunk_deserialize refuses more than this many files
   per chunk (see MAX_FILES_PER_CHUNK in chunk.c). */
#define DIRS_CHUNK_MAX_FILES 65536U

/* Build the File for the transfer root directory itself (the `-d <dir>`
 * no-trailing-slash case). */
static File* dirs_root_dir_file(DirectoryScanner* scanner) {
  struct stat st;
  if (stat(scanner->root_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
    log_perror("Could not stat source directory");
    scanner->failed = true;
    return NULL;
  }
  File* file = file_create(scanner->root_path);
  if (!file) {
    scanner->failed = true;
    return NULL;
  }
  file->is_dir = true;
  if (scanner->options.use_metadata) {
    file->metadata = file_metadata_create(scanner->root_path, &st, scanner->options.preserve_atimes,
                                          scanner->options.preserve_crtimes);
    if (!file->metadata) {
      file_destroy(file);
      scanner->failed = true;
      return NULL;
    }
  }
  if (scanner->options.relative_prefix && scanner->options.relative_prefix[0] != '\0') {
    file->send_path = str_dup(scanner->options.relative_prefix);
    if (!file->send_path) {
      file_destroy(file);
      scanner->failed = true;
      return NULL;
    }
  }
  scanner_capture_xattrs(scanner, file);
  return file;
}

/* Map one normalized --files-from entry to a File (a directory entry or a
 * regular file to transfer), or NULL to skip the entry. */
static File* dirs_file_for_entry(DirectoryScanner* scanner, const char* entry) {
  if (entry[0] == '\0') {
    /* "." (whole tree): under -R the bare receive root is the destination and
       there is nothing to create for the root itself; otherwise mirror the
       source-root directory (empty). */
    if (scanner->relative_mode)
      return NULL;
    return dirs_root_dir_file(scanner);
  }
  char* abs_path = path_cat(scanner->root_path, entry);
  if (!abs_path) {
    scanner->failed = true;
    return NULL;
  }
  struct stat link_stats;
  if (lstat(abs_path, &link_stats) != 0) {
    /* --ignore-missing-args (implied by --delete-missing-args): an explicitly
       listed entry that does not exist under the source is a preflight-detected
       missing argument and is skipped here, exactly as the recursive scan skips
       nothing (missing entries never appear there).  Without the flags it stays
       a hard pre-transfer error. */
    if (scanner->options.ignore_missing_args) {
      char* escaped_entry = output_escape(entry, log_get_8_bit_output());
      log_info_message(LOG_INFO_MISC, "skipping missing --files-from entry '%s'",
                       escaped_entry ? escaped_entry : "<allocation failed>");
      free(escaped_entry);
      free(abs_path);
      return NULL;
    }
    {
      char* escaped_entry = output_escape(entry, log_get_8_bit_output());
      log_message(LOG_LEVEL_ERROR, "--dirs listed entry is not present under the source: %s",
                  escaped_entry ? escaped_entry : "<allocation failed>");
      free(escaped_entry);
    }
    free(abs_path);
    scanner->failed = true;
    return NULL;
  }
  struct stat effective = link_stats;
  bool emit_symlink = false;
  char* symlink_target = NULL;
  if (S_ISLNK(link_stats.st_mode)) {
    /* Resolve the listed symlink with the same precedence as the recursive
       scanner: dereference or carry the link. */
    char link_target[4096];
    LinkAction action =
        scanner_link_action(&scanner->options, abs_path, entry, link_target, sizeof(link_target));
    if (action == LINK_ACTION_SKIP || action == LINK_ACTION_SKIP_PROTECTED) {
      free(abs_path);
      return NULL;
    }
    if (action == LINK_ACTION_DEREF) {
      if (stat(abs_path, &effective) != 0) {
        free(abs_path);
        return NULL;
      }
    } else {
      emit_symlink = true;
      symlink_target = str_dup(link_target);
      if (!symlink_target) {
        free(abs_path);
        scanner->failed = true;
        return NULL;
      }
      if (scanner->options.munge_links)
        file_symlink_unmunge(symlink_target);
    }
  }
  bool is_dir = S_ISDIR(effective.st_mode);
  bool is_file = S_ISREG(effective.st_mode);
  if (!emit_symlink && !is_dir && !is_file) {
    free(symlink_target);
    free(abs_path);
    return NULL;
  }
  File* file = file_create(abs_path);
  free(abs_path);
  if (!file) {
    free(symlink_target);
    scanner->failed = true;
    return NULL;
  }
  if (emit_symlink) {
    file->is_symlink = true;
    file->symlink_target = symlink_target;
    symlink_target = NULL;
  } else {
    file->is_dir = is_dir;
    file->data->size = is_file ? (unsigned long long)effective.st_size : 0;
  }
  if (scanner->relative_mode) {
    file->send_path = str_dup(entry);
    if (!file->send_path) {
      file_destroy(file);
      scanner->failed = true;
      return NULL;
    }
  } else if (scanner->options.relative_prefix) {
    file->send_path = scanner_prefix_send_path(scanner->options.relative_prefix, entry);
    if (!file->send_path) {
      file_destroy(file);
      scanner->failed = true;
      return NULL;
    }
  }
  if (scanner->options.use_metadata) {
    file->metadata = file_metadata_create(file->path, &effective, scanner->options.preserve_atimes,
                                          scanner->options.preserve_crtimes);
    if (!file->metadata) {
      file_destroy(file);
      scanner->failed = true;
      return NULL;
    }
  }
  scanner_capture_xattrs(scanner, file);
  return file;
}

/* True when the directory contains no entries at all (ignoring "." and "..").
   An unreadable directory is reported as non-empty so the regular (erroring)
   root-entry path runs instead of silently transferring nothing. */
static bool dirs_source_dir_is_empty(const char* path) {
  DIR* dir = opendir(path);
  if (!dir)
    return false;
  bool empty = true;
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      empty = false;
      break;
    }
  }
  closedir(dir);
  return empty;
}

/* The next immediate child of the source root for a one-level --dirs listing
 * (rsync: -d DIR/ lists DIR's immediate contents without recursing). */
static File* dirs_next_child(DirectoryScanner* scanner) {
  if (!scanner->current_dir)
    return NULL;
  const struct dirent* entry;
  while ((entry = readdir(scanner->current_dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    File* file = dirs_file_for_entry(scanner, entry->d_name);
    if (scanner->failed)
      return NULL;
    if (file && !entry_passes_selection(scanner->options.file_list, scanner->options.base_filters,
                                        NULL, entry->d_name, entry->d_name, file->is_dir,
                                        scanner->options.per_dir_filters,
                                        scanner->options.exclude_per_dir_filter_files, NULL)) {
      file_destroy(file);
      continue;
    }
    if (file && file->is_dir && scanner->options.prune_empty_dirs &&
        dirs_source_dir_is_empty(file->path)) {
      file_destroy(file);
      continue;
    }
    if (file)
      return file;
  }
  closedir(scanner->current_dir);
  scanner->current_dir = NULL;
  return NULL;
}

/* The next File from the --dirs generator, or NULL when exhausted. */
static File* dirs_next_file(DirectoryScanner* scanner) {
  if (!scanner->options.file_list) {
    const char* spec = scanner->root_path ? scanner->root_path : "";
    size_t n = strlen(spec);
    /* rsync: a trailing slash or "/." on the source argument lists the
       directory's immediate contents (files and empty directory entries)
       without recursing.  A bare directory sends only its own entry. */
    bool list_children =
        (n == 1 && spec[0] == '.') ||
        (n > 0 && (spec[n - 1] == '/' || (n >= 2 && spec[n - 1] == '.' && spec[n - 2] == '/')));
    if (list_children) {
      if (!scanner->dirs_root_emitted) {
        scanner->dirs_root_emitted = true;
        if (scanner->options.prune_empty_dirs && dirs_source_dir_is_empty(scanner->root_path))
          return NULL;
        scanner->current_dir = opendir(scanner->root_path);
        if (!scanner->current_dir) {
          scanner->io_error = true;
          log_perror("Could not open directory");
          scanner->failed = true;
          return NULL;
        }
      }
      return dirs_next_child(scanner);
    }
    if (scanner->dirs_root_emitted)
      return NULL;
    scanner->dirs_root_emitted = true;
    /* --prune-empty-dirs: a physically empty source directory's explicit entry
       would only create an empty destination directory, so it is omitted. */
    if (scanner->options.prune_empty_dirs && dirs_source_dir_is_empty(scanner->root_path))
      return NULL;
    return dirs_root_dir_file(scanner);
  }
  while (scanner->list_index < scanner->options.file_list->count) {
    const char* entry = scanner->options.file_list->entries[scanner->list_index++];
    File* file = dirs_file_for_entry(scanner, entry);
    if (scanner->failed)
      return NULL;
    if (file)
      return file;
  }
  return NULL;
}

static Chunk* dirs_flush_batch(DirectoryScanner* scanner) {
  if (!scanner->dirs_batch || scanner->dirs_batch->size == 0) {
    array_list_delete(scanner->dirs_batch);
    scanner->dirs_batch = NULL;
    scanner->dirs_batch_size = 0;
    return NULL;
  }
  ArrayList* batch = scanner->dirs_batch;
  scanner->dirs_batch = NULL;
  scanner->dirs_batch_size = 0;
  Chunk* chunk = chunk_data_to_chunk(batch);
  if (!chunk)
    scanner->failed = true;
  return chunk;
}

static Chunk* directory_scanner_next_dirs(DirectoryScanner* scanner) {
  while (scanner->dirs_batch == NULL || scanner->dirs_batch_size <= scanner->options.chunk_size) {
    if (scanner->options.stop_condition &&
        stop_condition_reached(scanner->options.stop_condition)) {
      Chunk* leftover = dirs_flush_batch(scanner);
      if (leftover)
        chunk_destroy(leftover);
      return NULL;
    }
    if (!scanner->dirs_batch) {
      scanner->dirs_batch = array_list_create(file_destroy);
      if (!scanner->dirs_batch) {
        scanner->failed = true;
        return NULL;
      }
      scanner->dirs_batch_size = 0;
    }
    File* file = dirs_next_file(scanner);
    if (scanner->failed) {
      dirs_flush_batch(scanner);
      return NULL;
    }
    if (!file) {
      return dirs_flush_batch(scanner);
    }
    if (!array_list_add(scanner->dirs_batch, file)) {
      file_destroy(file);
      scanner->failed = true;
      dirs_flush_batch(scanner);
      return NULL;
    }
    scanner->dirs_batch_size += file->data ? file->data->size : 0;
    /* Empty directory entries carry no bytes, so a large --dirs --files-from
       list must also be bounded by element count (the chunk deserializer caps
       the number of files per chunk). */
    if (scanner->dirs_batch->size >= (int)DIRS_CHUNK_MAX_FILES)
      return dirs_flush_batch(scanner);
  }
  return dirs_flush_batch(scanner);
}

Chunk* directory_scanner_next(DirectoryScanner* scanner) {
  if (scanner && scanner->options.dirs)
    return directory_scanner_next_dirs(scanner);
  ArrayList* chunk_data = array_list_create(file_destroy);
  if (!chunk_data) {
    scanner->failed = true;
    return NULL;
  }
  unsigned long long chunk_data_size = 0;

  while (1) {
    if (scanner->options.stop_condition &&
        stop_condition_reached(scanner->options.stop_condition)) {
      array_list_delete(chunk_data);
      return NULL;
    }
    if (scanner->current_dir == NULL) {
      int ret = open_next_directory(scanner);
      if (ret == 0)
        break;
      if (ret < 0)
        break;
    }

    const struct dirent* entry = readdir(scanner->current_dir);
    if (entry == NULL) {
      /* The directory is exhausted: if nothing was transferred or descended
         from it, recreate it at the destination as an explicit entry. */
      if (scanner->options.emit_empty_dirs && !scanner->current_dir_produced &&
          !scanner->options.prune_empty_dirs && !scanner->options.list_dirs &&
          scanner->options.file_list == NULL) {
        if (!scanner_emit_empty_dir(scanner, chunk_data))
          scanner->failed = true;
      }
      closedir(scanner->current_dir);
      scanner->current_dir = NULL;
      free(scanner->current_path);
      scanner->current_path = NULL;
      if (scanner->failed) {
        array_list_delete(chunk_data);
        return NULL;
      }
      continue;
    }

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    ScannerEntry inspected;
    char* link_rel = child_rel_path(scanner->current_rel, entry->d_name);
    if (!link_rel) {
      scanner->failed = true;
      break;
    }
    int inspection = scanner_inspect_entry(&scanner->options, scanner->current_path, link_rel,
                                           entry->d_name, &inspected);
    free(link_rel);
    if (inspection < 0) {
      scanner->failed = true;
      break;
    }
    if (inspection == 0) {
      /* A dereferenced symlink with no referent is a partial-transfer error
         (rsync exit 23): record it as a non-fatal scan I/O error. */
      if (inspected.referent_error)
        scanner->io_error = true;
      /* A user-selection exclude protects its destination mirror from --delete
         unless --delete-excluded; a size prune is always protected.  Other
         skips (unreadable, symlink policy) protect nothing.  Under -R +
         --files-from the protected prefix must be the entry's bare relative
         wire path, not its source path (which would not match the destination
         layout and would leave the mirror deletable). */
      if (inspected.excluded) {
        char* protected_path;
        if (scanner->relative_mode) {
          protected_path = child_rel_path(scanner->current_rel, entry->d_name);
        } else if (scanner->options.relative_prefix) {
          char* relc = child_rel_path(scanner->current_rel, entry->d_name);
          protected_path =
              relc ? scanner_prefix_send_path(scanner->options.relative_prefix, relc) : NULL;
          free(relc);
        } else {
          protected_path = path_cat(scanner->current_path, entry->d_name);
        }
        if (!protected_path) {
          scanner->failed = true;
          break;
        }
        if (inspected.size_excluded)
          scanner_record_size_skipped(scanner, protected_path);
        else
          scanner_record_excluded(scanner, protected_path);
        free(protected_path);
      }
      continue;
    }
    char* cur_path = inspected.path;
    struct stat stats = inspected.stats;

    /* --files-from allow-set and the filter layer apply to files and to
     * directories (an excluded directory is not descended into). */
    bool is_dir = inspected.is_directory;
    char* rel = child_rel_path(scanner->current_rel, entry->d_name);
    if (!rel) {
      free(cur_path);
      scanner->failed = true;
      break;
    }
    bool protect = false;
    bool passes_selection = entry_passes_selection(
        scanner->options.file_list, scanner->options.base_filters, scanner->current_node, rel,
        entry->d_name, is_dir, scanner->options.per_dir_filters,
        scanner->options.exclude_per_dir_filter_files, &protect);
    /* A sender-side hide leaves the entry out of the transfer; an independent
       receiver-side protect rule keeps a transferred entry's destination mirror
       from being deleted.  Both are recorded in the same protection set. */
    if (!passes_selection || protect) {
      /* --files-from subset pruning is not a filter exclusion: its delete
         semantics stay keep-set-only (an unlisted source path is treated as
         absent, so its destination mirror is a deletable extra).  A rule-based
         exclusion is recorded as a protected prefix.  -R + --files-from bare
         wire paths are never recorded (see ScannerOptions.excluded_paths). */
      bool files_from_prune =
          scanner->options.file_list && !file_list_affects(scanner->options.file_list, rel);
      if (protect && scanner->relative_mode) {
        /* -R + --files-from: the destination/wire path is the bare relative
           name, so the protected mirror prefix must be `rel` (not the source
           path) for the delete walker to match it. */
        scanner_record_excluded(scanner, rel);
      } else if (!files_from_prune && !scanner->relative_mode) {
        if (scanner->options.relative_prefix) {
          char* wrel = scanner_prefix_send_path(scanner->options.relative_prefix, rel);
          if (!wrel) {
            free(rel);
            free(cur_path);
            scanner->failed = true;
            break;
          }
          scanner_record_excluded(scanner, wrel);
          free(wrel);
        } else {
          scanner_record_excluded(scanner, cur_path);
        }
      }
    }
    /* With -R the wire/destination path is a reconstructed relative path, not
       the source path; keep `rel` alive to build it for a transferred file. */
    bool needs_rel = scanner->relative_mode || scanner->options.relative_prefix != NULL;
    char* rel_copy = needs_rel ? str_dup(rel) : NULL;
    free(rel);
    if (rel_copy == NULL && needs_rel) {
      free(cur_path);
      scanner->failed = true;
      break;
    }
    if (!passes_selection) {
      free(rel_copy);
      free(cur_path);
      continue;
    }

    if (is_dir) {
      free(rel_copy);
      if (!scanner_same_filesystem(scanner->options.one_file_system, scanner->root_dev,
                                   stats.st_dev)) {
        /* rsync's -x/--one-file-system emits the mount-point directory entry
           itself (so the destination gets an empty directory) but does NOT
           descend into it.  Build a payload-less directory File and hand it to
           the caller; never enqueue it for traversal. */
        File* mount = scanner_build_dir_file(cur_path, &stats, &scanner->options);
        if (mount == NULL || !array_list_add(chunk_data, mount)) {
          file_destroy(mount);
          free(cur_path);
          scanner->failed = true;
          break;
        }
        scanner->current_dir_produced = true;
        free(cur_path);
        continue;
      }
      /* --list-only: list directory entries too (rsync prints them), even
         though a real transfer never sends them explicitly. */
      if (scanner->options.list_dirs) {
        File* dir = scanner_build_dir_file(cur_path, &stats, &scanner->options);
        if (dir == NULL || !array_list_add(chunk_data, dir)) {
          file_destroy(dir);
          free(cur_path);
          scanner->failed = true;
          break;
        }
      }
      scanner->current_dir_produced = true;
      int next_depth = scanner->current_depth + 1;
      if (scanner->options.max_depth <= 0 || next_depth < scanner->options.max_depth) {
        DirEntry* de = dir_entry_create(cur_path, next_depth, scanner->current_node);
        if (!de || !queue_enqueue(scanner->directories, de)) {
          dir_entry_destroy(de);
          scanner->failed = true;
        }
      }
      free(cur_path);
    } else {
      if (scanner->options.max_depth > 0 &&
          scanner->current_depth + 1 > scanner->options.max_depth) {
        free(rel_copy);
        free(cur_path);
        continue;
      }
      File* file = file_create(cur_path);
      free(cur_path);
      if (file == NULL) {
        free(rel_copy);
        free(inspected.link_target);
        inspected.link_target = NULL;
        scanner->failed = true;
        continue;
      }
      if (inspected.is_symlink) {
        file->is_symlink = true;
        file->symlink_target = inspected.link_target;
        inspected.link_target = NULL;
      } else {
        file->data->size = stats.st_size;
      }
      if (scanner->relative_mode) {
        file->send_path = rel_copy;
        rel_copy = NULL;
      } else if (scanner->options.relative_prefix) {
        file->send_path = scanner_prefix_send_path(scanner->options.relative_prefix, rel_copy);
        free(rel_copy);
        rel_copy = NULL;
        if (!file->send_path) {
          file_destroy(file);
          scanner->failed = true;
          break;
        }
      }
      /* --devices/--specials: a device/FIFO/socket entry marked for preservation
         becomes a node to recreate (is_special, no data, rdev captured); an
         unrequested non-regular entry is skipped (rsync default). */
      ScannerSpecial special = scanner_prepare_special(scanner->options.preserve_devices,
                                                       scanner->options.preserve_specials,
                                                       scanner->options.copy_devices, file, &stats);
      if (special == SCANNER_SPECIAL_SKIP) {
        free(rel_copy);
        file_destroy(file);
        continue;
      }
      if (scanner->options.hardlinks && S_ISREG(stats.st_mode))
        scanner_assign_hardlink(scanner, scanner->options.hardlinks, file, &stats);
      if (scanner->options.use_metadata)
        file->metadata = file_metadata_create(file->path, &stats, scanner->options.preserve_atimes,
                                              scanner->options.preserve_crtimes);
      if (scanner->options.use_metadata && !file->metadata) {
        free(rel_copy);
        file_destroy(file);
        scanner->failed = true;
        break;
      }
      if (!(file->link_group != 0 && !file->link_first))
        scanner_capture_xattrs(scanner, file);
      if (!array_list_add(chunk_data, file)) {
        free(rel_copy);
        file_destroy(file);
        scanner->failed = true;
        break;
      }
      scanner->current_dir_produced = true;
      chunk_data_size += file->data->size;
      if (chunk_data_size > scanner->options.chunk_size) {
        free(rel_copy);
        Chunk* result = chunk_data_to_chunk(chunk_data);
        if (!result)
          scanner->failed = true;
        return result;
      }
      free(rel_copy);
    }
  }

  if (chunk_data->size > 0) {
    Chunk* result = chunk_data_to_chunk(chunk_data);
    if (!result)
      scanner->failed = true;
    return result;
  }
  array_list_delete(chunk_data);
  return NULL;
}

bool directory_scanner_failed(const DirectoryScanner* scanner) {
  return scanner == NULL || scanner->failed;
}

bool directory_scanner_had_io_error(const DirectoryScanner* scanner) {
  return scanner != NULL && scanner->io_error;
}

typedef struct {
  ParallelScanner* ps;
  char** dirs;
  int dir_count;
  char* root_dir; /* the transfer root, for relative-path computation */
  ScannerOptions options;
  ProtocolSession* allocation_session;
} ParallelWorkerArg;

static int parallel_worker_thread(void* arg) {
  ParallelWorkerArg* wa = (ParallelWorkerArg*)arg;
  ProtocolSession* allocation_session = wa->allocation_session;
  if (allocation_session)
    protocol_session_bind(allocation_session);
  for (int i = 0; i < wa->dir_count; i++) {
    DirectoryScanner* ds = directory_scanner_create_with_options(wa->dirs[i], &wa->options);
    if (!ds) {
      mtx_lock(&wa->ps->result_mutex);
      wa->ps->failed = true;
      atomic_store(&wa->ps->cancelled, true);
      cnd_broadcast(&wa->ps->result_not_empty);
      cnd_broadcast(&wa->ps->result_not_full);
      mtx_unlock(&wa->ps->result_mutex);
      for (int j = i; j < wa->dir_count; j++)
        free(wa->dirs[j]);
      break;
    }
    /* Root .rsync-filter rules (parsed by the parallel scanner) apply to the
     * contents of every assigned subdirectory. Relative paths (used by the
     * allow-set and per-directory rules) are computed against the transfer
     * root, not the subdirectory the worker is seeded with.  Exclusion
     * recording shares one caller-owned list across the workers. */
    free(ds->root_path);
    ds->root_path = str_dup(wa->root_dir);
    ds->seed_node = wa->ps->root_filter_node;
    ds->options.excluded_mutex = &wa->ps->result_mutex;
    Chunk* chunk;
    while ((chunk = directory_scanner_next(ds)) != NULL) {
      if (!queue_enqueue_multithreaded_cancel(wa->ps->result_queue, chunk, &wa->ps->result_mutex,
                                              &wa->ps->result_not_empty, &wa->ps->result_not_full,
                                              &wa->ps->cancelled)) {
        chunk_destroy(chunk);
        break;
      }
    }
    if (directory_scanner_failed(ds)) {
      mtx_lock(&wa->ps->result_mutex);
      wa->ps->failed = true;
      atomic_store(&wa->ps->cancelled, true);
      cnd_broadcast(&wa->ps->result_not_empty);
      cnd_broadcast(&wa->ps->result_not_full);
      mtx_unlock(&wa->ps->result_mutex);
    } else if (directory_scanner_had_io_error(ds)) {
      /* --ignore-errors path: an unreadable directory was skipped, not fatal. */
      mtx_lock(&wa->ps->result_mutex);
      wa->ps->io_error = true;
      mtx_unlock(&wa->ps->result_mutex);
    }
    directory_scanner_destroy(ds);
    free(wa->dirs[i]);
  }
  ParallelScanner* ps = wa->ps;
  free(wa->root_dir);
  free(wa->dirs);
  free(wa);
  mtx_lock(&ps->result_mutex);
  ps->completed++;
  if (ps->completed >= ps->expected_threads) {
    ps->done = true;
    cnd_signal(&ps->result_not_empty);
  }
  mtx_unlock(&ps->result_mutex);
  if (allocation_session)
    protocol_session_unbind();
  return thrd_success;
}

static void parallel_scanner_creation_failed(ParallelScanner* ps) {
  mtx_lock(&ps->result_mutex);
  ps->failed = true;
  atomic_store(&ps->cancelled, true);
  ps->expected_threads = ps->created_threads;
  if (ps->completed >= ps->expected_threads)
    ps->done = true;
  cnd_broadcast(&ps->result_not_empty);
  cnd_broadcast(&ps->result_not_full);
  mtx_unlock(&ps->result_mutex);
}

/* Initialize result queue and synchronization primitives. Returns true on success. */
static bool parallel_scanner_init(ParallelScanner* ps) {
  ps->result_queue = queue_create(100, chunk_destroy);
  if (!ps->result_queue)
    return false;
  atomic_init(&ps->cancelled, false);
  int init = 0;
  bool ok = true;
  if (mtx_init(&ps->result_mutex, mtx_plain) != thrd_success)
    ok = false;
  if (ok) {
    init++;
    if (cnd_init(&ps->result_not_empty) != thrd_success)
      ok = false;
  }
  if (ok) {
    // cppcheck-suppress unreadVariable
    init++;
    if (cnd_init(&ps->result_not_full) != thrd_success)
      ok = false;
  }
  if (!ok) {
    if (init >= 3)
      cnd_destroy(&ps->result_not_full);
    if (init >= 2)
      cnd_destroy(&ps->result_not_empty);
    if (init >= 1)
      mtx_destroy(&ps->result_mutex);
    queue_destroy(ps->result_queue);
    ps->result_queue = NULL;
    return false;
  }
  return true;
}

/* Split files into chunks of roughly chunk_size bytes. Returns the first chunk (also stored
 * chunks beyond the first are enqueued on `queue`). Nulls out consumed entries in `files`.
 * Sets *failed on allocation/enqueue errors. */
static Chunk* batch_files(ArrayList* files, unsigned long long chunk_size, Queue* queue,
                          bool* failed) {
  Chunk* first = NULL;
  if (files->size <= 0)
    return NULL;
  ArrayList* batch = array_list_create(NULL);
  if (!batch) {
    *failed = true;
    return NULL;
  }
  unsigned long long batch_size = 0;
  for (int i = 0; i < files->size; i++) {
    File* f = (File*)files->items[i];
    if (!array_list_add(batch, f)) {
      *failed = true;
      break;
    }
    batch_size += f->data->size;
    if (batch_size >= chunk_size || i == files->size - 1) {
      void** items = array_list_to_array(batch);
      if (!items) {
        *failed = true;
        array_list_delete(batch);
        batch = NULL;
        break;
      }
      Chunk* c = chunk_create((File**)items, batch->size);
      free(items);
      if (!c) {
        *failed = true;
        array_list_delete(batch);
        batch = NULL;
        break;
      }
      int batch_start = i - batch->size + 1;
      for (int j = batch_start; j <= i; j++)
        files->items[j] = NULL;
      batch->item_destroyer = NULL;
      array_list_delete(batch);
      batch = NULL;
      if (!first) {
        first = c;
      } else {
        if (!queue_enqueue(queue, c)) {
          chunk_destroy(c);
          *failed = true;
        }
      }
      if (i < files->size - 1) {
        batch = array_list_create(NULL);
        if (!batch) {
          *failed = true;
          break;
        }
        batch_size = 0;
      }
    }
  }
  if (batch) {
    batch->item_destroyer = NULL;
    array_list_delete(batch);
  }
  return first;
}

/* Scan one root-directory entry into either the subdirs or files list. */
static void scan_root_entry(const ScannerOptions* options, const FilterNode* root_node,
                            const char* root_directory, const struct dirent* entry,
                            ArrayList* root_files, ArrayList* subdirs, dev_t root_dev,
                            ParallelScanner* ps) {
  ScannerEntry inspected;
  int inspection =
      scanner_inspect_entry(options, root_directory, entry->d_name, entry->d_name, &inspected);
  if (inspection < 0) {
    ps->failed = true;
    return;
  }
  if (inspection == 0) {
    if (inspected.referent_error)
      ps->io_error = true;
    ArrayList* sink = NULL;
    if (inspected.excluded)
      sink = inspected.size_excluded ? options->size_skipped_paths : options->excluded_paths;
    if (sink) {
      /* A root-level prune protects the destination mirror of the entry's wire
         path: under -R + --files-from that is the bare relative name, otherwise
         it is the full source path with a leading '/' removed (matching the
         send_path/file_wire_path the scanner hands the sender). */
      if (options->relative && options->file_list != NULL) {
        if (!excluded_sink_append(sink, options->excluded_mutex, entry->d_name))
          ps->failed = true;
      } else if (options->relative_prefix) {
        char* wrel = scanner_prefix_send_path(options->relative_prefix, entry->d_name);
        if (!wrel) {
          ps->failed = true;
        } else {
          if (!excluded_sink_append(sink, options->excluded_mutex, wrel))
            ps->failed = true;
          free(wrel);
        }
      } else {
        char* abs_path = path_cat(root_directory, entry->d_name);
        if (!abs_path) {
          ps->failed = true;
        } else {
          const char* rel = *abs_path == '/' ? abs_path + 1 : abs_path;
          if (!excluded_sink_append(sink, options->excluded_mutex, rel))
            ps->failed = true;
          free(abs_path);
        }
      }
    }
    return;
  }
  char* cur_path = inspected.path;
  struct stat st = inspected.stats;
  bool is_dir = inspected.is_directory;
  char* rel = str_dup(entry->d_name);
  if (!rel) {
    free(cur_path);
    ps->failed = true;
    return;
  }
  bool protect = false;
  bool passes = entry_passes_selection(options->file_list, options->base_filters, root_node, rel,
                                       entry->d_name, is_dir, options->per_dir_filters,
                                       options->exclude_per_dir_filter_files, &protect);
  /* -R + --files-from: root-level files keep their bare relative send path. */
  bool use_rel = options->relative && options->file_list != NULL;
  if (!passes || protect) {
    /* --files-from subset pruning is not a filter exclusion; -R bare-wire-path
       exclusions are never recorded (see ScannerOptions.excluded_paths). */
    bool files_from_prune = options->file_list && !file_list_affects(options->file_list, rel);
    if ((!files_from_prune && !use_rel) || protect) {
      const char* rel_path;
      char* prefixed = NULL;
      if (use_rel) {
        /* -R + --files-from: the destination/wire path is the bare relative
           name, not the source path. */
        rel_path = rel;
      } else if (options->relative_prefix) {
        prefixed = scanner_prefix_send_path(options->relative_prefix, entry->d_name);
        if (!prefixed) {
          free(rel);
          free(cur_path);
          ps->failed = true;
          return;
        }
        rel_path = prefixed;
      } else {
        rel_path = *cur_path == '/' ? cur_path + 1 : cur_path;
      }
      if (options->excluded_paths &&
          !excluded_sink_append(options->excluded_paths, options->excluded_mutex, rel_path))
        ps->failed = true;
      free(prefixed);
    }
    if (!passes) {
      free(rel);
      free(cur_path);
      return;
    }
  }
  if (is_dir) {
    if (!scanner_same_filesystem(options->one_file_system, root_dev, st.st_dev)) {
      /* -x/--one-file-system: emit the mount-point directory entry (empty) but
         do not descend into it (see the sequential scanner for the same rule). */
      File* mount = file_create(cur_path);
      free(cur_path);
      if (mount == NULL) {
        free(rel);
        ps->failed = true;
        return;
      }
      mount->is_dir = true;
      if (options->use_metadata) {
        mount->metadata = file_metadata_create(mount->path, &st, options->preserve_atimes,
                                               options->preserve_crtimes);
        if (!mount->metadata) {
          free(rel);
          file_destroy(mount);
          ps->failed = true;
          return;
        }
      }
      if (options->relative_prefix) {
        mount->send_path = scanner_prefix_send_path(options->relative_prefix, rel);
        if (!mount->send_path) {
          free(rel);
          file_destroy(mount);
          ps->failed = true;
          return;
        }
      }
      free(rel);
      if (!array_list_add(root_files, mount)) {
        file_destroy(mount);
        ps->failed = true;
      }
      return;
    }
    free(rel);
    if (!array_list_add(subdirs, cur_path)) {
      free(cur_path);
      ps->failed = true;
    }
    return;
  }
  File* file = file_create(cur_path);
  free(cur_path);
  if (!file) {
    free(rel);
    free(inspected.link_target);
    inspected.link_target = NULL;
    ps->failed = true;
    return;
  }
  if (inspected.is_symlink) {
    file->is_symlink = true;
    file->symlink_target = inspected.link_target;
    inspected.link_target = NULL;
  } else {
    file->data->size = st.st_size;
  }
  if (use_rel) {
    file->send_path = rel;
    rel = NULL;
  } else if (options->relative_prefix) {
    file->send_path = scanner_prefix_send_path(options->relative_prefix, rel);
    free(rel);
    rel = NULL;
    if (!file->send_path) {
      file_destroy(file);
      ps->failed = true;
      return;
    }
  }
  ScannerSpecial special = scanner_prepare_special(
      options->preserve_devices, options->preserve_specials, options->copy_devices, file, &st);
  if (special == SCANNER_SPECIAL_SKIP) {
    free(rel);
    file_destroy(file);
    return;
  }
  if (options->hardlinks && S_ISREG(st.st_mode)) {
    int gid;
    bool is_first;
    char* first_path = NULL;
    if (!hardlink_table_assign((HardLinkTable*)options->hardlinks, file_wire_path(file), st.st_dev,
                               st.st_ino, &gid, &is_first, &first_path)) {
      ps->failed = true;
    } else {
      file->link_group = gid;
      file->link_first = is_first;
      if (!is_first) {
        file->hardlink_target = first_path;
        file->data->size = 0;
      } else {
        free(first_path);
      }
    }
  }
  if (options->use_metadata)
    file->metadata =
        file_metadata_create(file->path, &st, options->preserve_atimes, options->preserve_crtimes);
  if (options->use_metadata && !file->metadata) {
    free(rel);
    file_destroy(file);
    ps->failed = true;
    return;
  }
  if ((options->preserve_xattrs || options->preserve_acls) &&
      !(file->link_group != 0 && !file->link_first))
    file->xattrs = xattr_capture_path(file->path, options->preserve_acls);
  if (!array_list_add(root_files, file)) {
    free(rel);
    file_destroy(file);
    ps->failed = true;
    return;
  }
  free(rel);
}

/* Scan the root directory itself, collecting root files and subdirectories.
 * Returns false if the root directory could not be opened. */
static bool scan_root_directory(ParallelScanner* ps, const char* root_directory,
                                const ScannerOptions* options, const FilterNode* root_node,
                                dev_t root_dev, ArrayList* root_files, ArrayList* subdirs) {
  DIR* dir = opendir(root_directory);
  if (!dir) {
    log_perror("Could not open root directory for parallel scan");
    return false;
  }
  /* The parallel scanner opens the transfer root directly (not through
     open_next_directory), so record it as synchronized here. */
  if (!scanner_record_synced_dir(options, root_directory, "",
                                 options->relative && options->file_list != NULL)) {
    closedir(dir);
    ps->failed = true;
    return false;
  }
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    scan_root_entry(options, root_node, root_directory, entry, root_files, subdirs, root_dev, ps);
  }
  closedir(dir);
  return true;
}

/* Spawn worker threads, one per group of subdirectories. */
static void spawn_parallel_workers(ParallelScanner* ps, ArrayList* subdirs,
                                   const ScannerOptions* options, const char* root_directory,
                                   unsigned long long cs) {
  if (subdirs->size <= 0)
    return;
  int n = options->num_threads > 0 ? options->num_threads : 4;
  if (n > subdirs->size)
    n = subdirs->size;

  ps->num_threads = n;
  ps->expected_threads = n;
  ps->threads = calloc(n, sizeof(thrd_t));
  if (!ps->threads) {
    ps->num_threads = 0;
    ps->expected_threads = 0;
    ps->failed = true;
    return;
  }
  int dirs_per_thread = subdirs->size / n;
  int remainder = subdirs->size % n;
  int start = 0;
  ps->num_threads = 0;
  for (int t = 0; t < n; t++) {
    int count = dirs_per_thread + (t < remainder ? 1 : 0);
    if (count == 0)
      break;
    ParallelWorkerArg* wa = calloc(1, sizeof(ParallelWorkerArg));
    if (!wa) {
      parallel_scanner_creation_failed(ps);
      break;
    }
    wa->ps = ps;
    wa->dirs = calloc(count, sizeof(char*));
    wa->root_dir = str_dup(root_directory);
    if (!wa->dirs || !wa->root_dir) {
      free(wa->root_dir);
      free(wa->dirs);
      free(wa);
      parallel_scanner_creation_failed(ps);
      break;
    }
    bool dup_ok = true;
    for (int j = 0; j < count; j++) {
      wa->dirs[j] = str_dup((char*)subdirs->items[start + j]);
      if (!wa->dirs[j])
        dup_ok = false;
    }
    if (!dup_ok) {
      for (int j = 0; j < count; j++)
        free(wa->dirs[j]);
      free(wa->root_dir);
      free(wa->dirs);
      free(wa);
      parallel_scanner_creation_failed(ps);
      break;
    }
    wa->dir_count = count;
    wa->options = *options;
    wa->options.chunk_size = cs;
    wa->allocation_session = ps->allocation_session;
    start += count;
    if (thrd_create(&ps->threads[t], parallel_worker_thread, wa) != thrd_success) {
      for (int j = 0; j < count; j++)
        free(wa->dirs[j]);
      free(wa->root_dir);
      free(wa->dirs);
      free(wa);
      parallel_scanner_creation_failed(ps);
      break;
    }
    ps->num_threads++;
    ps->created_threads++;
  }
}

ParallelScanner* parallel_scanner_create_with_options(const char* root_directory,
                                                      const ScannerOptions* options,
                                                      ProtocolSession* allocation_session) {
  if (!root_directory || !options)
    return NULL;
  ParallelScanner* ps = calloc(1, sizeof(ParallelScanner));
  if (!ps)
    return NULL;
  if (!parallel_scanner_init(ps)) {
    free(ps);
    return NULL;
  }
  ps->allocation_session = allocation_session;

  ArrayList* root_files = array_list_create(file_destroy);
  ArrayList* subdirs = array_list_create(free);
  if (!root_files || !subdirs) {
    array_list_delete(root_files);
    array_list_delete(subdirs);
    parallel_scanner_destroy(ps);
    return NULL;
  }

  dev_t root_dev = 0;
  if (options->one_file_system) {
    struct stat root_stats;
    if (stat(root_directory, &root_stats) != 0) {
      log_perror("Could not stat source directory");
      array_list_delete(root_files);
      array_list_delete(subdirs);
      parallel_scanner_destroy(ps);
      return NULL;
    }
    root_dev = root_stats.st_dev;
  }

  /* Build the root directory's per-directory filter context once; workers seed
   * their scanners with it so per-dir rules behave identically to the sequential
   * scanner. */
  FilterNode* root_node = NULL;
  {
    char err[256];
    bool any_exists = false;
    FilterRuleList* own =
        read_dir_filters(options, root_directory, "", &any_exists, err, sizeof(err));
    if (!own) {
      /* A parse/allocation failure must fail the scan even when an earlier
         merge file in the same directory existed (see the sequential scanner). */
      if (err[0] != '\0') {
        log_message(LOG_LEVEL_ERROR, "invalid per-directory filter in %s: %s", root_directory, err);
        array_list_delete(root_files);
        array_list_delete(subdirs);
        parallel_scanner_destroy(ps);
        return NULL;
      }
      /* no files exist: leave root_node NULL */
    } else if (any_exists && (own->count > 0 || own->dir_merge_count > 0)) {
      root_node = filter_node_alloc(NULL, own);
      if (!root_node) {
        filter_rule_list_free(own);
        array_list_delete(root_files);
        array_list_delete(subdirs);
        parallel_scanner_destroy(ps);
        return NULL;
      }
    } else {
      filter_rule_list_free(own);
    }
  }
  ps->root_filter_node = root_node;

  if (!scan_root_directory(ps, root_directory, options, root_node, root_dev, root_files, subdirs)) {
    array_list_delete(root_files);
    array_list_delete(subdirs);
    parallel_scanner_destroy(ps);
    return NULL;
  }
  /* P7 Wave D: the parallel scanner never runs a DirectoryScanner over the
     transfer root itself (it hands the root's immediate subdirectories to
     workers), so capture the root's directory time here. */
  if (options->capture_dir_times &&
      !scanner_capture_dir_time(
          options->dir_entries, options->dir_entries_mutex, root_directory, root_directory,
          options->relative && options->file_list != NULL, options->relative_prefix,
          options->preserve_atimes, options->preserve_crtimes, options->preserve_xattrs,
          options->preserve_acls, options->no_implied_dirs, options->file_list)) {
    array_list_delete(root_files);
    array_list_delete(subdirs);
    parallel_scanner_destroy(ps);
    return NULL;
  }

  unsigned long long cs = options->chunk_size > 0 ? options->chunk_size : DESIRED_CHUNK_SIZE;
  ps->initial_chunk = batch_files(root_files, cs, ps->result_queue, &ps->failed);
  array_list_delete(root_files);

  spawn_parallel_workers(ps, subdirs, options, root_directory, cs);
  array_list_delete(subdirs);
  return ps;
}

Chunk* parallel_scanner_next(ParallelScanner* ps) {
  if (ps->initial_chunk) {
    Chunk* c = ps->initial_chunk;
    ps->initial_chunk = NULL;
    return c;
  }
  if (ps->num_threads == 0) {
    mtx_lock(&ps->result_mutex);
    if (!queue_is_empty(ps->result_queue)) {
      Chunk* chunk = queue_dequeue(ps->result_queue);
      mtx_unlock(&ps->result_mutex);
      return chunk;
    }
    ps->done = true;
    mtx_unlock(&ps->result_mutex);
    return NULL;
  }
  Chunk* chunk = queue_dequeue_multithreaded(
      ps->result_queue, &ps->result_mutex, &ps->result_not_empty, &ps->result_not_full, &ps->done);
  return chunk;
}

bool parallel_scanner_failed(const ParallelScanner* ps) {
  return ps == NULL || ps->failed;
}

bool parallel_scanner_had_io_error(const ParallelScanner* ps) {
  return ps != NULL && ps->io_error;
}

void parallel_scanner_destroy(ParallelScanner* ps) {
  if (!ps)
    return;
  mtx_lock(&ps->result_mutex);
  ps->done = true;
  atomic_store(&ps->cancelled, true);
  cnd_broadcast(&ps->result_not_empty);
  cnd_broadcast(&ps->result_not_full);
  mtx_unlock(&ps->result_mutex);
  for (int i = 0; i < ps->num_threads; i++)
    thrd_join(ps->threads[i], NULL);
  free(ps->threads);
  if (ps->root_filter_node)
    filter_node_destroy(ps->root_filter_node);
  if (ps->initial_chunk)
    chunk_destroy(ps->initial_chunk);
  queue_destroy(ps->result_queue);
  mtx_destroy(&ps->result_mutex);
  cnd_destroy(&ps->result_not_empty);
  cnd_destroy(&ps->result_not_full);
  free(ps);
}
