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
#include <threads.h>
#include <unistd.h>
#include <limits.h>

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

/* Evaluate a rule chain for an entry inside the directory whose content
 * context is `node`. rsync precedence, highest first: the innermost (current)
 * directory's .rsync-filter rules, then each ancestor's, then the root's, and
 * finally the command-line base rules (--filter/-C). A deeper per-directory
 * file therefore overrides a shallower one, and per-directory files override
 * the base rules by default. Returns FILTER_ACTION_NONE when nothing matched. */
static FilterAction chain_rules_apply(const FilterRuleList* base, const FilterNode* node,
                                      const char* rel, const char* leaf, bool is_dir) {
  if (node) {
    FilterAction own_action = filter_rules_apply(node->own, rel, leaf, is_dir);
    if (own_action != FILTER_ACTION_NONE)
      return own_action;
    return chain_rules_apply(base, node->parent, rel, leaf, is_dir);
  }
  return base ? filter_rules_apply(base, rel, leaf, is_dir) : FILTER_ACTION_NONE;
}

static bool entry_allowed(const FilterRuleList* base, const FilterNode* node, const char* rel,
                          const char* leaf, bool is_dir, bool per_dir_filters) {
  /* -F: per-directory .rsync-filter files are never transferred. */
  if (per_dir_filters && !is_dir && strcmp(leaf, ".rsync-filter") == 0)
    return false;
  return chain_rules_apply(base, node, rel, leaf, is_dir) != FILTER_ACTION_EXCLUDE;
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

static bool safe_relative_link(const char* source_root, const char* containing_dir,
                               const char* link_target) {
  char root[PATH_MAX];
  if (!realpath(source_root, root))
    return false;
  char* joined = path_cat(containing_dir, link_target);
  char resolved[PATH_MAX];
  bool safe = joined && realpath(joined, resolved) && strncmp(root, resolved, strlen(root)) == 0 &&
              (resolved[strlen(root)] == '\0' || resolved[strlen(root)] == '/');
  free(joined);
  return safe;
}

typedef struct {
  char* path;
  struct stat stats;
  bool is_directory;
  /* True when the entry was pruned by a user selection rule (--filter/-C/per-dir
     rules, the --exclude/--include layer, or --max-size/--min-size) rather than
     skipped for another reason (unreadable, symlink policy, not applicable). */
  bool excluded;
} ScannerEntry;

/* --one-file-system (-x) decision. Only directories can carry a different
 * device than their parent (mount points), so this is checked when a child
 * directory is about to be descended into. */
bool scanner_same_filesystem(bool one_file_system, dev_t root_device, dev_t entry_device) {
  return !one_file_system || entry_device == root_device;
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

/* Relative path of a child entry below the current directory. */
static char* child_rel_path(const char* parent_rel, const char* name) {
  if (!parent_rel || parent_rel[0] == '\0')
    return str_dup(name);
  return path_cat(parent_rel, name);
}

/* Apply the --files-from allow-set and the filter layer to one entry. */
static bool entry_passes_selection(const FileListSet* file_list, const FilterRuleList* base,
                                   const FilterNode* node, const char* rel, const char* leaf,
                                   bool is_dir, bool per_dir_filters) {
  if (file_list && !file_list_affects(file_list, rel))
    return false;
  if (base || per_dir_filters)
    return entry_allowed(base, node, rel, leaf, is_dir, per_dir_filters);
  return true;
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

/* Record one pruned-by-user-selection filesystem path in the scanner's
   exclusion sink (see ScannerOptions.excluded_paths).  The stored form is the
   entry's wire/destination-relative path (a single leading '/' removed, exactly
   how manifest keep entries are stored), so the receiver's walker prefixes
   match the destination layout.  An allocation failure is a fatal scan error. */
static void scanner_record_excluded(DirectoryScanner* scanner, const char* fs_path) {
  if (!scanner->excluded_paths || !fs_path)
    return;
  const char* rel = *fs_path == '/' ? fs_path + 1 : fs_path;
  if (!excluded_sink_append(scanner->excluded_paths, scanner->excluded_mutex, rel))
    scanner->failed = true;
}

/* Merge the open directory's own .rsync-filter rules into the inherited
 * context, returning the context used for this directory's entries. On a parse
 * error the scanner is marked failed. Returns 0 on success, -1 on failure. */
static int open_directory_filter_context(DirectoryScanner* scanner, const FilterNode* inherited) {
  if (!scanner->per_dir_filters) {
    scanner->current_node = (FilterNode*)inherited;
    return 0;
  }
  char err[256];
  bool exists = false;
  FilterRuleList* own =
      filter_file_read(scanner->current_path, scanner->current_rel ? scanner->current_rel : "",
                       &exists, err, sizeof(err));
  if (!own) {
    log_message(LOG_LEVEL_ERROR, "invalid .rsync-filter in %s: %s", scanner->current_path, err);
    scanner->failed = true;
    return -1;
  }
  if (exists && own->count > 0) {
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

/* Inspect symlinks, resolve the entry type, and apply file filters once for both scanners. */
static int scanner_inspect_entry(const ScannerOptions* options, const char* source_root,
                                 const char* containing_dir, const char* name,
                                 ScannerEntry* entry) {
  entry->excluded = false;
  entry->path = path_cat(containing_dir, name);
  if (!entry->path)
    return -1;

  struct stat link_stats;
  if (lstat(entry->path, &link_stats) != 0) {
    free(entry->path);
    return 0;
  }
  bool is_symlink = S_ISLNK(link_stats.st_mode);
  if (is_symlink && !options->follow_symlinks && !options->copy_links && !options->safe_links &&
      !options->copy_unsafe_links)
    goto skip;

  if (is_symlink && options->safe_links) {
    char link_target[4096];
    ssize_t length = readlink(entry->path, link_target, sizeof(link_target) - 1);
    if (length < 0)
      goto skip;
    link_target[length] = '\0';
    if (link_target[0] == '/' || !safe_relative_link(source_root, containing_dir, link_target))
      goto skip;
  }

  if (is_symlink && options->copy_unsafe_links && !options->copy_links) {
    char link_target[4096];
    ssize_t length = readlink(entry->path, link_target, sizeof(link_target) - 1);
    if (length < 0)
      goto skip;
    link_target[length] = '\0';
    if (link_target[0] != '/')
      goto skip;
  }

  if (is_symlink && options->follow_symlinks && !options->copy_links)
    entry->stats = link_stats;
  else if (stat(entry->path, &entry->stats) != 0)
    goto skip;

  entry->is_directory = S_ISDIR(entry->stats.st_mode);
  if (entry->is_directory)
    return 1;
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
    goto skip;
  }
  return 1;

skip:
  free(entry->path);
  entry->path = NULL;
  return 0;
}

DirectoryScanner* directory_scanner_create_with_options(const char* root_directory,
                                                        const ScannerOptions* options) {
  if (!root_directory || !options)
    return NULL;
  DirectoryScanner* scanner = calloc(1, sizeof(DirectoryScanner));
  if (scanner == NULL)
    return NULL;
  scanner->directories = queue_create(100, dir_entry_destroy);
  if (!scanner->directories) {
    free(scanner);
    return NULL;
  }
  scanner->current_dir = NULL;
  scanner->current_path = NULL;
  scanner->use_metadata = options->use_metadata;
  scanner->chunk_size = options->chunk_size > 0 ? options->chunk_size : DESIRED_CHUNK_SIZE;
  scanner->exclude_patterns = options->exclude_patterns;
  scanner->exclude_count = options->exclude_count;
  scanner->include_patterns = options->include_patterns;
  scanner->include_count = options->include_count;
  scanner->max_size = options->max_size;
  scanner->min_size = options->min_size;
  scanner->max_depth = options->max_depth;
  scanner->current_depth = 0;
  scanner->follow_symlinks = options->follow_symlinks;
  scanner->copy_links = options->copy_links;
  scanner->safe_links = options->safe_links;
  scanner->copy_unsafe_links = options->copy_unsafe_links;
  scanner->checksum = options->checksum;
  scanner->one_file_system = options->one_file_system;
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
  scanner->file_list = options->file_list;
  scanner->base_filters = options->base_filters;
  scanner->per_dir_filters = options->per_dir_filters;
  scanner->excluded_paths = options->excluded_paths;
  scanner->excluded_mutex = options->excluded_mutex;
  scanner->ignore_io_errors = options->ignore_io_errors;
  scanner->ignore_missing_args = options->ignore_missing_args;
  scanner->io_error = false;
  scanner->dirs_mode = options->dirs;
  scanner->relative_mode = options->relative && options->file_list != NULL;
  scanner->prune_empty_dirs = options->prune_empty_dirs;
  scanner->dirs_root_emitted = false;
  scanner->list_index = 0;
  scanner->dirs_batch = NULL;
  scanner->dirs_batch_size = 0;
  scanner->filter_nodes = NULL;
  if (scanner->base_filters || scanner->per_dir_filters) {
    scanner->filter_nodes = array_list_create(filter_node_destroy);
    if (!scanner->filter_nodes) {
      free(scanner->root_path);
      queue_destroy(scanner->directories);
      free(scanner);
      return NULL;
    }
  }
  if (scanner->one_file_system) {
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
  if (!chunk_items)
    return NULL;
  Chunk* chunk = chunk_create((File**)chunk_items, chunk_data->size);
  free(chunk_items);
  if (!chunk)
    return NULL;
  chunk_data->item_destroyer = NULL;
  array_list_delete(chunk_data);
  return chunk;
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
      if (!scanner->ignore_io_errors || is_root_seed) {
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
    return 1;
  }
  return 0;
}

/* ---- --dirs mode ----
   With -d the scanner transfers directory entries and never recurses into
   contents.  A plain `-d <dir>` sends only the source-root directory mirror
   (created empty at the destination).  With -d + --files-from exactly the
   listed items are sent: listed directories become empty directory entries and
   listed regular files are transferred as files; nothing else is scanned, so
   no descent into a listed directory can happen. */

/* Directory entries carry no payload, so the dirs generator also bounds every
   chunk by element count; chunk_deserialize refuses more than this many files
   per chunk (see MAX_FILES_PER_CHUNK in chunk.c). */
#define DIRS_CHUNK_MAX_FILES 65536U

/* Build the File for the transfer root directory itself (the `-d <dir>` and
 * "." cases). */
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
  if (scanner->use_metadata) {
    file->metadata = file_metadata_create(&st);
    if (!file->metadata) {
      file_destroy(file);
      scanner->failed = true;
      return NULL;
    }
  }
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
    if (scanner->ignore_missing_args) {
      log_info_message(LOG_INFO_MISC, "skipping missing --files-from entry '%s'", entry);
      free(abs_path);
      return NULL;
    }
    log_message(LOG_LEVEL_ERROR, "--dirs listed entry is not present under the source: %s", entry);
    free(abs_path);
    scanner->failed = true;
    return NULL;
  }
  struct stat effective = link_stats;
  if (S_ISLNK(link_stats.st_mode)) {
    /* A symlink is transferred (following its referent) only when a link
       resolution option is active, mirroring the regular scanner. */
    bool resolve = scanner->follow_symlinks || scanner->copy_links || scanner->safe_links ||
                   scanner->copy_unsafe_links;
    if (!resolve || stat(abs_path, &effective) != 0) {
      free(abs_path);
      return NULL;
    }
  }
  bool is_dir = S_ISDIR(effective.st_mode);
  bool is_file = S_ISREG(effective.st_mode);
  if (!is_dir && !is_file) {
    free(abs_path);
    return NULL;
  }
  File* file = file_create(abs_path);
  free(abs_path);
  if (!file) {
    scanner->failed = true;
    return NULL;
  }
  file->is_dir = is_dir;
  file->data->size = is_file ? (unsigned long long)effective.st_size : 0;
  if (scanner->relative_mode) {
    file->send_path = str_dup(entry);
    if (!file->send_path) {
      file_destroy(file);
      scanner->failed = true;
      return NULL;
    }
  }
  if (scanner->use_metadata) {
    file->metadata = file_metadata_create(&effective);
    if (!file->metadata) {
      file_destroy(file);
      scanner->failed = true;
      return NULL;
    }
  }
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

/* The next File from the --dirs generator, or NULL when exhausted. */
static File* dirs_next_file(DirectoryScanner* scanner) {
  if (!scanner->file_list) {
    if (scanner->dirs_root_emitted)
      return NULL;
    scanner->dirs_root_emitted = true;
    /* --prune-empty-dirs: a physically empty source directory's explicit entry
       would only create an empty destination directory, so it is omitted. */
    if (scanner->prune_empty_dirs && dirs_source_dir_is_empty(scanner->root_path))
      return NULL;
    return dirs_root_dir_file(scanner);
  }
  while (scanner->list_index < scanner->file_list->count) {
    const char* entry = scanner->file_list->entries[scanner->list_index++];
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
  while (scanner->dirs_batch == NULL || scanner->dirs_batch_size <= scanner->chunk_size) {
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
  if (scanner && scanner->dirs_mode)
    return directory_scanner_next_dirs(scanner);
  ArrayList* chunk_data = array_list_create(file_destroy);
  if (!chunk_data) {
    scanner->failed = true;
    return NULL;
  }
  unsigned long long chunk_data_size = 0;

  while (1) {
    if (scanner->current_dir == NULL) {
      int ret = open_next_directory(scanner);
      if (ret == 0)
        break;
      if (ret < 0)
        break;
    }

    const struct dirent* entry = readdir(scanner->current_dir);
    if (entry == NULL) {
      closedir(scanner->current_dir);
      scanner->current_dir = NULL;
      free(scanner->current_path);
      scanner->current_path = NULL;
      continue;
    }

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    ScannerOptions options = {
        .use_metadata = scanner->use_metadata,
        .chunk_size = scanner->chunk_size,
        .exclude_patterns = scanner->exclude_patterns,
        .exclude_count = scanner->exclude_count,
        .include_patterns = scanner->include_patterns,
        .include_count = scanner->include_count,
        .max_size = scanner->max_size,
        .min_size = scanner->min_size,
        .max_depth = scanner->max_depth,
        .num_threads = 0,
        .follow_symlinks = scanner->follow_symlinks,
        .copy_links = scanner->copy_links,
        .safe_links = scanner->safe_links,
        .copy_unsafe_links = scanner->copy_unsafe_links,
        .checksum = scanner->checksum,
        .one_file_system = scanner->one_file_system,
        .file_list = scanner->file_list,
        .base_filters = scanner->base_filters,
        .per_dir_filters = scanner->per_dir_filters,
        .dirs = false,
        .relative = false,
    };
    ScannerEntry inspected;
    int inspection = scanner_inspect_entry(&options, scanner->current_path, scanner->current_path,
                                           entry->d_name, &inspected);
    if (inspection < 0) {
      scanner->failed = true;
      break;
    }
    if (inspection == 0) {
      /* The entry was pruned by a user selection rule (exclude/include/size) or
         skipped for another reason; only the user-selection prunes protect the
         corresponding destination mirror from --delete. */
      if (inspected.excluded) {
        char* abs_path = path_cat(scanner->current_path, entry->d_name);
        if (!abs_path) {
          scanner->failed = true;
          break;
        }
        scanner_record_excluded(scanner, abs_path);
        free(abs_path);
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
    bool passes_selection =
        entry_passes_selection(scanner->file_list, scanner->base_filters, scanner->current_node,
                               rel, entry->d_name, is_dir, scanner->per_dir_filters);
    if (!passes_selection) {
      /* --files-from subset pruning is not a filter exclusion: its delete
         semantics stay keep-set-only (an unlisted source path is treated as
         absent, so its destination mirror is a deletable extra).  A rule-based
         exclusion is recorded as a protected prefix.  -R + --files-from bare
         wire paths are never recorded (see ScannerOptions.excluded_paths). */
      bool files_from_prune = scanner->file_list && !file_list_affects(scanner->file_list, rel);
      if (!files_from_prune && !scanner->relative_mode)
        scanner_record_excluded(scanner, cur_path);
    }
    /* With -R + --files-from the wire/destination path is the entry's bare
       relative path; keep `rel` alive to attach it to a transferred file. */
    char* rel_copy = scanner->relative_mode ? str_dup(rel) : NULL;
    free(rel);
    if (rel_copy == NULL && scanner->relative_mode) {
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
      if (!scanner_same_filesystem(scanner->one_file_system, scanner->root_dev, stats.st_dev)) {
        free(cur_path);
        continue;
      }
      int next_depth = scanner->current_depth + 1;
      if (scanner->max_depth <= 0 || next_depth < scanner->max_depth) {
        DirEntry* de = dir_entry_create(cur_path, next_depth, scanner->current_node);
        if (!de || !queue_enqueue(scanner->directories, de)) {
          dir_entry_destroy(de);
          scanner->failed = true;
        }
      }
      free(cur_path);
    } else {
      if (scanner->max_depth > 0 && scanner->current_depth + 1 > scanner->max_depth) {
        free(rel_copy);
        free(cur_path);
        continue;
      }
      File* file = file_create(cur_path);
      free(cur_path);
      if (file == NULL) {
        free(rel_copy);
        scanner->failed = true;
        continue;
      }
      file->data->size = stats.st_size;
      if (scanner->relative_mode) {
        file->send_path = rel_copy;
        rel_copy = NULL;
      }
      if (scanner->use_metadata)
        file->metadata = file_metadata_create(&stats);
      if (scanner->use_metadata && !file->metadata) {
        free(rel_copy);
        file_destroy(file);
        scanner->failed = true;
        break;
      }
      if (!array_list_add(chunk_data, file)) {
        free(rel_copy);
        file_destroy(file);
        scanner->failed = true;
        break;
      }
      chunk_data_size += file->data->size;
      if (chunk_data_size > scanner->chunk_size) {
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
    ds->excluded_mutex = &wa->ps->result_mutex;
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
      scanner_inspect_entry(options, root_directory, root_directory, entry->d_name, &inspected);
  if (inspection < 0) {
    ps->failed = true;
    return;
  }
  if (inspection == 0) {
    if (inspected.excluded && options->excluded_paths) {
      /* A root-level user-selection prune protects the destination mirror of
         the same-named wire path (at the root the bare name is the wire path in
         every layout). */
      char* abs_path = path_cat(root_directory, entry->d_name);
      if (!abs_path) {
        ps->failed = true;
      } else {
        const char* rel = *abs_path == '/' ? abs_path + 1 : abs_path;
        if (!excluded_sink_append(options->excluded_paths, options->excluded_mutex, rel))
          ps->failed = true;
        free(abs_path);
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
  bool passes = entry_passes_selection(options->file_list, options->base_filters, root_node, rel,
                                       entry->d_name, is_dir, options->per_dir_filters);
  /* -R + --files-from: root-level files keep their bare relative send path. */
  bool use_rel = options->relative && options->file_list != NULL;
  if (!passes) {
    /* --files-from subset pruning is not a filter exclusion; -R bare-wire-path
       exclusions are never recorded (see ScannerOptions.excluded_paths). */
    bool files_from_prune = options->file_list && !file_list_affects(options->file_list, rel);
    if (!files_from_prune && !use_rel && options->excluded_paths) {
      const char* rel_path = *cur_path == '/' ? cur_path + 1 : cur_path;
      if (!excluded_sink_append(options->excluded_paths, options->excluded_mutex, rel_path))
        ps->failed = true;
    }
    free(rel);
    free(cur_path);
    return;
  }
  if (is_dir) {
    free(rel);
    if (!scanner_same_filesystem(options->one_file_system, root_dev, st.st_dev)) {
      free(cur_path);
      return;
    }
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
    ps->failed = true;
    return;
  }
  file->data->size = st.st_size;
  if (use_rel) {
    file->send_path = rel;
    rel = NULL;
  }
  if (options->use_metadata)
    file->metadata = file_metadata_create(&st);
  if (options->use_metadata && !file->metadata) {
    free(rel);
    file_destroy(file);
    ps->failed = true;
    return;
  }
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

  /* Build the root directory's .rsync-filter context once; workers seed their
   * scanners with it so per-dir rules behave identically to the sequential
   * scanner. */
  FilterNode* root_node = NULL;
  if (options->per_dir_filters) {
    char err[256];
    bool exists = false;
    FilterRuleList* own = filter_file_read(root_directory, "", &exists, err, sizeof(err));
    if (!own) {
      log_message(LOG_LEVEL_ERROR, "invalid .rsync-filter in %s: %s", root_directory, err);
      array_list_delete(root_files);
      array_list_delete(subdirs);
      parallel_scanner_destroy(ps);
      return NULL;
    }
    if (exists && own->count > 0) {
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
