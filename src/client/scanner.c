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

/* One inspected directory entry buffered so the sequential scanner can emit the
   stream in rsync's flist order.  `name` is the raw dirent name (owned here);
   `entry` is the scanner_inspect_entry() result whose path/link_target are owned
   when `inspection == 1`; `inspection` is that call's return code (1 keep,
   0 skip, <0 fatal). */
typedef struct {
  char* name;
  ScannerEntry entry;
  int inspection;
} SortedEntry;

static void sorted_entry_destroy(void* item) {
  SortedEntry* se = (SortedEntry*)item;
  if (!se)
    return;
  free(se->name);
  free(se->entry.path);
  free(se->entry.link_target);
}

/* rsync flist order within one directory: non-directories first, then
   directories, each group by ascending name.  strcmp() compares as unsigned
   char, matching rsync's f_name_cmp(). */
static int sorted_entry_cmp(const void* a, const void* b) {
  const SortedEntry* x = (const SortedEntry*)a;
  const SortedEntry* y = (const SortedEntry*)b;
  bool x_dir = x->inspection > 0 && x->entry.is_directory;
  bool y_dir = y->inspection > 0 && y->entry.is_directory;
  if (x_dir != y_dir)
    return x_dir ? 1 : -1;
  return strcmp(x->name, y->name);
}

static void scanner_free_sorted(DirectoryScanner* scanner) {
  SortedEntry* entries = (SortedEntry*)scanner->sorted_entries;
  for (size_t i = 0; i < scanner->sorted_count; i++)
    sorted_entry_destroy(&entries[i]);
  free(entries);
  scanner->sorted_entries = NULL;
  scanner->sorted_count = 0;
  scanner->sorted_index = 0;
}

/* Read every entry of the open directory, inspect it once and store it sorted in
   rsync's flist order.  Returns 0 on success, -1 on a fatal error (the caller
   aborts the scan). */
static int scanner_buffer_current_directory(DirectoryScanner* scanner) {
  size_t capacity = 64;
  size_t count = 0;
  SortedEntry* entries = malloc(capacity * sizeof(*entries));
  if (!entries) {
    scanner->failed = true;
    return -1;
  }
  const struct dirent* dirent;
  while ((dirent = readdir(scanner->current_dir)) != NULL) {
    if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0)
      continue;
    if (count == capacity) {
      size_t next = capacity * 2;
      SortedEntry* grown = realloc(entries, next * sizeof(*entries));
      if (!grown) {
        scanner->failed = true;
        break;
      }
      entries = grown;
      capacity = next;
    }
    char* name = str_dup(dirent->d_name);
    if (!name) {
      scanner->failed = true;
      break;
    }
    char* link_rel = child_rel_path(scanner->current_rel, dirent->d_name);
    if (!link_rel) {
      free(name);
      scanner->failed = true;
      break;
    }
    int inspection = scanner_inspect_entry(&scanner->options, scanner->current_path, link_rel,
                                           dirent->d_name, &entries[count].entry);
    free(link_rel);
    if (inspection < 0) {
      free(name);
      scanner->failed = true;
      break;
    }
    entries[count].name = name;
    entries[count].inspection = inspection;
    count++;
  }
  if (scanner->failed) {
    for (size_t i = 0; i < count; i++)
      sorted_entry_destroy(&entries[i]);
    free(entries);
    return -1;
  }
  qsort(entries, count, sizeof(*entries), sorted_entry_cmp);
  scanner->sorted_entries = entries;
  scanner->sorted_count = count;
  scanner->sorted_index = 0;
  return 0;
}

/* Push this directory's collected child directories onto the LIFO stack in
   reverse so the first (ascending) child is popped first (depth-first). */
static void scanner_push_pending_dirs(DirectoryScanner* scanner) {
  ArrayList* pending = (ArrayList*)scanner->pending_dirs;
  if (!pending)
    return;
  for (int i = pending->size - 1; i >= 0; i--) {
    if (!queue_push(scanner->directories, pending->items[i])) {
      dir_entry_destroy(pending->items[i]);
      scanner->failed = true;
    }
  }
  pending->size = 0;
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
  scanner->pending_dirs = array_list_create(NULL);
  if (!scanner->pending_dirs) {
    queue_destroy(scanner->directories);
    free(scanner);
    return NULL;
  }
  scanner->current_dir = NULL;
  scanner->current_path = NULL;
  scanner->current_depth = 0;
  scanner->failed = false;
  scanner->sorted_entries = NULL;
  scanner->sorted_count = 0;
  scanner->sorted_index = 0;
  scanner->root_path = str_dup(root_directory);
  if (!scanner->root_path) {
    array_list_delete(scanner->pending_dirs);
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
      array_list_delete(scanner->pending_dirs);
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
      array_list_delete(scanner->pending_dirs);
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
    array_list_delete(scanner->pending_dirs);
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
  scanner_free_sorted(scanner);
  ArrayList* pending = (ArrayList*)scanner->pending_dirs;
  if (pending) {
    for (int i = 0; i < pending->size; i++)
      dir_entry_destroy(pending->items[i]);
    array_list_delete(pending);
  }
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
bool scanner_capture_dir_time(ArrayList* dir_entries, mtx_t* mutex, const char* root_path,
                              const char* fs_path, bool relative_mode, const char* relative_prefix,
                              bool preserve_atimes, bool preserve_crtimes, bool preserve_xattrs,
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
  if (lstat(scanner->current_path, &st) != 0 || !S_ISDIR(st.st_mode))
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
  /* The directory was counted when it was opened; this inline entry represents
     it, so drop the counter to avoid counting it twice in --stats. */
  scanner_dir_count_uncount(&scanner->options);
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
    DirEntry* de = (DirEntry*)queue_pop(scanner->directories);
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
      if (is_root_seed) {
        /* The transfer ROOT being unreadable is always fatal: an empty keep-set
           would delete the whole destination.  Mark the scan as errored so the
           client can report the partial-transfer exit code (rsync's 23). */
        scanner->root_io_error = true;
        scanner->failed = true;
        return -1;
      }
      /* A subdirectory that cannot be opened is always skipped (rsync continues
         with a partial transfer), whether or not --ignore-errors is set.  The
         error is recorded so the client exits 23; --ignore-errors only changes
         what the deletion phase does with the recorded error. */
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
    scanner_dir_count_count(&scanner->options);
    log_debug_message(LOG_DEBUG_FLIST, "flist: scanning %s", scanner->current_path);
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
    /* Buffer and sort this directory's entries in rsync's flist order. */
    if (scanner_buffer_current_directory(scanner) != 0) {
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
        /* The listed directory's direct children are about to be enumerated, so
           its destination mirror is a synchronized directory: record it for the
           per-directory delete plan.  The plan keeps the enumerated children and
           shields untraversed subdirectories, so --delete-during removes extras
           directly inside the listed directory without descending into a kept
           (but untraversed) child -- exactly rsync's `-d DIR/ --delete`. */
        if (!scanner_record_synced_dir(&scanner->options, scanner->root_path, "",
                                       scanner->relative_mode)) {
          scanner->failed = true;
          return NULL;
        }
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

/* Result of processing one inspected entry inside directory_scanner_next(). */
typedef enum {
  SCANNER_ACTION_CONTINUE, /* advance to the next buffered entry */
  SCANNER_ACTION_BREAK,    /* stop the scan loop (failure recorded) */
  SCANNER_ACTION_CHUNK,    /* return the Chunk produced in *out_chunk */
} ScannerAction;

/* Reconstruct the delete-protection path for a skipped (inspection == 0) entry
 * whose destination mirror must be protected. */
static char* scanner_entry_protected_path(DirectoryScanner* scanner, const char* name) {
  if (scanner->relative_mode)
    return child_rel_path(scanner->current_rel, name);
  if (scanner->options.relative_prefix) {
    char* relc = child_rel_path(scanner->current_rel, name);
    char* prefixed = relc ? scanner_prefix_send_path(scanner->options.relative_prefix, relc) : NULL;
    free(relc);
    return prefixed;
  }
  return path_cat(scanner->current_path, name);
}

/* Handle a buffered entry that scanner_inspect_entry() skipped (inspection ==
 * 0): record a partial-transfer I/O error and protect the destination mirror
 * of a user-selection or size prune.  Returns 0 to continue, -1 on failure. */
static int scanner_handle_skipped_entry(DirectoryScanner* scanner, const ScannerEntry* inspected,
                                        const char* name) {
  /* A dereferenced symlink with no referent is a partial-transfer error
     (rsync exit 23): record it as a non-fatal scan I/O error. */
  if (inspected->referent_error)
    scanner->io_error = true;
  /* A user-selection exclude protects its destination mirror from --delete
     unless --delete-excluded; a size prune is always protected.  Other
     skips (unreadable, symlink policy) protect nothing.  Under -R +
     --files-from the protected prefix must be the entry's bare relative
     wire path, not its source path (which would not match the destination
     layout and would leave the mirror deletable). */
  if (inspected->excluded) {
    char* protected_path = scanner_entry_protected_path(scanner, name);
    if (!protected_path) {
      scanner->failed = true;
      return -1;
    }
    if (inspected->size_excluded)
      scanner_record_size_skipped(scanner, protected_path);
    else
      scanner_record_excluded(scanner, protected_path);
    free(protected_path);
  }
  return 0;
}

/* Record the delete-protection prefix for an entry dropped by the --files-from
 * allow-set or a filter rule (sender-hide or receiver-protect).  Returns 0 on
 * success, -1 on allocation failure (caller reports it). */
static int scanner_record_selection_protection(DirectoryScanner* scanner, bool protect,
                                               bool passes_selection, const char* rel,
                                               const char* cur_path) {
  if (passes_selection && !protect)
    return 0;
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
      if (!wrel)
        return -1;
      scanner_record_excluded(scanner, wrel);
      free(wrel);
    } else {
      scanner_record_excluded(scanner, cur_path);
    }
  }
  return 0;
}

/* -x/--one-file-system handling for a directory entry: 1 when the entry was
 * fully handled (caller continues), 0 when it is on the same filesystem as the
 * root (caller descends), -1 on a fatal allocation failure. */
static int scanner_handle_mount_dir(DirectoryScanner* scanner, ArrayList* chunk_data,
                                    const char* cur_path, const struct stat* stats) {
  if (scanner_same_filesystem(scanner->options.one_file_system, scanner->root_dev, stats->st_dev))
    return 0;
  if (scanner->options.one_file_system > 1) {
    /* rsync's -xx drops the mount-point directory entirely (the plain -x
       path below keeps it as an empty directory) and prints the
       --info=mount line when that category is enabled. */
    scanner_note_mount(&scanner->options, cur_path);
    return 1;
  }
  /* rsync's -x/--one-file-system emits the mount-point directory entry
     itself (so the destination gets an empty directory) but does NOT
     descend into it.  Build a payload-less directory File and hand it to
     the caller; never enqueue it for traversal. */
  File* mount = scanner_build_dir_file(cur_path, stats, &scanner->options);
  if (mount == NULL || !array_list_add(chunk_data, mount)) {
    file_destroy(mount);
    scanner->failed = true;
    return -1;
  }
  scanner->current_dir_produced = true;
  return 1;
}

/* Finish the open directory (exhausted entries): emit an empty-directory entry
 * when appropriate, push its pending children and reset the per-directory
 * state.  Returns false when the scanner failed. */
static bool scanner_finish_current_directory(DirectoryScanner* scanner, ArrayList* chunk_data) {
  /* The directory is exhausted: if nothing was transferred or descended
     from it, recreate it at the destination as an explicit entry. */
  if (scanner->options.emit_empty_dirs && !scanner->current_dir_produced &&
      !scanner->options.prune_empty_dirs && !scanner->options.list_dirs &&
      scanner->options.file_list == NULL) {
    if (!scanner_emit_empty_dir(scanner, chunk_data))
      scanner->failed = true;
  }
  scanner_push_pending_dirs(scanner);
  closedir(scanner->current_dir);
  scanner->current_dir = NULL;
  free(scanner->current_path);
  scanner->current_path = NULL;
  scanner_free_sorted(scanner);
  return !scanner->failed;
}

/* Handle one kept buffered entry (inspection == 1): selection recording,
 * directory descent and regular-file emission.  `*chunk_data_size` tracks the
 * accumulated payload so a chunk is cut at the same point as before. */
static ScannerAction scanner_process_entry(DirectoryScanner* scanner, ArrayList* chunk_data,
                                           unsigned long long* chunk_data_size, SortedEntry* sorted,
                                           Chunk** out_chunk) {
  const char* name = sorted->name;
  ScannerEntry* inspected = &sorted->entry;
  char* cur_path = inspected->path;
  struct stat stats = inspected->stats;

  /* --files-from allow-set and the filter layer apply to files and to
   * directories (an excluded directory is not descended into). */
  bool is_dir = inspected->is_directory;
  char* rel = child_rel_path(scanner->current_rel, name);
  if (!rel) {
    scanner->failed = true;
    return SCANNER_ACTION_BREAK;
  }
  bool protect = false;
  bool passes_selection = entry_passes_selection(
      scanner->options.file_list, scanner->options.base_filters, scanner->current_node, rel, name,
      is_dir, scanner->options.per_dir_filters, scanner->options.exclude_per_dir_filter_files,
      &protect);
  /* A sender-side hide leaves the entry out of the transfer; an independent
     receiver-side protect rule keeps a transferred entry's destination mirror
     from being deleted.  Both are recorded in the same protection set. */
  if (!passes_selection || protect) {
    if (scanner_record_selection_protection(scanner, protect, passes_selection, rel, cur_path) !=
        0) {
      free(rel);
      scanner->failed = true;
      return SCANNER_ACTION_BREAK;
    }
  }
  /* With -R the wire/destination path is a reconstructed relative path, not
     the source path; keep `rel` alive to build it for a transferred file. */
  bool needs_rel = scanner->relative_mode || scanner->options.relative_prefix != NULL;
  char* rel_copy = needs_rel ? str_dup(rel) : NULL;
  free(rel);
  if (rel_copy == NULL && needs_rel) {
    scanner->failed = true;
    return SCANNER_ACTION_BREAK;
  }
  if (!passes_selection) {
    scanner_note_filter(&scanner->options, name);
    free(rel_copy);
    return SCANNER_ACTION_CONTINUE;
  }

  if (is_dir) {
    free(rel_copy);
    int mount = scanner_handle_mount_dir(scanner, chunk_data, cur_path, &stats);
    if (mount < 0)
      return SCANNER_ACTION_BREAK;
    if (mount > 0)
      return SCANNER_ACTION_CONTINUE;
    /* --list-only: list directory entries too (rsync prints them), even
       though a real transfer never sends them explicitly. */
    if (scanner->options.list_dirs) {
      File* dir = scanner_build_dir_file(cur_path, &stats, &scanner->options);
      if (dir == NULL || !array_list_add(chunk_data, dir)) {
        file_destroy(dir);
        scanner->failed = true;
        return SCANNER_ACTION_BREAK;
      }
    }
    scanner->current_dir_produced = true;
    int next_depth = scanner->current_depth + 1;
    if (scanner->options.max_depth <= 0 || next_depth < scanner->options.max_depth) {
      DirEntry* de = dir_entry_create(cur_path, next_depth, scanner->current_node);
      if (!de || !array_list_add((ArrayList*)scanner->pending_dirs, de)) {
        dir_entry_destroy(de);
        scanner->failed = true;
      }
    }
    return SCANNER_ACTION_CONTINUE;
  }

  if (scanner->options.max_depth > 0 && scanner->current_depth + 1 > scanner->options.max_depth) {
    free(rel_copy);
    return SCANNER_ACTION_CONTINUE;
  }
  File* file = file_create(cur_path);
  if (file == NULL) {
    free(rel_copy);
    free(inspected->link_target);
    inspected->link_target = NULL;
    scanner->failed = true;
    return SCANNER_ACTION_CONTINUE;
  }
  if (inspected->is_symlink) {
    file->is_symlink = true;
    file->symlink_target = inspected->link_target;
    inspected->link_target = NULL;
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
      return SCANNER_ACTION_BREAK;
    }
  }
  /* --devices/--specials: a device/FIFO/socket entry marked for preservation
     becomes a node to recreate (is_special, no data, rdev captured); an
     unrequested non-regular entry is skipped (rsync default). */
  ScannerSpecial special =
      scanner_prepare_special(scanner->options.preserve_devices, scanner->options.preserve_specials,
                              scanner->options.copy_devices, file, &stats);
  if (special == SCANNER_SPECIAL_SKIP) {
    scanner_note_nonreg(&scanner->options, file->path);
    free(rel_copy);
    file_destroy(file);
    return SCANNER_ACTION_CONTINUE;
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
    return SCANNER_ACTION_BREAK;
  }
  if (!(file->link_group != 0 && !file->link_first))
    scanner_capture_xattrs(scanner, file);
  if (!array_list_add(chunk_data, file)) {
    free(rel_copy);
    file_destroy(file);
    scanner->failed = true;
    return SCANNER_ACTION_BREAK;
  }
  scanner->current_dir_produced = true;
  *chunk_data_size += file->data->size;
  if (*chunk_data_size > scanner->options.chunk_size) {
    free(rel_copy);
    Chunk* result = chunk_data_to_chunk(chunk_data);
    if (!result)
      scanner->failed = true;
    *out_chunk = result;
    return SCANNER_ACTION_CHUNK;
  }
  free(rel_copy);
  return SCANNER_ACTION_CONTINUE;
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

    if (scanner->sorted_index >= scanner->sorted_count) {
      if (!scanner_finish_current_directory(scanner, chunk_data)) {
        array_list_delete(chunk_data);
        return NULL;
      }
      continue;
    }

    SortedEntry* sorted = &((SortedEntry*)scanner->sorted_entries)[scanner->sorted_index++];
    int inspection = sorted->inspection;

    if (inspection == 0) {
      if (scanner_handle_skipped_entry(scanner, &sorted->entry, sorted->name) != 0)
        break;
      continue;
    }

    Chunk* result = NULL;
    ScannerAction action =
        scanner_process_entry(scanner, chunk_data, &chunk_data_size, sorted, &result);
    if (action == SCANNER_ACTION_CHUNK)
      return result;
    if (action == SCANNER_ACTION_BREAK)
      break;
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
  return scanner != NULL && (scanner->io_error || scanner->root_io_error);
}
