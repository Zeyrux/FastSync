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
} DirEntry;

static void dir_entry_destroy(void* item) {
  if (item) {
    DirEntry* de = (DirEntry*)item;
    free(de->path);
    free(de);
  }
}

static DirEntry* dir_entry_create(const char* path, int depth) {
  DirEntry* de = malloc(sizeof(DirEntry));
  if (!de)
    return NULL;
  de->path = str_dup(path);
  if (!de->path) {
    free(de);
    return NULL;
  }
  de->depth = depth;
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
} ScannerEntry;

/* Inspect symlinks, resolve the entry type, and apply file filters once for both scanners. */
static int scanner_inspect_entry(const ScannerOptions* options, const char* source_root,
                                 const char* containing_dir, const char* name,
                                 ScannerEntry* entry) {
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
    if (glob_match(options->exclude_patterns[i], name))
      goto skip;
  if (options->include_count > 0) {
    bool included = false;
    for (int i = 0; i < options->include_count; i++)
      if (glob_match(options->include_patterns[i], name))
        included = true;
    if (!included)
      goto skip;
  }
  if ((options->max_size > 0 && (unsigned long long)entry->stats.st_size > options->max_size) ||
      (options->min_size > 0 && (unsigned long long)entry->stats.st_size < options->min_size))
    goto skip;
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
  scanner->failed = false;
  DirEntry* root = dir_entry_create(root_directory, 0);
  if (!root) {
    queue_destroy(scanner->directories);
    free(scanner);
    return NULL;
  }
  if (!queue_enqueue(scanner->directories, root)) {
    dir_entry_destroy(root);
    queue_destroy(scanner->directories);
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
      use_metadata,    chunk_size, exclude_patterns, exclude_count,     include_patterns,
      include_count,   max_size,   min_size,         max_depth,         0,
      follow_symlinks, copy_links, safe_links,       copy_unsafe_links, checksum};
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

static int open_next_directory(DirectoryScanner* scanner) {
  if (scanner->current_dir) {
    closedir(scanner->current_dir);
    scanner->current_dir = NULL;
  }
  free(scanner->current_path);

  if (queue_is_empty(scanner->directories))
    return 0;

  DirEntry* de = (DirEntry*)queue_dequeue(scanner->directories);
  scanner->current_path = de->path;
  scanner->current_depth = de->depth;
  free(de);
  scanner->current_dir = opendir(scanner->current_path);
  if (scanner->current_dir == NULL) {
    perror("Could not open directory");
    free(scanner->current_path);
    scanner->current_path = NULL;
    scanner->failed = true;
    return -1;
  }
  return 1;
}

Chunk* directory_scanner_next(DirectoryScanner* scanner) {
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

    ScannerOptions options = {scanner->use_metadata,     scanner->chunk_size,
                              scanner->exclude_patterns, scanner->exclude_count,
                              scanner->include_patterns, scanner->include_count,
                              scanner->max_size,         scanner->min_size,
                              scanner->max_depth,        0,
                              scanner->follow_symlinks,  scanner->copy_links,
                              scanner->safe_links,       scanner->copy_unsafe_links,
                              scanner->checksum};
    ScannerEntry inspected;
    int inspection = scanner_inspect_entry(&options, scanner->current_path, scanner->current_path,
                                           entry->d_name, &inspected);
    if (inspection < 0) {
      scanner->failed = true;
      break;
    }
    if (inspection == 0)
      continue;
    char* cur_path = inspected.path;
    struct stat stats = inspected.stats;

    if (inspected.is_directory) {
      int next_depth = scanner->current_depth + 1;
      if (scanner->max_depth <= 0 || next_depth < scanner->max_depth) {
        DirEntry* de = dir_entry_create(cur_path, next_depth);
        if (!de || !queue_enqueue(scanner->directories, de)) {
          dir_entry_destroy(de);
          scanner->failed = true;
        }
      }
      free(cur_path);
    } else {
      if (scanner->max_depth > 0 && scanner->current_depth + 1 > scanner->max_depth) {
        free(cur_path);
        continue;
      }
      File* file = file_create(cur_path);
      if (file == NULL) {
        free(cur_path);
        scanner->failed = true;
        continue;
      }
      file->data->size = stats.st_size;
      if (scanner->use_metadata)
        file->metadata = file_metadata_create(&stats);
      if (scanner->use_metadata && !file->metadata) {
        file_destroy(file);
        free(cur_path);
        scanner->failed = true;
        break;
      }
      if (!array_list_add(chunk_data, file)) {
        file_destroy(file);
        scanner->failed = true;
        break;
      }
      chunk_data_size += file->data->size;
      if (chunk_data_size > scanner->chunk_size) {
        free(cur_path);
        Chunk* result = chunk_data_to_chunk(chunk_data);
        if (!result)
          scanner->failed = true;
        return result;
      }
      free(cur_path);
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

typedef struct {
  ParallelScanner* ps;
  char** dirs;
  int dir_count;
  ScannerOptions options;
} ParallelWorkerArg;

static int parallel_worker_thread(void* arg) {
  ParallelWorkerArg* wa = (ParallelWorkerArg*)arg;
  for (int i = 0; i < wa->dir_count; i++) {
    DirectoryScanner* ds = directory_scanner_create_with_options(wa->dirs[i], &wa->options);
    if (!ds) {
      mtx_lock(&wa->ps->result_mutex);
      wa->ps->failed = true;
      atomic_store(&wa->ps->cancelled, true);
      cnd_broadcast(&wa->ps->result_not_empty);
      cnd_broadcast(&wa->ps->result_not_full);
      mtx_unlock(&wa->ps->result_mutex);
      break;
    }
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
    }
    directory_scanner_destroy(ds);
    free(wa->dirs[i]);
  }
  ParallelScanner* ps = wa->ps;
  free(wa->dirs);
  free(wa);
  mtx_lock(&ps->result_mutex);
  ps->completed++;
  if (ps->completed >= ps->expected_threads) {
    ps->done = true;
    cnd_signal(&ps->result_not_empty);
  }
  mtx_unlock(&ps->result_mutex);
  return thrd_success;
}

ParallelScanner* parallel_scanner_create_with_options(const char* root_directory,
                                                      const ScannerOptions* options) {
  if (!root_directory || !options)
    return NULL;
  ParallelScanner* ps = calloc(1, sizeof(ParallelScanner));
  if (!ps)
    return NULL;
  ps->result_queue = queue_create(100, chunk_destroy);
  if (!ps->result_queue) {
    free(ps);
    return NULL;
  }
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
    free(ps);
    return NULL;
  }

  DIR* dir = opendir(root_directory);
  if (!dir) {
    perror("Could not open root directory for parallel scan");
    parallel_scanner_destroy(ps);
    return NULL;
  }

  ArrayList* root_files = array_list_create(file_destroy);
  ArrayList* subdirs = array_list_create(free);
  if (!root_files || !subdirs) {
    array_list_delete(root_files);
    array_list_delete(subdirs);
    closedir(dir);
    parallel_scanner_destroy(ps);
    return NULL;
  }
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    ScannerEntry inspected;
    int inspection =
        scanner_inspect_entry(options, root_directory, root_directory, entry->d_name, &inspected);
    if (inspection < 0) {
      ps->failed = true;
      continue;
    }
    if (inspection == 0)
      continue;
    char* cur_path = inspected.path;
    struct stat st = inspected.stats;
    if (inspected.is_directory) {
      if (!array_list_add(subdirs, cur_path)) {
        free(cur_path);
        ps->failed = true;
      }
    } else {
      File* file = file_create(cur_path);
      free(cur_path);
      if (!file) {
        ps->failed = true;
        continue;
      }
      file->data->size = st.st_size;
      if (options->use_metadata)
        file->metadata = file_metadata_create(&st);
      if (options->use_metadata && !file->metadata) {
        file_destroy(file);
        ps->failed = true;
        continue;
      }
      if (!array_list_add(root_files, file)) {
        file_destroy(file);
        ps->failed = true;
      }
    }
  }
  closedir(dir);

  unsigned long long cs = options->chunk_size > 0 ? options->chunk_size : DESIRED_CHUNK_SIZE;
  if (root_files->size > 0) {
    ArrayList* batch = array_list_create(NULL);
    if (!batch) {
      ps->failed = true;
      array_list_delete(root_files);
      array_list_delete(subdirs);
      parallel_scanner_destroy(ps);
      return NULL;
    }
    unsigned long long batch_size = 0;
    Chunk* first = NULL;
    for (int i = 0; i < root_files->size; i++) {
      File* f = (File*)root_files->items[i];
      if (!array_list_add(batch, f)) {
        ps->failed = true;
        break;
      }
      batch_size += f->data->size;
      if (batch_size >= cs || i == root_files->size - 1) {
        void** items = array_list_to_array(batch);
        if (!items) {
          ps->failed = true;
          batch->item_destroyer = file_destroy;
          array_list_delete(batch);
          batch = NULL;
          break;
        }
        Chunk* c = chunk_create((File**)items, batch->size);
        free(items);
        if (!c) {
          ps->failed = true;
          batch->item_destroyer = file_destroy;
          array_list_delete(batch);
          batch = NULL;
          break;
        }
        batch->item_destroyer = NULL;
        array_list_delete(batch);
        batch = NULL;
        if (!first) {
          first = c;
        } else {
          if (!queue_enqueue(ps->result_queue, c)) {
            chunk_destroy(c);
            ps->failed = true;
          }
        }
        if (i < root_files->size - 1) {
          batch = array_list_create(NULL);
          if (!batch) {
            ps->failed = true;
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
    ps->initial_chunk = first;
    root_files->item_destroyer = NULL;
  }
  array_list_delete(root_files);

  int n = options->num_threads > 0 ? options->num_threads : 4;
  if (n > subdirs->size)
    n = subdirs->size > 0 ? subdirs->size : 1;

  if (subdirs->size > 0) {
    ps->num_threads = n;
    ps->expected_threads = n;
    ps->threads = calloc(n, sizeof(thrd_t));
    if (!ps->threads) {
      array_list_delete(subdirs);
      parallel_scanner_destroy(ps);
      return NULL;
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
        ps->failed = true;
        break;
      }
      wa->ps = ps;
      wa->dirs = calloc(count, sizeof(char*));
      if (!wa->dirs) {
        free(wa);
        ps->failed = true;
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
        free(wa->dirs);
        free(wa);
        ps->failed = true;
        break;
      }
      wa->dir_count = count;
      wa->options = *options;
      wa->options.chunk_size = cs;
      start += count;
      if (thrd_create(&ps->threads[t], parallel_worker_thread, wa) != thrd_success) {
        for (int j = 0; j < count; j++)
          free(wa->dirs[j]);
        free(wa->dirs);
        free(wa);
        ps->failed = true;
        atomic_store(&ps->cancelled, true);
        ps->expected_threads = ps->created_threads;
        mtx_lock(&ps->result_mutex);
        cnd_broadcast(&ps->result_not_empty);
        cnd_broadcast(&ps->result_not_full);
        mtx_unlock(&ps->result_mutex);
        break;
      }
      ps->num_threads++;
      ps->created_threads++;
    }
  }
  array_list_delete(subdirs);
  return ps;
}

ParallelScanner* parallel_scanner_create(const char* root_directory, bool use_metadata,
                                         unsigned long long chunk_size, char** exclude_patterns,
                                         int exclude_count, char** include_patterns,
                                         int include_count, unsigned long long max_size,
                                         unsigned long long min_size, int max_depth,
                                         int num_threads, bool follow_symlinks, bool copy_links,
                                         bool safe_links, bool copy_unsafe_links, bool checksum) {
  ScannerOptions options = {use_metadata,     chunk_size,        exclude_patterns, exclude_count,
                            include_patterns, include_count,     max_size,         min_size,
                            max_depth,        num_threads,       follow_symlinks,  copy_links,
                            safe_links,       copy_unsafe_links, checksum};
  return parallel_scanner_create_with_options(root_directory, &options);
}

Chunk* parallel_scanner_next(ParallelScanner* ps) {
  if (ps->initial_chunk) {
    Chunk* c = ps->initial_chunk;
    ps->initial_chunk = NULL;
    return c;
  }
  if (ps->num_threads == 0) {
    mtx_lock(&ps->result_mutex);
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
  if (ps->initial_chunk)
    chunk_destroy(ps->initial_chunk);
  queue_destroy(ps->result_queue);
  mtx_destroy(&ps->result_mutex);
  cnd_destroy(&ps->result_not_empty);
  cnd_destroy(&ps->result_not_full);
  free(ps);
}
