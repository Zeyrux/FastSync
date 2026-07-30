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
  if (de) {
    de->path = str_dup(path);
    de->depth = depth;
  }
  return de;
}

DirectoryScanner* directory_scanner_create(const char* root_directory, bool use_metadata,
                                           unsigned long long chunk_size, char** exclude_patterns,
                                           int exclude_count, char** include_patterns,
                                           int include_count, unsigned long long max_size,
                                           unsigned long long min_size, int max_depth,
                                           bool follow_symlinks, bool copy_links, bool safe_links,
                                           bool copy_unsafe_links, bool checksum) {
  DirectoryScanner* scanner = malloc(sizeof(DirectoryScanner));
  if (scanner == NULL)
    return NULL;
  scanner->directories = queue_create(100, dir_entry_destroy);
  scanner->current_dir = NULL;
  scanner->current_path = NULL;
  scanner->use_metadata = use_metadata;
  scanner->chunk_size = chunk_size > 0 ? chunk_size : DESIRED_CHUNK_SIZE;
  scanner->exclude_patterns = exclude_patterns;
  scanner->exclude_count = exclude_count;
  scanner->include_patterns = include_patterns;
  scanner->include_count = include_count;
  scanner->max_size = max_size;
  scanner->min_size = min_size;
  scanner->max_depth = max_depth;
  scanner->current_depth = 0;
  scanner->follow_symlinks = follow_symlinks;
  scanner->copy_links = copy_links;
  scanner->safe_links = safe_links;
  scanner->copy_unsafe_links = copy_unsafe_links;
  scanner->checksum = checksum;
  queue_enqueue(scanner->directories, dir_entry_create(root_directory, 0));
  return scanner;
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
  Chunk* chunk = chunk_create((File**)chunk_items, chunk_data->size);
  free(chunk_items);
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
    return -1;
  }
  return 1;
}

Chunk* directory_scanner_next(DirectoryScanner* scanner) {
  ArrayList* chunk_data = array_list_create(file_destroy);
  unsigned long long chunk_data_size = 0;

  while (1) {
    if (scanner->current_dir == NULL) {
      int ret = open_next_directory(scanner);
      if (ret == 0)
        break;
      if (ret < 0)
        continue;
    }

    struct dirent* entry = readdir(scanner->current_dir);
    if (entry == NULL) {
      closedir(scanner->current_dir);
      scanner->current_dir = NULL;
      free(scanner->current_path);
      scanner->current_path = NULL;
      continue;
    }

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    char* cur_path = path_cat(scanner->current_path, entry->d_name);
    struct stat stats;
    struct stat lstats;
    bool is_symlink = false;
    if (lstat(cur_path, &lstats) != 0) {
      free(cur_path);
      continue;
    }
    is_symlink = S_ISLNK(lstats.st_mode);

    if (is_symlink && !scanner->follow_symlinks && !scanner->copy_links && !scanner->safe_links &&
        !scanner->copy_unsafe_links) {
      free(cur_path);
      continue;
    }

    if (is_symlink && scanner->safe_links) {
      char link_target[4096];
      ssize_t len = readlink(cur_path, link_target, sizeof(link_target) - 1);
      if (len < 0) {
        free(cur_path);
        continue;
      }
      link_target[len] = '\0';
      if (link_target[0] == '/') {
        free(cur_path);
        continue;
      }
    }

    if (is_symlink && scanner->copy_unsafe_links && !scanner->copy_links) {
      char link_target[4096];
      ssize_t len = readlink(cur_path, link_target, sizeof(link_target) - 1);
      if (len < 0) {
        free(cur_path);
        continue;
      }
      link_target[len] = '\0';
      bool unsafe = (link_target[0] == '/');
      if (!unsafe) {
        free(cur_path);
        continue;
      }
    }

    bool use_lstat = is_symlink && scanner->follow_symlinks && !scanner->copy_links;
    if (use_lstat) {
      stats = lstats;
    } else {
      if (stat(cur_path, &stats) != 0) {
        free(cur_path);
        continue;
      }
    }

    if (S_ISDIR(stats.st_mode)) {
      int next_depth = scanner->current_depth + 1;
      if (scanner->max_depth <= 0 || next_depth < scanner->max_depth) {
        DirEntry* de = dir_entry_create(cur_path, next_depth);
        if (!queue_enqueue(scanner->directories, de))
          dir_entry_destroy(de);
      }
      free(cur_path);
    } else {
      if (scanner->max_depth > 0 && scanner->current_depth + 1 > scanner->max_depth) {
        free(cur_path);
        continue;
      }
      bool excluded = false;
      for (int i = 0; i < scanner->exclude_count; i++) {
        if (glob_match(scanner->exclude_patterns[i], entry->d_name)) {
          excluded = true;
          break;
        }
      }
      if (excluded) {
        free(cur_path);
        continue;
      }

      if (scanner->include_count > 0) {
        bool included = false;
        for (int i = 0; i < scanner->include_count; i++) {
          if (glob_match(scanner->include_patterns[i], entry->d_name)) {
            included = true;
            break;
          }
        }
        if (!included) {
          free(cur_path);
          continue;
        }
      }

      if ((scanner->max_size > 0 && (unsigned long long)stats.st_size > scanner->max_size) ||
          (scanner->min_size > 0 && (unsigned long long)stats.st_size < scanner->min_size)) {
        free(cur_path);
        continue;
      }

      File* file = file_create(cur_path);
      if (file == NULL) {
        free(cur_path);
        continue;
      }
      file->data->size = stats.st_size;
      if (scanner->use_metadata)
        file->metadata = file_metadata_create(&stats);
      array_list_add(chunk_data, file);
      chunk_data_size += file->data->size;
      if (chunk_data_size > scanner->chunk_size) {
        free(cur_path);
        return chunk_data_to_chunk(chunk_data);
      }
      free(cur_path);
    }
  }

  if (chunk_data->size > 0)
    return chunk_data_to_chunk(chunk_data);
  array_list_delete(chunk_data);
  return NULL;
}

typedef struct {
  ParallelScanner* ps;
  char** dirs;
  int dir_count;
  bool use_metadata;
  unsigned long long chunk_size;
  char** exclude_patterns;
  int exclude_count;
  char** include_patterns;
  int include_count;
  unsigned long long max_size;
  unsigned long long min_size;
  int max_depth;
  bool follow_symlinks;
  bool copy_links;
  bool safe_links;
  bool copy_unsafe_links;
  bool checksum;
} ParallelWorkerArg;

static int parallel_worker_thread(void* arg) {
  ParallelWorkerArg* wa = (ParallelWorkerArg*)arg;
  for (int i = 0; i < wa->dir_count; i++) {
    DirectoryScanner* ds = directory_scanner_create(
        wa->dirs[i], wa->use_metadata, wa->chunk_size, wa->exclude_patterns, wa->exclude_count,
        wa->include_patterns, wa->include_count, wa->max_size, wa->min_size, wa->max_depth,
        wa->follow_symlinks, wa->copy_links, wa->safe_links, wa->copy_unsafe_links, wa->checksum);
    Chunk* chunk;
    while ((chunk = directory_scanner_next(ds)) != NULL) {
      queue_enqueue_multithreaded(wa->ps->result_queue, chunk, &wa->ps->result_mutex,
                                  &wa->ps->result_not_empty, &wa->ps->result_not_full);
    }
    directory_scanner_destroy(ds);
    free(wa->dirs[i]);
  }
  ParallelScanner* ps = wa->ps;
  free(wa->dirs);
  free(wa);
  mtx_lock(&ps->result_mutex);
  ps->completed++;
  if (ps->completed >= ps->num_threads) {
    ps->done = true;
    cnd_signal(&ps->result_not_empty);
  }
  mtx_unlock(&ps->result_mutex);
  return thrd_success;
}

ParallelScanner* parallel_scanner_create(char* root_directory, bool use_metadata,
                                          unsigned long long chunk_size, char** exclude_patterns,
                                          int exclude_count, char** include_patterns,
                                          int include_count, unsigned long long max_size,
                                          unsigned long long min_size, int max_depth,
                                          int num_threads, bool follow_symlinks, bool copy_links,
                                          bool safe_links, bool copy_unsafe_links, bool checksum) {
  ParallelScanner* ps = calloc(1, sizeof(ParallelScanner));
  if (!ps)
    return NULL;
  ps->result_queue = queue_create(100, chunk_destroy);
  if (!ps->result_queue) {
    free(ps);
    return NULL;
  }
  if (mtx_init(&ps->result_mutex, mtx_plain) != thrd_success ||
      cnd_init(&ps->result_not_empty) != thrd_success ||
      cnd_init(&ps->result_not_full) != thrd_success) {
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
  struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    char* cur_path = path_cat(root_directory, entry->d_name);
    if (!cur_path)
      continue;
    struct stat lstats;
    if (lstat(cur_path, &lstats) != 0) {
      free(cur_path);
      continue;
    }
    bool is_symlink = S_ISLNK(lstats.st_mode);

    // Skip symlinks unless the user explicitly enabled following/copying them.
    if (is_symlink && !follow_symlinks && !copy_links && !safe_links &&
        !copy_unsafe_links) {
      free(cur_path);
      continue;
    }

    // --safe-links: reject symlinks pointing outside the source tree.
    if (is_symlink && safe_links) {
      char link_target[4096];
      ssize_t len = readlink(cur_path, link_target, sizeof(link_target) - 1);
      if (len < 0) {
        free(cur_path);
        continue;
      }
      link_target[len] = 0;
      if (link_target[0] == '/') {
        free(cur_path);
        continue;
      }
    }

    // --copy-unsafe-links (without --copy-links): only copy absolute symlinks.
    if (is_symlink && copy_unsafe_links && !copy_links) {
      char link_target[4096];
      ssize_t len = readlink(cur_path, link_target, sizeof(link_target) - 1);
      if (len < 0) {
        free(cur_path);
        continue;
      }
      link_target[len] = 0;
      bool unsafe = (link_target[0] == '/');
      if (!unsafe) {
        free(cur_path);
        continue;
      }
    }

    // Determine whether to use lstat or stat results for the entry.
    struct stat st;
    bool use_lstat_res = is_symlink && follow_symlinks && !copy_links;
    if (use_lstat_res) {
      st = lstats;
    } else {
      if (stat(cur_path, &st) != 0) {
        free(cur_path);
        continue;
      }
    }

    if (S_ISDIR(st.st_mode)) {
      array_list_add(subdirs, cur_path);
    } else {
      bool excluded = false;
      for (int i = 0; i < exclude_count; i++) {
        if (glob_match(exclude_patterns[i], entry->d_name)) {
          excluded = true;
          break;
        }
      }
      if (excluded) {
        free(cur_path);
        continue;
      }
      if (include_count > 0) {
        bool included = false;
        for (int i = 0; i < include_count; i++) {
          if (glob_match(include_patterns[i], entry->d_name)) {
            included = true;
            break;
          }
        }
        if (!included) {
          free(cur_path);
          continue;
        }
      }
      if ((max_size > 0 && (unsigned long long)st.st_size > max_size) ||
          (min_size > 0 && (unsigned long long)st.st_size < min_size)) {
        free(cur_path);
        continue;
      }
      File* file = file_create(cur_path);
      free(cur_path);
      if (!file)
        continue;
      file->data->size = st.st_size;
      if (use_metadata)
        file->metadata = file_metadata_create(&st);
      array_list_add(root_files, file);
    }
  }
  closedir(dir);

  unsigned long long cs = chunk_size > 0 ? chunk_size : DESIRED_CHUNK_SIZE;
  if (root_files->size > 0) {
    ArrayList* batch = array_list_create(NULL);
    unsigned long long batch_size = 0;
    Chunk* first = NULL;
    for (int i = 0; i < root_files->size; i++) {
      File* f = (File*)root_files->items[i];
      array_list_add(batch, f);
      batch_size += f->data->size;
      if (batch_size >= cs || i == root_files->size - 1) {
        void** items = array_list_to_array(batch);
        Chunk* c = chunk_create((File**)items, batch->size);
        free(items);
        batch->item_destroyer = NULL;
        array_list_delete(batch);
        batch = NULL;
        if (!first) {
          first = c;
        } else {
          queue_enqueue_multithreaded(ps->result_queue, c, &ps->result_mutex, &ps->result_not_empty,
                                      &ps->result_not_full);
        }
        if (i < root_files->size - 1) {
          batch = array_list_create(NULL);
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

  int n = num_threads > 0 ? num_threads : 4;
  if (n > subdirs->size)
    n = subdirs->size > 0 ? subdirs->size : 1;

  if (subdirs->size > 0) {
    ps->num_threads = n;
    ps->threads = calloc(n, sizeof(thrd_t));
    if (!ps->threads) {
      array_list_delete(subdirs);
      parallel_scanner_destroy(ps);
      return NULL;
    }
    int dirs_per_thread = subdirs->size / n;
    int remainder = subdirs->size % n;
    int start = 0;
    for (int t = 0; t < n; t++) {
      int count = dirs_per_thread + (t < remainder ? 1 : 0);
      if (count == 0)
        break;
      ParallelWorkerArg* wa = calloc(1, sizeof(ParallelWorkerArg));
      if (!wa)
        break;
      wa->ps = ps;
      wa->dirs = calloc(count, sizeof(char*));
      if (!wa->dirs) {
        free(wa);
        break;
      }
      for (int j = 0; j < count; j++)
        wa->dirs[j] = str_dup((char*)subdirs->items[start + j]);
      wa->dir_count = count;
      wa->use_metadata = use_metadata;
      wa->chunk_size = cs;
      wa->exclude_patterns = exclude_patterns;
      wa->exclude_count = exclude_count;
      wa->include_patterns = include_patterns;
      wa->include_count = include_count;
      wa->max_size = max_size;
      wa->min_size = min_size;
      wa->max_depth = max_depth;
      wa->follow_symlinks = follow_symlinks;
      wa->copy_links = copy_links;
      wa->safe_links = safe_links;
      wa->copy_unsafe_links = copy_unsafe_links;
      wa->checksum = checksum;
      start += count;
      if (thrd_create(&ps->threads[t], parallel_worker_thread, wa) != thrd_success) {
        for (int j = 0; j < count; j++)
          free(wa->dirs[j]);
        free(wa->dirs);
        free(wa);
        ps->num_threads = t;
        break;
      }
    }
  }
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
    ps->done = true;
    return NULL;
  }
  Chunk* chunk = queue_dequeue_multithreaded(
      ps->result_queue, &ps->result_mutex, &ps->result_not_empty, &ps->result_not_full, &ps->done);
  return chunk;
}

void parallel_scanner_destroy(ParallelScanner* ps) {
  if (!ps)
    return;
  ps->done = true;
  cnd_signal(&ps->result_not_empty);
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
