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

DirectoryScanner* directory_scanner_create(char* root_directory, bool use_metadata,
                                           unsigned long long chunk_size, char** exclude_patterns,
                                           int exclude_count, char** include_patterns,
                                           int include_count, unsigned long long max_size,
                                           unsigned long long min_size,
                                           int max_depth) {
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

// Returns: 1 on success, 0 if no more directories in queue, -1 on opendir failure
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
    if (stat(cur_path, &stats) != 0) {
      free(cur_path);
      continue;
    }

    if (S_ISDIR(stats.st_mode)) {
      int next_depth = scanner->current_depth + 1;
      if (scanner->max_depth <= 0 || next_depth < scanner->max_depth)
        queue_enqueue(scanner->directories, dir_entry_create(cur_path, next_depth));
      else
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
