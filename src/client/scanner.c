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

DirectoryScanner* directory_scanner_create(char* root_directory, bool use_metadata,
                                           unsigned long long chunk_size, char** exclude_patterns,
                                           int exclude_count, char** include_patterns,
                                           int include_count, unsigned long long max_size,
                                           unsigned long long min_size) {
  return directory_scanner_create_full(root_directory, use_metadata, chunk_size, exclude_patterns,
                                       exclude_count, include_patterns, include_count, max_size,
                                       min_size, true);
}

DirectoryScanner* directory_scanner_create_full(char* root_directory, bool use_metadata,
                                                unsigned long long chunk_size,
                                                char** exclude_patterns, int exclude_count,
                                                char** include_patterns, int include_count,
                                                unsigned long long max_size,
                                                unsigned long long min_size, bool follow_symlinks) {
  DirectoryScanner* scanner = malloc(sizeof(DirectoryScanner));
  if (scanner == NULL)
    return NULL;
  scanner->directories = queue_create(100, free);
  scanner->current_dir = NULL;
  scanner->current_path = NULL;
  scanner->use_metadata = use_metadata;
  scanner->chunk_size = chunk_size > 0 ? chunk_size : DESIRED_CHUNK_SIZE;
  /* Deep-copy exclude patterns */
  if (exclude_count > 0 && exclude_patterns != NULL) {
    scanner->exclude_patterns = malloc((size_t)exclude_count * sizeof(char*));
    if (scanner->exclude_patterns == NULL) {
      queue_destroy(scanner->directories);
      free(scanner);
      return NULL;
    }
    for (int i = 0; i < exclude_count; i++) {
      scanner->exclude_patterns[i] = str_dup(exclude_patterns[i]);
      if (scanner->exclude_patterns[i] == NULL) {
        for (int j = 0; j < i; j++)
          free(scanner->exclude_patterns[j]);
        free(scanner->exclude_patterns);
        queue_destroy(scanner->directories);
        free(scanner);
        return NULL;
      }
    }
  } else {
    scanner->exclude_patterns = NULL;
  }
  scanner->exclude_count = exclude_count;

  /* Deep-copy include patterns */
  if (include_count > 0 && include_patterns != NULL) {
    scanner->include_patterns = malloc((size_t)include_count * sizeof(char*));
    if (scanner->include_patterns == NULL) {
      for (int i = 0; i < exclude_count; i++)
        free(scanner->exclude_patterns[i]);
      free(scanner->exclude_patterns);
      queue_destroy(scanner->directories);
      free(scanner);
      return NULL;
    }
    for (int i = 0; i < include_count; i++) {
      scanner->include_patterns[i] = str_dup(include_patterns[i]);
      if (scanner->include_patterns[i] == NULL) {
        for (int j = 0; j < i; j++)
          free(scanner->include_patterns[j]);
        free(scanner->include_patterns);
        for (int j = 0; j < exclude_count; j++)
          free(scanner->exclude_patterns[j]);
        free(scanner->exclude_patterns);
        queue_destroy(scanner->directories);
        free(scanner);
        return NULL;
      }
    }
  } else {
    scanner->include_patterns = NULL;
  }
  scanner->include_count = include_count;
  scanner->max_size = max_size;
  scanner->min_size = min_size;
  scanner->follow_symlinks = follow_symlinks;
  char* root_copy = str_dup(root_directory);
  if (root_copy == NULL) {
    for (int i = 0; i < scanner->include_count; i++)
      free(scanner->include_patterns[i]);
    free(scanner->include_patterns);
    for (int i = 0; i < scanner->exclude_count; i++)
      free(scanner->exclude_patterns[i]);
    free(scanner->exclude_patterns);
    queue_destroy(scanner->directories);
    free(scanner);
    return NULL;
  }
  queue_enqueue(scanner->directories, root_copy);
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
  for (int i = 0; i < scanner->exclude_count; i++)
    free(scanner->exclude_patterns[i]);
  free(scanner->exclude_patterns);
  for (int i = 0; i < scanner->include_count; i++)
    free(scanner->include_patterns[i]);
  free(scanner->include_patterns);
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

  scanner->current_path = (char*)queue_dequeue(scanner->directories);
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
    // Use lstat to detect symlinks
    if (lstat(cur_path, &stats) != 0) {
      free(cur_path);
      continue;
    }

    // If follow_symlinks is enabled and this is a symlink, resolve it
    if (scanner->follow_symlinks && S_ISLNK(stats.st_mode)) {
      struct stat target_stats;
      if (stat(cur_path, &target_stats) != 0) {
        // Broken symlink, skip
        free(cur_path);
        continue;
      }
      stats = target_stats;
    }

    if (S_ISDIR(stats.st_mode)) {
      queue_enqueue(scanner->directories, (void*)cur_path);
    } else if (S_ISLNK(stats.st_mode)) {
      // Handle symlink (not following)
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

      File* file = file_create(cur_path);
      if (file == NULL) {
        free(cur_path);
        continue;
      }
      file->type = FILE_TYPE_SYMLINK;
      // Read link target
      char link_buf[4096];
      ssize_t link_len = readlink(cur_path, link_buf, sizeof(link_buf) - 1);
      if (link_len >= 0) {
        link_buf[link_len] = '\0';
        file->link_target = str_dup(link_buf);
        if (file->link_target == NULL) {
          file_destroy(file);
          free(cur_path);
          continue;
        }
      }
      file->data->size = 0;
      if (scanner->use_metadata)
        file->metadata = file_metadata_create(&stats);
      array_list_add(chunk_data, file);
      chunk_data_size += 1; // small size for symlinks
      if (chunk_data_size > scanner->chunk_size) {
        free(cur_path);
        return chunk_data_to_chunk(chunk_data);
      }
      free(cur_path);
    } else {
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
