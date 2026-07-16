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

DirectoryScanner *directory_scanner_create(char *root_directory, bool use_metadata, unsigned long long chunk_size, char **exclude_patterns, int exclude_count) {
  DirectoryScanner *scanner = malloc(sizeof(DirectoryScanner));
  scanner->directories = queue_create(100, free);
  scanner->current_dir = NULL;
  scanner->current_path = NULL;
  scanner->use_metadata = use_metadata;
  scanner->chunk_size = chunk_size > 0 ? chunk_size : DESIRED_CHUNK_SIZE;
  scanner->exclude_patterns = exclude_patterns;
  scanner->exclude_count = exclude_count;
  queue_enqueue(scanner->directories, str_dup(root_directory));
  return scanner;
}

void directory_scanner_destroy(DirectoryScanner *scanner) {
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

static Chunk *chunk_data_to_chunk(ArrayList *chunk_data) {
  void **chunk_items = array_list_to_array(chunk_data);
  Chunk *chunk = chunk_create((File **)chunk_items, chunk_data->size);
  free(chunk_items);
  chunk_data->item_destroyer = NULL;
  array_list_delete(chunk_data);
  return chunk;
}

static int open_next_directory(DirectoryScanner *scanner) {
  if (scanner->current_dir) {
    closedir(scanner->current_dir);
    scanner->current_dir = NULL;
  }
  free(scanner->current_path);

  if (queue_is_empty(scanner->directories))
    return 0;

  scanner->current_path = (char *)queue_dequeue(scanner->directories);
  scanner->current_dir = opendir(scanner->current_path);
  if (scanner->current_dir == NULL) {
    perror("Could not open directory!");
    exit(EXIT_FAILURE);
  }
  return 1;
}

Chunk *directory_scanner_next(DirectoryScanner *scanner) {
  ArrayList *chunk_data = array_list_create(file_destroy);
  unsigned long long chunk_data_size = 0;

  while (1) {
    if (scanner->current_dir == NULL) {
      if (!open_next_directory(scanner))
        break;
    }

    struct dirent *entry = readdir(scanner->current_dir);
    if (entry == NULL) {
      closedir(scanner->current_dir);
      scanner->current_dir = NULL;
      free(scanner->current_path);
      scanner->current_path = NULL;
      continue;
    }

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    char *cur_path = path_cat(scanner->current_path, entry->d_name);
    struct stat stats;
    if (stat(cur_path, &stats) != 0) {
      free(cur_path);
      continue;
    }

    if (S_ISDIR(stats.st_mode)) {
      queue_enqueue(scanner->directories, (void *)cur_path);
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
      File *file = file_create(cur_path);
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
  return NULL;
}
