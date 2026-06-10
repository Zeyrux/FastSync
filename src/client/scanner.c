#include "scanner.h"
#include "array_list.h"
#include "chunk.h"
#include "queue.h"
#include "utils.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DirectoryScanner *directory_scanner_create(char *root_directory) {
  DirectoryScanner *scanner = malloc(sizeof(DirectoryScanner));
  scanner->directories = queue_create(100, free);
  queue_enqueue(scanner->directories, str_dup(root_directory));
  return scanner;
}

void directory_scanner_destroy(DirectoryScanner *scanner) {
  if (scanner == NULL)
    return;
  queue_destroy(scanner->directories);
  free(scanner);
}

Chunk *chunk_data_to_chunk(ArrayList *chunk_data) {
  void **chunk_items = array_list_to_array(chunk_data);
  Chunk *chunk = chunk_create((File **)chunk_items, chunk_data->size);
  free(chunk_items);
  chunk_data->item_destroyer = NULL;
  array_list_delete(chunk_data);
  return chunk;
}

Chunk *directory_scanner_next(DirectoryScanner *scanner) {
  ArrayList *chunk_data = array_list_create(file_destroy);
  unsigned long long chunk_data_size = 0;

  while (!queue_is_empty(scanner->directories)) {
    char *path = (char *)queue_dequeue(scanner->directories);
    DIR *dir;
    struct dirent *entry;
    dir = opendir(path);
    if (dir == NULL) {
      perror("Could not open directory!");
      exit(EXIT_FAILURE);
    }
    while ((entry = readdir(dir)) != NULL) {
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
        continue;
      }
      char *cur_path = path_cat(path, entry->d_name);
      struct stat stats;
      stat(cur_path, &stats);
      if (!S_ISREG(stats.st_mode))
        queue_enqueue(scanner->directories, (void *)cur_path);
      else {
        File *file = file_create(cur_path, &stats);
        array_list_add(chunk_data, file);
        chunk_data_size += file->stats.st_size;
        if (chunk_data_size > DESIRED_CHUNK_SIZE)
          return chunk_data_to_chunk(chunk_data);
        free(cur_path);
      }
    }
    closedir(dir);
    free(path);
  }
  if (chunk_data->size > 0)
    return chunk_data_to_chunk(chunk_data);
  return NULL;
}
