#include <dirent.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chunk.h"
#include "array_list.h"
#include "data.h"
#include "file.h"
#include "log.h"

Chunk *chunk_create(File **items, int element_count) {
  Chunk *chunk = (Chunk *)malloc(sizeof(Chunk));
  if (chunk == NULL) {
    perror("FATAL ERROR: Could not allocate memory for chunk structure");
    exit(EXIT_FAILURE);
  }

  chunk->items = (File **)malloc(element_count * sizeof(File *));
  if (chunk->items == NULL) {
    perror("FATAL ERROR: Could not allocate memory for items of chunk "
           "structure");
    free(chunk);
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < element_count; i++) {
    chunk->items[i] = items[i];
  }
  chunk->element_count = element_count;
  return chunk;
}

void chunk_destroy(void *item) {
  if (item == NULL) {
    return;
  }
  Chunk *chunk = (Chunk *)item;
  for (int i = 0; i < chunk->element_count; ++i) {
    if (chunk->items[i] != NULL) {
      file_destroy(chunk->items[i]);
    }
  }
  free(chunk->items);
  free(chunk);
}

void chunk_print(void *item) {
  if (item == NULL)
    return;
  Chunk *chunk = (Chunk *)item;
  for (int i = 0; i < chunk->element_count; ++i)
    if (chunk->items[i] != NULL)
      file_print(chunk->items[i]);
}

Data *chunk_format(Chunk *chunk) {
  unsigned long long buffer_size = 0;
  for (int i = 0; i < chunk->element_count; ++i) {
    buffer_size += sizeof(int);
    buffer_size += strlen(chunk->items[i]->path);
    buffer_size += sizeof(unsigned long long);
    buffer_size += chunk->items[i]->stats.st_size;
  }

  char *data = malloc(buffer_size);
  if (data == NULL) {
    perror("Could not allocate data for ChunkFormated!");
    exit(EXIT_FAILURE);
  }
  char *current_data_pointer = data;
  for (int i = 0; i < chunk->element_count; ++i) {
    File *file = chunk->items[i];
    // add path len
    int path_length = (int)strlen(file->path);
    memcpy(current_data_pointer, &path_length, sizeof(int));
    current_data_pointer += sizeof(int);
    // add path
    memcpy(current_data_pointer, file->path, path_length);
    current_data_pointer += path_length;
    // add file data len
    unsigned long long file_length = file->stats.st_size;
    memcpy(current_data_pointer, &file_length, sizeof(unsigned long long));
    current_data_pointer += sizeof(unsigned long long);
    // add file data
    if (file->data == NULL) {
      file_load_data(file);
    }
    memcpy(current_data_pointer, file->data->data, file_length);
    current_data_pointer += file_length;
  }
  if (current_data_pointer - data != (long)(long)buffer_size) {
    perror("Buffer of Chunk wasn't filled enough!");
    exit(EXIT_FAILURE);
  }
  return chunk_data_create(data, buffer_size);
}

Data *chunk_serialize(Chunk *chunk) {
  unsigned long long data_size = 0;
  for (int i = 0; i < chunk->element_count; i++) {
    data_size += sizeof(size_t);
    data_size += strlen(chunk->items[i]->path);
    data_size += sizeof(size_t);
    data_size += chunk->items[i]->stats.st_size;
  }
  Data *data = data_create_empty(data_size);
  if (data == NULL) {
    log_message(LOG_LEVEL_ERROR,
                "Could not allocate memory for chunk serialization");
    exit(EXIT_FAILURE);
  }
  char *data_pointer = data->data;
  for (int i = 0; i < chunk->element_count; i++) {
    size_t path_len = strlen(chunk->items[i]->path);
    memcpy(data_pointer, &path_len, sizeof(size_t));
    data_pointer += sizeof(size_t);
    memcpy(data_pointer, chunk->items[i]->path, path_len);
    data_pointer += path_len;

    size_t file_data_size = chunk->items[i]->stats.st_size;
    memcpy(data_pointer, &file_data_size, sizeof(size_t));
    data_pointer += sizeof(size_t);
    memcpy(data_pointer, chunk->items[i]->data->data, file_data_size);
    data_pointer += file_data_size;
  }
  return data;
}

Chunk *chunk_deserialize(Data *data) {
  ArrayList *files = array_list_create(file_destroy);
  char *data_pointer = data->data;
  size_t remaining_size = data->size;

  while (remaining_size > 0) {
    if (remaining_size < sizeof(size_t)) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for path length");
      array_list_delete(files);
      return NULL;
    }

    size_t path_len = *(size_t *)data_pointer;
    data_pointer += sizeof(size_t);
    remaining_size -= sizeof(size_t);

    if (remaining_size < path_len) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for path");
      array_list_delete(files);
      return NULL;
    }

    char *path = malloc(path_len + 1);
    if (path == NULL) {
      perror("Could not allocate memory for file path");
      array_list_delete(files);
      return NULL;
    }
    memcpy(path, data_pointer, path_len);
    path[path_len] = '\0';
    data_pointer += path_len;
    remaining_size -= path_len;

    if (remaining_size < sizeof(size_t)) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for data size");
      free(path);
      array_list_delete(files);
      return NULL;
    }

    size_t file_data_size = *(size_t *)data_pointer;
    data_pointer += sizeof(size_t);
    remaining_size -= sizeof(size_t);

    if (remaining_size < file_data_size) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for file content");
      free(path);
      array_list_delete(files);
      return NULL;
    }

    struct stat st = {0};
    st.st_size = file_data_size;
    File *file = file_create(path, &st);
    if (file == NULL) {
      free(path);
      array_list_delete(files);
      return NULL;
    }

    void *file_data = malloc(file_data_size);
    if (file_data == NULL) {
      perror("Could not allocate memory for file data");
      free(path);
      array_list_delete(files);
      return NULL;
    }
    memcpy(file_data, data_pointer, file_data_size);
    file->data = data_create(file_data, file_data_size);
    data_pointer += file_data_size;
    remaining_size -= file_data_size;

    array_list_add(files, file);
    free(path);
  }

  File **file_array = (File **)array_list_to_array(files);
  Chunk *chunk = chunk_create(file_array, files->size);

  free(file_array);
  files->item_destroyer = NULL;
  array_list_delete(files);

  return chunk;
}

Data *chunk_compress(Chunk *chunk, int compression_level) {
  log_message(LOG_LEVEL_DEBUG, "Starting to compress chunk");
  Data *serialized = chunk_serialize(chunk);
  Data *compressed = data_compress(serialized, compression_level);
  data_destroy(serialized);
  log_message(LOG_LEVEL_DEBUG, "Chunk successfully compressed");
  return compressed;
}

Chunk *chunk_decompress(Data *compressed_data) {
  log_message(LOG_LEVEL_DEBUG, "Starting to decompress chunk");
  Data *uncompressed_data = data_decompress(compressed_data);
  if (uncompressed_data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to decompress chunk data");
    return NULL;
  }

  Chunk *chunk = chunk_deserialize(uncompressed_data);
  if (chunk == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to deserialize chunk data");
    data_destroy(uncompressed_data);
    return NULL;
  }

  data_destroy(uncompressed_data);
  log_message(LOG_LEVEL_DEBUG, "Chunk successfully decompressed");
  return chunk;
}

Data *chunk_data_create(void *data, unsigned long long data_size) {
  Data *chunk_formated = malloc(sizeof(Data));
  if (chunk_formated == NULL) {
    perror("Could not allocate memory for ChunkFormated");
    exit(EXIT_FAILURE);
  }
  chunk_formated->data = data;
  chunk_formated->size = data_size;
  return chunk_formated;
}

void chunk_data_delete(void *chunk) {
  Data *chunk_data = (Data *)chunk;
  free(chunk_data->data);
  free(chunk_data);
}

// void chunk_data_to_disk(ChunkData *chunk_formated, char *root_directory) {
//   char *current_data_pointer = chunk_formated->data;
//   while (current_data_pointer - (char *)chunk_formated->data <
//          chunk_formated->data_size) {
//     // get path length
//     int path_length = 0;
//     memcpy(&path_length, (int *)current_data_pointer, sizeof(int));
//     current_data_pointer += sizeof(int);
//     // get path
//     int path_dir_size =
//         (strlen(root_directory) + path_length + 1) * sizeof(char);
//     char *path = (char *)malloc(path_dir_size);
//     if (path == NULL) {
//       perror("Could not allocate memory for path!");
//       exit(EXIT_FAILURE);
//     }
//     snprintf(path, path_dir_size, "%s%.*s", root_directory, path_length,
//              current_data_pointer);
//     current_data_pointer += sizeof(char) * path_length;
//     // get data length
//     unsigned long long data_size = 0;
//     memcpy(&data_size, (unsigned long long *)current_data_pointer,
//            sizeof(unsigned long long));
//     current_data_pointer += sizeof(unsigned long long);
//     // create File Receive
//     FileReceive *file =
//         file_receive_create(path, data_size, current_data_pointer);
//     file_receive_print(file);
//     file_receive_to_disk(file);
//     current_data_pointer += sizeof(char) * data_size;
//   }
// }
