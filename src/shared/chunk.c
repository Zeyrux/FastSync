#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array_list.h"
#include "chunk.h"
#include "compression.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"

Chunk *chunk_create(File **items, int element_count) {
  Chunk *chunk = (Chunk *)malloc(sizeof(Chunk));
  if (chunk == NULL) {
    perror("ERROR: Could not allocate memory for chunk structure");
    return NULL;
  }

  chunk->items = (File **)malloc(element_count * sizeof(File *));
  if (chunk->items == NULL) {
    free(chunk);
    return NULL;
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

static unsigned long long per_file_serialize_size(File *file, bool use_metadata) {
  return sizeof(size_t) + strlen(file->path) +
         (use_metadata ? sizeof(int) + (file->metadata ? FILE_METADATA_WIRE_SIZE : 0) : 0) +
         sizeof(size_t) + file->data->size;
}

Data *chunk_serialize(Chunk *chunk, bool use_metadata) {
  unsigned long long data_size = 0;
  for (int i = 0; i < chunk->element_count; i++) {
    data_size += per_file_serialize_size(chunk->items[i], use_metadata);
  }
  Data *data = data_create_empty(data_size);
  if (data == NULL) {
    log_message(LOG_LEVEL_ERROR,
                "Could not allocate memory for chunk serialization");
    return NULL;
  }
  char *data_pointer = data->data;
  for (int i = 0; i < chunk->element_count; i++) {
    File *file = chunk->items[i];
    size_t path_len = strlen(file->path);
    memcpy(data_pointer, &path_len, sizeof(size_t));
    data_pointer += sizeof(size_t);
    memcpy(data_pointer, file->path, path_len);
    data_pointer += path_len;

    if (use_metadata)
      metadata_to_buf(&data_pointer, file->metadata);

    size_t file_data_size = file->data->size;
    memcpy(data_pointer, &file_data_size, sizeof(size_t));
    data_pointer += sizeof(size_t);
    memcpy(data_pointer, file->data->data, file_data_size);
    data_pointer += file_data_size;
  }
  return data;
}

Chunk *chunk_deserialize(Data *data, bool use_metadata) {
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

    File *file = file_create(path);
    free(path);

    if (use_metadata) {
      file->metadata = metadata_from_buf(&data_pointer);
      remaining_size -= sizeof(int);
      if (file->metadata)
        remaining_size -= FILE_METADATA_WIRE_SIZE;
    }

    if (remaining_size < sizeof(size_t)) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for data size");
      array_list_delete(files);
      return NULL;
    }

    size_t file_data_size = *(size_t *)data_pointer;
    data_pointer += sizeof(size_t);
    remaining_size -= sizeof(size_t);

    if (remaining_size < file_data_size) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for file content");
      array_list_delete(files);
      return NULL;
    }

    void *file_data = malloc(file_data_size);
    if (file_data == NULL) {
      perror("Could not allocate memory for file data");
      array_list_delete(files);
      return NULL;
    }
    memcpy(file_data, data_pointer, file_data_size);
    data_destroy(file->data);
    file->data = data_create(file_data, file_data_size);
    data_pointer += file_data_size;
    remaining_size -= file_data_size;

    array_list_add(files, file);
  }

  File **file_array = (File **)array_list_to_array(files);
  Chunk *chunk = chunk_create(file_array, files->size);

  free(file_array);
  files->item_destroyer = NULL;
  array_list_delete(files);

  return chunk;
}

Data *chunk_compress(Chunk *chunk, int compression_level, bool use_metadata) {
  log_message(LOG_LEVEL_DEBUG, "Starting to compress chunk");
  Data *serialized = chunk_serialize(chunk, use_metadata);
  if (serialized == NULL) return NULL;
  Data *compressed = data_compress(serialized, compression_level);
  data_destroy(serialized);
  if (compressed == NULL) return NULL;
  log_message(LOG_LEVEL_DEBUG, "Chunk successfully compressed");
  return compressed;
}

Chunk *receive_chunk_data(int fd, Config *config) {
  Data *chunk_data = receive_data(fd);
  if (chunk_data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to receive chunk data");
    return NULL;
  }
  Data *data_to_process = chunk_data;
  if (config->use_compression) {
    data_to_process = data_decompress(chunk_data);
    data_destroy(chunk_data);
    if (data_to_process == NULL) {
      log_message(LOG_LEVEL_ERROR, "Failed to decompress chunk");
      return NULL;
    }
  }
  Chunk *chunk = chunk_deserialize(data_to_process, config->use_metadata);
  data_destroy(data_to_process);
  if (chunk == NULL)
    log_message(LOG_LEVEL_ERROR, "Failed to deserialize chunk, skipping");
  return chunk;
}



