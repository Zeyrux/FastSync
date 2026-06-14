#include <dirent.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

#include "chunk.h"
#include "data.h"
#include "log.h"
#include "socket.h"

File *file_create(const char *path, struct stat *stats) {
  File *file = (File *)malloc(sizeof(File));
  if (file == NULL) {
    perror("FATAL ERROR: Could not allocate memory for file struct");
    exit(EXIT_FAILURE);
  }

  file->stats = *stats;

  int path_len = strlen(path);
  file->path = (char *)malloc(path_len + 1);
  if (file->path == NULL) {
    perror("FATAL ERROR: Could not allocate memory for path file string");
    free(file);
    exit(EXIT_FAILURE);
  }

  strcpy(file->path, path);
  file->data = NULL;
  return file;
}

void file_destroy(void *item) {
  if (item == NULL)
    return;
  File *file = (File *)item;
  free(file->data);
  file->data = NULL;
  free(file->path);
  file->path = NULL;
  free(file);
}

void file_load_data(File *file) {
  if (file == NULL)
    return;
  file->data = malloc(file->stats.st_size);
  if (file->data == NULL) {
    perror("Could not allocate memeor y for file data!");
    exit(EXIT_FAILURE);
  }
  file_content_to_buffer(file, file->data);
}

void file_print(void *item) {
  if (item == NULL)
    return;
  printf("%s\n", ((File *)item)->path);
}

void file_send_single_calls(File *file, int file_descriptor) {
  send_str(file_descriptor, file->path);
  send_data(file_descriptor, file->data, file->stats.st_size);
}

void file_content_to_buffer(File *file, char *buffer) {
  if (buffer == NULL) {
    perror("Buffer is to write file content to is NULL!");
    exit(EXIT_FAILURE);
  }
  FILE *file_pointer = fopen(file->path, "rb");
  if (file_pointer == NULL) {
    perror("Could not open the file!");
    exit(EXIT_FAILURE);
  }
  size_t bytes_read = fread(buffer, 1, file->stats.st_size, file_pointer);
  if (bytes_read != (size_t)file->stats.st_size) {
    perror("Read to many or to less bytes from File!");
    exit(EXIT_FAILURE);
  }
  fclose(file_pointer);
}

FileReceive *file_receive_create(char *path, Data *data) {
  FileReceive *file = malloc(sizeof(FileReceive));
  file->path = path;
  file->data_fragment = data;
  return file;
}

void file_receive_destroy(void *file_receive) {
  if (file_receive == NULL)
    return;
  FileReceive *file = (FileReceive *)file_receive;
  data_destroy(file->data_fragment);
  free(file->path);
  free(file);
}

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
    file_content_to_buffer(file, current_data_pointer);
    current_data_pointer += file_length;
  }
  if (current_data_pointer - data != (long)(long)buffer_size) {
    perror("Buffer of Chunk wasn't filled enough!");
    exit(EXIT_FAILURE);
  }
  return chunk_data_create(data, buffer_size);
}

Data *chunk_compress(Chunk *chunk, int compression_level) {
  log_message(LOG_LEVEL_DEBUG, "Starting to gather data for chunk compression");
  unsigned long long data_size = 0;
  for (int i = 0; i < chunk->element_count; i++) {
    data_size += sizeof(unsigned long long);
    data_size += strlen(chunk->items[i]->path);
    data_size += sizeof(unsigned long long);
    data_size += chunk->items[i]->stats.st_size;
  }
  Data *data = data_create_empty(data_size);
  if (data == NULL) {
    log_message(LOG_LEVEL_ERROR,
                "Could not allocate memory for chunk compression");
    exit(EXIT_FAILURE);
  }
  char *data_pointer = data->data;
  for (int i = 0; i < chunk->element_count; i++) {
    // path length
    unsigned long long path_len = strlen(chunk->items[i]->path);
    memcpy(data_pointer, &path_len, sizeof(unsigned long long));
    data_pointer += sizeof(unsigned long long);
    memcpy(data_pointer, chunk->items[i]->path, path_len);
    data_pointer += path_len;
    // file data
    unsigned long long data_size = chunk->items[i]->stats.st_size;
    memcpy(data_pointer, &data_size, sizeof(unsigned long long));
    data_pointer += sizeof(unsigned long long);
    memcpy(data_pointer, chunk->items[i]->data, data_size);
    data_pointer += data_size;
  }

  log_message(LOG_LEVEL_DEBUG, "Chunk succesfully compressed");
  return compress_data(data, compression_level);
}

Chunk *chunk_decompress(Data *data, int compression_level) {
  // ArrayList *files = array_list_create(file_destroy);
  // size_t data_size = ZSTD_getFrameContentSize(const void *src, size_t
  // srcSize);
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
