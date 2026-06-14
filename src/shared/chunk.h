#ifndef CHUNK_H
#define CHUNK_H

#include "data.h"
#include <sys/stat.h>

#define DESIRED_CHUNK_SIZE 10 * 1024 * 1024
#define FILE_PATH_SEPERATOR "#&&SEPP&&#"
#define FILE_PATH_DATA_SEPERATOR "#&&SEPD&&#"

typedef struct {
  char *path;
  struct stat stats;
  char *data;
} File;

typedef struct {
  char *path;
  Data *data;
} FileReceive;

typedef struct {
  File **items;
  int element_count;
} Chunk;

File *file_create(const char *path, struct stat *stats);
void file_destroy(void *item);
void file_load_data(File *file);
void file_print(void *item);
void file_send_single_calls(File *file, int file_descriptor);
void file_content_to_buffer(File *file, char *buffer);

FileReceive *file_receive_create(char *path, Data *data);
void file_receive_destroy(void *file_receive);

Chunk *chunk_create(File **items, int element_count);
void chunk_destroy(void *chunk);
void chunk_print(void *chunk);
Data *chunk_format(Chunk *chunk);
Data *chunk_compress(Chunk *chunk, int compression_level);
Chunk *chunk_decompress(Data *data, int compression_level);

Data *chunk_data_create(void *data, unsigned long long data_size);
void chunk_data_delete(void *chunk);
void chunk_data_to_disk(Data *chunk, char *root_directory);
#endif
