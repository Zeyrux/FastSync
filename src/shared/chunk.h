#ifndef CHUNK_H
#define CHUNK_H

#include "data.h"
#include "file.h"
#include <sys/stat.h>

#define DESIRED_CHUNK_SIZE 10 * 1024 * 1024
#define FILE_PATH_SEPERATOR "#&&SEPP&&#"
#define FILE_PATH_DATA_SEPERATOR "#&&SEPD&&#"

typedef struct {
  File **items;
  int element_count;
} Chunk;

Chunk *chunk_create(File **items, int element_count);
void chunk_destroy(void *chunk);
void chunk_print(void *chunk);
Data *chunk_format(Chunk *chunk);
Data *chunk_compress(Chunk *chunk, int compression_level);
Chunk *chunk_decompress(Data *compressed_data);

Data *chunk_data_create(void *data, unsigned long long data_size);
void chunk_data_delete(void *chunk);
void chunk_data_to_disk(Data *chunk, char *root_directory);
#endif
