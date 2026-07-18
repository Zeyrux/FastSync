#ifndef CHUNK_H
#define CHUNK_H

#include "config.h"
#include "data.h"
#include "file.h"
#include <stdbool.h>
#include <sys/stat.h>

#define DESIRED_CHUNK_SIZE (10 * 1024 * 1024)

typedef struct {
  File **items;
  int element_count;
} Chunk;

Chunk *chunk_create(File **items, int element_count);
void chunk_destroy(void *chunk);
Data *chunk_serialize(Chunk *chunk, bool use_metadata);
Chunk *chunk_deserialize(Data *data, bool use_metadata);
Data *chunk_compress(Chunk *chunk, int compression_level, bool use_metadata);
Chunk *receive_chunk_data(int fd, Config *config);

#endif
