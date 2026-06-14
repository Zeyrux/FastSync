#ifndef DATA_H
#define DATA_H

#include "stdlib.h"

typedef struct {
  void *data;
  size_t size;
} Data;

Data *data_create_empty(size_t data_size);
Data *data_create(void *data, size_t data_size);
void data_destroy(Data *data);
Data *compress_data(Data *data_to_compress, int compression_level);
Data *decompress_data(Data *compressed_data);

#endif
