#ifndef COMPRESSION_H
#define COMPRESSION_H

#include "data.h"
#include <stdbool.h>

Data* data_compress(Data* data_to_compress, int compression_level);
Data* data_decompress(Data* compressed_data);
Data* data_decompress_limited(Data* compressed_data, size_t maximum_size);
bool compression_should_skip(const char* path);
bool compression_should_skip_with_suffixes(const char* path, char* const* suffixes, int count);

#endif
