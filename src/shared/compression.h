#ifndef COMPRESSION_H
#define COMPRESSION_H

#include "data.h"
#include <stdbool.h>

Data* data_compress(Data* data_to_compress, int compression_level);
Data* data_decompress(Data* compressed_data);
bool compression_should_skip(const char* path);

#endif
