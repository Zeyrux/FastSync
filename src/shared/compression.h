#ifndef COMPRESSION_H
#define COMPRESSION_H

#include "data.h"

Data* data_compress(Data* data_to_compress, int compression_level);
Data* data_decompress(Data* compressed_data);

#endif
