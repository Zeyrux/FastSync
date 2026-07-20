#include "compression.h"
#include "data.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0)
    return 0;

  void* buf = malloc(size);
  if (!buf)
    return 0;
  memcpy(buf, data, size);

  Data* d = data_create(buf, size);
  if (!d)
    return 0;

  Data* compressed = data_compress(d, 3);
  if (compressed) {
    Data* decompressed = data_decompress(compressed);
    if (decompressed) {
      data_destroy(decompressed);
    }
    data_destroy(compressed);
  }

  data_destroy(d);
  return 0;
}
