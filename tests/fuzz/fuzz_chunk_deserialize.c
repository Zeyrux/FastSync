#include "chunk.h"
#include "data.h"
#include <stdint.h>
#include <stdlib.h>

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

  Chunk* chunk = chunk_deserialize(d, false);
  if (chunk)
    chunk_destroy(chunk);

  data_destroy(d);
  return 0;
}
