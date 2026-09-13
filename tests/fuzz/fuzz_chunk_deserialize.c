#include "chunk.h"
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

  /* Exercise both the metadata and non-metadata chunk layouts: the
     metadata branch (present flag + 4-vs-72 advance) is only reachable with
     use_metadata=true, so base the choice on the input rather than hardcoding
     false. */
  Chunk* chunk = chunk_deserialize(d, (data[0] & 1) != 0);
  if (chunk)
    chunk_destroy(chunk);

  data_destroy(d);
  return 0;
}
