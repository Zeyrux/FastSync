#include "metadata.h"
#include "file.h"
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < sizeof(int))
    return 0;

  char* buf = malloc(size);
  if (!buf)
    return 0;
  memcpy(buf, data, size);

  char* original_buf = buf;
  FileMetadata* m = metadata_from_buf(&buf);
  if (m)
    free(m);

  free(original_buf);
  return 0;
}
