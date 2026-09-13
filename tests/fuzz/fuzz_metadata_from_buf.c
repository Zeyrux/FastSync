#include "metadata.h"
#include "file.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  /* Exercise the bounds-checked decoder on EVERY input length, including
   * records shorter than a full metadata body; the decoder must reject those
   * without reading past `size`. */
  char* buf = malloc(size > 0 ? size : 1);
  if (!buf)
    return 0;
  if (size > 0)
    memcpy(buf, data, size);

  FileMetadata* m = metadata_from_buf((const uint8_t*)buf, size);
  if (m)
    free(m);

  free(buf);
  return 0;
}
