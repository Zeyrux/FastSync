#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2)
    return 0;

  // Split input into pattern and string at the midpoint
  size_t mid = size / 2;

  char* pattern = malloc(mid + 1);
  char* str = malloc(size - mid + 1);
  if (!pattern || !str) {
    free(pattern);
    free(str);
    return 0;
  }

  memcpy(pattern, data, mid);
  pattern[mid] = '\0';

  memcpy(str, data + mid, size - mid);
  str[size - mid] = '\0';

  glob_match(pattern, str);

  free(pattern);
  free(str);
  return 0;
}
