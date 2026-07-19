#include "delta.h"
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

  DeltaSignature* sig = delta_signature_deserialize(d);
  if (sig)
    delta_signature_destroy(sig);

  data_destroy(d);
  return 0;
}
