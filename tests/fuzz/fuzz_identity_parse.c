/*
 * Fuzz the CLI-time identity parsers (identity.h):
 *   - identity_parse_copy_as
 *   - identity_parse_map (user and group variants)
 *   - identity_parse_chown
 *
 * Each parser mutates a Config, so every input gets a fresh config_create()
 * (freed afterwards).  After a successful parse the shared wire validator and
 * the ownership predicate are also exercised on the mutated config.  The input
 * is NUL-terminated; embedded NULs simply shorten the effective spec, which is
 * fine for a parser fuzzer.
 */
#include "config.h"
#include "identity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void exercise(Config* c, const char* spec, int which) {
  if (!c)
    return;
  switch (which) {
  case 0:
    (void)identity_parse_copy_as(c, spec);
    break;
  case 1:
    (void)identity_parse_map(c, spec, false);
    break;
  case 2:
    (void)identity_parse_map(c, spec, true);
    break;
  default:
    (void)identity_parse_chown(c, spec);
    break;
  }
  (void)identity_wire_valid(c);
  (void)identity_ownership_requested(c);
  config_delete(c);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0)
    return 0;

  char* spec = malloc(size + 1);
  if (!spec)
    return 0;
  memcpy(spec, data, size);
  spec[size] = '\0';

  exercise(config_create(), spec, 0);
  exercise(config_create(), spec, 1);
  exercise(config_create(), spec, 2);
  exercise(config_create(), spec, 3);

  free(spec);
  return 0;
}
