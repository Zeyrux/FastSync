#include "chmod.h"
#include <stddef.h>
#include <string.h>

static bool parse_clause(mode_t* mode, const char* begin, const char* end) {
  const char* p = begin;
  unsigned who = 0;
  while (p < end && strchr("ugoa", *p)) {
    if (*p == 'a')
      who = 7;
    else
      who |= *p == 'u' ? 1U : (*p == 'g' ? 2U : 4U);
    p++;
  }
  if (who == 0)
    who = 7;
  if (p == end || (*p != '+' && *p != '-' && *p != '='))
    return false;
  char operation = *p++;
  mode_t bits = 0;
  while (p < end) {
    mode_t bit;
    switch (*p++) {
    case 'r':
      bit = 4;
      break;
    case 'w':
      bit = 2;
      break;
    case 'x':
      bit = 1;
      break;
    default:
      return false;
    }
    bits |= bit;
  }
  for (unsigned class_index = 0; class_index < 3; class_index++) {
    unsigned class_bit = 1U << class_index;
    if (!(who & class_bit))
      continue;
    mode_t shift = (mode_t)((2U - class_index) * 3U);
    mode_t mask = (mode_t)(7U << shift);
    mode_t class_bits = (mode_t)(bits << shift);
    if (operation == '+')
      *mode |= class_bits;
    else if (operation == '-')
      *mode &= ~class_bits;
    else
      *mode = (*mode & ~mask) | class_bits;
  }
  return true;
}

bool chmod_apply(mode_t mode, const char* spec, mode_t* result) {
  if (!spec || !*spec || !result)
    return false;
  bool numeric = true;
  size_t length = strlen(spec);
  if (length > 4)
    numeric = false;
  for (size_t i = 0; i < length && numeric; i++)
    numeric = spec[i] >= '0' && spec[i] <= '7';
  if (numeric) {
    if (length < 3 || (length == 4 && spec[0] != '0'))
      return false;
    mode_t parsed = 0;
    for (size_t i = 0; i < length; i++)
      parsed = (mode_t)((parsed << 3) | (spec[i] - '0'));
    *result = (*result & ~07777) | parsed;
    return true;
  }

  mode_t changed = mode;
  const char* begin = spec;
  while (*begin) {
    const char* end = strchr(begin, ',');
    if (!end)
      end = begin + strlen(begin);
    if (!parse_clause(&changed, begin, end))
      return false;
    if (*end == '\0')
      break;
    begin = end + 1;
    if (!*begin)
      return false;
  }
  *result = changed;
  return true;
}
