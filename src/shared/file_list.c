#include "file_list.h"
#include "log.h"
#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char** items;
  int count;
  int capacity;
} StringList;

static void string_list_destroy(StringList* list) {
  if (!list)
    return;
  for (int i = 0; i < list->count; i++)
    free(list->items[i]);
  free(list->items);
}

static bool string_list_add(StringList* list, const char* text) {
  if (list->count == list->capacity) {
    int new_cap = list->capacity > 0 ? list->capacity * 2 : 16;
    char** grown = realloc(list->items, (size_t)new_cap * sizeof(char*));
    if (!grown)
      return false;
    list->items = grown;
    list->capacity = new_cap;
  }
  list->items[list->count] = str_dup(text);
  if (!list->items[list->count])
    return false;
  list->count++;
  return true;
}

/* Validate and normalize one entry. Returns:
 *   1 -> added to `out`
 *   0 -> blank entry, skip
 *  -1 -> invalid (message set in `err`)
 * `strip_line_endings` trims a trailing CR/LF (line mode only); NUL mode keeps
 * the entry bytes verbatim so names ending in CR/LF survive. */
static int normalize_entry(const char* raw, size_t len, bool strip_line_endings, StringList* out,
                           char* err, size_t err_size) {
  if (strip_line_endings) {
    while (len > 0 && (raw[len - 1] == '\n' || raw[len - 1] == '\r'))
      len--;
  }
  if (len == 0)
    return 0;
  if (raw[0] == '/') {
    snprintf(err, err_size, "absolute path entries are not allowed: '%.*s'", (int)len, raw);
    return -1;
  }
  /* Reject NUL bytes inside a token defensively (NUL-delimited mode splits on
   * them, so this only guards against embedded garbage). */
  char* dup = malloc(len + 1);
  if (!dup) {
    snprintf(err, err_size, "memory allocation failed");
    return -1;
  }
  memcpy(dup, raw, len);
  dup[len] = '\0';

  /* Rebuild the path token-by-token: skip '.' and empty segments, reject '..'. */
  size_t out_len = 0;
  for (const char* part = dup;;) {
    const char* slash = strchr(part, '/');
    size_t part_len = slash ? (size_t)(slash - part) : strlen(part);
    if (part_len == 1 && part[0] == '.') {
      /* skip "." segment */
    } else if (part_len == 2 && part[0] == '.' && part[1] == '.') {
      snprintf(err, err_size, "path traversal entry is not allowed: '%s'", dup);
      free(dup);
      return -1;
    } else if (part_len > 0) {
      if (out_len > 0)
        dup[out_len++] = '/';
      memmove(dup + out_len, part, part_len);
      out_len += part_len;
    }
    if (!slash)
      break;
    part = slash + 1;
  }
  dup[out_len] = '\0';

  int result;
  if (out_len == 0) {
    /* "." / "./" lists the source root: the whole tree is transferred. */
    result = string_list_add(out, "") ? 1 : -1;
    if (result < 0)
      snprintf(err, err_size, "memory allocation failed");
  } else {
    result = string_list_add(out, dup) ? 1 : -1;
    if (result < 0)
      snprintf(err, err_size, "memory allocation failed");
  }
  free(dup);
  return result;
}

static FileListSet* string_list_to_set(StringList* raw, char* err, size_t err_size) {
  FileListSet* set = malloc(sizeof(FileListSet));
  if (!set) {
    snprintf(err, err_size, "memory allocation failed");
    return NULL;
  }
  set->count = raw->count;
  set->entries = raw->items;
  raw->items = NULL;
  raw->count = 0;
  return set;
}

FileListSet* file_list_load(const char* path, bool null_separated, char* err, size_t err_size) {
  if (err && err_size > 0)
    err[0] = '\0';
  if (!path || !*path) {
    snprintf(err, err_size, "no file given");
    return NULL;
  }
  FILE* fp = fopen(path, "r");
  if (!fp) {
    char* escaped = output_escape(path, false);
    snprintf(err, err_size, "could not open '%s': %s", escaped ? escaped : path, strerror(errno));
    free(escaped);
    return NULL;
  }

  StringList raw = {0};
  char* line = NULL;
  size_t line_cap = 0;
  ssize_t n;
  bool ok = true;
  char delim = null_separated ? '\0' : '\n';
  while (ok && (n = getdelim(&line, &line_cap, delim, fp)) != -1) {
    int r = normalize_entry(line, (size_t)n, !null_separated, &raw, err, err_size);
    if (r < 0) {
      ok = false;
      break;
    }
  }
  free(line);
  fclose(fp);
  if (!ok) {
    string_list_destroy(&raw);
    return NULL;
  }
  FileListSet* set = string_list_to_set(&raw, err, err_size);
  if (!set)
    string_list_destroy(&raw);
  return set;
}

void file_list_destroy(FileListSet* set) {
  if (!set)
    return;
  for (int i = 0; i < set->count; i++)
    free(set->entries[i]);
  free(set->entries);
  free(set);
}

static bool path_has_prefix(const char* path, const char* prefix) {
  size_t plen = strlen(prefix);
  if (strncmp(path, prefix, plen) != 0)
    return false;
  return path[plen] == '/' || path[plen] == '\0';
}

bool file_list_affects(const FileListSet* set, const char* rel) {
  if (!set)
    return true;
  if (!rel)
    return false;
  for (int i = 0; i < set->count; i++) {
    const char* entry = set->entries[i];
    if (entry[0] == '\0')
      return true; /* whole tree listed */
    if (strcmp(rel, entry) == 0)
      return true; /* the entry itself is listed */
    if (path_has_prefix(rel, entry))
      return true; /* rel lives under a listed directory */
    if (path_has_prefix(entry, rel))
      return true; /* rel is an ancestor directory of a listed entry */
  }
  return false;
}
