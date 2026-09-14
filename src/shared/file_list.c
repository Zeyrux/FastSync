#include "file_list.h"
#include "log.h"
#include "utils.h"
#include <errno.h>
#include <limits.h>
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
    if (list->capacity > INT_MAX / 2)
      return false;
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
    int print_len = len > (size_t)INT_MAX ? INT_MAX : (int)len;
    snprintf(err, err_size, "absolute path entries are not allowed: '%.*s'", print_len, raw);
    return -1;
  }
  /* Reject NUL bytes inside a token defensively.  In NUL-delimited mode the
   * delimiter itself is the final byte and is expected; in line mode any NUL is
   * embedded garbage (strlen-based parsing would otherwise silently truncate). */
  size_t scan_len = strip_line_endings ? len : len - 1;
  if (memchr(raw, '\0', scan_len)) {
    snprintf(err, err_size, "entry contains an embedded NUL byte");
    return -1;
  }
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

/* Build the membership index over the exact entries only.  `file_list_affects`
   combines the exact/descendant lookups with a walk of the query's own ancestor
   prefixes, so no ancestor prefix is ever materialized as a copy and the index
   stays O(entry count) memory regardless of path depth.  An empty entry (the
   source root) sets whole_tree and short-circuits every query. */
static bool file_list_index_build(FileListSet* set, char* err, size_t err_size) {
  if (!path_index_build(&set->index, (const char* const*)set->entries, (size_t)set->count)) {
    snprintf(err, err_size, "memory allocation failed");
    return false;
  }
  for (int i = 0; i < set->count; i++) {
    if (set->entries[i][0] == '\0') {
      set->whole_tree = true;
      break;
    }
  }
  return true;
}

static FileListSet* string_list_to_set(StringList* raw, char* err, size_t err_size) {
  FileListSet* set = calloc(1, sizeof(FileListSet));
  if (!set) {
    snprintf(err, err_size, "memory allocation failed");
    return NULL;
  }
  set->count = raw->count;
  set->entries = raw->items;
  raw->items = NULL;
  raw->count = 0;
  if (!file_list_index_build(set, err, err_size)) {
    file_list_destroy(set);
    return NULL;
  }
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
  bool ok = true;
  char delim = null_separated ? '\0' : '\n';
  while (ok) {
    ssize_t n = utils_getdelim_bounded(fp, &line, &line_cap, delim, UTILS_MAX_LINE_LEN);
    if (n < 0) {
      if (errno == EFBIG)
        snprintf(err, err_size, "entry in file list exceeds %d bytes", (int)UTILS_MAX_LINE_LEN);
      else
        snprintf(err, err_size, "error reading file list: %s", strerror(errno));
      ok = false;
      break;
    }
    if (n == 0)
      break;
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
  path_index_free(&set->index);
  for (int i = 0; i < set->count; i++)
    free(set->entries[i]);
  free(set->entries);
  free(set);
}

bool file_list_affects(const FileListSet* set, const char* rel) {
  if (!set)
    return true;
  if (!rel)
    return false;
  if (set->whole_tree)
    return true; /* whole tree listed */
  /* An exact entry match means `rel` itself is listed. */
  if (path_index_contains(&set->index, rel))
    return true;
  /* Otherwise `rel` is affected when a listed entry is an ancestor directory of
     it; walk rel's own directory prefixes (which preserve path-boundary
     semantics) and test each for an exact entry.  No prefixes are stored. */
  size_t len = strlen(rel);
  while (len > 0) {
    const char* slash = NULL;
    for (size_t i = len; i-- > 0;) {
      if (rel[i] == '/') {
        slash = rel + i;
        break;
      }
    }
    if (!slash)
      break;
    len = (size_t)(slash - rel);
    if (path_index_contains_n(&set->index, rel, len))
      return true;
  }
  /* Finally `rel` is affected when it is an ancestor directory of a listed
     entry (binary search for the first entry at or after `rel` + '/'). */
  return path_index_has_descendant(&set->index, rel);
}
