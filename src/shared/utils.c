#include "utils.h"
#include "array_list.h"
#include "log.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xxhash.h>

static int authorized_root_fd = -1;
static char* authorized_root_path;

bool utils_set_authorized_root(int fd, const char* canonical_path) {
  char* path_copy = canonical_path ? str_dup(canonical_path) : NULL;
  if (canonical_path && !path_copy) {
    authorized_root_fd = -1;
    free(authorized_root_path);
    authorized_root_path = NULL;
    return false;
  }
  authorized_root_fd = fd;
  free(authorized_root_path);
  authorized_root_path = path_copy;
  return true;
}

void utils_set_authorized_root_fd(int fd) {
  (void)utils_set_authorized_root(fd, NULL);
}

/* Accessors for the process-global authorized root.  The path pointer is
 * borrowed and valid until the next setter call; the root is a single-threaded,
 * set-before-worker-threads value (see server.c), so these carry no locking. */
int utils_get_authorized_root_fd(void) {
  return authorized_root_fd;
}

const char* utils_get_authorized_root_path(void) {
  return authorized_root_path;
}

bool path_is_within_root(const char* root, const char* path) {
  size_t root_len = strlen(root);
  return strncmp(root, path, root_len) == 0 && (path[root_len] == '\0' || path[root_len] == '/');
}

/* Open the destination root directory itself, confined to the authorized root.
 * NOTE (do not merge with file_open_secure_parent): this walk opens dest_root
 * (a directory that must already exist) and returns its fd, whereas
 * file_open_secure_parent resolves the PARENT of a file path, optionally
 * creating missing components and honouring --keep-dirlinks / --copy-as.  The
 * two differ in create-vs-no-create, in what path component they stop at, and
 * in the extra receiver policies they apply, so they are intentionally kept
 * separate.  Both rely on the shared lexical path_is_within_root check. */
int utils_open_authorized_destination(const char* dest_root) {
  int root_fd = utils_get_authorized_root_fd();
  const char* root_path = utils_get_authorized_root_path();
  if (root_fd < 0 || !root_path || !dest_root || !path_is_within_root(root_path, dest_root))
    return -1;

  int dirfd = dup(root_fd);
  if (dirfd < 0)
    return -1;

  const char* relative_path = dest_root + strlen(root_path);
  while (*relative_path == '/')
    relative_path++;
  char* relative = str_dup(*relative_path ? relative_path : ".");
  if (!relative) {
    close(dirfd);
    return -1;
  }

  char* saveptr = NULL;
  char* component = strtok_r(relative, "/", &saveptr);
  while (component) {
    if (strcmp(component, "..") == 0) {
      free(relative);
      close(dirfd);
      return -1;
    }
    if (strcmp(component, ".") == 0) {
      component = strtok_r(NULL, "/", &saveptr);
      continue;
    }
    int next = openat(dirfd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0) {
      free(relative);
      close(dirfd);
      return -1;
    }
    close(dirfd);
    dirfd = next;
    component = strtok_r(NULL, "/", &saveptr);
  }

  free(relative);
  return dirfd;
}

char* str_dup(const char* string) {
  if (string == NULL)
    return NULL;
  size_t str_len = strlen(string);
  char* new_string = (char*)malloc(str_len + 1);
  if (new_string == NULL)
    return NULL;
  memcpy(new_string, string, str_len + 1);
  return new_string;
}

#define STR_HASH_SET_MIN_CAPACITY 16

static size_t str_hash_set_hash(const char* key, size_t len) {
  return (size_t)XXH64(key, len, 0);
}

/* Store a borrowed key.  Returns 1 when a new slot was filled and 0 for a
 * duplicate. */
static int str_hash_set_put(StrHashSet* set, const char* key, size_t len) {
  size_t mask = set->capacity - 1;
  size_t index = str_hash_set_hash(key, len) & mask;
  while (true) {
    StrHashSetSlot* slot = &set->slots[index];
    if (!slot->key) {
      slot->key = key;
      set->size++;
      return 1;
    }
    if (strlen(slot->key) == len && memcmp(slot->key, key, len) == 0)
      return 0;
    index = (index + 1) & mask;
  }
}

static bool str_hash_set_resize(StrHashSet* set, size_t new_capacity) {
  StrHashSetSlot* old_slots = set->slots;
  size_t old_capacity = set->capacity;
  StrHashSetSlot* slots = calloc(new_capacity, sizeof(StrHashSetSlot));
  if (!slots)
    return false;
  set->slots = slots;
  set->capacity = new_capacity;
  set->size = 0;
  for (size_t i = 0; i < old_capacity; i++) {
    if (old_slots[i].key)
      (void)str_hash_set_put(set, old_slots[i].key, strlen(old_slots[i].key));
  }
  free(old_slots);
  return true;
}

static bool str_hash_set_grow(StrHashSet* set) {
  if (set->capacity != 0 && (set->size + 1) * 4 <= set->capacity * 3)
    return true;
  size_t new_capacity = set->capacity ? set->capacity * 2 : STR_HASH_SET_MIN_CAPACITY;
  return str_hash_set_resize(set, new_capacity);
}

bool str_hash_set_init(StrHashSet* set, size_t hint) {
  if (!set)
    return false;
  set->slots = NULL;
  set->capacity = 0;
  set->size = 0;
  size_t capacity = STR_HASH_SET_MIN_CAPACITY;
  while (capacity < (hint + 1) * 2 && capacity <= SIZE_MAX / 2)
    capacity *= 2;
  set->slots = calloc(capacity, sizeof(StrHashSetSlot));
  if (!set->slots)
    return false;
  set->capacity = capacity;
  return true;
}

void str_hash_set_free(StrHashSet* set) {
  if (!set)
    return;
  free(set->slots);
  set->slots = NULL;
  set->capacity = 0;
  set->size = 0;
}

bool str_hash_set_insert_ref(StrHashSet* set, const char* key) {
  if (!set || !key)
    return false;
  if (!str_hash_set_grow(set))
    return false;
  /* put() returns 1 for a new slot and 0 for a duplicate; both are success. */
  (void)str_hash_set_put(set, key, strlen(key));
  return true;
}

static const StrHashSetSlot* str_hash_set_find_n(const StrHashSet* set, const char* key,
                                                 size_t len) {
  if (!set || set->capacity == 0 || !key)
    return NULL;
  size_t mask = set->capacity - 1;
  size_t index = str_hash_set_hash(key, len) & mask;
  while (true) {
    const StrHashSetSlot* slot = &set->slots[index];
    if (!slot->key)
      return NULL;
    if (strlen(slot->key) == len && memcmp(slot->key, key, len) == 0)
      return slot;
    index = (index + 1) & mask;
  }
}

bool str_hash_set_lookup_n(const StrHashSet* set, const char* key, size_t len) {
  return str_hash_set_find_n(set, key, len) != NULL;
}

bool str_hash_set_lookup(const StrHashSet* set, const char* key) {
  if (!key)
    return false;
  return str_hash_set_lookup_n(set, key, strlen(key));
}

static int str_sorted_array_compare(const void* left, const void* right) {
  const char* const* left_key = left;
  const char* const* right_key = right;
  return strcmp(*left_key, *right_key);
}

bool str_sorted_array_build(StrSortedArray* array, const char* const* items, size_t count) {
  if (!array)
    return false;
  array->items = NULL;
  array->count = 0;
  if (count == 0)
    return true;
  if (!items || count > SIZE_MAX / sizeof(const char*))
    return false;
  const char** sorted = malloc(count * sizeof(*sorted));
  if (!sorted)
    return false;
  for (size_t i = 0; i < count; i++)
    sorted[i] = items[i];
  qsort(sorted, count, sizeof(*sorted), str_sorted_array_compare);
  array->items = sorted;
  array->count = count;
  return true;
}

void str_sorted_array_free(StrSortedArray* array) {
  if (!array)
    return;
  free(array->items);
  array->items = NULL;
  array->count = 0;
}

bool str_sorted_array_contains(const StrSortedArray* array, const char* key) {
  if (!array || !key || array->count == 0)
    return false;
  size_t lo = 0;
  size_t hi = array->count;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int cmp = strcmp(array->items[mid], key);
    if (cmp < 0)
      lo = mid + 1;
    else if (cmp > 0)
      hi = mid;
    else
      return true;
  }
  return false;
}

/* Compare `entry` against the virtual key `key` + '/' without allocating the
 * concatenation.  Returns <0, 0 or >0 as `entry` sorts before, equal to, or
 * after that virtual key. */
static int str_sorted_array_compare_prefix(const char* entry, const char* key, size_t key_len) {
  int cmp = strncmp(entry, key, key_len);
  if (cmp != 0)
    return cmp;
  unsigned char next = (unsigned char)entry[key_len];
  if (next == '\0')
    return -1; /* entry == key sorts before key + '/' */
  return (int)next - (int)'/';
}

bool str_sorted_array_has_child_prefix(const StrSortedArray* array, const char* key) {
  if (!array || !key || array->count == 0 || key[0] == '\0')
    return false;
  size_t key_len = strlen(key);
  size_t lo = 0;
  size_t hi = array->count;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    if (str_sorted_array_compare_prefix(array->items[mid], key, key_len) < 0)
      lo = mid + 1;
    else
      hi = mid;
  }
  if (lo >= array->count)
    return false;
  const char* entry = array->items[lo];
  return strncmp(entry, key, key_len) == 0 && entry[key_len] == '/';
}

bool path_index_build(PathIndex* index, const char* const* entries, size_t count) {
  if (!index)
    return false;
  index->exact.slots = NULL;
  index->exact.capacity = 0;
  index->exact.size = 0;
  index->sorted.items = NULL;
  index->sorted.count = 0;
  if (!str_hash_set_init(&index->exact, count))
    return false;
  if (!str_sorted_array_build(&index->sorted, entries, count)) {
    str_hash_set_free(&index->exact);
    return false;
  }
  for (size_t i = 0; i < count; i++) {
    if (!str_hash_set_insert_ref(&index->exact, entries[i])) {
      path_index_free(index);
      return false;
    }
  }
  return true;
}

void path_index_free(PathIndex* index) {
  if (!index)
    return;
  str_hash_set_free(&index->exact);
  str_sorted_array_free(&index->sorted);
}

bool path_index_contains(const PathIndex* index, const char* path) {
  return index && str_hash_set_lookup(&index->exact, path);
}

bool path_index_contains_n(const PathIndex* index, const char* path, size_t len) {
  return index && str_hash_set_lookup_n(&index->exact, path, len);
}

bool path_index_has_descendant(const PathIndex* index, const char* path) {
  return index && str_sorted_array_has_child_prefix(&index->sorted, path);
}

char* output_escape(const char* string, bool eight_bit_output) {
  if (!string)
    return NULL;
  size_t length = strlen(string);
  if (length > (SIZE_MAX - 1) / 5)
    return NULL;
  char* escaped = malloc(length * 5 + 1);
  if (!escaped)
    return NULL;
  size_t out = 0;
  for (size_t i = 0; i < length; i++) {
    unsigned char byte = (unsigned char)string[i];
    if ((byte >= 32 && byte <= 126) || (eight_bit_output && byte >= 128)) {
      escaped[out++] = (char)byte;
    } else {
      escaped[out++] = '\\';
      escaped[out++] = '#';
      escaped[out++] = (char)('0' + ((byte >> 6) & 7));
      escaped[out++] = (char)('0' + ((byte >> 3) & 7));
      escaped[out++] = (char)('0' + (byte & 7));
    }
  }
  escaped[out] = '\0';
  return escaped;
}

ssize_t utils_getdelim_bounded(FILE* stream, char** line, size_t* cap, int delim, size_t max_len) {
  if (!stream || !line || !cap || max_len == 0) {
    errno = EINVAL;
    return -1;
  }
  size_t limit = max_len + 1; /* content bytes plus the terminating NUL */
  if (*line == NULL || *cap < 2) {
    size_t initial = limit < 256 ? limit : 256;
    char* buf = malloc(initial);
    if (!buf)
      return -1;
    free(*line);
    *line = buf;
    *cap = initial;
  }
  size_t len = 0;
  int c;
  while ((c = getc_unlocked(stream)) != EOF) {
    if (len >= max_len) {
      errno = EFBIG;
      return -1;
    }
    if (len + 2 > *cap) {
      size_t new_cap = *cap * 2;
      if (new_cap < len + 2)
        new_cap = len + 2;
      if (new_cap > limit)
        new_cap = limit;
      char* grown = realloc(*line, new_cap);
      if (!grown)
        return -1;
      *line = grown;
      *cap = new_cap;
    }
    (*line)[len++] = (char)c;
    if (c == delim)
      break;
  }
  if (c == EOF && len == 0)
    return 0;
  (*line)[len] = '\0';
  return (ssize_t)len;
}

/* Match a glob pattern against a string. Supported wildcards:
 *   ?      matches any single character except '/'.
 *   *      matches any sequence of characters within one path component (no '/').
 *   **     matches any sequence of characters, including '/' (cross-directory).
 *   slash-star-star-slash is treated as a cross-directory wildcard when it appears between
 * literals.
 *
 * The matcher is an iterative O(pattern * string) dynamic program rather than the
 * original backtracking recursion: overlapping `*`/`**` wildcards made a pattern
 * like `*a*a*a*...*b` run in exponential time against a long run of `a`, a CPU
 * denial-of-service vector reachable from a hostile --exclude/--include pattern
 * or `.rsync-filter`.  The DP reasons over (pattern position, string position)
 * so every state is visited once; the transitions below mirror the original
 * recursion exactly. */
bool glob_match(const char* pattern, const char* str) {
  if (!pattern || !str)
    return false;
  size_t pattern_len = strlen(pattern);
  size_t str_len = strlen(str);
  if (pattern_len == 0)
    return str_len == 0;
  /* Defensive work cap: the DP is bounded by pattern*string states, but a
   * 64 KiB pattern against a 64 KiB path would still cost billions of steps.
   * Treat the pattern as non-matching above the cap instead of burning CPU. */
  if (str_len > (SIZE_MAX / (pattern_len + 1)) - 1)
    return false;
  if ((pattern_len + 1) * (str_len + 1) > 64u * 1024u * 1024u)
    return false;

  size_t row_bytes = str_len + 1;
  /* Rows for pattern positions i, i+1, i+2 and i+3 are live at once (the
   * globstar transition can skip up to three pattern bytes).  Four rotating
   * rows keep memory at O(string length); a stack buffer avoids an allocation
   * for the common short-leaf case. */
  enum { STACK_ROW = 257 };
  uint8_t stack_rows[4 * STACK_ROW];
  uint8_t* rows = stack_rows;
  if (row_bytes > STACK_ROW) {
    rows = malloc(4 * row_bytes);
    if (!rows)
      return false;
  }

#define GLOB_ROW(i) (rows + ((pattern_len - (i)) & 3) * row_bytes)

  /* Base row: pattern position `pattern_len` matches only the string's end. */
  for (size_t j = 0; j <= str_len; j++)
    GLOB_ROW(pattern_len)[j] = (j == str_len) ? 1 : 0;

  for (size_t i = pattern_len; i-- > 0;) {
    const char pc = pattern[i];
    uint8_t* cur = GLOB_ROW(i);
    const uint8_t* next = GLOB_ROW(i + 1);
    if (pc == '*') {
      if (i + 1 < pattern_len && pattern[i + 1] == '*') {
        /* Globstar: skip `**` and an optional following '/', then consume any
         * (possibly empty) run of characters -- including '/'. */
        size_t rest = i + 2;
        if (rest < pattern_len && pattern[rest] == '/')
          rest++;
        const uint8_t* rest_row = GLOB_ROW(rest);
        for (size_t j = str_len + 1; j-- > 0;) {
          bool v = rest_row[j] != 0;
          if (!v && j < str_len)
            v = cur[j + 1] != 0;
          cur[j] = v ? 1 : 0;
        }
      } else {
        /* Single `*`: zero characters, or one non-'/' character. */
        for (size_t j = str_len + 1; j-- > 0;) {
          bool v = next[j] != 0;
          if (!v && j < str_len && str[j] != '/')
            v = cur[j + 1] != 0;
          cur[j] = v ? 1 : 0;
        }
      }
    } else if (pc == '?') {
      for (size_t j = str_len + 1; j-- > 0;) {
        bool v = j < str_len && str[j] != '/' && next[j + 1] != 0;
        cur[j] = v ? 1 : 0;
      }
    } else {
      /* Literal: consume an equal character, or -- for a '/' immediately before
       * a globstar -- let the '/' match zero directories and continue at `**`. */
      for (size_t j = str_len + 1; j-- > 0;) {
        bool v = false;
        if (j < str_len && str[j] == pc) {
          v = next[j + 1] != 0;
        } else if (pc == '/' && i + 2 < pattern_len && pattern[i + 1] == '*' &&
                   pattern[i + 2] == '*') {
          size_t rest = i + 3;
          if (rest < pattern_len && pattern[rest] == '/')
            rest++;
          v = GLOB_ROW(rest)[j] != 0;
        }
        cur[j] = v ? 1 : 0;
      }
    }
  }

  bool matched = GLOB_ROW(0)[0] != 0;
#undef GLOB_ROW
  if (rows != stack_rows)
    free(rows);
  return matched;
}

bool format_human_bytes(unsigned long long bytes, char* buffer, size_t buffer_size) {
  static const char* const units[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB"};
  double value = (double)bytes;
  size_t unit = 0;
  int written;

  if (!buffer || buffer_size == 0)
    return false;
  while (value >= 1024.0 && unit < sizeof(units) / sizeof(units[0]) - 1) {
    value /= 1024.0;
    unit++;
  }
  if (unit == 0)
    written = snprintf(buffer, buffer_size, "%llu %s", bytes, units[unit]);
  else
    written = snprintf(buffer, buffer_size, "%.1f %s", value, units[unit]);
  return written >= 0 && (size_t)written < buffer_size;
}

/* Build the keep-set index from the exact manifest entries only.  A lookup of
   `rel` succeeds iff `rel` is a kept entry, a kept directory, or an ancestor
   directory of kept content (the old is_dir_in_manifest predicate); the sorted
   view answers "is an ancestor of kept content" without materializing any
   per-component prefix copy, so the index is O(manifest size) memory. */
static bool build_keep_index(const ArrayList* manifest, PathIndex* index) {
  if (!manifest || manifest->size <= 0)
    return path_index_build(index, NULL, 0);
  return path_index_build(index, (const char* const*)manifest->items, (size_t)manifest->size);
}

static bool keep_is_dir(const PathIndex* index, const char* rel_path) {
  return path_index_contains(index, rel_path) || path_index_has_descendant(index, rel_path);
}

static bool keep_is_file(const PathIndex* index, const char* rel_path) {
  return path_index_contains(index, rel_path);
}

/* True when child_rel is, or lies below, a protected entry.  A prefix "a"
   therefore protects "a" and "a/b/c" but not "ab".  Entries with top_level_only
   set only protect DIRECT children of the receive root (at_root); nested
   directories that share such a name stay ordinary destination content. */
bool path_under_skip_prefix(const char* child_rel, bool at_root, const DeleteSkipEntry* skips,
                            int skip_count) {
  for (int i = 0; i < skip_count; i++) {
    if (skips[i].top_level_only && !at_root)
      continue;
    size_t prefix_len = strlen(skips[i].prefix);
    if (strncmp(child_rel, skips[i].prefix, prefix_len) == 0 &&
        (child_rel[prefix_len] == '\0' || child_rel[prefix_len] == '/'))
      return true;
  }
  return false;
}

/* Per-run deletion budget and tallies.  `max_delete` is the cap on the number
   of entries the walker may remove (SIZE_MAX = unlimited); once it is reached
   the remaining extras are counted in `skipped` and left in place, matching
   rsync's partial --max-delete behavior. */
typedef struct {
  size_t max_delete;
  size_t deleted;
  size_t skipped;
  bool limit_hit;
} DeleteBudget;

/* True when direct children of the directory named by `rel` may be removed.
   With no synchronization info (dirs == NULL) the whole tree is deletable; when
   a dirs index is supplied only its exact entries are (the receive root is the
   "." sentinel). */
static bool is_synced_dir(const PathIndex* dirs, const char* rel) {
  if (!dirs)
    return true;
  return path_index_contains(dirs, rel[0] == '\0' ? "." : rel);
}

/* Remove the extras directly inside the directory open on `dirfd`, recursing
   into every child directory so kept content below a synchronized prefix is
   reached.  `all_removed` reports whether every child entry was removed (so the
   caller may rmdir this directory).  A child directory is never removed when it
   is itself a synchronized directory or holds kept content; with a dirs index
   supplied, direct children of a non-synchronized directory are never extras at
   all (they are left in place but still descended into).  Symlinks are unlinked
   like any other non-directory extra (never followed). */
static bool delete_extras_fd(int dirfd, const char* rel_path, const PathIndex* keep,
                             const PathIndex* dirs, DeleteBudget* budget,
                             const DeleteSkipEntry* skips, int skip_count, bool parent_deletable,
                             bool* all_removed) {
  /* openat(dirfd, ".") opens an independent file description: a dup() would
     share dirfd's file offset and a prior pass could leave the stream drained. */
  int scanfd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (scanfd < 0)
    return false;
  DIR* dir = fdopendir(scanfd);
  if (!dir) {
    close(scanfd);
    return false;
  }
  bool operation_ok = true;
  bool local_survives = false;
  /* A directory is deletable when it or ANY ancestor is synchronized; the
     `parent_deletable` flag carries that down the recursion so dest-only
     directories below a synchronized root are removed wholesale. */
  bool deletable = parent_deletable || is_synced_dir(dirs, rel_path);
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    char* child_rel = path_cat((char*)rel_path, entry->d_name);
    if (!child_rel) {
      operation_ok = false;
      continue;
    }
    /* A --delay-updates run keeps its staging directory as a direct child of
       the receive root, and basis-dir snapshots live below it too.  Their
       contents are not manifest entries, so descending into them would delete
       every staged / basis file as an "extra".  Only the staging name (a
       top-level-only prefix) and the basis prefixes are protected: a nested
       destination directory that happens to be called .fastsync-stage is
       ordinary content. */
    if (path_under_skip_prefix(child_rel, rel_path[0] == '\0', skips, skip_count)) {
      local_survives = true;
      free(child_rel);
      continue;
    }
    struct stat st;
    if (fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno != ENOENT)
        operation_ok = false;
      free(child_rel);
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      int childfd = openat(dirfd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      bool child_all_removed = false;
      if (childfd >= 0) {
        if (!delete_extras_fd(childfd, child_rel, keep, dirs, budget, skips, skip_count, deletable,
                              &child_all_removed))
          operation_ok = false;
        close(childfd);
      } else if (errno != ENOENT) {
        operation_ok = false;
      }
      bool child_synced = dirs && path_index_contains(dirs, child_rel);
      if (child_synced || keep_is_dir(keep, child_rel)) {
        /* A synchronized directory and a directory holding kept content are
           never removed. */
        local_survives = true;
      } else if (child_all_removed && deletable) {
        if (budget->deleted >= budget->max_delete) {
          budget->limit_hit = true;
          budget->skipped++;
          local_survives = true;
        } else if (unlinkat(dirfd, entry->d_name, AT_REMOVEDIR) != 0) {
          /* ENOENT: already gone (fine).  ENOTEMPTY/EEXIST: the directory
             still holds entries the walker leaves in place (a protected
             excluded prefix, a kept file the manifest protects, a symlink);
             rsync leaves such a directory behind, so this is not an error.
             Only genuine I/O failures abort the deletion. */
          if (errno != ENOENT && errno != ENOTEMPTY && errno != EEXIST)
            operation_ok = false;
          local_survives = true;
        } else {
          budget->deleted++;
        }
      } else {
        local_survives = true;
      }
    } else {
      bool found = keep_is_file(keep, child_rel);
      if (found || !deletable) {
        /* Kept file, or a child of a directory that is not synchronized: never
           an extra for this run. */
        local_survives = true;
      } else if (budget->deleted >= budget->max_delete) {
        budget->limit_hit = true;
        budget->skipped++;
        local_survives = true;
      } else if (unlinkat(dirfd, entry->d_name, 0) != 0) {
        if (errno != ENOENT)
          operation_ok = false;
        local_survives = true;
      } else {
        budget->deleted++;
        char* escaped_path = output_escape(child_rel, log_get_8_bit_output());
        fprintf(stderr, "  Deleted: %s\n", escaped_path ? escaped_path : "<allocation failed>");
        free(escaped_path);
      }
    }
    free(child_rel);
  }
  closedir(dir);
  *all_removed = !local_survives;
  return operation_ok;
}

DeleteWalkResult delete_extras_limited(const char* dest_root, const ArrayList* manifest,
                                       const ArrayList* synced_dirs, size_t max_delete,
                                       const DeleteSkipEntry* skips, int skip_count,
                                       size_t* deleted_out, size_t* skipped_out) {
  if (deleted_out)
    *deleted_out = 0;
  if (skipped_out)
    *skipped_out = 0;
  if (!manifest)
    return DELETE_WALK_ERROR;
  /* Index the keep-set (and the synchronized-dir set, when supplied) once so
     membership is answered in O(path length) instead of scanning every entry
     for every destination entry. */
  PathIndex keep;
  if (!build_keep_index(manifest, &keep))
    return DELETE_WALK_ERROR;
  PathIndex dirs;
  bool have_dirs = synced_dirs != NULL;
  if (have_dirs &&
      !path_index_build(&dirs, (const char* const*)synced_dirs->items, (size_t)synced_dirs->size)) {
    path_index_free(&keep);
    return DELETE_WALK_ERROR;
  }
  int rootfd;
  int root_fd = utils_get_authorized_root_fd();
  if (root_fd >= 0) {
    if (utils_get_authorized_root_path())
      rootfd = utils_open_authorized_destination(dest_root);
    else if (dest_root == NULL)
      rootfd = dup(root_fd);
    else
      rootfd = -1;
  } else {
    rootfd = open(dest_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  }
  if (rootfd < 0) {
    path_index_free(&keep);
    if (have_dirs)
      path_index_free(&dirs);
    return DELETE_WALK_ERROR;
  }
  DeleteBudget budget = {.max_delete = max_delete, .deleted = 0, .skipped = 0, .limit_hit = false};
  bool all_removed = false;
  bool ok = delete_extras_fd(rootfd, "", &keep, have_dirs ? &dirs : NULL, &budget, skips,
                             skip_count, false, &all_removed);
  if (close(rootfd) != 0)
    ok = false;
  path_index_free(&keep);
  if (have_dirs)
    path_index_free(&dirs);
  if (deleted_out)
    *deleted_out = budget.deleted;
  if (skipped_out)
    *skipped_out = budget.skipped;
  if (!ok)
    return DELETE_WALK_ERROR;
  return budget.limit_hit ? DELETE_WALK_LIMIT_REACHED : DELETE_WALK_OK;
}

bool delete_extras(const char* dest_root, const ArrayList* manifest) {
  return delete_extras_limited(dest_root, manifest, NULL, SIZE_MAX, NULL, 0, NULL, NULL) ==
         DELETE_WALK_OK;
}

bool has_path_traversal(const char* path) {
  if (!path)
    return true;
  char* dup = str_dup(path);
  if (!dup)
    return true;
  char* saveptr;
  const char* part = strtok_r(dup, "/", &saveptr);
  while (part) {
    if (strcmp(part, "..") == 0) {
      free(dup);
      return true;
    }
    part = strtok_r(NULL, "/", &saveptr);
  }
  free(dup);
  return false;
}

bool utils_valid_batch_path(const char* path) {
  return path && path[0] != '\0' && path[0] != '/' && !has_path_traversal(path);
}

char* path_cat(const char* path1, const char* path2) {
  if (path1 == NULL || *path1 == '\0')
    return str_dup(path2);
  if (path2 == NULL || *path2 == '\0')
    return str_dup(path1);
  size_t path1_len = strlen(path1);
  size_t path2_len = strlen(path2);
  size_t offset = 0;
  if (path1[path1_len - 1] == '/')
    path1_len -= 1;
  if (path2[0] == '/') {
    offset = 1;
    path2_len -= 1;
  }
  if (path1_len > SIZE_MAX - path2_len - 2)
    return NULL;
  char* new_path = malloc(path1_len + path2_len + 2);
  if (new_path == NULL)
    return NULL;
  memcpy(new_path, path1, path1_len);
  new_path[path1_len] = '/';
  memcpy(new_path + path1_len + 1, path2 + offset, path2_len);
  new_path[path1_len + path2_len + 1] = '\0';
  return new_path;
}

bool append_resume_eligible(unsigned long long old_size, unsigned long long check_size) {
  return old_size < check_size;
}

bool append_tail_length(unsigned long long old_size, unsigned long long check_size,
                        unsigned long long* tail_out) {
  if (!tail_out || !append_resume_eligible(old_size, check_size))
    return false;
  *tail_out = check_size - old_size;
  return true;
}

/* True when a bound/peer socket address is on the loopback interface: any
   127.0.0.0/8 IPv4 address, IPv6 ::1, or an IPv4-mapped ::ffff:127.x.x.x.  This
   is the transport-local test the daemon auth gate uses to decide whether a
   plaintext connection is a trustworthy local/SSH channel. */
bool utils_sockaddr_is_loopback(const struct sockaddr* addr) {
  if (!addr)
    return false;
  if (addr->sa_family == AF_INET) {
    const struct sockaddr_in* v4 = (const struct sockaddr_in*)addr;
    uint32_t host = ntohl(v4->sin_addr.s_addr);
    return (host & 0xff000000u) == 0x7f000000u;
  }
  if (addr->sa_family == AF_INET6) {
    const struct sockaddr_in6* v6 = (const struct sockaddr_in6*)addr;
    if (IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr))
      return true;
    /* An IPv4-mapped ::ffff:127.x.x.x is loopback too. */
    if (IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr) && v6->sin6_addr.s6_addr[12] == 127)
      return true;
    return false;
  }
  return false;
}

/* True when the fd's peer is provably a loopback TCP peer: getpeername must
   succeed AND the returned address must classify as loopback.  Everything else
   is NOT local, including a non-socket descriptor (pipe/socketpair): a failed
   getpeername (ENOTSOCK, ENOTCONN, ...) fails closed.  The daemon auth gate
   must not treat "I cannot tell" as "trusted", and daemon auth modules are
   daemon-only anyway (the --stdio path never loads a daemon config). */
bool utils_fd_peer_is_local(int fd) {
  if (fd < 0)
    return false;
  struct sockaddr_storage peer;
  socklen_t length = sizeof(peer);
  if (getpeername(fd, (struct sockaddr*)&peer, &length) != 0)
    return false;
  return utils_sockaddr_is_loopback((const struct sockaddr*)&peer);
}

/* Numeric peer address of a connected fd.  Only AF_INET/AF_INET6 peers are
   formatted; every other descriptor/family (pipe, AF_UNIX socketpair, ...) or a
   getpeername failure returns false with buf emptied.  The caller must treat
   that as "cannot tell". */
bool utils_fd_peer_ip(int fd, char* buf, size_t len) {
  if (!buf || len == 0)
    return false;
  buf[0] = '\0';
  if (fd < 0)
    return false;
  struct sockaddr_storage peer;
  socklen_t peer_len = sizeof(peer);
  if (getpeername(fd, (struct sockaddr*)&peer, &peer_len) != 0)
    return false;
  const void* src = NULL;
  int family = peer.ss_family;
  if (family == AF_INET) {
    src = &((const struct sockaddr_in*)&peer)->sin_addr;
  } else if (family == AF_INET6) {
    const struct sockaddr_in6* peer6 = (const struct sockaddr_in6*)&peer;
    /* A dual-stack IPv6 listener reports IPv4 peers as ::ffff:a.b.c.d.  Emit
     * the IPv4 form so IPv4 ACL patterns (and logs) see the real address. */
    if (IN6_IS_ADDR_V4MAPPED(&peer6->sin6_addr)) {
      struct in_addr v4;
      memcpy(&v4, &peer6->sin6_addr.s6_addr[12], sizeof(v4));
      return inet_ntop(AF_INET, &v4, buf, (socklen_t)len) != NULL;
    }
    src = &peer6->sin6_addr;
  } else {
    return false;
  }
  return inet_ntop(family, src, buf, (socklen_t)len) != NULL;
}

/* "ip:port" / "[ip]:port" for a connected peer, used to log the connecting
   address in the accept loop.  Returns false for a non-INET family. */
bool utils_sockaddr_to_string(const struct sockaddr* addr, char* buf, size_t len) {
  if (!addr || !buf || len == 0)
    return false;
  buf[0] = '\0';
  char ip[INET6_ADDRSTRLEN];
  unsigned short port;
  int written;
  if (addr->sa_family == AF_INET) {
    const struct sockaddr_in* v4 = (const struct sockaddr_in*)addr;
    if (!inet_ntop(AF_INET, &v4->sin_addr, ip, sizeof(ip)))
      return false;
    port = ntohs(v4->sin_port);
    written = snprintf(buf, len, "%s:%u", ip, port);
  } else if (addr->sa_family == AF_INET6) {
    const struct sockaddr_in6* v6 = (const struct sockaddr_in6*)addr;
    if (!inet_ntop(AF_INET6, &v6->sin6_addr, ip, sizeof(ip)))
      return false;
    port = ntohs(v6->sin6_port);
    written = snprintf(buf, len, "[%s]:%u", ip, port);
  } else {
    return false;
  }
  if (written < 0 || (size_t)written >= len) {
    buf[0] = '\0';
    return false;
  }
  return true;
}

/* True when a client-supplied host string names a loopback destination:
   "localhost", any 127.0.0.0/8 literal, "::1", or "[::1]". */
bool utils_host_is_loopback(const char* host) {
  if (!host || host[0] == '\0')
    return false;
  if (strcmp(host, "localhost") == 0)
    return true;
  struct in_addr v4;
  if (inet_pton(AF_INET, host, &v4) == 1)
    return (ntohl(v4.s_addr) & 0xff000000u) == 0x7f000000u;
  struct in6_addr addr6;
  if (host[0] == '[') {
    size_t len = strlen(host);
    if (len < 3 || host[len - 1] != ']')
      return false;
    /* inet_pton needs the bare address, not the bracketed form. */
    char bare[INET6_ADDRSTRLEN];
    if (len - 2 >= sizeof(bare))
      return false;
    memcpy(bare, host + 1, len - 2);
    bare[len - 2] = '\0';
    return inet_pton(AF_INET6, bare, &addr6) == 1 && IN6_IS_ADDR_LOOPBACK(&addr6);
  }
  return inet_pton(AF_INET6, host, &addr6) == 1 && IN6_IS_ADDR_LOOPBACK(&addr6);
}
