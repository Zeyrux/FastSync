#include "utils.h"
#include "array_list.h"
#include "libgen.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

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

static bool path_is_within_root(const char* root, const char* path) {
  size_t root_len = strlen(root);
  return strncmp(root, path, root_len) == 0 && (path[root_len] == '\0' || path[root_len] == '/');
}

static int open_authorized_destination(const char* dest_root) {
  if (authorized_root_fd < 0 || !authorized_root_path || !dest_root ||
      !path_is_within_root(authorized_root_path, dest_root))
    return -1;

  int dirfd = dup(authorized_root_fd);
  if (dirfd < 0)
    return -1;

  const char* relative_path = dest_root + strlen(authorized_root_path);
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

bool mkdir_r(const char* path) {
  if (!path || *path == '\0')
    return false;
  char* duplicate = str_dup(path);
  if (!duplicate)
    return false;
  int dirfd = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (dirfd < 0) {
    free(duplicate);
    return false;
  }
  bool ok = true;
  char* saveptr = NULL;
  char* component = strtok_r(duplicate, "/", &saveptr);
  while (component) {
    if (strcmp(component, "..") == 0) {
      ok = false;
      break;
    }
    if (strcmp(component, ".") != 0) {
      int next = openat(dirfd, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      if (next < 0 && errno == ENOENT) {
        if (mkdirat(dirfd, component, 0755) == 0 || errno == EEXIST)
          next = openat(dirfd, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      }
      if (next < 0) {
        ok = false;
        break;
      }
      close(dirfd);
      dirfd = next;
    }
    component = strtok_r(NULL, "/", &saveptr);
  }
  close(dirfd);
  free(duplicate);
  return ok;
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

/* Match a glob pattern against a string. Supported wildcards:
 *   ?      matches any single character except '/'.
 *   *      matches any sequence of characters within one path component (no '/').
 *   **     matches any sequence of characters, including '/' (cross-directory).
 *   slash-star-star-slash is treated as a cross-directory wildcard when it appears between
 * literals.
 */
bool glob_match(const char* pattern, const char* str) {
  while (*pattern) {
    if (*pattern == '*') {
      if (*(pattern + 1) == '*') {
        /* globstar: match across directories */
        pattern += 2;
        if (*pattern == '\0')
          return true;
        if (*pattern == '/')
          pattern++;
        while (*str) {
          if (glob_match(pattern, str))
            return true;
          str++;
        }
        return glob_match(pattern, str);
      }
      /* single *: match within one path component */
      pattern++;
      while (*str && *str != '/') {
        if (glob_match(pattern, str))
          return true;
        str++;
      }
      return glob_match(pattern, str);
    } else if (*pattern == '?') {
      if (!*str || *str == '/')
        return false;
      pattern++;
      str++;
    } else {
      if (*pattern != *str) {
        /* allow literal / ** / rest to match any number of directories */
        if (*pattern == '/' && *(pattern + 1) == '*' && *(pattern + 2) == '*') {
          const char* rest = pattern + 3;
          if (*rest == '/')
            rest++;
          return glob_match(rest, str);
        }
        return false;
      }
      pattern++;
      str++;
    }
  }
  return *str == '\0';
}

static bool is_dir_in_manifest(const char* rel_path, ArrayList* manifest) {
  size_t len = strlen(rel_path);
  for (int i = 0; i < manifest->size; i++) {
    const char* entry = (const char*)manifest->items[i];
    // Check if entry starts with rel_path + '/' or matches exactly
    if (strncmp(entry, rel_path, len) == 0 && (entry[len] == '/' || entry[len] == '\0'))
      return true;
  }
  return false;
}

static bool delete_extras_fd(int dirfd, const char* rel_path, ArrayList* manifest,
                             size_t max_delete, size_t* deleted_count) {
  int scanfd = dup(dirfd);
  if (scanfd < 0)
    return false;
  DIR* dir = fdopendir(scanfd);
  if (!dir) {
    close(scanfd);
    return false;
  }
  bool operation_ok = true;
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    char* child_rel = path_cat((char*)rel_path, entry->d_name);
    if (!child_rel) {
      operation_ok = false;
      continue;
    }
    struct stat st;
    if (fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno != ENOENT)
        operation_ok = false;
      free(child_rel);
      continue;
    }
    // Skip symlinks to prevent following them outside the destination tree
    if (S_ISLNK(st.st_mode)) {
      free(child_rel);
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      int childfd = openat(dirfd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      bool child_removed = false;
      if (childfd >= 0) {
        child_removed = delete_extras_fd(childfd, child_rel, manifest, max_delete, deleted_count);
        if (!child_removed)
          operation_ok = false;
        close(childfd);
      } else if (errno != ENOENT) {
        operation_ok = false;
      }
      if (child_removed && !is_dir_in_manifest(child_rel, manifest)) {
        if (*deleted_count >= max_delete) {
          operation_ok = false;
        } else {
          if (unlinkat(dirfd, entry->d_name, AT_REMOVEDIR) != 0) {
            if (errno != ENOENT)
              operation_ok = false;
          } else {
            (*deleted_count)++;
          }
        }
      }
    } else {
      // Check if relative path is in manifest
      bool found = false;
      for (int i = 0; i < manifest->size; i++) {
        if (strcmp((char*)manifest->items[i], child_rel) == 0) {
          found = true;
          break;
        }
      }
      if (!found) {
        if (*deleted_count >= max_delete) {
          operation_ok = false;
          free(child_rel);
          continue;
        }
        if (unlinkat(dirfd, entry->d_name, 0) != 0) {
          if (errno != ENOENT)
            operation_ok = false;
        } else {
          (*deleted_count)++;
        }
        fprintf(stderr, "  Deleted: %s\n", child_rel);
      }
    }
    free(child_rel);
  }
  closedir(dir);
  return operation_ok;
}

bool delete_extras_limited(const char* dest_root, ArrayList* manifest, size_t max_delete) {
  if (!manifest)
    return false;
  int rootfd;
  if (authorized_root_fd >= 0) {
    if (authorized_root_path)
      rootfd = open_authorized_destination(dest_root);
    else if (dest_root == NULL)
      rootfd = dup(authorized_root_fd);
    else
      rootfd = -1;
  } else {
    rootfd = open(dest_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  }
  if (rootfd < 0)
    return false;
  size_t deleted_count = 0;
  bool ok = delete_extras_fd(rootfd, "", manifest, max_delete, &deleted_count);
  if (close(rootfd) != 0)
    ok = false;
  return ok;
}

bool delete_extras(const char* dest_root, ArrayList* manifest) {
  return delete_extras_limited(dest_root, manifest, SIZE_MAX);
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
