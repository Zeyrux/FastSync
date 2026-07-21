#include "utils.h"
#include "array_list.h"
#include "libgen.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool mkdir_r(const char* path) {
  char* path_duplicate = malloc(strlen(path) + 1);
  if (!path_duplicate)
    return false;
  strcpy(path_duplicate, path);
  char* path_current = (char*)malloc((strlen(path) + 2) * sizeof(char));
  if (!path_current) {
    free(path_duplicate);
    return false;
  }
  char* path_current_position = path_current;
  if (path[0] == '/') {
    strcpy(path_current, "/");
    path_current_position += 1;
  } else {
    path_current[0] = '\0';
  }
  const char* delimiter = "/";
  char* saveptr;
  const char* part = strtok_r(path_duplicate, delimiter, &saveptr);
  bool ok = true;
  while (part != NULL) {
    strcpy(path_current_position, part);
    path_current_position += strlen(part) * sizeof(char);
    strcpy(path_current_position, "/");
    path_current_position += sizeof(char);
    struct stat st;
    if (stat(path_current, &st) != 0) {
      if (mkdir(path_current, 0755) != 0) {
        perror("Could not create directory");
        ok = false;
        break;
      }
    }
    part = strtok_r(NULL, delimiter, &saveptr);
  }
  free(path_duplicate);
  free(path_current);
  return ok;
}

char* str_dup(const char* string) {
  if (string == NULL)
    return NULL;
  char* new_string = (char*)malloc(strlen(string) + 1);
  strcpy(new_string, string);
  return new_string;
}

bool glob_match(const char* pattern, const char* str) {
  while (*pattern) {
    if (*pattern == '*') {
      if (*(pattern + 1) == '*') {
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

static void delete_extras_walk(const char* abs_path, const char* rel_path, ArrayList* manifest) {
  DIR* dir = opendir(abs_path);
  if (!dir)
    return;
  bool all_removed = true;
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    char* child_abs = path_cat((char*)abs_path, entry->d_name);
    char* child_rel = path_cat((char*)rel_path, entry->d_name);
    struct stat st;
    if (stat(child_abs, &st) != 0) {
      free(child_abs);
      free(child_rel);
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      delete_extras_walk(child_abs, child_rel, manifest);
      // After recursion, try to remove the subdirectory if it's now empty.
      // Ignore ENOENT: the recursive call may have already removed it.
      if (rmdir(child_abs) != 0 && errno != ENOENT) {
        all_removed = false;
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
        unlink(child_abs);
        fprintf(stderr, "  Deleted: %s\n", child_rel);
      } else {
        all_removed = false;
      }
    }
    free(child_abs);
    free(child_rel);
  }
  closedir(dir);
  // Only remove the directory itself if it is not in the manifest
  // and contained no kept entries.
  if (all_removed && rel_path[0] != '\0' && !is_dir_in_manifest(rel_path, manifest)) {
    rmdir(abs_path);
  }
}

void delete_extras(const char* dest_root, ArrayList* manifest) {
  delete_extras_walk(dest_root, "", manifest);
}

bool has_path_traversal(const char* path) {
  if (!path)
    return false;
  char* dup = str_dup(path);
  if (!dup)
    return false;
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
  char* new_path = malloc(path1_len + path2_len + 2);
  if (new_path == NULL)
    return NULL;
  memcpy(new_path, path1, path1_len);
  new_path[path1_len] = '/';
  memcpy(new_path + path1_len + 1, path2 + offset, path2_len);
  new_path[path1_len + path2_len + 1] = '\0';
  return new_path;
}
