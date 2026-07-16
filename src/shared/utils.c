#include "utils.h"
#include "array_list.h"
#include "libgen.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void mkdir_r(char *path) {
  char *path_duplicate = malloc(strlen(path) + 1);
  strcpy(path_duplicate, path);
  char *path_current = (char *)malloc((strlen(path) + 2) * sizeof(char));
  char *path_current_position = path_current;
  if (path[0] == '/') {
    strcpy(path_current, "/");
    path_current_position += 1;
  } else {
    path_current[0] = '\0';
  }
  const char *delimiter = "/";
  char *part = strtok(path_duplicate, delimiter);
  while (part != NULL) {
    strcpy(path_current_position, part);
    path_current_position += strlen(part) * sizeof(char);
    strcpy(path_current_position, "/");
    path_current_position += sizeof(char);
    struct stat st;
    if (stat(path_current, &st) != 0) {
      if (mkdir(path_current, 0755) != 0) {
        perror("Could not create directory");
        exit(EXIT_FAILURE);
      }
    }
    part = strtok(NULL, delimiter);
  }
  free(path_duplicate);
  free(path_current);
}

char *str_dup(const char *string) {
  if (string == NULL)
    return NULL;
  char *new_string = (char *)malloc(strlen(string) + 1);
  strcpy(new_string, string);
  return new_string;
}

bool glob_match(const char *pattern, const char *str) {
  while (*pattern) {
    if (*pattern == '*') {
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
      if (*pattern != *str)
        return false;
      pattern++;
      str++;
    }
  }
  return *str == '\0';
}

static void delete_extras_walk(const char *abs_path, const char *rel_path,
                               ArrayList *manifest) {
  DIR *dir = opendir(abs_path);
  if (!dir)
    return;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    char *child_abs = path_cat((char *)abs_path, entry->d_name);
    char *child_rel = path_cat((char *)rel_path, entry->d_name);
    struct stat st;
    if (stat(child_abs, &st) != 0) {
      free(child_abs);
      free(child_rel);
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      delete_extras_walk(child_abs, child_rel, manifest);
    } else {
      // Check if relative path is in manifest
      bool found = false;
      for (int i = 0; i < manifest->size; i++) {
        if (strcmp((char *)manifest->items[i], child_rel) == 0) {
          found = true;
          break;
        }
      }
      if (!found) {
        unlink(child_abs);
        fprintf(stderr, "  Deleted: %s\n", child_rel);
      }
    }
    free(child_abs);
    free(child_rel);
  }
  closedir(dir);
  rmdir(abs_path);
}

void delete_extras(const char *dest_root, ArrayList *manifest) {
  delete_extras_walk(dest_root, "", manifest);
}

char *path_cat(char *path1, char *path2) {
  if (path1 == NULL || *path1 == '\0')
    return str_dup(path2);
  if (path2 == NULL || *path2 == '\0')
    return str_dup(path1);
  int path1_len = strlen(path1);
  int path2_len = strlen(path2);
  char *path2_pointer = path2;
  if (path1[path1_len - 1] == '/')
    path1_len -= 1;
  if (path2[0] == '/') {
    path2_pointer += 1;
    path2_len -= 1;
  }
  char *new_path = malloc(path1_len + path2_len + 2);
  memcpy(new_path, path1, path1_len);
  new_path[path1_len] = '/';
  memcpy(new_path + path1_len + 1, path2_pointer, path2_len);
  new_path[path1_len + path2_len + 1] = '\0';
  return new_path;
}
