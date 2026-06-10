#include "utils.h"
#include "libgen.h"
#include "sys/stat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void mkdir_r(char *path) {
  char *path_duplicate = malloc(strlen(path) + 1);
  strcpy(path_duplicate, path);
  char *path_current = (char *)malloc((strlen(path) + 2) * sizeof(char));
  char *path_current_position = path_current;
  const char *delimiter = "/";
  char *part = strtok(path_duplicate, delimiter);
  // struct stat st;
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

char *str_dup(char *string) {
  if (string == NULL)
    return NULL;
  char *new_string = (char *)malloc(strlen(string) + 1);
  strcpy(new_string, string);
  return new_string;
}

void to_disk(char *path, void *data, unsigned long long data_size) {
  char *directory = str_dup(path);
  char *dir_to_free = directory;
  directory = dirname(directory);
  mkdir_r(directory);
  FILE *file_pointer = fopen(path, "wb");
  if (file_pointer == NULL) {
    perror("Could not open File");
    exit(EXIT_FAILURE);
  }
  fwrite(data, 1, data_size, file_pointer);
  fclose(file_pointer);
  free(dir_to_free);
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
