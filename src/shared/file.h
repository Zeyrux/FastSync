#ifndef FILE_H
#define FILE_H

#include "data.h"
#include <sys/stat.h>

typedef struct {
  char *path;
  struct stat stats;
  Data *data;
} File;

typedef struct {
  char *path;
  Data *data;
} FileReceive;

File *file_create(const char *path, struct stat *stats);
void file_destroy(void *item);
void file_load_data(File *file);
void file_print(void *item);
void file_send_single_calls(File *file, int file_descriptor);
size_t file_content_to_buffer(File *file);

FileReceive *file_receive_create(char *path, Data *data);
void file_receive_destroy(void *file_receive);

#endif
