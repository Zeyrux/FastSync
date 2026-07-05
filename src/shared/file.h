#ifndef FILE_H
#define FILE_H

#include "data.h"
#include <sys/stat.h>

typedef struct {
  mode_t mode;
  uid_t uid;
  gid_t gid;
  time_t mtime_sec;
  long mtime_nsec;
} FileMetadata;

typedef struct {
  char *path;
  Data *data;
  FileMetadata *metadata;
} File;

File *file_create(const char *path);
void file_destroy(void *item);
void file_load_data(File *file);
void file_print(void *item);
void file_send_single_calls(File *file, int file_descriptor);
size_t file_content_to_buffer(File *file);
FileMetadata *file_metadata_create(struct stat *stats);
void file_metadata_destroy(void *metadata);
FileMetadata *file_receive_metadata(int file_descriptor);

#endif
