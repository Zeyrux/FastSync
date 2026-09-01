#ifndef FILE_TYPES_H
#define FILE_TYPES_H

#include "data.h"
#include <stdbool.h>
#include <sys/stat.h>

typedef enum { FILE_TYPE_REGULAR, FILE_TYPE_SYMLINK, FILE_TYPE_DIR } FileType;

typedef struct {
  mode_t mode;
  uid_t uid;
  gid_t gid;
  time_t mtime_sec;
  long mtime_nsec;
} FileMetadata;

typedef struct {
  char* path;
  Data* data;
  FileMetadata* metadata;
  bool skip;
} File;

#endif
