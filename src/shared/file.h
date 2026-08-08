#ifndef FILE_H
#define FILE_H

#include "config.h"
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

File* file_create(const char* path);
void file_destroy(void* item);
bool file_load_data(File* file);
bool file_checksum(File* file, uint64_t* checksum);
File* file_receive(const Config* config, int file_descriptor);
bool file_send_single_calls(File* file, int file_descriptor, bool use_metadata,
                            int compression_level, bool send_path);
bool file_send_sendfile(File* file, int file_descriptor, bool use_metadata, int compression_level,
                        bool send_path);
size_t file_content_to_buffer(File* file);
FileMetadata* file_metadata_create(const struct stat* stats);
void file_metadata_destroy(void* metadata);
bool to_disk(const char* path, const void* data, unsigned long long data_size, bool inplace,
             bool sparse);
bool file_save_to_disk(const char* root_directory, File* file, const Config* config);
File* receive_incremental_check(int fd, const Config* config, bool* skipped);
int receive_manifest(int fd, const Config* config, int* next_status);

#endif
