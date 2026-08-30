#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "data.h"
#include "delta.h"
#include "file.h"
#include "file_store.h"
#include "log.h"
#include "utils.h"

bool file_checksum(File* file, uint64_t* checksum) {
  if (!file || !checksum || !file->data)
    return false;
  if (file->data->size == 0) {
    *checksum = delta_xxhash64("", 0);
    return true;
  }
  if (!file->data->data && !file_load_data(file))
    return false;
  *checksum = delta_xxhash64(file->data->data, file->data->size);
  return true;
}

File* file_create(const char* path) {
  if (!path)
    return NULL;
  File* file = (File*)malloc(sizeof(File));
  if (file == NULL) {
    perror("ERROR: Could not allocate memory for file struct");
    return NULL;
  }

  int path_len = strlen(path);
  file->path = (char*)malloc(path_len + 1);
  if (file->path == NULL) {
    free(file);
    return NULL;
  }

  memcpy(file->path, path, path_len);
  file->path[path_len] = '\0';
  file->data = data_create_reserve(0);
  if (file->data == NULL) {
    free(file->path);
    free(file);
    return NULL;
  }
  file->metadata = NULL;
  file->skip = false;
  return file;
}

void file_destroy(void* item) {
  if (item == NULL)
    return;
  File* file = (File*)item;
  data_destroy(file->data);
  file->data = NULL;
  file_metadata_destroy(file->metadata);
  file->metadata = NULL;
  free(file->path);
  file->path = NULL;
  free(file);
}

FileMetadata* file_metadata_create(const struct stat* stats) {
  FileMetadata* m = malloc(sizeof(FileMetadata));
  if (m == NULL) {
    perror("ERROR: Could not allocate memory for file metadata");
    return NULL;
  }
  m->mode = stats->st_mode;
  m->uid = stats->st_uid;
  m->gid = stats->st_gid;
  m->mtime_sec = stats->st_mtime;
#ifdef __linux__
  m->mtime_nsec = stats->st_mtim.tv_nsec;
#else
  m->mtime_nsec = 0;
#endif
  return m;
}

void file_metadata_destroy(void* metadata) {
  free(metadata);
}

bool file_load_data(File* file) {
  if (file == NULL)
    return false;
  if (file->data->data == NULL) {
    if (file->data->size == 0)
      return true;
    file->data->data = malloc(file->data->size);
    if (file->data->data == NULL) {
      perror("Could not allocate memory for file data");
      return false;
    }
  }
  size_t bytes_read = file_content_to_buffer(file);
  if (bytes_read != file->data->size) {
    log_message(LOG_LEVEL_ERROR, "Did not read expected amount of bytes from file");
    free(file->data->data);
    file->data->data = NULL;
    file->data->size = 0;
    return false;
  }
  return true;
}

bool file_set_authorized_root(int fd, const char* canonical_path) {
  return file_store_set_authorized_root(fd, canonical_path);
}

bool file_write_to_disk(const char* path, const void* data, unsigned long long data_size,
                        bool inplace, bool sparse) {
  if (!path || (!data && data_size != 0) || has_path_traversal(path))
    return false;
  return file_store_write_secure(path, data, data_size, inplace, sparse, NULL);
}

size_t file_content_to_buffer(File* file) {
  FILE* file_pointer = fopen(file->path, "rb");
  if (file_pointer == NULL) {
    perror("Could not open the file!");
    return 0;
  }
  size_t bytes_read = fread(file->data->data, 1, file->data->size, file_pointer);
  if (bytes_read != (size_t)file->data->size) {
    fclose(file_pointer);
    perror("Read unexpected number of bytes from File!");
    return 0;
  }
  fclose(file_pointer);
  return bytes_read;
}
