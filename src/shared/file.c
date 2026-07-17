#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#include "compression.h"
#include "log.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"

File *file_create(const char *path) {
  File *file = (File *)malloc(sizeof(File));
  if (file == NULL) {
    perror("ERROR: Could not allocate memory for file struct");
    return NULL;
  }

  int path_len = strlen(path);
  file->path = (char *)malloc(path_len + 1);
  if (file->path == NULL) {
    free(file);
    return NULL;
  }

  strcpy(file->path, path);
  file->data = data_create_reserve(0);
  if (file->data == NULL) {
    free(file->path);
    free(file);
    return NULL;
  }
  file->metadata = NULL;
  return file;
}

void file_destroy(void *item) {
  if (item == NULL)
    return;
  File *file = (File *)item;
  data_destroy(file->data);
  file->data = NULL;
  file_metadata_destroy(file->metadata);
  file->metadata = NULL;
  free(file->path);
  file->path = NULL;
  free(file);
}

FileMetadata *file_metadata_create(struct stat *stats) {
  FileMetadata *m = malloc(sizeof(FileMetadata));
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

void file_metadata_destroy(void *metadata) {
  free(metadata);
}

bool file_load_data(File *file) {
  if (file == NULL) return false;
  if (file->data->data == NULL) {
    file->data->data = malloc(file->data->size);
    if (file->data->data == NULL) {
      perror("Could not allocate memory for file data");
      return false;
    }
  }
  size_t bytes_read = file_content_to_buffer(file);
  if (bytes_read != file->data->size) {
    log_message(LOG_LEVEL_ERROR, "Did not read expected amount of bytes from file");
    return false;
  }
  return true;
}

bool file_send_single_calls_no_path(File *file, int file_descriptor, bool use_metadata, int compression_level) {
  Data *data_to_send = file->data;
  Data *compressed_data = NULL;
  if (compression_level > 0) {
    compressed_data = data_compress(file->data, compression_level);
    if (compressed_data == NULL) {
      log_message(LOG_LEVEL_ERROR, "Failed to compress file data");
      return false;
    }
    data_to_send = compressed_data;
  }
  if (use_metadata && !metadata_send(file_descriptor, file->metadata)) {
    data_destroy(compressed_data);
    return false;
  }
  if (!send_data(file_descriptor, data_to_send)) {
    data_destroy(compressed_data);
    return false;
  }
  data_destroy(compressed_data);
  return true;
}

bool file_send_sendfile_no_path(File *file, int file_descriptor, bool use_metadata) {
  if (use_metadata && !metadata_send(file_descriptor, file->metadata)) return false;

  int fd = open(file->path, O_RDONLY);
  if (fd == -1) {
    perror("Could not open file for sendfile");
    return false;
  }

  unsigned long long file_size = file->data->size;
  if (!send_n_data(file_descriptor, &file_size, sizeof(unsigned long long))) {
    close(fd);
    return false;
  }

  off_t offset = 0;
  while (offset < file_size) {
    ssize_t sent = sendfile(file_descriptor, fd, &offset, file_size - offset);
    if (sent == -1) {
      perror("sendfile failed");
      close(fd);
      return false;
    }
  }

  close(fd);
  return true;
}

bool file_send_single_calls(File *file, int file_descriptor, bool use_metadata, int compression_level) {
  Data *data_to_send = file->data;
  Data *compressed_data = NULL;
  if (compression_level > 0) {
    compressed_data = data_compress(file->data, compression_level);
    if (compressed_data == NULL) {
      log_message(LOG_LEVEL_ERROR, "Failed to compress file data");
      return false;
    }
    data_to_send = compressed_data;
  }
  if (!send_str(file_descriptor, file->path)) {
    data_destroy(compressed_data);
    return false;
  }
  if (use_metadata && !metadata_send(file_descriptor, file->metadata)) {
    data_destroy(compressed_data);
    return false;
  }
  if (!send_data(file_descriptor, data_to_send)) {
    data_destroy(compressed_data);
    return false;
  }
  data_destroy(compressed_data);
  return true;
}

bool to_disk(const char *path, const void *data, unsigned long long data_size) {
  char *directory = str_dup(path);
  char *dir_to_free = directory;
  directory = dirname(directory);
  if (!mkdir_r(directory)) {
    free(dir_to_free);
    return false;
  }
  FILE *file_pointer = fopen(path, "wb");
  if (file_pointer == NULL) {
    perror("Could not open File");
    free(dir_to_free);
    return false;
  }
  if (fwrite(data, 1, data_size, file_pointer) != data_size) {
    perror("Failed to write all data to disk");
    fclose(file_pointer);
    free(dir_to_free);
    return false;
  }
  fclose(file_pointer);
  free(dir_to_free);
  return true;
}

bool file_send_sendfile(File *file, int file_descriptor, bool use_metadata) {
  if (!send_str(file_descriptor, file->path)) return false;
  if (use_metadata && !metadata_send(file_descriptor, file->metadata)) return false;

  int fd = open(file->path, O_RDONLY);
  if (fd == -1) {
    perror("Could not open file for sendfile");
    return false;
  }

  unsigned long long file_size = file->data->size;
  if (!send_n_data(file_descriptor, &file_size, sizeof(unsigned long long))) {
    close(fd);
    return false;
  }

  off_t offset = 0;
  while (offset < file_size) {
    ssize_t sent = sendfile(file_descriptor, fd, &offset, file_size - offset);
    if (sent == -1) {
      perror("sendfile failed");
      close(fd);
      return false;
    }
  }

  close(fd);
  return true;
}

File *file_receive(Config *config, int file_descriptor) {
  char *path = receive_str(file_descriptor);
  if (path == NULL) return NULL;
  File *file = file_create(path);
  free(path);
  if (file == NULL) return NULL;
  if (config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(file_descriptor, &meta_ok);
    if (!meta_ok) { file_destroy(file); return NULL; }
  }
  Data *file_data = receive_data(file_descriptor);
  if (file_data == NULL) {
    file_destroy(file);
    return NULL;
  }
  if (config->use_compression) {
    Data *file_data_uncompressed = data_decompress(file_data);
    data_destroy(file_data);
    if (file_data_uncompressed == NULL) {
      file_destroy(file);
      return NULL;
    }
    file_data = file_data_uncompressed;
  }
  data_destroy(file->data);
  file->data = file_data;
  return file;
}

size_t file_content_to_buffer(File *file) {
  FILE *file_pointer = fopen(file->path, "rb");
  if (file_pointer == NULL) {
    perror("Could not open the file!");
    return 0;
  }
  size_t bytes_read =
      fread(file->data->data, 1, file->data->size, file_pointer);
  if (bytes_read != (size_t)file->data->size) {
    fclose(file_pointer);
    perror("Read unexpected number of bytes from File!");
    return 0;
  }
  fclose(file_pointer);
  return bytes_read;
}


