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
    perror("FATAL ERROR: Could not allocate memory for file struct");
    exit(EXIT_FAILURE);
  }

  int path_len = strlen(path);
  file->path = (char *)malloc(path_len + 1);
  if (file->path == NULL) {
    perror("FATAL ERROR: Could not allocate memory for path file string");
    free(file);
    exit(EXIT_FAILURE);
  }

  strcpy(file->path, path);
  file->data = data_create_reserve(0);
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
    perror("FATAL ERROR: Could not allocate memory for file metadata");
    exit(EXIT_FAILURE);
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

void file_load_data(File *file) {
  if (file == NULL)
    return;
  if (file->data->data == NULL) {
    file->data->data = malloc(file->data->size);
    if (file->data->data == NULL) {
      perror("Could not allocate memory for file data");
      exit(EXIT_FAILURE);
    }
  }
  size_t bytes_read = file_content_to_buffer(file);
  if (bytes_read != file->data->size) {
    log_message(STATUS_ERROR, "Didnt read expected amount of bytes from file");
    exit(EXIT_FAILURE);
  }
}

void file_send_single_calls(File *file, int file_descriptor, bool use_metadata, int compression_level) {
  if (compression_level > 0) {
    Data *compressed_data = data_compress(file->data, compression_level);
    data_destroy(file->data);
    file->data = compressed_data;
  }
  send_str(file_descriptor, file->path);
  if (use_metadata)
    metadata_send(file_descriptor, file->metadata);
  send_data(file_descriptor, file->data);
}

void to_disk(const char *path, const void *data, unsigned long long data_size) {
  char *directory = str_dup(path);
  char *dir_to_free = directory;
  directory = dirname(directory);
  mkdir_r(directory);
  FILE *file_pointer = fopen(path, "wb");
  if (file_pointer == NULL) {
    perror("Could not open File");
    exit(EXIT_FAILURE);
  }
  if (fwrite(data, 1, data_size, file_pointer) != data_size) {
    perror("Failed to write all data to disk");
    fclose(file_pointer);
    exit(EXIT_FAILURE);
  }
  fclose(file_pointer);
  free(dir_to_free);
}

void file_send_sendfile(File *file, int file_descriptor, bool use_metadata) {
  send_str(file_descriptor, file->path);
  if (use_metadata)
    metadata_send(file_descriptor, file->metadata);

  int fd = open(file->path, O_RDONLY);
  if (fd == -1) {
    perror("Could not open file for sendfile");
    exit(EXIT_FAILURE);
  }

  unsigned long long file_size = file->data->size;
  send_n_data(file_descriptor, &file_size, sizeof(unsigned long long));

  off_t offset = 0;
  while (offset < file_size) {
    ssize_t sent = sendfile(file_descriptor, fd, &offset, file_size - offset);
    if (sent == -1) {
      perror("sendfile failed");
      close(fd);
      exit(EXIT_FAILURE);
    }
  }

  close(fd);
}

File *file_receive(Config *config, int file_descriptor) {
  char *path = (char *)receive_str(file_descriptor);
  File *file = file_create(path);
  free(path);
  if (config->use_metadata)
    file->metadata = metadata_receive(file_descriptor);
  Data *file_data = receive_data(file_descriptor);
  if (config->use_compression) {
    Data *file_data_uncompressed = data_decompress(file_data);
    data_destroy(file_data);
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


