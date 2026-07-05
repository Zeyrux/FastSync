#include <dirent.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

#include "data.h"
#include "file.h"
#include "log.h"
#include "socket.h"

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
  if (file->data->data == NULL)
    file->data->data = malloc(file->data->size);
  printf("%ld is file big", file->data->size);
  size_t bytes_read = file_content_to_buffer(file);
  if (bytes_read != file->data->size) {
    log_message(STATUS_ERROR, "Didnt read expected amount of bytes from file");
    exit(EXIT_FAILURE);
  }
}

void file_print(void *item) {
  if (item == NULL)
    return;
  printf("%s\n", ((File *)item)->path);
}

static void metadata_send(int file_descriptor, FileMetadata *m) {
  if (m == NULL) {
    int zero = 0;
    send_n_data(file_descriptor, &zero, sizeof(int));
    return;
  }
  int present = 1;
  send_n_data(file_descriptor, &present, sizeof(int));
  send_n_data(file_descriptor, &m->mode, sizeof(mode_t));
  send_n_data(file_descriptor, &m->uid, sizeof(uid_t));
  send_n_data(file_descriptor, &m->gid, sizeof(gid_t));
  send_n_data(file_descriptor, &m->mtime_sec, sizeof(time_t));
  send_n_data(file_descriptor, &m->mtime_nsec, sizeof(long));
}

FileMetadata *file_receive_metadata(int file_descriptor) {
  int present;
  receive_n_data(file_descriptor, &present, sizeof(int));
  if (!present)
    return NULL;
  FileMetadata *m = malloc(sizeof(FileMetadata));
  receive_n_data(file_descriptor, &m->mode, sizeof(mode_t));
  receive_n_data(file_descriptor, &m->uid, sizeof(uid_t));
  receive_n_data(file_descriptor, &m->gid, sizeof(gid_t));
  receive_n_data(file_descriptor, &m->mtime_sec, sizeof(time_t));
  receive_n_data(file_descriptor, &m->mtime_nsec, sizeof(long));
  return m;
}

void file_send_single_calls(File *file, int file_descriptor) {
  send_str(file_descriptor, file->path);
  metadata_send(file_descriptor, file->metadata);
  printf("Sending File: %ld", file->data->size);
  send_data(file_descriptor, file->data->data, file->data->size);
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
    perror("Read to many or to less bytes from File!");
    return 0;
  }
  fclose(file_pointer);
  return bytes_read;
}
