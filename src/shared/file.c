#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <zstd.h>

#include "data.h"
#include "file.h"
#include "log.h"
#include "socket.h"

File *file_create(const char *path, struct stat *stats) {
  File *file = (File *)malloc(sizeof(File));
  if (file == NULL) {
    perror("FATAL ERROR: Could not allocate memory for file struct");
    exit(EXIT_FAILURE);
  }

  file->stats = *stats;

  int path_len = strlen(path);
  file->path = (char *)malloc(path_len + 1);
  if (file->path == NULL) {
    perror("FATAL ERROR: Could not allocate memory for path file string");
    free(file);
    exit(EXIT_FAILURE);
  }

  strcpy(file->path, path);
  file->data = NULL;
  return file;
}

void file_destroy(void *item) {
  if (item == NULL)
    return;
  File *file = (File *)item;
  data_destroy(file->data);
  file->data = NULL;
  free(file->path);
  file->path = NULL;
  free(file);
}

void file_load_data(File *file) {
  if (file == NULL)
    return;
  file->data = data_create_empty(file->stats.st_size);
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

void file_send_single_calls(File *file, int file_descriptor) {
  send_str(file_descriptor, file->path);
  printf("Sending File: %ld", file->data->size);
  send_data(file_descriptor, file->data->data, file->data->size);
}

void file_send_sendfile(File *file, int file_descriptor) {
  send_str(file_descriptor, file->path);

  int fd = open(file->path, O_RDONLY);
  if (fd == -1) {
    perror("Could not open file for sendfile");
    exit(EXIT_FAILURE);
  }

  unsigned long long file_size = file->stats.st_size;
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

size_t file_content_to_buffer(File *file) {
  FILE *file_pointer = fopen(file->path, "rb");
  if (file_pointer == NULL) {
    perror("Could not open the file!");
    return 0;
  }
  size_t bytes_read =
      fread(file->data->data, 1, file->stats.st_size, file_pointer);
  if (bytes_read != (size_t)file->stats.st_size) {
    perror("Read to many or to less bytes from File!");
    return 0;
  }
  fclose(file_pointer);
  return bytes_read;
}

FileReceive *file_receive_create(char *path, Data *data) {
  FileReceive *file = malloc(sizeof(FileReceive));
  file->path = path;
  file->data = data;
  return file;
}

void file_receive_destroy(void *file_receive) {
  if (file_receive == NULL)
    return;
  FileReceive *file = (FileReceive *)file_receive;
  data_destroy(file->data);
  free(file->path);
  free(file);
}


