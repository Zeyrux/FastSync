#include "io.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static __thread int io_read_fd = -1;
static __thread int io_write_fd = -1;

void io_set_fds(int read_fd, int write_fd) {
  io_read_fd = read_fd;
  io_write_fd = write_fd;
}

static int io_fd(int dir_fd, int file_descriptor) {
  return (dir_fd != -1) ? dir_fd : file_descriptor;
}

void send_n_data(int file_descriptor, void *data, size_t data_size) {
  log_message(LOG_LEVEL_DEBUG, "    Sending n Data: %zu", data_size);
  int fd = io_fd(io_write_fd, file_descriptor);
  ssize_t total_bytes_send = 0;
  while (total_bytes_send < data_size) {
    ssize_t bytes_send =
        write(fd, (char *)data + total_bytes_send, data_size - total_bytes_send);
    if (bytes_send <= 0) {
      perror("Could not send data!");
      exit(EXIT_FAILURE);
    }
    total_bytes_send += bytes_send;
  }
  log_message(LOG_LEVEL_DEBUG, "    Send n Data: %zu", total_bytes_send);
}

void receive_n_data(int file_descriptor, void *data, size_t data_size) {
  log_message(LOG_LEVEL_DEBUG, "    Receiving n Data: %zu", data_size);
  int fd = io_fd(io_read_fd, file_descriptor);
  size_t total_bytes_received = 0;
  while (total_bytes_received < data_size) {
    ssize_t bytes_received =
        read(fd, (char *)data + total_bytes_received, data_size - total_bytes_received);
    if (bytes_received == -1 || bytes_received == 0) {
      perror("Could not receive bytes!");
      exit(EXIT_FAILURE);
    }
    total_bytes_received += bytes_received;
  }
  log_message(LOG_LEVEL_DEBUG, "    Received n Data: %zu", total_bytes_received);
}
