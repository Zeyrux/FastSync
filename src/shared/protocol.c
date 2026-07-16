#include "protocol.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

bool send_n_data(int file_descriptor, void *data, size_t data_size) {
  log_message(LOG_LEVEL_DEBUG, "    Sending n Data: %zu", data_size);
  int fd = io_fd(io_write_fd, file_descriptor);
  ssize_t total_bytes_send = 0;
  while (total_bytes_send < data_size) {
    ssize_t bytes_send =
        write(fd, (char *)data + total_bytes_send, data_size - total_bytes_send);
    if (bytes_send <= 0) {
      log_message(LOG_LEVEL_ERROR, "Could not send data");
      return false;
    }
    total_bytes_send += bytes_send;
  }
  log_message(LOG_LEVEL_DEBUG, "    Send n Data: %zu", total_bytes_send);
  return true;
}

bool receive_n_data(int file_descriptor, void *data, size_t data_size) {
  log_message(LOG_LEVEL_DEBUG, "    Receiving n Data: %zu", data_size);
  int fd = io_fd(io_read_fd, file_descriptor);
  size_t total_bytes_received = 0;
  while (total_bytes_received < data_size) {
    ssize_t bytes_received =
        read(fd, (char *)data + total_bytes_received, data_size - total_bytes_received);
    if (bytes_received <= 0) {
      if (bytes_received == 0)
        log_message(LOG_LEVEL_ERROR, "Connection closed while receiving data");
      else
        log_message(LOG_LEVEL_ERROR, "Could not receive bytes");
      return false;
    }
    total_bytes_received += bytes_received;
  }
  log_message(LOG_LEVEL_DEBUG, "    Received n Data: %zu", total_bytes_received);
  return true;
}

static const char *status_to_string(Status status) {
  switch (status) {
  case STATUS_OK:
    return "OK";
  case STATUS_ERROR:
    return "ERROR";
  case STATUS_FINISHED:
    return "FINISHED";
  case STATUS_NEXT:
    return "NEXT";
  case STATUS_CHUNK:
    return "CHUNK";
  default:
    return "UNKNOWN";
  }
}

bool send_str(int file_descriptor, char *data) {
  size_t size = strlen(data);
  if (!send_n_data(file_descriptor, &size, sizeof(size_t))) return false;
  if (!send_n_data(file_descriptor, data, size)) return false;
  log_message(LOG_LEVEL_DEBUG, "Send String: %s", data);
  return true;
}

char *receive_str(int file_descriptor) {
  size_t size;
  if (!receive_n_data(file_descriptor, &size, sizeof(size_t))) return NULL;
  char *data = (char *)malloc(size + 1);
  if (data == NULL) return NULL;
  if (!receive_n_data(file_descriptor, data, size)) {
    free(data);
    return NULL;
  }
  data[size] = '\0';
  log_message(LOG_LEVEL_DEBUG, "Received String: %s", data);
  return data;
}

bool send_data(int file_descriptor, Data *data) {
  unsigned long long data_size = data->size;
  if (!send_n_data(file_descriptor, &data_size, sizeof(unsigned long long)))
    return false;
  if (!send_n_data(file_descriptor, data->data, data_size))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Send %lld data", data_size);
  return true;
}

Data *receive_data(int file_descriptor) {
  unsigned long long size = 0;
  if (!receive_n_data(file_descriptor, &size, sizeof(unsigned long long)))
    return NULL;
  void *data = malloc((size_t)size);
  if (data == NULL) return NULL;
  if (!receive_n_data(file_descriptor, data, (size_t)size)) {
    free(data);
    return NULL;
  }
  log_message(LOG_LEVEL_DEBUG, "Received %lld data", size);
  return data_create(data, (size_t)size);
}

bool send_int(int file_descriptor, int data) {
  if (!send_n_data(file_descriptor, &data, sizeof(int))) return false;
  log_message(LOG_LEVEL_DEBUG, "Send Int: %d", data);
  return true;
}

bool receive_int(int file_descriptor, int *data) {
  if (!receive_n_data(file_descriptor, data, sizeof(int))) return false;
  log_message(LOG_LEVEL_DEBUG, "Received Int: %d", *data);
  return true;
}

bool send_status(int file_descriptor, Status status) {
  if (!send_n_data(file_descriptor, &status, sizeof(Status))) return false;
  log_message(LOG_LEVEL_DEBUG, "Send Status: %s", status_to_string(status));
  return true;
}

bool receive_status(int file_descriptor, Status *status) {
  if (!receive_n_data(file_descriptor, status, sizeof(Status))) return false;
  log_message(LOG_LEVEL_DEBUG, "Received Status: %s", status_to_string(*status));
  return true;
}
