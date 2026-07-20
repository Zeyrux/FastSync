#include "protocol.h"
#include "log.h"
#include <errno.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static __thread int io_read_fd = -1;
static __thread int io_write_fd = -1;
static SSL* io_ssl = NULL;

static unsigned long long io_bwlimit = 0;
static long long bw_tokens = 0;
static struct timespec bw_last_refill = {0, 0};

void io_set_fds(int read_fd, int write_fd) {
  io_read_fd = read_fd;
  io_write_fd = write_fd;
}

void io_set_bwlimit(unsigned long long bytes_per_sec) {
  io_bwlimit = bytes_per_sec;
  bw_tokens = (long long)io_bwlimit;
  clock_gettime(CLOCK_MONOTONIC, &bw_last_refill);
}

static void bw_throttle(size_t bytes_written) {
  if (io_bwlimit == 0)
    return;

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  long long elapsed_ns =
      (now.tv_sec - bw_last_refill.tv_sec) * 1000000000LL + (now.tv_nsec - bw_last_refill.tv_nsec);
  bw_last_refill = now;

  long long tokens_to_add = (long long)((double)io_bwlimit * elapsed_ns / 1000000000.0);
  bw_tokens += tokens_to_add;
  if (bw_tokens > (long long)io_bwlimit)
    bw_tokens = (long long)io_bwlimit;

  bw_tokens -= (long long)bytes_written;

  if (bw_tokens < 0) {
    long long deficit_ns = (long long)((double)(-bw_tokens) / io_bwlimit * 1000000000.0);
    struct timespec sleep_time, remaining;
    sleep_time.tv_sec = deficit_ns / 1000000000LL;
    sleep_time.tv_nsec = deficit_ns % 1000000000LL;
    while (nanosleep(&sleep_time, &remaining) < 0 && errno == EINTR)
      sleep_time = remaining;
    bw_tokens = 0;
    clock_gettime(CLOCK_MONOTONIC, &bw_last_refill);
  }
}

void io_set_ssl(SSL* ssl) {
  io_ssl = ssl;
}

static int io_fd(int dir_fd, int file_descriptor) {
  return (dir_fd != -1) ? dir_fd : file_descriptor;
}

bool send_n_data(int file_descriptor, const void* data, size_t data_size) {
  log_message(LOG_LEVEL_DEBUG, "    Sending n Data: %zu", data_size);
  int fd = io_fd(io_write_fd, file_descriptor);
  ssize_t total_bytes_send = 0;
  while ((size_t)total_bytes_send < data_size) {
    size_t chunk = data_size - total_bytes_send;
    if (io_bwlimit > 0 && chunk > 65536)
      chunk = 65536;
    ssize_t bytes_send;
    if (io_ssl)
      bytes_send = SSL_write(io_ssl, (const char*)data + total_bytes_send, chunk);
    else
      bytes_send = write(fd, (const char*)data + total_bytes_send, chunk);
    if (bytes_send <= 0) {
      log_message(LOG_LEVEL_ERROR, "Could not send data");
      return false;
    }
    bw_throttle((size_t)bytes_send);
    total_bytes_send += bytes_send;
  }
  log_message(LOG_LEVEL_DEBUG, "    Send n Data: %zu", total_bytes_send);
  return true;
}

bool receive_n_data(int file_descriptor, void* data, size_t data_size) {
  log_message(LOG_LEVEL_DEBUG, "    Receiving n Data: %zu", data_size);
  int fd = io_fd(io_read_fd, file_descriptor);
  size_t total_bytes_received = 0;
  while (total_bytes_received < data_size) {
    ssize_t bytes_received;
    if (io_ssl)
      bytes_received =
          SSL_read(io_ssl, (char*)data + total_bytes_received, data_size - total_bytes_received);
    else
      bytes_received =
          read(fd, (char*)data + total_bytes_received, data_size - total_bytes_received);
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

static const char* status_to_string(Status status) {
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
  case STATUS_CHECK:
    return "CHECK";
  case STATUS_DELTA_SIGNATURE:
    return "DELTA_SIGNATURE";
  case STATUS_DELTA_DATA:
    return "DELTA_DATA";
  default:
    return "UNKNOWN";
  }
}

bool send_str(int file_descriptor, const char* data) {
  if (data == NULL) {
    log_message(LOG_LEVEL_ERROR, "send_str called with NULL data");
    return false;
  }
  size_t size = strlen(data);
  if (!send_n_data(file_descriptor, &size, sizeof(size_t)))
    return false;
  if (!send_n_data(file_descriptor, data, size))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Send String: %s", data);
  return true;
}

char* receive_str(int file_descriptor) {
  size_t size;
  if (!receive_n_data(file_descriptor, &size, sizeof(size_t)))
    return NULL;
  if (size > MAX_STRING_SIZE) {
    log_message(LOG_LEVEL_ERROR, "receive_str: size %zu exceeds maximum %zu", size,
                (size_t)MAX_STRING_SIZE);
    return NULL;
  }
  char* data = (char*)malloc(size + 1);
  if (data == NULL)
    return NULL;
  if (!receive_n_data(file_descriptor, data, size)) {
    free(data);
    return NULL;
  }
  data[size] = '\0';
  log_message(LOG_LEVEL_DEBUG, "Received String: %s", data);
  return data;
}

bool send_data(int file_descriptor, const Data* data) {
  unsigned long long data_size = data->size;
  if (!send_n_data(file_descriptor, &data_size, sizeof(unsigned long long)))
    return false;
  if (!send_n_data(file_descriptor, data->data, data_size))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Send %lld data", data_size);
  return true;
}

Data* receive_data(int file_descriptor) {
  unsigned long long size = 0;
  if (!receive_n_data(file_descriptor, &size, sizeof(unsigned long long)))
    return NULL;
  void* data = malloc((size_t)size);
  if (data == NULL)
    return NULL;
  if (!receive_n_data(file_descriptor, data, (size_t)size)) {
    free(data);
    return NULL;
  }
  log_message(LOG_LEVEL_DEBUG, "Received %lld data", size);
  return data_create(data, (size_t)size);
}

bool send_int(int file_descriptor, int data) {
  if (!send_n_data(file_descriptor, &data, sizeof(int)))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Send Int: %d", data);
  return true;
}

bool receive_int(int file_descriptor, int* data) {
  if (!receive_n_data(file_descriptor, data, sizeof(int)))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Received Int: %d", *data);
  return true;
}

bool send_status(int file_descriptor, Status status) {
  if (!send_n_data(file_descriptor, &status, sizeof(Status)))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Send Status: %s", status_to_string(status));
  return true;
}

bool receive_status(int file_descriptor, Status* status) {
  if (!receive_n_data(file_descriptor, status, sizeof(Status)))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Received Status: %s", status_to_string(*status));
  return true;
}
