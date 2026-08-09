#include "protocol.h"
#include "log.h"
#include <errno.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

#define RECEIVE_TIMEOUT_SEC 60 /* 60 second per-message timeout */
#define SEND_TIMEOUT_SEC 60
#define MAX_CONNECTION_MEMORY (1024ULL * 1024 * 1024) /* 1 GB total per connection */

static __thread int io_read_fd = -1;
static __thread int io_write_fd = -1;
static __thread SSL* io_ssl;

static unsigned long long io_bwlimit = 0;
static long long bw_tokens = 0;
static struct timespec bw_last_refill = {0, 0};
static mtx_t bw_mutex;
static once_flag bw_mutex_once = ONCE_FLAG_INIT;

static __thread unsigned long long total_allocated_bytes = 0;

void io_set_fds(int read_fd, int write_fd) {
  io_read_fd = read_fd;
  io_write_fd = write_fd;
  /* A descriptor switch starts a new transport; never reuse a TLS object
     belonging to a previous connection or test pipe. */
  io_ssl = NULL;
}

static void bw_mutex_init(void) {
  mtx_init(&bw_mutex, mtx_plain);
}

void io_set_bwlimit(unsigned long long bytes_per_sec) {
  call_once(&bw_mutex_once, bw_mutex_init);
  mtx_lock(&bw_mutex);
  io_bwlimit = bytes_per_sec;
  bw_tokens = (long long)io_bwlimit;
  clock_gettime(CLOCK_MONOTONIC, &bw_last_refill);
  mtx_unlock(&bw_mutex);
}

static void bw_throttle(size_t bytes_written) {
  if (io_bwlimit == 0)
    return;
  call_once(&bw_mutex_once, bw_mutex_init);
  mtx_lock(&bw_mutex);

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
    long long deficit_us = (long long)((double)(-bw_tokens) / io_bwlimit * 1000000.0);
    if (deficit_us >= 1000)
      poll(NULL, 0, (int)(deficit_us / 1000));
    else
      usleep((useconds_t)deficit_us);
    bw_tokens = 0;
    clock_gettime(CLOCK_MONOTONIC, &bw_last_refill);
  }
  mtx_unlock(&bw_mutex);
}

void io_set_ssl(SSL* ssl) {
  io_ssl = ssl;
}

SSL* io_get_ssl(void) {
  return io_ssl;
}

static int io_fd(int dir_fd, int file_descriptor) {
  return (dir_fd != -1) ? dir_fd : file_descriptor;
}

static int deadline_remaining_ms(const struct timespec* deadline) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  long long ns =
      (long long)(deadline->tv_sec - now.tv_sec) * 1000000000LL + deadline->tv_nsec - now.tv_nsec;
  if (ns <= 0)
    return 0;
  long long ms = (ns + 999999) / 1000000;
  return ms > INT_MAX ? INT_MAX : (int)ms;
}

bool send_n_data(int file_descriptor, const void* data, size_t data_size) {
  log_message(LOG_LEVEL_DEBUG, "    Sending n Data: %zu", data_size);
  int fd = io_fd(io_write_fd, file_descriptor);
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += SEND_TIMEOUT_SEC;
  short wait_events = POLLOUT;
  ssize_t total_bytes_send = 0;
  while ((size_t)total_bytes_send < data_size) {
    size_t chunk = data_size - total_bytes_send;
    if (io_bwlimit > 0 && chunk > 65536)
      chunk = 65536;
    struct pollfd pfd = {.fd = fd, .events = wait_events};
    int poll_result = poll(&pfd, 1, deadline_remaining_ms(&deadline));
    if (poll_result == 0 || (poll_result < 0 && errno != EINTR)) {
      log_message(LOG_LEVEL_ERROR, "Send timeout or poll failure");
      return false;
    }
    if (poll_result == 0)
      return false;
    if (poll_result < 0)
      continue;
    if (pfd.revents & (POLLERR | POLLNVAL))
      return false;
    ssize_t bytes_send;
    if (io_ssl)
      bytes_send = SSL_write(io_ssl, (const char*)data + total_bytes_send, chunk);
    else
      bytes_send = write(fd, (const char*)data + total_bytes_send, chunk);
    if (bytes_send <= 0) {
      if (io_ssl) {
        int ssl_err = SSL_get_error(io_ssl, (int)bytes_send);
        if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
          wait_events = ssl_err == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
          continue;
        }
      }
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

  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += RECEIVE_TIMEOUT_SEC;

  size_t total_bytes_received = 0;
  short wait_events = POLLIN;
  while (total_bytes_received < data_size) {
    struct pollfd pfd = {.fd = fd, .events = wait_events};
    int poll_result = poll(&pfd, 1, deadline_remaining_ms(&deadline));
    if (poll_result == 0) {
      log_message(LOG_LEVEL_ERROR, "Receive timeout after %ds", RECEIVE_TIMEOUT_SEC);
      return false;
    }
    if (poll_result < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    /* POLLHUP may accompany the final readable bytes on pipes/sockets. */
    if (pfd.revents & (POLLERR | POLLNVAL))
      return false;

    ssize_t bytes_received;
    if (io_ssl)
      bytes_received =
          SSL_read(io_ssl, (char*)data + total_bytes_received, data_size - total_bytes_received);
    else
      bytes_received =
          read(fd, (char*)data + total_bytes_received, data_size - total_bytes_received);
    if (bytes_received <= 0) {
      if (io_ssl) {
        int ssl_err = SSL_get_error(io_ssl, (int)bytes_received);
        if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
          wait_events = ssl_err == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
          continue;
        }
      }
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
  case STATUS_KEEPALIVE:
    return "KEEPALIVE";
  case STATUS_ABORT:
    return "ABORT";
  case STATUS_CHECK_BATCH:
    return "CHECK_BATCH";
  default:
    return "UNKNOWN";
  }
}

bool send_str(int file_descriptor, const char* data) {
  if (data == NULL)
    return false;
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
  if (size > MAX_STRING_SIZE || size > SIZE_MAX - 1 ||
      total_allocated_bytes > MAX_CONNECTION_MEMORY - (size + 1)) {
    log_message(LOG_LEVEL_ERROR, "String size %zu exceeds maximum %llu", size,
                (unsigned long long)MAX_STRING_SIZE);
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
  if (size > MAX_DATA_PAYLOAD_SIZE) {
    log_message(LOG_LEVEL_ERROR, "Data size %llu exceeds maximum %llu", size,
                (unsigned long long)MAX_DATA_PAYLOAD_SIZE);
    return NULL;
  }
  if (total_allocated_bytes + size > MAX_CONNECTION_MEMORY) {
    log_message(LOG_LEVEL_ERROR, "Per-connection memory limit exceeded (%llu + %llu > %llu)",
                (unsigned long long)total_allocated_bytes, size,
                (unsigned long long)MAX_CONNECTION_MEMORY);
    return NULL;
  }
  void* data = malloc((size_t)size);
  if (data == NULL)
    return NULL;
  if (!receive_n_data(file_descriptor, data, (size_t)size)) {
    free(data);
    return NULL;
  }
  total_allocated_bytes += size + 1;
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
