#include "protocol.h"
#include "log.h"
#include "utils.h"
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
#define MAX_CONNECTION_MEMORY (256ULL * 1024 * 1024) /* bounded cumulative receive budget */

static __thread int io_read_fd = -1;
static __thread int io_write_fd = -1;
static __thread SSL* io_ssl;
static __thread ProtocolSession* bound_session;
static __thread ProtocolSession legacy_io_session = {.read_fd = -1, .write_fd = -1};

static unsigned long long io_bwlimit = 0;
static mtx_t bw_mutex;
static once_flag bw_mutex_once = ONCE_FLAG_INIT;

static unsigned long long global_bwlimit(void);

void protocol_release_memory(size_t charge) {
  ProtocolSession* session = bound_session ? bound_session : &legacy_io_session;
  if ((unsigned long long)charge >= session->total_allocated_bytes)
    session->total_allocated_bytes = 0;
  else
    session->total_allocated_bytes -= charge;
}
void io_set_fds(int read_fd, int write_fd) {
  bound_session = NULL;
  io_read_fd = read_fd;
  io_write_fd = write_fd;
  /* A descriptor switch starts a new transport; never reuse a TLS object
     belonging to a previous connection or test pipe. */
  io_ssl = NULL;
  legacy_io_session.read_fd = read_fd;
  legacy_io_session.write_fd = write_fd;
  legacy_io_session.ssl = NULL;
  legacy_io_session.total_allocated_bytes = 0;
  protocol_session_set_bwlimit(&legacy_io_session, global_bwlimit());
}

void protocol_session_init(ProtocolSession* session, int read_fd, int write_fd) {
  if (!session)
    return;
  memset(session, 0, sizeof(*session));
  session->read_fd = read_fd;
  session->write_fd = write_fd;
  protocol_session_set_bwlimit(session, global_bwlimit());
}

void protocol_session_bind(ProtocolSession* session) {
  bound_session = session;
}

void protocol_session_unbind(void) {
  bound_session = NULL;
}

void protocol_session_set_ssl(ProtocolSession* session, SSL* ssl) {
  if (session)
    session->ssl = ssl;
}

static void bw_mutex_init(void) {
  mtx_init(&bw_mutex, mtx_plain);
}

static unsigned long long global_bwlimit(void) {
  unsigned long long limit;
  call_once(&bw_mutex_once, bw_mutex_init);
  mtx_lock(&bw_mutex);
  limit = io_bwlimit;
  mtx_unlock(&bw_mutex);
  return limit;
}

void io_set_bwlimit(unsigned long long bytes_per_sec) {
  call_once(&bw_mutex_once, bw_mutex_init);
  mtx_lock(&bw_mutex);
  io_bwlimit =
      bytes_per_sec > (unsigned long long)LLONG_MAX ? (unsigned long long)LLONG_MAX : bytes_per_sec;
  mtx_unlock(&bw_mutex);
}

void protocol_session_set_bwlimit(ProtocolSession* session, unsigned long long bytes_per_sec) {
  if (!session)
    return;
  session->bwlimit =
      bytes_per_sec > (unsigned long long)LLONG_MAX ? (unsigned long long)LLONG_MAX : bytes_per_sec;
  session->bw_tokens = (long long)session->bwlimit;
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  session->bw_last_refill_sec = now.tv_sec;
  session->bw_last_refill_nsec = now.tv_nsec;
}

static void bw_throttle_session(ProtocolSession* session, size_t bytes_written) {
  if (session->bwlimit == 0)
    return;

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  long long elapsed_ns = (now.tv_sec - session->bw_last_refill_sec) * 1000000000LL +
                         (now.tv_nsec - session->bw_last_refill_nsec);
  session->bw_last_refill_sec = now.tv_sec;
  session->bw_last_refill_nsec = now.tv_nsec;

  long long tokens_to_add = (long long)((double)session->bwlimit * elapsed_ns / 1000000000.0);
  session->bw_tokens += tokens_to_add;
  if (session->bw_tokens > (long long)session->bwlimit)
    session->bw_tokens = (long long)session->bwlimit;

  session->bw_tokens -= bytes_written;

  if (session->bw_tokens < 0) {
    long long deficit_us =
        (long long)((double)(-session->bw_tokens) / session->bwlimit * 1000000.0);
    if (deficit_us >= 1000)
      poll(NULL, 0, (int)(deficit_us / 1000));
    else
      usleep((useconds_t)deficit_us);
    session->bw_tokens = 0;
    session->bw_last_refill_sec = now.tv_sec;
    session->bw_last_refill_nsec = now.tv_nsec;
  }
}

void io_set_ssl(SSL* ssl) {
  bound_session = NULL;
  io_ssl = ssl;
}

SSL* io_get_ssl(void) {
  return io_ssl;
}

static ProtocolSession* legacy_session(int read_fd, int write_fd) {
  if (bound_session)
    return bound_session;
  int target_read_fd = io_read_fd != -1 ? io_read_fd : read_fd;
  int target_write_fd = io_write_fd != -1 ? io_write_fd : write_fd;
  if (legacy_io_session.read_fd != target_read_fd ||
      legacy_io_session.write_fd != target_write_fd) {
    legacy_io_session.read_fd = target_read_fd;
    legacy_io_session.write_fd = target_write_fd;
    legacy_io_session.total_allocated_bytes = 0;
    protocol_session_set_bwlimit(&legacy_io_session, global_bwlimit());
  } else if (legacy_io_session.bwlimit != global_bwlimit()) {
    protocol_session_set_bwlimit(&legacy_io_session, global_bwlimit());
  }
  legacy_io_session.ssl = io_ssl;
  return &legacy_io_session;
}

bool send_n_data(int file_descriptor, const void* data, size_t data_size) {
  return protocol_send_n_data(legacy_session(-1, file_descriptor), data, data_size);
}

bool receive_n_data(int file_descriptor, void* data, size_t data_size) {
  return protocol_receive_n_data(legacy_session(file_descriptor, -1), data, data_size);
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

bool protocol_send_n_data(ProtocolSession* session, const void* data, size_t data_size) {
  if (!data && data_size != 0)
    return false;
  log_message(LOG_LEVEL_DEBUG, "    Sending n Data: %zu", data_size);
  if (!session)
    return false;
  int fd = session->write_fd;
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += SEND_TIMEOUT_SEC;
  short wait_events = POLLOUT;
  ssize_t total_bytes_send = 0;
  while ((size_t)total_bytes_send < data_size) {
    size_t chunk = data_size - total_bytes_send;
    if (session->bwlimit > 0 && chunk > 65536)
      chunk = 65536;
    struct pollfd pfd = {.fd = fd, .events = wait_events};
    int poll_result = poll(&pfd, 1, deadline_remaining_ms(&deadline));
    if (poll_result == 0 || (poll_result < 0 && errno != EINTR)) {
      log_message(LOG_LEVEL_ERROR, "Send timeout or poll failure");
      return false;
    }
    if (poll_result < 0)
      continue;
    if (pfd.revents & (POLLERR | POLLNVAL))
      return false;
    ssize_t bytes_send;
    if (session->ssl)
      bytes_send = SSL_write(session->ssl, (const char*)data + total_bytes_send, chunk);
    else
      bytes_send = write(fd, (const char*)data + total_bytes_send, chunk);
    if (bytes_send <= 0) {
      if (session->ssl) {
        int ssl_err = SSL_get_error(session->ssl, (int)bytes_send);
        if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
          wait_events = ssl_err == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
          continue;
        }
      }
      log_message(LOG_LEVEL_ERROR, "Could not send data");
      return false;
    }
    bw_throttle_session(session, (size_t)bytes_send);
    total_bytes_send += bytes_send;
    if (session->ssl)
      wait_events = POLLOUT;
  }
  log_message(LOG_LEVEL_DEBUG, "    Send n Data: %zu", total_bytes_send);
  return true;
}

bool protocol_receive_n_data(ProtocolSession* session, void* data, size_t data_size) {
  log_message(LOG_LEVEL_DEBUG, "    Receiving n Data: %zu", data_size);
  if (!session)
    return false;
  int fd = session->read_fd;

  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += RECEIVE_TIMEOUT_SEC;

  size_t total_bytes_received = 0;
  short wait_events = POLLIN;
  while (total_bytes_received < data_size) {
    if (!session->ssl || SSL_pending(session->ssl) == 0) {
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
    }

    ssize_t bytes_received;
    if (session->ssl)
      bytes_received = SSL_read(session->ssl, (char*)data + total_bytes_received,
                                data_size - total_bytes_received);
    else
      bytes_received =
          read(fd, (char*)data + total_bytes_received, data_size - total_bytes_received);
    if (bytes_received <= 0) {
      if (session->ssl) {
        int ssl_err = SSL_get_error(session->ssl, (int)bytes_received);
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
    total_bytes_received += (size_t)bytes_received;
    if (session->ssl)
      wait_events = POLLIN;
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

bool protocol_send_str(ProtocolSession* session, const char* data) {
  if (data == NULL)
    return false;
  size_t size = strlen(data);
  if (!protocol_send_n_data(session, &size, sizeof(size_t)))
    return false;
  if (!protocol_send_n_data(session, data, size))
    return false;
  char* escaped = output_escape(data, log_get_8_bit_output());
  log_message(LOG_LEVEL_DEBUG, "Send String: %s", escaped ? escaped : "<allocation failed>");
  free(escaped);
  return true;
}

char* protocol_receive_str(ProtocolSession* session) {
  size_t size;
  if (!protocol_receive_n_data(session, &size, sizeof(size_t)))
    return NULL;
  if (size > MAX_STRING_SIZE || size > SIZE_MAX - 1 ||
      size + 1 > MAX_CONNECTION_MEMORY - session->total_allocated_bytes) {
    log_message(LOG_LEVEL_ERROR, "String size %zu exceeds maximum %llu", size,
                (unsigned long long)MAX_STRING_SIZE);
    return NULL;
  }
  char* data = (char*)malloc(size + 1);
  if (data == NULL)
    return NULL;
  if (!protocol_receive_n_data(session, data, size)) {
    free(data);
    return NULL;
  }
  if (memchr(data, '\0', size) != NULL) {
    free(data);
    log_message(LOG_LEVEL_ERROR, "Received string contains an embedded NUL");
    return NULL;
  }
  data[size] = '\0';
  session->total_allocated_bytes += size + 1;
  char* escaped = output_escape(data, log_get_8_bit_output());
  log_message(LOG_LEVEL_DEBUG, "Received String: %s", escaped ? escaped : "<allocation failed>");
  free(escaped);
  return data;
}

bool protocol_send_data(ProtocolSession* session, const Data* data) {
  if (!data || (!data->data && data->size != 0))
    return false;
  if (!session)
    return false;
  unsigned long long data_size = data->size;
  if (!protocol_send_n_data(session, &data_size, sizeof(unsigned long long)))
    return false;
  if (!protocol_send_n_data(session, data->data, data_size))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Send %lld data", data_size);
  return true;
}

Data* protocol_receive_data_limited(ProtocolSession* session, unsigned long long maximum_size) {
  if (!session)
    return NULL;
  unsigned long long size = 0;
  if (!protocol_receive_n_data(session, &size, sizeof(unsigned long long)))
    return NULL;
  if (size > MAX_DATA_PAYLOAD_SIZE || size > maximum_size) {
    log_message(LOG_LEVEL_ERROR, "Data size %llu exceeds maximum %llu", size,
                (unsigned long long)MAX_DATA_PAYLOAD_SIZE);
    return NULL;
  }
  size_t allocation_size = size == 0 ? 1 : (size_t)size;
  if (allocation_size > MAX_CONNECTION_MEMORY - session->total_allocated_bytes) {
    log_message(LOG_LEVEL_ERROR, "Per-connection memory limit exceeded (%llu + %llu > %llu)",
                (unsigned long long)session->total_allocated_bytes, size,
                (unsigned long long)MAX_CONNECTION_MEMORY);
    return NULL;
  }
  void* data = malloc(allocation_size);
  if (data == NULL)
    return NULL;
  if (!protocol_receive_n_data(session, data, (size_t)size)) {
    free(data);
    return NULL;
  }
  session->total_allocated_bytes += allocation_size;
  log_message(LOG_LEVEL_DEBUG, "Received %lld data", size);
  Data* result = data_create(data, (size_t)size);
  if (!result) {
    session->total_allocated_bytes -= allocation_size;
    return NULL;
  }
  result->protocol_charge = allocation_size;
  return result;
}

Data* protocol_receive_data(ProtocolSession* session) {
  return protocol_receive_data_limited(session, MAX_DATA_PAYLOAD_SIZE);
}

bool protocol_send_int(ProtocolSession* session, int data) {
  if (!protocol_send_n_data(session, &data, sizeof(int)))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Send Int: %d", data);
  return true;
}

bool protocol_receive_int(ProtocolSession* session, int* data) {
  if (!protocol_receive_n_data(session, data, sizeof(int)))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Received Int: %d", *data);
  return true;
}

bool protocol_send_status(ProtocolSession* session, Status status) {
  if (!protocol_send_n_data(session, &status, sizeof(Status)))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Send Status: %s", status_to_string(status));
  return true;
}

bool protocol_receive_status(ProtocolSession* session, Status* status) {
  if (!protocol_receive_n_data(session, status, sizeof(Status)))
    return false;
  log_message(LOG_LEVEL_DEBUG, "Received Status: %s", status_to_string(*status));
  return true;
}

bool send_str(int fd, const char* data) {
  return protocol_send_str(legacy_session(-1, fd), data);
}
char* receive_str(int fd) {
  return protocol_receive_str(legacy_session(fd, -1));
}
bool send_data(int fd, const Data* data) {
  return protocol_send_data(legacy_session(-1, fd), data);
}
Data* receive_data(int fd) {
  return protocol_receive_data_limited(legacy_session(fd, -1), MAX_DATA_PAYLOAD_SIZE);
}
Data* receive_data_limited(int fd, unsigned long long maximum_size) {
  return protocol_receive_data_limited(legacy_session(fd, -1), maximum_size);
}
bool send_int(int fd, int data) {
  return protocol_send_int(legacy_session(-1, fd), data);
}
bool receive_int(int fd, int* data) {
  return protocol_receive_int(legacy_session(fd, -1), data);
}
bool send_status(int fd, Status status) {
  return protocol_send_status(legacy_session(-1, fd), status);
}
bool receive_status(int fd, Status* status) {
  return protocol_receive_status(legacy_session(fd, -1), status);
}
