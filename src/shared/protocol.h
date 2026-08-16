#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "data.h"
#include <stdbool.h>
#include <stddef.h>

/* Maximum allowed string size for receive_str (64 KB) */
#define MAX_STRING_SIZE (64 * 1024)

/* Maximum allowed data payload size for receive_data (100 MB) */
#define MAX_DATA_PAYLOAD_SIZE (100ULL * 1024 * 1024)
/* Maximum uncompressed file payload accepted by the receiver. */
#define MAX_RECEIVE_FILE_SIZE (64ULL * 1024 * 1024)

/* Maximum chunk size (64 MB) — prevents unbounded allocation from the wire */
#define MAX_CHUNK_SIZE (64ULL * 1024 * 1024)
#define MAX_MANIFEST_ENTRIES (1024 * 1024)
/* Aggregate bytes retained by one received deletion manifest. */
#define MAX_MANIFEST_BYTES (16ULL * 1024 * 1024)

typedef struct ssl_st SSL;

typedef int Status;
enum NET_STATUS {
  STATUS_OK,
  STATUS_ERROR,
  STATUS_FINISHED,
  STATUS_NEXT,
  STATUS_CHUNK,
  STATUS_MANIFEST,
  STATUS_CHECK,
  STATUS_DELTA_SIGNATURE,
  STATUS_DELTA_DATA,
  STATUS_KEEPALIVE,
  STATUS_ABORT,
  STATUS_CHECK_BATCH
};

void io_set_fds(int read_fd, int write_fd);
void io_set_bwlimit(unsigned long long bytes_per_sec);
void io_set_ssl(SSL* ssl);
SSL* io_get_ssl(void);
bool send_n_data(int file_descriptor, const void* data, size_t data_size);
bool receive_n_data(int file_descriptor, void* data, size_t data_size);

bool send_str(int file_descriptor, const char* data);
char* receive_str(int file_descriptor);
bool send_data(int file_descriptor, const Data* data);
Data* receive_data(int file_descriptor);
Data* receive_data_limited(int file_descriptor, unsigned long long maximum_size);
bool send_int(int file_descriptor, int data);
bool receive_int(int file_descriptor, int* data);
bool send_status(int file_descriptor, Status status);
bool receive_status(int file_descriptor, Status* status);

#endif
