#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "data.h"
#include <stdbool.h>
#include <stddef.h>

/* Maximum allowed string size for receive_str (10 MB) */
#define MAX_STRING_SIZE (10 * 1024 * 1024)

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
bool send_n_data(int file_descriptor, const void* data, size_t data_size);
bool receive_n_data(int file_descriptor, void* data, size_t data_size);

bool send_str(int file_descriptor, const char* data);
char* receive_str(int file_descriptor);
bool send_data(int file_descriptor, const Data* data);
Data* receive_data(int file_descriptor);
bool send_int(int file_descriptor, int data);
bool receive_int(int file_descriptor, int* data);
bool send_status(int file_descriptor, Status status);
bool receive_status(int file_descriptor, Status* status);

#endif
