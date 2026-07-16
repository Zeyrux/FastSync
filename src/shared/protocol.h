#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "data.h"
#include <stdbool.h>
#include <stddef.h>

typedef int Status;
enum NET_STATUS { STATUS_OK, STATUS_ERROR, STATUS_FINISHED, STATUS_NEXT, STATUS_CHUNK, STATUS_MANIFEST };

void io_set_fds(int read_fd, int write_fd);
bool send_n_data(int file_descriptor, void *data, size_t data_size);
bool receive_n_data(int file_descriptor, void *data, size_t data_size);

bool send_str(int file_descriptor, char *data);
char *receive_str(int file_descriptor);
bool send_data(int file_descriptor, Data *data);
Data *receive_data(int file_descriptor);
bool send_int(int file_descriptor, int data);
bool receive_int(int file_descriptor, int *data);
bool send_status(int file_descriptor, Status status);
bool receive_status(int file_descriptor, Status *status);

#endif
