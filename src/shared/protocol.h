#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "data.h"
#include <stddef.h>

typedef int Status;
enum NET_STATUS { STATUS_OK, STATUS_ERROR, STATUS_FINISHED, STATUS_NEXT, STATUS_CHUNK };

void io_set_fds(int read_fd, int write_fd);
void send_n_data(int file_descriptor, void *data, size_t data_size);
void receive_n_data(int file_descriptor, void *data, size_t data_size);

void send_str(int file_descriptor, char *data);
char *receive_str(int file_descriptor);
void send_data(int file_descriptor, Data *data);
Data *receive_data(int file_descriptor);
void send_int(int file_descriptor, int data);
int receive_int(int file_descriptor);
void send_status(int file_descriptor, Status status);
Status receive_status(int file_descriptor);

#endif
