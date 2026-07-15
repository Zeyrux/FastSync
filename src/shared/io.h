#ifndef IO_H
#define IO_H

#include <stddef.h>

void io_set_fds(int read_fd, int write_fd);
void send_n_data(int file_descriptor, void *data, size_t data_size);
void receive_n_data(int file_descriptor, void *data, size_t data_size);

#endif
