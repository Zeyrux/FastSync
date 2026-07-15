#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "data.h"
#include "io.h"
#include <stddef.h>

typedef int Status;
enum NET_STATUS { STATUS_OK, STATUS_ERROR, STATUS_FINISHED, STATUS_NEXT, STATUS_CHUNK };

void send_str(int file_descriptor, char *data);
char *receive_str(int file_descriptor);
void send_data(int file_descriptor, void *data, unsigned long long data_size);
Data *receive_data(int file_descriptor);
void send_int(int file_descriptor, int data);
int receive_int(int file_descriptor);
void send_status(int file_descriptor, Status status);
Status receive_status(int file_descriptor);

#endif
