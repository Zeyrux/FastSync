#include "protocol.h"
#include "io.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void send_str(int file_descriptor, char *data) {
  size_t size = strlen(data);
  send_n_data(file_descriptor, &size, sizeof(size_t));
  send_n_data(file_descriptor, data, size);
  log_message(LOG_LEVEL_DEBUG, "Send String: %s", data);
}

char *receive_str(int file_descriptor) {
  size_t size;
  receive_n_data(file_descriptor, &size, sizeof(size_t));
  char *data = (char *)malloc(size + 1);
  receive_n_data(file_descriptor, data, size);
  data[size] = '\0';
  log_message(LOG_LEVEL_DEBUG, "Received String: %s", data);
  return data;
}

void send_data(int file_descriptor, void *data, unsigned long long data_size) {
  send_n_data(file_descriptor, &data_size, sizeof(unsigned long long));
  send_n_data(file_descriptor, data, data_size);
  log_message(LOG_LEVEL_DEBUG, "Send %lld data", data_size);
}

Data *receive_data(int file_descriptor) {
  size_t size = 0;
  receive_n_data(file_descriptor, &size, sizeof(unsigned long long));
  void *data = malloc(size);
  receive_n_data(file_descriptor, data, size);
  log_message(LOG_LEVEL_DEBUG, "Received %lld data", size);
  return data_create(data, size);
}

void send_int(int file_descriptor, int data) {
  send_n_data(file_descriptor, &data, sizeof(int));
  log_message(LOG_LEVEL_DEBUG, "Send Int: %d", data);
}

int receive_int(int file_descriptor) {
  int data;
  receive_n_data(file_descriptor, &data, sizeof(int));
  log_message(LOG_LEVEL_DEBUG, "Received Int: %d", data);
  return data;
}

void send_status(int file_descriptor, Status status) {
  send_n_data(file_descriptor, &status, sizeof(Status));
  log_message(LOG_LEVEL_DEBUG, "Send Status: %s", status_to_string(status));
}

Status receive_status(int file_descriptor) {
  Status data;
  receive_n_data(file_descriptor, &data, sizeof(Status));
  log_message(LOG_LEVEL_DEBUG, "Received Status: %s", status_to_string(data));
  return data;
}
