#include "data.h"
#include "log.h"
#include "stdlib.h"

Data* data_create_empty(size_t data_size) {
  void* data = malloc(data_size);
  if (data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Could not allocate memory for empty data");
    return NULL;
  }
  return data_create(data, data_size);
}

Data* data_create_reserve(size_t size) {
  Data* d = malloc(sizeof(Data));
  if (d == NULL) {
    log_message(LOG_LEVEL_ERROR, "Could not allocate memory for data");
    return NULL;
  }
  d->data = NULL;
  d->size = size;
  return d;
}

Data* data_create(void* data, size_t data_size) {
  Data* new_data = malloc(sizeof(Data));
  if (new_data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Could not allocate memory for data");
    free(data);
    return NULL;
  }
  new_data->data = data;
  new_data->size = data_size;
  return new_data;
}

void data_destroy(Data* data) {
  if (data == NULL)
    return;
  free(data->data);
  free(data);
}
