#include "data.h"
#include "log.h"
#include "protocol.h"
#include <stdlib.h>

Data* data_create_empty(size_t data_size) {
  /* malloc(0) is UB; allocate at least 1 byte but preserve requested size */
  size_t alloc_size = data_size > 0 ? data_size : 1;
  void* data = protocol_alloc(alloc_size);
  if (data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Could not allocate memory for empty data");
    return NULL;
  }
  return data_create(data, data_size);
}

Data* data_create_reserve(size_t size) {
  Data* d = protocol_alloc(sizeof(Data));
  if (d == NULL) {
    log_message(LOG_LEVEL_ERROR, "Could not allocate memory for data");
    return NULL;
  }
  d->data = NULL;
  d->size = size;
  d->protocol_charge = 0;
  d->owner = NULL;
  return d;
}

Data* data_create(void* data, size_t data_size) {
  Data* new_data = protocol_alloc(sizeof(Data));
  if (new_data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Could not allocate memory for data");
    free(data);
    return NULL;
  }
  new_data->data = data;
  new_data->size = data_size;
  new_data->protocol_charge = 0;
  new_data->owner = NULL;
  return new_data;
}

void data_destroy(Data* data) {
  if (data == NULL)
    return;
  if (data->protocol_charge != 0) {
    if (data->owner != NULL)
      protocol_release_memory_for_session(data->owner, data->protocol_charge);
    else
      protocol_release_memory(data->protocol_charge);
  }
  free(data->data);
  free(data);
}
