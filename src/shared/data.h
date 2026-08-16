#ifndef DATA_H
#define DATA_H

#include <stdlib.h>

typedef struct {
  void* data;
  size_t size;
  /* Non-zero only for a buffer charged to the protocol connection budget. */
  size_t protocol_charge;
} Data;

Data* data_create_empty(size_t data_size);
Data* data_create_reserve(size_t size);
Data* data_create(void* data, size_t data_size);
void data_destroy(Data* data);
void protocol_release_memory(size_t charge);

#endif
