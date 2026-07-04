
#include "data.h"
#include "log.h"
#include "stdlib.h"
#include "zstd.h"

Data *data_create_empty(size_t data_size) {
  void *data = malloc(data_size);
  if (data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Could not allocate memory for empty data");
    exit(EXIT_FAILURE);
  }
  return data_create(data, data_size);
}

Data *data_create(void *data, size_t data_size) {
  Data *new_data = malloc(sizeof(Data));
  if (new_data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Could not allocate memory for data");
    exit(EXIT_FAILURE);
  }
  new_data->data = data;
  new_data->size = data_size;
  return new_data;
}

void data_destroy(Data *data) {
  free(data->data);
  free(data);
}

Data *data_compress(Data *data_to_compress, int compression_level) {
  log_message(LOG_LEVEL_DEBUG, "Starting to compress data");
  Data *compressed_data =
      data_create_empty(ZSTD_compressBound(data_to_compress->size));

  compressed_data->size = ZSTD_compress(
      compressed_data->data, compressed_data->size, data_to_compress->data,
      data_to_compress->size, compression_level);
  if (ZSTD_isError(compressed_data->size)) {
    log_message(LOG_LEVEL_ERROR, "Compression failed: %s",
                ZSTD_getErrorName(compressed_data->size));
    exit(EXIT_FAILURE);
  }

  log_message(LOG_LEVEL_DEBUG, "Data succesfully compressed from %zu to %zu",
              data_to_compress->size, compressed_data->size);
  return compressed_data;
}

Data *data_decompress(Data *compressed_data) {
  log_message(LOG_LEVEL_DEBUG, "Start to decompress data");
  Data *uncompressed_data = data_create_empty(
      ZSTD_getFrameContentSize(compressed_data->data, compressed_data->size));
  if (ZSTD_isError(uncompressed_data->size)) {
    log_message(LOG_LEVEL_ERROR, "Decompression failed: %s",
                ZSTD_getErrorName(uncompressed_data->size));
    exit(EXIT_FAILURE);
  }

  uncompressed_data->size =
      ZSTD_decompress(uncompressed_data->data, uncompressed_data->size,
                      compressed_data->data, compressed_data->size);
  if (ZSTD_isError(uncompressed_data->size)) {
    log_message(LOG_LEVEL_ERROR, "Decompression failed: %s",
                ZSTD_getErrorName(uncompressed_data->size));
    exit(EXIT_FAILURE);
  }
  log_message(LOG_LEVEL_DEBUG, "Decompressed data successfully");
  return uncompressed_data;
}
