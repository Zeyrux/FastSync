#include "compression.h"
#include "data.h"
#include "log.h"
#include "stdlib.h"
#include "zstd.h"

Data *data_compress(Data *data_to_compress, int compression_level) {
  log_message(LOG_LEVEL_DEBUG, "Starting to compress data");
  size_t dst_size = ZSTD_compressBound(data_to_compress->size);
  Data *compressed_data = data_create_empty(dst_size);

  ZSTD_CCtx *cctx = ZSTD_createCCtx();
  if (!cctx) {
    log_message(LOG_LEVEL_ERROR, "Failed to create ZSTD compression context");
    exit(EXIT_FAILURE);
  }

  ZSTD_inBuffer input = {data_to_compress->data, data_to_compress->size, 0};
  ZSTD_outBuffer output = {compressed_data->data, dst_size, 0};

  size_t ret;
  do {
    ret = ZSTD_compressStream2(cctx, &output, &input, ZSTD_e_end);
    if (ZSTD_isError(ret)) {
      log_message(LOG_LEVEL_ERROR, "Compression failed: %s",
                  ZSTD_getErrorName(ret));
      exit(EXIT_FAILURE);
    }
  } while (ret > 0);

  compressed_data->size = output.pos;
  ZSTD_freeCCtx(cctx);

  log_message(LOG_LEVEL_DEBUG, "Data succesfully compressed from %zu to %zu",
              data_to_compress->size, compressed_data->size);
  return compressed_data;
}

Data *data_decompress(Data *compressed_data) {
  log_message(LOG_LEVEL_DEBUG, "Start to decompress data");
  unsigned long long dst_size = ZSTD_getFrameContentSize(
      compressed_data->data, compressed_data->size);
  if (ZSTD_isError(dst_size)) {
    log_message(LOG_LEVEL_ERROR, "Failed to get decompressed size: %s",
                ZSTD_getErrorName(dst_size));
    exit(EXIT_FAILURE);
  }

  Data *uncompressed_data = data_create_empty((size_t)dst_size);

  ZSTD_DCtx *dctx = ZSTD_createDCtx();
  if (!dctx) {
    log_message(LOG_LEVEL_ERROR,
                "Failed to create ZSTD decompression context");
    exit(EXIT_FAILURE);
  }

  ZSTD_inBuffer input = {compressed_data->data, compressed_data->size, 0};
  ZSTD_outBuffer output = {uncompressed_data->data, (size_t)dst_size, 0};

  size_t ret;
  do {
    ret = ZSTD_decompressStream(dctx, &output, &input);
    if (ZSTD_isError(ret)) {
      log_message(LOG_LEVEL_ERROR, "Decompression failed: %s",
                  ZSTD_getErrorName(ret));
      exit(EXIT_FAILURE);
    }
  } while (ret > 0);

  uncompressed_data->size = output.pos;
  ZSTD_freeDCtx(dctx);

  log_message(LOG_LEVEL_DEBUG, "Decompressed data successfully");
  return uncompressed_data;
}
