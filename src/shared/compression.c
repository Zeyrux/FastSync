#include "compression.h"
#include "data.h"
#include "log.h"
#include "stdlib.h"
#include "zstd.h"

#define INITIAL_DECOMPRESS_BUF_SIZE (1024 * 1024)

Data *data_compress(Data *data_to_compress, int compression_level) {
  log_message(LOG_LEVEL_DEBUG, "Starting to compress data");
  size_t dst_size = ZSTD_compressBound(data_to_compress->size);
  Data *compressed_data = data_create_empty(dst_size);
  if (!compressed_data) {
    log_message(LOG_LEVEL_ERROR, "Failed to allocate compression buffer");
    return NULL;
  }

  ZSTD_CCtx *cctx = ZSTD_createCCtx();
  if (!cctx) {
    log_message(LOG_LEVEL_ERROR, "Failed to create ZSTD compression context");
    data_destroy(compressed_data);
    return NULL;
  }

  ZSTD_inBuffer input = {data_to_compress->data, data_to_compress->size, 0};
  ZSTD_outBuffer output = {compressed_data->data, dst_size, 0};

  size_t ret;
  do {
    ret = ZSTD_compressStream2(cctx, &output, &input, ZSTD_e_end);
    if (ZSTD_isError(ret)) {
      log_message(LOG_LEVEL_ERROR, "Compression failed: %s",
                  ZSTD_getErrorName(ret));
      ZSTD_freeCCtx(cctx);
      data_destroy(compressed_data);
      return NULL;
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

  ZSTD_DCtx *dctx = ZSTD_createDCtx();
  if (!dctx) {
    log_message(LOG_LEVEL_ERROR,
                "Failed to create ZSTD decompression context");
    return NULL;
  }

  size_t buf_size = (!ZSTD_isError(dst_size) && dst_size > 0)
                        ? (size_t)dst_size
                        : INITIAL_DECOMPRESS_BUF_SIZE;
  Data *uncompressed_data = data_create_empty(buf_size);
  if (!uncompressed_data) {
    log_message(LOG_LEVEL_ERROR, "Failed to allocate decompression buffer");
    ZSTD_freeDCtx(dctx);
    return NULL;
  }

  ZSTD_inBuffer input = {compressed_data->data, compressed_data->size, 0};
  ZSTD_outBuffer output = {uncompressed_data->data, buf_size, 0};

  size_t ret;
  do {
    ret = ZSTD_decompressStream(dctx, &output, &input);
    if (ZSTD_isError(ret)) {
      log_message(LOG_LEVEL_ERROR, "Decompression failed: %s",
                  ZSTD_getErrorName(ret));
      ZSTD_freeDCtx(dctx);
      data_destroy(uncompressed_data);
      return NULL;
    }
    if (ret > 0 && output.pos == output.size) {
      buf_size *= 2;
      void *new_data = realloc(uncompressed_data->data, buf_size);
      if (!new_data) {
        log_message(LOG_LEVEL_ERROR, "Failed to grow decompression buffer");
        ZSTD_freeDCtx(dctx);
        data_destroy(uncompressed_data);
        return NULL;
      }
      uncompressed_data->data = new_data;
      output.dst = new_data;
      output.size = buf_size;
    }
  } while (ret > 0);

  uncompressed_data->size = output.pos;
  ZSTD_freeDCtx(dctx);

  log_message(LOG_LEVEL_DEBUG, "Decompressed data successfully");
  return uncompressed_data;
}
