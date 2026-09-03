#include "compression.h"
#include "data.h"
#include "log.h"
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <zstd.h>

#define INITIAL_DECOMPRESS_BUF_SIZE (1024 * 1024)
#define MAX_DECOMPRESSED_SIZE (100ULL * 1024 * 1024) /* 100 MB hard ceiling */

static char* SKIP_COMPRESSION_EXTENSIONS[] = {".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mkv",
                                              ".zip", ".gz",   ".xz",  ".zst", NULL};

bool compression_should_skip(const char* path) {
  return compression_should_skip_with_suffixes(path, NULL, -1);
}

bool compression_should_skip_with_suffixes(const char* path, char* const* suffixes, int count) {
  if (!path)
    return false;
  const char* dot = strrchr(path, '.');
  if (!dot)
    return false;
  if (count < 0) {
    suffixes = SKIP_COMPRESSION_EXTENSIONS;
    count = 0;
    while (SKIP_COMPRESSION_EXTENSIONS[count])
      count++;
  }
  for (int i = 0; i < count; i++) {
    if (strcasecmp(dot, suffixes[i]) == 0)
      return true;
  }
  return false;
}

Data* data_compress(Data* data_to_compress, int compression_level) {
  log_message(LOG_LEVEL_DEBUG, "Starting to compress data");
  size_t dst_size = ZSTD_compressBound(data_to_compress->size);
  Data* compressed_data = data_create_empty(dst_size);
  if (compressed_data == NULL)
    return NULL;

  ZSTD_CCtx* cctx = ZSTD_createCCtx();
  if (!cctx) {
    log_message(LOG_LEVEL_ERROR, "Failed to create ZSTD compression context");
    data_destroy(compressed_data);
    return NULL;
  }

  size_t zret = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, compression_level);
  if (ZSTD_isError(zret)) {
    log_message(LOG_LEVEL_ERROR, "Failed to set compression level: %s", ZSTD_getErrorName(zret));
    ZSTD_freeCCtx(cctx);
    data_destroy(compressed_data);
    return NULL;
  }

  ZSTD_inBuffer input = {data_to_compress->data, data_to_compress->size, 0};
  ZSTD_outBuffer output = {compressed_data->data, dst_size, 0};

  size_t ret;
  do {
    ret = ZSTD_compressStream2(cctx, &output, &input, ZSTD_e_end);
    if (ZSTD_isError(ret)) {
      log_message(LOG_LEVEL_ERROR, "Compression failed: %s", ZSTD_getErrorName(ret));
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

Data* data_decompress_limited(Data* compressed_data, size_t maximum_size) {
  if (!compressed_data || (!compressed_data->data && compressed_data->size != 0) ||
      maximum_size == 0)
    return NULL;
  log_message(LOG_LEVEL_DEBUG, "Start to decompress data");
  unsigned long long dst_size =
      ZSTD_getFrameContentSize(compressed_data->data, compressed_data->size);
  if (ZSTD_isError(dst_size)) {
    log_message(LOG_LEVEL_ERROR, "Failed to get decompressed size: %s",
                ZSTD_getErrorName(dst_size));
    return NULL;
  }

  // ZSTD_CONTENTSIZE_UNKNOWN (~2^64) can cause massive allocation;
  // fall back to a conservative estimate (3x compressed size) when unknown.
  if (dst_size == ZSTD_CONTENTSIZE_UNKNOWN) {
    if (compressed_data->size > ULLONG_MAX / 3)
      return NULL;
    dst_size = compressed_data->size * 3;
    if (dst_size < INITIAL_DECOMPRESS_BUF_SIZE)
      dst_size = INITIAL_DECOMPRESS_BUF_SIZE;
  }
  unsigned long long hard_limit =
      maximum_size < MAX_DECOMPRESSED_SIZE ? maximum_size : MAX_DECOMPRESSED_SIZE;
  if (dst_size > hard_limit) {
    log_message(LOG_LEVEL_ERROR, "Declared decompressed size exceeds %llu bytes", hard_limit);
    return NULL;
  }

  ZSTD_DCtx* dctx = ZSTD_createDCtx();
  if (!dctx) {
    log_message(LOG_LEVEL_ERROR, "Failed to create ZSTD decompression context");
    return NULL;
  }

  size_t buf_size = (dst_size > 0) ? (size_t)dst_size : INITIAL_DECOMPRESS_BUF_SIZE;
  if (buf_size > maximum_size)
    buf_size = maximum_size;
  Data* uncompressed_data = data_create_empty(buf_size);
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
      log_message(LOG_LEVEL_ERROR, "Decompression failed: %s", ZSTD_getErrorName(ret));
      ZSTD_freeDCtx(dctx);
      data_destroy(uncompressed_data);
      return NULL;
    }
    if (ret > 0 && output.pos == output.size) {
      if (buf_size >= hard_limit || buf_size > SIZE_MAX / 2) {
        log_message(LOG_LEVEL_ERROR, "Decompressed data exceeds %llu bytes",
                    (unsigned long long)MAX_DECOMPRESSED_SIZE);
        ZSTD_freeDCtx(dctx);
        data_destroy(uncompressed_data);
        return NULL;
      }
      buf_size *= 2;
      if (buf_size > hard_limit)
        buf_size = (size_t)hard_limit;
      void* new_data = realloc(uncompressed_data->data, buf_size);
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

Data* data_decompress(Data* compressed_data) {
  return data_decompress_limited(compressed_data, MAX_DECOMPRESSED_SIZE);
}
