#include "compression.h"
#include "data.h"
#include "log.h"
#include "protocol.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <threads.h>
#include <unistd.h>
#include <zstd.h>

#define INITIAL_DECOMPRESS_BUF_SIZE (1024 * 1024)
#define MAX_DECOMPRESSED_SIZE (100ULL * 1024 * 1024) /* 100 MB hard ceiling */

static char* SKIP_COMPRESSION_EXTENSIONS[] = {".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mkv",
                                              ".zip", ".gz",   ".xz",  ".zst", NULL};

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

/* Per-thread cache of zstd contexts plus the grow-only compression scratch
 * buffer.  zstd contexts are stateful and not safe to share between threads,
 * so each thread keeps its own (see compression_get_thread_ctx).  The cache is
 * stored in a C11 thread-specific storage slot whose destructor releases the
 * contexts when the thread exits; this keeps LeakSanitizer clean for the
 * short-lived sender/receiver/scanner worker threads without every worker
 * entry point having to remember to call compression_free_thread_contexts().
 * The main thread's slot is not torn down by tss at process exit, so an atexit
 * hook releases it (and compression_free_thread_contexts allows eager
 * release). */
typedef struct {
  ZSTD_CCtx* cctx;
  ZSTD_DCtx* dctx;
  void* out_buf;  /* reusable ZSTD_compressBound-sized output scratch */
  size_t out_cap; /* bytes currently allocated for out_buf */
  int level;      /* compression level currently applied to cctx */
  int workers;    /* nbWorkers currently applied to cctx */
  bool params_set;
  bool cached; /* false when the TSS slot could not be used: caller owns */
} CompressionThreadCtx;

static once_flag compression_tls_once = ONCE_FLAG_INIT;
static tss_t compression_tls_key;
static bool compression_tls_ready;

static void compression_tls_make_key(void);

static void compression_ctx_free(CompressionThreadCtx* ctx) {
  if (!ctx)
    return;
  if (ctx->cctx)
    ZSTD_freeCCtx(ctx->cctx);
  if (ctx->dctx)
    ZSTD_freeDCtx(ctx->dctx);
  free(ctx->out_buf);
  free(ctx);
}

static void compression_tls_destructor(void* value) {
  compression_ctx_free((CompressionThreadCtx*)value);
}

void compression_free_thread_contexts(void) {
  call_once(&compression_tls_once, compression_tls_make_key);
  if (!compression_tls_ready)
    return;
  CompressionThreadCtx* ctx = (CompressionThreadCtx*)tss_get(compression_tls_key);
  if (!ctx)
    return;
  /* Clear the slot first so the thread-exit destructor cannot free it twice. */
  tss_set(compression_tls_key, NULL);
  compression_ctx_free(ctx);
}

static void compression_atexit_cleanup(void) {
  compression_free_thread_contexts();
}

static void compression_tls_make_key(void) {
  if (tss_create(&compression_tls_key, compression_tls_destructor) == thrd_success) {
    compression_tls_ready = true;
    atexit(compression_atexit_cleanup);
  }
}

static CompressionThreadCtx* compression_get_thread_ctx(void) {
  call_once(&compression_tls_once, compression_tls_make_key);
  if (!compression_tls_ready) {
    /* Extremely unlikely: fall back to an uncached context the caller frees. */
    return (CompressionThreadCtx*)calloc(1, sizeof(CompressionThreadCtx));
  }
  CompressionThreadCtx* ctx = (CompressionThreadCtx*)tss_get(compression_tls_key);
  if (ctx)
    return ctx;
  ctx = (CompressionThreadCtx*)calloc(1, sizeof(CompressionThreadCtx));
  if (!ctx)
    return NULL;
  ctx->cached = true;
  if (tss_set(compression_tls_key, ctx) != thrd_success)
    ctx->cached = false;
  return ctx;
}

/* Release an uncached context immediately; cached contexts are owned by the
 * thread's TSS slot and freed on thread exit / compression_free_thread_contexts. */
static void compression_ctx_put(CompressionThreadCtx* ctx) {
  if (ctx && !ctx->cached)
    compression_ctx_free(ctx);
}

Data* data_compress(Data* data_to_compress, int compression_level) {
  return data_compress_with_threads(data_to_compress, compression_level, 0);
}

Data* data_compress_with_threads(Data* data_to_compress, int compression_level,
                                 int compression_threads) {
  if (!data_to_compress || (!data_to_compress->data && data_to_compress->size != 0) ||
      compression_threads < 0 || compression_threads > COMPRESSION_MAX_THREADS)
    return NULL;
  log_message(LOG_LEVEL_DEBUG, "Starting to compress data");
  size_t dst_size = ZSTD_compressBound(data_to_compress->size);

  CompressionThreadCtx* ctx = compression_get_thread_ctx();
  if (ctx == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to allocate ZSTD compression context");
    return NULL;
  }
  Data* compressed_data = NULL;

  if (!ctx->cctx) {
    ctx->cctx = ZSTD_createCCtx();
    if (!ctx->cctx) {
      log_message(LOG_LEVEL_ERROR, "Failed to create ZSTD compression context");
      goto cleanup;
    }
    ctx->params_set = false;
  }

  /* Reset only the session: parameters (and any already-allocated zstd worker
   * pool) stay attached to the context, so compressing the next file does not
   * rebuild the pool. */
  ZSTD_CCtx_reset(ctx->cctx, ZSTD_reset_session_only);

  if (!ctx->params_set || ctx->level != compression_level) {
    size_t zret = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_compressionLevel, compression_level);
    if (ZSTD_isError(zret)) {
      log_message(LOG_LEVEL_ERROR, "Failed to set compression level: %s", ZSTD_getErrorName(zret));
      goto cleanup;
    }
    ctx->level = compression_level;
  }

  int available_threads = 0;
  if (compression_threads > 0) {
    long online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    available_threads = online_cpus > 0 && online_cpus < compression_threads ? (int)online_cpus
                                                                             : compression_threads;
  }
  if (!ctx->params_set || ctx->workers != available_threads) {
    size_t zret = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_nbWorkers, available_threads);
    if (ZSTD_isError(zret)) {
      log_message(LOG_LEVEL_ERROR, "Failed to set compression threads: %s",
                  ZSTD_getErrorName(zret));
      goto cleanup;
    }
    ctx->workers = available_threads;
  }
  ctx->params_set = true;

  if (available_threads > 0) {
    /* Streaming compression needs the source size before threaded mode can end a frame. */
    size_t zret = ZSTD_CCtx_setPledgedSrcSize(ctx->cctx, data_to_compress->size);
    if (ZSTD_isError(zret)) {
      log_message(LOG_LEVEL_ERROR, "Failed to set compression source size: %s",
                  ZSTD_getErrorName(zret));
      goto cleanup;
    }
  }

  if (ctx->out_cap < dst_size) {
    void* grown = protocol_realloc(ctx->out_buf, dst_size);
    if (grown == NULL) {
      log_message(LOG_LEVEL_ERROR, "Failed to allocate compression buffer");
      goto cleanup;
    }
    ctx->out_buf = grown;
    ctx->out_cap = dst_size;
  }

  ZSTD_inBuffer input = {data_to_compress->data, data_to_compress->size, 0};
  ZSTD_outBuffer output = {ctx->out_buf, dst_size, 0};

  size_t ret;
  do {
    ret = ZSTD_compressStream2(ctx->cctx, &output, &input, ZSTD_e_end);
    if (ZSTD_isError(ret)) {
      log_message(LOG_LEVEL_ERROR, "Compression failed: %s", ZSTD_getErrorName(ret));
      goto cleanup;
    }
  } while (ret > 0);

  /* Hand off an exactly-sized copy; the scratch buffer stays cached so the next
   * call does not reallocate a ZSTD_compressBound-sized block. */
  compressed_data = data_create_empty(output.pos);
  if (compressed_data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to allocate compressed data");
    goto cleanup;
  }
  if (output.pos > 0)
    memcpy(compressed_data->data, ctx->out_buf, output.pos);
  compressed_data->size = output.pos;

  log_debug_message(LOG_DEBUG_UTIL, "Data succesfully compressed from %zu to %zu",
                    data_to_compress->size, compressed_data->size);

cleanup:
  compression_ctx_put(ctx);
  return compressed_data;
}

Data* data_decompress_limited(Data* compressed_data, size_t maximum_size) {
  if (!compressed_data || (!compressed_data->data && compressed_data->size != 0) ||
      maximum_size == 0)
    return NULL;
  log_debug_message(LOG_DEBUG_UTIL, "Start to decompress data");
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

  CompressionThreadCtx* ctx = compression_get_thread_ctx();
  if (ctx == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to allocate ZSTD decompression context");
    return NULL;
  }
  Data* uncompressed_data = NULL;

  if (!ctx->dctx) {
    ctx->dctx = ZSTD_createDCtx();
    if (!ctx->dctx) {
      log_message(LOG_LEVEL_ERROR, "Failed to create ZSTD decompression context");
      goto cleanup;
    }
  }
  /* Reset only the session; decompression parameters are sticky. */
  ZSTD_DCtx_reset(ctx->dctx, ZSTD_reset_session_only);

  size_t buf_size = (dst_size > 0) ? (size_t)dst_size : INITIAL_DECOMPRESS_BUF_SIZE;
  if (buf_size > maximum_size)
    buf_size = maximum_size;
  uncompressed_data = data_create_empty(buf_size);
  if (!uncompressed_data) {
    log_message(LOG_LEVEL_ERROR, "Failed to allocate decompression buffer");
    goto cleanup;
  }

  ZSTD_inBuffer input = {compressed_data->data, compressed_data->size, 0};
  ZSTD_outBuffer output = {uncompressed_data->data, buf_size, 0};

  size_t ret;
  do {
    ret = ZSTD_decompressStream(ctx->dctx, &output, &input);
    if (ZSTD_isError(ret)) {
      log_message(LOG_LEVEL_ERROR, "Decompression failed: %s", ZSTD_getErrorName(ret));
      data_destroy(uncompressed_data);
      uncompressed_data = NULL;
      goto cleanup;
    }
    if (ret > 0 && output.pos == output.size) {
      if (buf_size >= hard_limit || buf_size > SIZE_MAX / 2) {
        log_message(LOG_LEVEL_ERROR, "Decompressed data exceeds %llu bytes",
                    (unsigned long long)MAX_DECOMPRESSED_SIZE);
        data_destroy(uncompressed_data);
        uncompressed_data = NULL;
        goto cleanup;
      }
      buf_size *= 2;
      if (buf_size > hard_limit)
        buf_size = (size_t)hard_limit;
      void* new_data = protocol_realloc(uncompressed_data->data, buf_size);
      if (!new_data) {
        log_message(LOG_LEVEL_ERROR, "Failed to grow decompression buffer");
        data_destroy(uncompressed_data);
        uncompressed_data = NULL;
        goto cleanup;
      }
      uncompressed_data->data = new_data;
      output.dst = new_data;
      output.size = buf_size;
      /* Re-attempt with the larger output buffer; the truncated-frame check
       * below must not reject a complete frame that merely filled the previous
       * buffer exactly. */
      continue;
    }
    /* A positive hint with all input consumed means the frame is incomplete: a
     * truncated stream would otherwise spin here forever (ZSTD_decompressStream
     * keeps returning the same hint).  Fail instead of burning CPU. */
    if (ret != 0 && input.pos == input.size) {
      log_message(LOG_LEVEL_ERROR,
                  "Truncated zstd frame: input exhausted with %zu bytes still expected", ret);
      data_destroy(uncompressed_data);
      uncompressed_data = NULL;
      goto cleanup;
    }
  } while (ret > 0);

  uncompressed_data->size = output.pos;

  log_debug_message(LOG_DEBUG_UTIL, "Decompressed data successfully");

cleanup:
  compression_ctx_put(ctx);
  return uncompressed_data;
}

Data* data_decompress(Data* compressed_data) {
  return data_decompress_limited(compressed_data, MAX_DECOMPRESSED_SIZE);
}
