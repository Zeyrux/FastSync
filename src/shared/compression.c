#include "compression.h"
#include "data.h"
#include "log.h"
#include "protocol.h"
#include <limits.h>
#include <lz4.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <threads.h>
#include <unistd.h>
#include <zlib.h>
#include <zstd.h>

#define INITIAL_DECOMPRESS_BUF_SIZE (1024 * 1024)
#define MAX_DECOMPRESSED_SIZE (100ULL * 1024 * 1024) /* 100 MB hard ceiling */

/* rsync 3.4.1's built-in skip-compress suffix list (the `--skip-compress`
 * defaults, in the man page's order).  rsync stores it as space-separated
 * "*.suffix" globs; FastSync matches the plain suffix after the final dot, so
 * the leading "*." is omitted here.  A user --skip-compress list replaces this
 * default entirely (matching rsync). */
#define DEFAULT_SKIP_COMPRESS_SUFFIXES                                                             \
  "3g2 3gp 7z aac ace apk avi bz2 deb dmg ear f4v flac flv gpg gz iso jar jpeg jpg lrz lz lz4 "    \
  "lzma "                                                                                          \
  "lzo m1a m1v m2a m2ts m2v m4a m4b m4p m4r m4v mka mkv mov mp1 mp2 mp3 mp4 mpa mpeg mpg mpv mts " \
  "odb odf odg odi odm odp ods odt oga ogg ogm ogv ogx opus otg oth otp ots ott oxt png qt rar "   \
  "rpm "                                                                                           \
  "rz rzip spx squashfs sxc sxd sxg sxm sxw sz tbz tbz2 tgz tlz ts txz tzo vob war webm webp xz "  \
  "z "                                                                                             \
  "zip zst"

/* Self-describing compressed frames: the first byte is the CompressionAlgo id.
 * zlib/lz4 store the uncompressed size as a little-endian uint32 after the
 * codec byte so decompression can be exactly pre-sized and bounded. */
#define LZ4_SIZE_PREFIX_LEN 4

static _Atomic int g_compression_algo = COMPRESSION_ALGO_ZSTD;

/* Case-insensitive match of a bare suffix (no leading dot) against a
 * space-separated suffix list. */
static bool suffix_in_list(const char* name, const char* list) {
  size_t name_len = strlen(name);
  while (*list) {
    while (*list == ' ')
      list++;
    const char* start = list;
    while (*list && *list != ' ')
      list++;
    size_t len = (size_t)(list - start);
    if (len == name_len && strncasecmp(name, start, len) == 0)
      return true;
  }
  return false;
}

bool compression_should_skip_with_suffixes(const char* path, char* const* suffixes, int count) {
  if (!path)
    return false;
  const char* dot = strrchr(path, '.');
  if (!dot || dot[1] == '\0')
    return false;
  const char* name = dot + 1;
  /* count < 0 (the user gave no --skip-compress) selects rsync's built-in
   * default list; a non-negative count is the user's explicit list. */
  if (count < 0)
    return suffix_in_list(name, DEFAULT_SKIP_COMPRESS_SUFFIXES);
  for (int i = 0; i < count; i++) {
    const char* suffix = suffixes[i];
    if (suffix[0] == '.')
      suffix++;
    if (strcasecmp(name, suffix) == 0)
      return true;
  }
  return false;
}

CompressionAlgo compression_default_algo(void) {
  return COMPRESSION_ALGO_ZSTD;
}

int compression_algo_from_name(const char* name) {
  if (!name)
    return -1;
  if (strcasecmp(name, "zstd") == 0)
    return (int)COMPRESSION_ALGO_ZSTD;
  if (strcasecmp(name, "lz4") == 0)
    return (int)COMPRESSION_ALGO_LZ4;
  if (strcasecmp(name, "zlib") == 0)
    return (int)COMPRESSION_ALGO_ZLIB;
  if (strcasecmp(name, "zlibx") == 0)
    return (int)COMPRESSION_ALGO_ZLIBX;
  if (strcasecmp(name, "none") == 0)
    return (int)COMPRESSION_ALGO_NONE;
  return -1;
}

const char* compression_algo_name(CompressionAlgo algo) {
  switch (algo) {
  case COMPRESSION_ALGO_NONE:
    return "none";
  case COMPRESSION_ALGO_ZSTD:
    return "zstd";
  case COMPRESSION_ALGO_LZ4:
    return "lz4";
  case COMPRESSION_ALGO_ZLIB:
    return "zlib";
  case COMPRESSION_ALGO_ZLIBX:
    return "zlibx";
  }
  return "<unknown>";
}

bool compression_algo_valid(int algo) {
  return algo == (int)COMPRESSION_ALGO_NONE || algo == (int)COMPRESSION_ALGO_ZSTD ||
         algo == (int)COMPRESSION_ALGO_LZ4 || algo == (int)COMPRESSION_ALGO_ZLIB ||
         algo == (int)COMPRESSION_ALGO_ZLIBX;
}

bool compression_algo_enabled(CompressionAlgo algo) {
  return algo != COMPRESSION_ALGO_NONE;
}

CompressionAlgo compression_negotiate_default(void) {
  /* rsync 3.4.1 default preference order; every entry is compiled in, so this
   * resolves to zstd. */
  static const CompressionAlgo preference[] = {
      COMPRESSION_ALGO_ZSTD, COMPRESSION_ALGO_LZ4,  COMPRESSION_ALGO_ZLIBX,
      COMPRESSION_ALGO_ZLIB, COMPRESSION_ALGO_NONE,
  };
  for (size_t i = 0; i < sizeof(preference) / sizeof(preference[0]); i++) {
    if (compression_algo_valid((int)preference[i]))
      return preference[i];
  }
  return COMPRESSION_ALGO_ZSTD;
}

void compression_set_algo(CompressionAlgo algo) {
  if (compression_algo_valid((int)algo))
    atomic_store(&g_compression_algo, (int)algo);
}

CompressionAlgo compression_get_algo(void) {
  return (CompressionAlgo)atomic_load(&g_compression_algo);
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

/* Build a frame consisting of a copy of `src` prefixed by `codec`. */
static Data* frame_with_codec(const void* src, size_t size, CompressionAlgo codec) {
  if (size > SIZE_MAX - 1)
    return NULL;
  Data* out = data_create_empty(size + 1);
  if (!out)
    return NULL;
  ((uint8_t*)out->data)[0] = (uint8_t)codec;
  if (size > 0)
    memcpy((uint8_t*)out->data + 1, src, size);
  out->size = size + 1;
  return out;
}

static Data* zstd_compress(Data* in, int compression_level, int compression_threads) {
  size_t dst_size = ZSTD_compressBound(in->size);
  if (dst_size > SIZE_MAX - 1)
    return NULL;
  dst_size += 1; /* codec prefix */

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
    size_t zret = ZSTD_CCtx_setPledgedSrcSize(ctx->cctx, in->size);
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

  ZSTD_inBuffer input = {in->data, in->size, 0};
  ZSTD_outBuffer output = {(uint8_t*)ctx->out_buf + 1, dst_size - 1, 0};

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
  compressed_data = data_create_empty(output.pos + 1);
  if (compressed_data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to allocate compressed data");
    goto cleanup;
  }
  ((uint8_t*)compressed_data->data)[0] = (uint8_t)COMPRESSION_ALGO_ZSTD;
  if (output.pos > 0)
    memcpy((uint8_t*)compressed_data->data + 1, (uint8_t*)ctx->out_buf + 1, output.pos);
  compressed_data->size = output.pos + 1;

  log_debug_message(LOG_DEBUG_UTIL, "Data succesfully compressed from %zu to %zu", in->size,
                    compressed_data->size);

cleanup:
  compression_ctx_put(ctx);
  return compressed_data;
}

static Data* lz4_compress(Data* in) {
  int bound = LZ4_compressBound((int)in->size);
  if (bound < 0 || in->size > (size_t)INT_MAX)
    return NULL;
  Data* out = data_create_empty((size_t)bound + 1 + LZ4_SIZE_PREFIX_LEN);
  if (!out)
    return NULL;
  uint32_t raw_size = (uint32_t)in->size;
  uint8_t* p = (uint8_t*)out->data;
  p[0] = (uint8_t)COMPRESSION_ALGO_LZ4;
  for (int i = 0; i < LZ4_SIZE_PREFIX_LEN; i++)
    p[1 + i] = (uint8_t)((raw_size >> (8 * i)) & 0xff);
  int written = 0;
  if (in->size > 0) {
    written = LZ4_compress_default((const char*)in->data, (char*)p + 1 + LZ4_SIZE_PREFIX_LEN,
                                   (int)in->size, bound);
    if (written <= 0) {
      data_destroy(out);
      return NULL;
    }
  }
  out->size = (size_t)written + 1 + LZ4_SIZE_PREFIX_LEN;
  return out;
}

static Data* zlib_compress(Data* in, CompressionAlgo algo, int compression_level) {
  int level = compression_level;
  if (level < 1)
    level = Z_DEFAULT_COMPRESSION;
  if (level > 9)
    level = 9;
  uLong bound = compressBound((uLong)in->size);
  if (in->size > (size_t)ULONG_MAX)
    return NULL;
  Data* out = data_create_empty((size_t)bound + 1 + LZ4_SIZE_PREFIX_LEN);
  if (!out)
    return NULL;
  uint32_t raw_size = (uint32_t)in->size;
  uint8_t* p = (uint8_t*)out->data;
  p[0] = (uint8_t)algo;
  for (int i = 0; i < LZ4_SIZE_PREFIX_LEN; i++)
    p[1 + i] = (uint8_t)((raw_size >> (8 * i)) & 0xff);
  uLongf dest_len = bound;
  int rc = compress2(p + 1 + LZ4_SIZE_PREFIX_LEN, &dest_len, (const Bytef*)in->data,
                     (uLong)in->size, level);
  if (rc != Z_OK) {
    data_destroy(out);
    return NULL;
  }
  out->size = (size_t)dest_len + 1 + LZ4_SIZE_PREFIX_LEN;
  return out;
}

Data* data_compress_codec(Data* data_to_compress, CompressionAlgo algo, int compression_level,
                          int compression_threads) {
  if (!data_to_compress || (!data_to_compress->data && data_to_compress->size != 0) ||
      compression_threads < 0 || compression_threads > COMPRESSION_MAX_THREADS)
    return NULL;
  if (!compression_algo_valid((int)algo))
    return NULL;
  log_message(LOG_LEVEL_DEBUG, "Starting to compress data");
  switch (algo) {
  case COMPRESSION_ALGO_NONE:
    return frame_with_codec(data_to_compress->data, data_to_compress->size, COMPRESSION_ALGO_NONE);
  case COMPRESSION_ALGO_ZSTD:
    return zstd_compress(data_to_compress, compression_level, compression_threads);
  case COMPRESSION_ALGO_LZ4:
    return lz4_compress(data_to_compress);
  case COMPRESSION_ALGO_ZLIB:
  case COMPRESSION_ALGO_ZLIBX:
    return zlib_compress(data_to_compress, algo, compression_level);
  }
  return NULL;
}

Data* data_compress_with_threads(Data* data_to_compress, int compression_level,
                                 int compression_threads) {
  return data_compress_codec(data_to_compress, compression_get_algo(), compression_level,
                             compression_threads);
}

Data* data_compress(Data* data_to_compress, int compression_level) {
  return data_compress_codec(data_to_compress, compression_get_algo(), compression_level, 0);
}

static Data* decompress_none(const Data* compressed_data, size_t maximum_size) {
  size_t size = compressed_data->size - 1;
  if (size > maximum_size)
    return NULL;
  Data* out = data_create_empty(size);
  if (!out)
    return NULL;
  if (size > 0)
    memcpy(out->data, (const uint8_t*)compressed_data->data + 1, size);
  out->size = size;
  return out;
}

/* Read the 4-byte little-endian raw size stored after the codec byte. */
static bool read_raw_size(const Data* in, uint32_t* raw_size) {
  if (in->size < 1 + LZ4_SIZE_PREFIX_LEN)
    return false;
  const uint8_t* p = (const uint8_t*)in->data;
  uint32_t v = 0;
  for (int i = 0; i < LZ4_SIZE_PREFIX_LEN; i++)
    v |= (uint32_t)p[1 + i] << (8 * i);
  *raw_size = v;
  return true;
}

static Data* lz4_decompress(Data* compressed_data, size_t maximum_size, size_t hard_limit) {
  uint32_t raw_size = 0;
  if (!read_raw_size(compressed_data, &raw_size))
    return NULL;
  if (raw_size > hard_limit || raw_size > maximum_size)
    return NULL;
  size_t comp_size = compressed_data->size - 1 - LZ4_SIZE_PREFIX_LEN;
  Data* out = data_create_empty(raw_size);
  if (!out)
    return NULL;
  if (raw_size == 0) {
    out->size = 0;
    return out;
  }
  int rc = LZ4_decompress_safe((const char*)compressed_data->data + 1 + LZ4_SIZE_PREFIX_LEN,
                               (char*)out->data, (int)comp_size, (int)raw_size);
  if (rc < 0 || (uint32_t)rc != raw_size) {
    log_message(LOG_LEVEL_ERROR, "LZ4 decompression failed");
    data_destroy(out);
    return NULL;
  }
  out->size = raw_size;
  return out;
}

static Data* zlib_decompress(Data* compressed_data, size_t maximum_size, size_t hard_limit) {
  uint32_t raw_size = 0;
  if (!read_raw_size(compressed_data, &raw_size))
    return NULL;
  if (raw_size > hard_limit || raw_size > maximum_size)
    return NULL;
  size_t comp_size = compressed_data->size - 1 - LZ4_SIZE_PREFIX_LEN;
  Data* out = data_create_empty(raw_size);
  if (!out)
    return NULL;
  if (raw_size == 0) {
    out->size = 0;
    return out;
  }
  uLongf dest_len = raw_size;
  int rc =
      uncompress((Bytef*)out->data, &dest_len,
                 (const Bytef*)compressed_data->data + 1 + LZ4_SIZE_PREFIX_LEN, (uLong)comp_size);
  if (rc != Z_OK || dest_len != raw_size) {
    log_message(LOG_LEVEL_ERROR, "zlib decompression failed");
    data_destroy(out);
    return NULL;
  }
  out->size = raw_size;
  return out;
}

static Data* zstd_decompress(Data* compressed_data, size_t maximum_size) {
  /* The zstd frame starts after the codec byte. */
  const void* frame = (const uint8_t*)compressed_data->data + 1;
  size_t frame_size = compressed_data->size - 1;
  log_debug_message(LOG_DEBUG_UTIL, "Start to decompress data");
  unsigned long long dst_size = ZSTD_getFrameContentSize(frame, frame_size);
  /* ZSTD_isError() is also true for ZSTD_CONTENTSIZE_ERROR and
   * ZSTD_CONTENTSIZE_UNKNOWN (both are encoded near (size_t)-1), so test the
   * sentinels explicitly instead of blanket-rejecting every error-ish value:
   * only CONTENTSIZE_ERROR means an unreadable header, while CONTENTSIZE_UNKNOWN
   * must reach the estimate fallback below. */
  if (dst_size == ZSTD_CONTENTSIZE_ERROR) {
    log_message(LOG_LEVEL_ERROR, "Failed to get decompressed size: invalid zstd frame");
    return NULL;
  }

  // ZSTD_CONTENTSIZE_UNKNOWN (~2^64) can cause massive allocation;
  // fall back to a conservative estimate (3x compressed size) when unknown.
  if (dst_size == ZSTD_CONTENTSIZE_UNKNOWN) {
    if (frame_size > ULLONG_MAX / 3)
      return NULL;
    dst_size = frame_size * 3;
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

  ZSTD_inBuffer input = {frame, frame_size, 0};
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

Data* data_decompress_limited(Data* compressed_data, size_t maximum_size) {
  if (!compressed_data || (!compressed_data->data && compressed_data->size != 0) ||
      maximum_size == 0)
    return NULL;
  if (compressed_data->size < 1)
    return NULL;
  unsigned long long hard_limit =
      maximum_size < MAX_DECOMPRESSED_SIZE ? maximum_size : MAX_DECOMPRESSED_SIZE;
  uint8_t codec = ((const uint8_t*)compressed_data->data)[0];
  if (!compression_algo_valid(codec))
    return NULL;
  switch ((CompressionAlgo)codec) {
  case COMPRESSION_ALGO_NONE:
    return decompress_none(compressed_data, (size_t)hard_limit);
  case COMPRESSION_ALGO_ZSTD:
    return zstd_decompress(compressed_data, (size_t)hard_limit);
  case COMPRESSION_ALGO_LZ4:
    return lz4_decompress(compressed_data, maximum_size, (size_t)hard_limit);
  case COMPRESSION_ALGO_ZLIB:
  case COMPRESSION_ALGO_ZLIBX:
    return zlib_decompress(compressed_data, maximum_size, (size_t)hard_limit);
  }
  return NULL;
}

Data* data_decompress(Data* compressed_data) {
  return data_decompress_limited(compressed_data, MAX_DECOMPRESSED_SIZE);
}
