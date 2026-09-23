#ifndef COMPRESSION_H
#define COMPRESSION_H

#include "data.h"
#include <stdbool.h>

#define COMPRESSION_MAX_THREADS 64

/* Compression algorithms selectable with --compress-choice / -z.  The ids are
 * the values placed on the wire (Config->compression_algo), so they must be
 * kept stable.  NONE is "no compression"; ZSTD is the historical FastSync
 * default and the negotiated "auto" choice.  ZLIBX is rsync's zlib-without-
 * matched-data variant: FastSync compresses only the delta/token bytes (it does
 * not put matched file data in the compression stream), so its zlib codec is
 * already the "x" form and zlib/zlibx share the same implementation, recorded
 * under distinct ids. */
typedef enum {
  COMPRESSION_ALGO_NONE = 0,
  COMPRESSION_ALGO_ZSTD = 1,
  COMPRESSION_ALGO_LZ4 = 2,
  COMPRESSION_ALGO_ZLIB = 3,
  COMPRESSION_ALGO_ZLIBX = 4
} CompressionAlgo;

/* Resolve a --compress-choice string (case-insensitive) to an algorithm id.
 * Accepts "zstd", "lz4", "zlib", "zlibx", "none".  "auto" is not an algorithm
 * here; the caller resolves it to the negotiated default.  Returns -1 for any
 * unrecognized name. */
int compression_algo_from_name(const char* name);
const char* compression_algo_name(CompressionAlgo algo);
bool compression_algo_valid(int algo);

/* Pick the first algorithm from FastSync's compiled-in preference list
 * (rsync 3.4.1's `--version` order: zstd lz4 zlibx zlib none).  Resolves
 * "auto". */
CompressionAlgo compression_negotiate_default(void);

/* Resolve "auto" the way rsync does: the first supported name in
 * RSYNC_COMPRESS_LIST (whitespace-separated, client half ends at '&'), then the
 * compiled-in preference order when the variable is unset/blank.  Returns -1
 * when the variable is set but names no supported codec (rsync's failed
 * negotiation), otherwise a valid CompressionAlgo id. */
int compression_choice_resolve(void);

/* rsync 3.4.1's per-codec default level, applied when the user did not pass
 * --compress-level/--zl.  zstd uses ZSTD_CLEVEL_DEFAULT (3) and zlib/zlibx the
 * resolved Z_DEFAULT_COMPRESSION (6).  lz4 has no tunable level in rsync
 * (always the default acceleration); FastSync returns a positive placeholder so
 * its "level > 0" compression gate stays engaged, and lz4_compress ignores the
 * value, so the output is identical to rsync's.  none is 0. */
int compression_default_level(CompressionAlgo algo);

/* Clamp an explicit --compress-level to the codec's accepted range the way
 * rsync's init_compression_level() does: zstd 1..22, zlib/zlibx 1..9, lz4
 * ignored (fixed positive placeholder), none 0. */
int compression_clamp_level(CompressionAlgo algo, int level);

/* True when the algorithm actually compresses (i.e. is not NONE). */
bool compression_algo_enabled(CompressionAlgo algo);

/* Select the process-wide codec used by the legacy wrappers below.  Each
 * process serves exactly one transfer config (the server forks per connection,
 * the client configures itself before spawning transfer threads), so a
 * process-global default is sufficient and constant for the lifetime of a
 * transfer.  Defaults to ZSTD when never set.  Thread-safe. */
void compression_set_algo(CompressionAlgo algo);
CompressionAlgo compression_get_algo(void);

/* Codec-aware primitives.  The compressed buffer is self-describing: its first
 * byte is the CompressionAlgo id, so decompression never needs the codec passed
 * separately (this keeps every existing Decompress call site source-compatible).
 * `data_compress_codec` returns NULL on invalid input or an unsupported codec. */
Data* data_compress_codec(Data* data_to_compress, CompressionAlgo algo, int compression_level,
                          int compression_threads);
Data* data_decompress_limited(Data* compressed_data, size_t maximum_size);

/* Legacy zstd-default wrappers retained for existing callers/tests. */
Data* data_compress(Data* data_to_compress, int compression_level);
Data* data_compress_with_threads(Data* data_to_compress, int compression_level,
                                 int compression_threads);
Data* data_decompress(Data* compressed_data);
bool compression_should_skip_with_suffixes(const char* path, char* const* suffixes, int count);

/* Streaming decompression for a payload too large to hold in memory.  The
 * caller consumes the frame's leading codec byte (and, for lz4/zlib/zlibx, the
 * 4-byte little-endian raw-size prefix) and then feeds the remaining frame
 * bytes in bounded chunks; decompressed output is written straight to `out_fd`
 * so neither the compressed nor the decompressed image is ever materialized.
 * Only zstd (the default), zlib/zlibx and none support streaming; lz4's block
 * format is one-shot, so its stream decompressor reports failure and the caller
 * falls back (the whole-buffer path keeps its existing bound). */
typedef struct CompressionStreamDecompressor CompressionStreamDecompressor;

CompressionStreamDecompressor*
compression_stream_decompressor_create(CompressionAlgo algo, unsigned long long expected_out);
/* Feed one chunk.  Returns false on a malformed frame, an I/O error, or when the
 * total output would exceed `expected_out` (when non-zero).  *done is set once
 * the frame end has been reached. */
bool compression_stream_decompressor_feed(CompressionStreamDecompressor* d, const void* in,
                                          size_t in_len, int out_fd, bool* done);
unsigned long long compression_stream_decompressor_total(const CompressionStreamDecompressor* d);
void compression_stream_decompressor_destroy(CompressionStreamDecompressor* d);

/* Peek the logical (decompressed) size from the leading bytes of a compressed
 * frame (codec byte + header), returning 0 when it cannot be determined from
 * the supplied prefix.  Used to decide whether a frame must take the streaming
 * path before its body is read. */
unsigned long long compression_peek_frame_content_size(const void* buf, size_t len);

/* Streaming compression (sender side).  Compresses a source in bounded chunks
 * into `out_fd` as one self-describing frame (codec byte, the lz4/zlib raw-size
 * prefix, then the codec stream), so a whole file can be compressed without
 * materializing it in memory.  zstd/zlib/zlibx/none are supported; lz4's block
 * format is one-shot, so its create() returns NULL and the caller keeps the
 * buffered path.  `raw_size` is the known source length (used for the zlib
 * prefix and, for zstd, the frame content-size field). */
typedef struct CompressionStreamCompressor CompressionStreamCompressor;

/* True when `algo` can be stream-compressed (zstd/zlib/zlibx; lz4's block format
 * is one-shot).  Used by the sender to decide whether an over-threshold source
 * may stay unloaded. */
bool compression_stream_compress_supported(CompressionAlgo algo);
CompressionStreamCompressor* compression_stream_compressor_create(CompressionAlgo algo, int level,
                                                                  int threads);
bool compression_stream_compressor_begin(CompressionStreamCompressor* c,
                                         unsigned long long raw_size, int out_fd);
bool compression_stream_compressor_feed(CompressionStreamCompressor* c, const void* in,
                                        size_t in_len, int out_fd);
bool compression_stream_compressor_finish(CompressionStreamCompressor* c, int out_fd);
void compression_stream_compressor_destroy(CompressionStreamCompressor* c);

/* Release the calling thread's cached zstd contexts (compressor, decompressor
 * and scratch buffer).  The cache is thread-local and is also released
 * automatically when a worker thread exits (via a C11 tss destructor) and for
 * the main thread at process exit; this explicit entry point exists so tests
 * and long-lived callers can drop the cache deterministically.  Safe to call
 * when no context has been created, and idempotent. */
void compression_free_thread_contexts(void);

#endif
