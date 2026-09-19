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

/* Release the calling thread's cached zstd contexts (compressor, decompressor
 * and scratch buffer).  The cache is thread-local and is also released
 * automatically when a worker thread exits (via a C11 tss destructor) and for
 * the main thread at process exit; this explicit entry point exists so tests
 * and long-lived callers can drop the cache deterministically.  Safe to call
 * when no context has been created, and idempotent. */
void compression_free_thread_contexts(void);

#endif
