#ifndef COMPRESSION_H
#define COMPRESSION_H

#include "data.h"
#include <stdbool.h>

#define COMPRESSION_MAX_THREADS 64

Data* data_compress(Data* data_to_compress, int compression_level);
Data* data_compress_with_threads(Data* data_to_compress, int compression_level,
                                 int compression_threads);
Data* data_decompress(Data* compressed_data);
Data* data_decompress_limited(Data* compressed_data, size_t maximum_size);
bool compression_should_skip_with_suffixes(const char* path, char* const* suffixes, int count);

/* Release the calling thread's cached zstd contexts (compressor, decompressor
 * and scratch buffer).  The cache is thread-local and is also released
 * automatically when a worker thread exits (via a C11 tss destructor) and for
 * the main thread at process exit; this explicit entry point exists so tests
 * and long-lived callers can drop the cache deterministically.  Safe to call
 * when no context has been created, and idempotent. */
void compression_free_thread_contexts(void);

#endif
