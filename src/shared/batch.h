#ifndef BATCH_H
#define BATCH_H
#include "chunk.h"
#include "config.h"

/* Phase 6 residual-batch codec.  A residual batch is a self-contained
 * single-file record of a whole source tree: a magic+format-version header
 * followed by length-prefixed chunk blobs (each built with chunk_serialize),
 * byte-identical by construction.  The batch is a client-only driver feature:
 * it never crosses the wire, so there is no PROTOCOL_VERSION bump and no server
 * change. */

#define BATCH_MAGIC "FSTRESBATCH"
#define BATCH_MAGIC_LEN 11
#define BATCH_FORMAT_VERSION 1
/* A single deserialized record is bounded by the chunk codec's 64 MB cap
 * (the same per-file data cap chunk_deserialize enforces). */
#define BATCH_MAX_RECORD (64ULL * 1024 * 1024)

bool batch_write_header(int fd, const Config* config);
bool batch_write_chunk(int fd, Chunk* chunk);
int batch_read_apply(int fd, const Config* config, const char* dest_root);

#endif