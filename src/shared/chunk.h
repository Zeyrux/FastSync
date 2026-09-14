#ifndef CHUNK_H
#define CHUNK_H

#include "config.h"
#include "data.h"
#include "file.h"
#include <stdbool.h>
#include <sys/stat.h>

#define DESIRED_CHUNK_SIZE (10 * 1024 * 1024)

typedef struct {
  File** items;
  int element_count;
} Chunk;

Chunk* chunk_create(File** items, int element_count);
void chunk_destroy(void* chunk);
Data* chunk_serialize(Chunk* chunk, bool use_metadata);
Chunk* chunk_deserialize(Data* data, bool use_metadata);
Data* chunk_compress(Chunk* chunk, int compression_level, bool use_metadata);
Data* chunk_compress_with_threads(Chunk* chunk, int compression_level, bool use_metadata,
                                  int compression_threads);
Chunk* receive_chunk_data(int fd, const Config* config);

/* Charge `charge` retained bytes of `data` against `session`'s per-connection
 * budget (MAX_CONNECTION_MEMORY), mirroring the protocol layer's accounting, and
 * record them on `data` so data_destroy() returns the charge through the
 * Data.owner path.  Returns false (leaving `data` uncharged) when the ceiling
 * would be exceeded.  A NULL/zero-size charge or a NULL session is a no-op
 * success.  The receive-side decompression and chunk-copy paths know the owning
 * session only through the Data.owner of the buffer they are processing, so
 * this is the entry point that lets them participate in the connection budget
 * without a session handle (B6). */
bool data_charge_session(Data* data, ProtocolSession* session, size_t charge);

#endif
