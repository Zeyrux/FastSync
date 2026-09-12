#ifndef CLIENT_SEND_H
#define CLIENT_SEND_H

#include "chunk.h"
#include "config.h"
#include "transport_tcp.h"

int send_chunk(Client* client, Chunk* chunk, Config* config);
int send_files(Config* config);
/* Takes ownership only when *config is set to NULL on return. */
int send_files_multithreaded(Config** config);
/* Phase 6 residual-batch (client-only).  See client_send.c. */
int write_batch_from_source(const Config* config, const char* batch_path);
int apply_batch_to_dest(const Config* config, const char* batch_path, const char* dest_root);

#endif
