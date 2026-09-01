#ifndef CLIENT_SEND_H
#define CLIENT_SEND_H

#include "chunk.h"
#include "config.h"
#include "transport_tcp.h"

int send_chunk(Client* client, Chunk* chunk, Config* config);
int send_files(Config* config);
/* Takes ownership only when *config is set to NULL on return. */
int send_files_multithreaded(Config** config);

#endif
