#ifndef CLIENT_SEND_H
#define CLIENT_SEND_H

#include "chunk.h"
#include "config.h"
#include "transport_tcp.h"

extern char *server_host;
extern int server_port;

int send_chunk(Client *client, Chunk *chunk, Config *config);
int send_files(Config *config);
int send_files_multithreaded(Config *config);

#endif
