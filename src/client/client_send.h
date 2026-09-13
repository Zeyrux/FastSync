#ifndef CLIENT_SEND_H
#define CLIENT_SEND_H

#include "chunk.h"
#include "config.h"
#include "transport_tcp.h"

/* Both sender entry points BORROW `config` for the duration of the call; they
 * never free it, and the caller retains ownership (freeing it with
 * config_delete() once the call returns). */
int send_files(Config* config);
int send_files_multithreaded(Config** config);
/* Phase 6 residual-batch (client-only).  See client_send.c. */
int write_batch_from_source(const Config* config, const char* batch_path);
int apply_batch_to_dest(const Config* config, const char* batch_path, const char* dest_root);

#endif
