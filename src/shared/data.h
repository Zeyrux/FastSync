#ifndef DATA_H
#define DATA_H

#include <stdlib.h>

/* Forward declaration for the connection budget a received Data is charged
 * against; defined in protocol.h (which includes this header). */
typedef struct ProtocolSession ProtocolSession;

typedef struct {
  void* data;
  size_t size;
  /* Non-zero only for a buffer charged to the protocol connection budget. */
  size_t protocol_charge;
  /* Session whose budget `protocol_charge` was reserved from.  The charge must
   * always be returned to this session, regardless of which session (if any) is
   * bound to the destroying thread.  NULL for uncharged Data. */
  ProtocolSession* owner;
} Data;

Data* data_create_empty(size_t data_size);
Data* data_create_reserve(size_t size);
Data* data_create(void* data, size_t data_size);
void data_destroy(Data* data);
void protocol_release_memory(size_t charge);
/* Release `charge` against `session` directly instead of the thread-local bound
 * session.  Used by data_destroy to honor Data.owner. */
void protocol_release_memory_for_session(ProtocolSession* session, size_t charge);

#endif
