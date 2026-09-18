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
  /* Session whose budget `protocol_charge` was reserved from.  When non-NULL,
   * the charge is returned to this session directly, regardless of which
   * session (if any) is bound to the destroying thread.  owner is not
   * guaranteed to be set whenever protocol_charge is non-zero: it is NULL for
   * uncharged Data and for Data that has no recorded owner, in which case any
   * charge falls back to the session bound at destroy time.
   *
   * Lifetime contract: a Data with a non-NULL owner must not outlive that
   * ProtocolSession -- data_destroy dereferences owner to return the charge. */
  ProtocolSession* owner;
} Data;

Data* data_create_empty(size_t data_size);
Data* data_create_reserve(size_t size);
Data* data_create(void* data, size_t data_size);
void data_destroy(Data* data);
void protocol_release_memory(size_t charge);
/* Release `charge` against `session` directly instead of the thread-local bound
 * session.  Used by data_destroy to honor Data.owner; `session` must outlive
 * the Data whose charge is being returned.  A NULL session is a no-op. */
void protocol_release_memory_for_session(ProtocolSession* session, size_t charge);

#endif
