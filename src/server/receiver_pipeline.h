#ifndef RECEIVER_PIPELINE_H
#define RECEIVER_PIPELINE_H

#include <stdatomic.h>
#include <stdbool.h>
#include <threads.h>

#include "config.h"
#include "file.h"
#include "file_receive.h"
#include "protocol.h"
#include "queue.h"
#include "receiver.h"
#include <openssl/ssl.h>

typedef struct PipelineContextReceiver {
  Queue* queue;
  Config* config;
  int file_descriptor;
  SSL* ssl;
  ProtocolSession session;
  ReceiverOutcomes outcomes;
  mtx_t mutex;
  cnd_t condition_not_full;
  cnd_t condition_not_empty;
  bool receiver_done;
  atomic_bool cancelled;
  /* Aggregate payload bytes that have been received but not yet released by
     the disk writer (queued or in the writer's hand).  Guarded by `mutex`.
     When `max_queue_bytes` is non-zero the receiver blocks before enqueuing
     once this total would exceed it, so decompressed/copied file payloads
     buffered ahead of a slow disk writer respect the per-connection memory
     budget instead of growing without bound. */
  size_t queued_bytes;
  size_t max_queue_bytes;
  /* Keep-set manifest for the commit-style (late) deletion
     (--delete/--delete-after/--delete-delay).  receive_thread parses the whole
     protocol stream but hands the manifest here instead of deleting while the
     disk writer may still be draining; the caller (server.c) commits the
     deletion after both threads have joined, so no extra is removed unless the
     transfer truly succeeded.  NULL in the early delete modes (which delete at
     the manifest). */
  DeleteManifest* deferred_manifest;
  /* Per-directory delete session for --delete-delay: receive_thread snapshots
     each plan's extras as it arrives and hands the session here instead of
     committing while the disk writer may still be draining; server.c commits it
     after both threads joined.  NULL for every other timing. */
  DeletePlanSession* deferred_plans;
  /* Set by server.c when the deferred delete commit hit the --max-delete
     budget; the terminal success frame then carries STATUS_DELETE_LIMIT
     (rsync exit 25) while the transfer itself still succeeds. */
  bool delete_limit_reached;
  /* P7 Wave D: directory metadata collected by write_thread from received
     directory entries.  Only write_thread mutates it (before it joins); the
     caller (server.c) applies it after the delete/delay-updates phase. */
  DirTimeList dir_times;
  /* End-of-transfer wire counters (protocol 2.25.0).  receive_thread accumulates
     matched_data under `mutex`; server.c adds the delete-commit tallies after
     both threads join and emits the STATUS_STATS frame. */
  ReceiverStats stats;
  /* -n/--dry-run --delete would-delete path list, collected by receive_thread
     and reported in the STATUS_STATS frame. */
  struct ArrayList* would_delete;
} PipelineContextReceiver;

PipelineContextReceiver* pipeline_context_receiver_create(Config* config, Queue* queue_receiver,
                                                          int file_descriptor, SSL* ssl);
void pipeline_context_receiver_destroy(PipelineContextReceiver* context);
/* Bound the bytes buffered ahead of the disk writer (see max_queue_bytes). */
void pipeline_context_receiver_set_queue_byte_limit(PipelineContextReceiver* context,
                                                    size_t max_bytes);
/* Blocking enqueue used by the receive pipeline sink.  Blocks while the queue
   is full by element count or when adding `file` would push queued_bytes over
   the configured byte limit; waits until the disk writer releases bytes.
   Takes ownership of `file` on success and destroys it on failure/cancel. */
bool pipeline_context_receiver_enqueue_file(PipelineContextReceiver* context, File* file);
/* Account for `released_bytes` of payload memory that has been freed by the
   disk writer, unblocking a receiver that is waiting on the byte limit. */
void pipeline_context_receiver_note_bytes_released(PipelineContextReceiver* context,
                                                   size_t released_bytes);
int receive_thread(void* pipeline_context);
int write_thread(void* pipeline_context);

#endif
