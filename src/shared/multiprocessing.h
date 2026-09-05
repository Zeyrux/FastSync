#ifndef MULTIPROCESSING_H
#define MULTIPROCESSING_H

#include <threads.h>
#include <stdatomic.h>

#include "array_list.h"
#include "config.h"
#include "file.h"
#include "protocol.h"
#include "queue.h"
#include "receiver.h"
#include <openssl/ssl.h>

typedef struct {
  Config* config;
  Queue* queue_scanner;
  mtx_t mutex_scanner;
  cnd_t condition_not_full_scanner;
  cnd_t condition_not_empty_scanner;
  bool scanner_done;
  Queue* queue_loader;
  mtx_t mutex_loader;
  cnd_t condition_not_full_loader;
  cnd_t condition_not_empty_loader;
  bool loader_done;
  ArrayList* manifest;
  ArrayList* remove_source_files;
  mtx_t mutex_progress;
  int total_files;
  unsigned long long progress_bytes;
  unsigned long long total_bytes;
  bool sender_done;
  atomic_bool cancelled;
  ProtocolSession allocation_session;
} PipelineContextSender;

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
} PipelineContextReceiver;

PipelineContextSender* pipeline_context_sender_create(Config* config, Queue* queue_scanner,
                                                      Queue* queue_loader);
void pipeline_context_sender_destroy(PipelineContextSender* context);
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
