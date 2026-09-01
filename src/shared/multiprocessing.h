#ifndef MULTIPROCESSING_H
#define MULTIPROCESSING_H

#include <threads.h>
#include <stdatomic.h>

#include "array_list.h"
#include "config.h"
#include "file.h"
#include "protocol.h"
#include "queue.h"
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
  mtx_t mutex_progress;
  unsigned long long progress_bytes;
  bool sender_done;
  atomic_bool cancelled;
} PipelineContextSender;

typedef struct PipelineContextReceiver {
  Queue* queue;
  Config* config;
  int file_descriptor;
  SSL* ssl;
  mtx_t mutex;
  cnd_t condition_not_full;
  cnd_t condition_not_empty;
  bool receiver_done;
  atomic_bool cancelled;
} PipelineContextReceiver;

typedef bool (*ReceivedFileHandler)(File* file, void* context);

int receive_files_common(const Config* config, int file_descriptor, ReceivedFileHandler handler,
                         void* context, bool send_completion_status);

PipelineContextSender* pipeline_context_sender_create(Config* config, Queue* queue_scanner,
                                                      Queue* queue_loader);
void pipeline_context_sender_destroy(PipelineContextSender* context);
PipelineContextReceiver* pipeline_context_receiver_create(Config* config, Queue* queue_receiver,
                                                          int file_descriptor, SSL* ssl);
void pipeline_context_receiver_destroy(PipelineContextReceiver* context);
int receive_thread(void* pipeline_context);
int write_thread(void* pipeline_context);
#endif
