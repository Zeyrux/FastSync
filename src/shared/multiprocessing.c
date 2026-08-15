#include "multiprocessing.h"
#include "receiver.h"

#include "array_list.h"
#include "chunk.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "protocol.h"
#include "queue.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

PipelineContextSender* pipeline_context_sender_create(Config* config, Queue* queue_scanner,
                                                      Queue* queue_loader) {
  PipelineContextSender* context = malloc(sizeof(PipelineContextSender));
  if (context == NULL)
    return NULL;
  context->config = config;
  context->queue_scanner = queue_scanner;
  context->queue_loader = queue_loader;
  context->scanner_done = false;
  context->loader_done = false;
  context->manifest = NULL;
  context->progress_bytes = 0;
  context->sender_done = false;
  atomic_init(&context->cancelled, false);
  int init = 0;
  if (mtx_init(&context->mutex_scanner, mtx_plain) != thrd_success)
    goto fail;
  init++;
  if (cnd_init(&context->condition_not_full_scanner) != thrd_success)
    goto fail;
  init++;
  if (cnd_init(&context->condition_not_empty_scanner) != thrd_success)
    goto fail;
  init++;
  if (mtx_init(&context->mutex_loader, mtx_plain) != thrd_success)
    goto fail;
  init++;
  if (cnd_init(&context->condition_not_full_loader) != thrd_success)
    goto fail;
  init++;
  if (cnd_init(&context->condition_not_empty_loader) != thrd_success)
    goto fail;
  init++;
  if (mtx_init(&context->mutex_progress, mtx_plain) != thrd_success)
    goto fail;
  // cppcheck-suppress unreadVariable
  init++;
  return context;

fail:
  perror("Error initializing synchronization objects");
  if (init >= 6)
    cnd_destroy(&context->condition_not_empty_loader);
  if (init >= 5)
    cnd_destroy(&context->condition_not_full_loader);
  if (init >= 4)
    mtx_destroy(&context->mutex_loader);
  if (init >= 3)
    cnd_destroy(&context->condition_not_empty_scanner);
  if (init >= 2)
    cnd_destroy(&context->condition_not_full_scanner);
  if (init >= 1)
    mtx_destroy(&context->mutex_scanner);
  free(context);
  return NULL;
}

void pipeline_context_sender_destroy(PipelineContextSender* context) {
  if (context->manifest) {
    array_list_delete(context->manifest);
  }
  config_delete(context->config);
  queue_destroy(context->queue_scanner);
  queue_destroy(context->queue_loader);
  mtx_destroy(&context->mutex_scanner);
  cnd_destroy(&context->condition_not_full_scanner);
  cnd_destroy(&context->condition_not_empty_scanner);
  mtx_destroy(&context->mutex_loader);
  cnd_destroy(&context->condition_not_full_loader);
  cnd_destroy(&context->condition_not_empty_loader);
  mtx_destroy(&context->mutex_progress);
  free(context);
}

PipelineContextReceiver* pipeline_context_receiver_create(Config* config, Queue* queue,
                                                          int file_descriptor, SSL* ssl) {
  PipelineContextReceiver* context = malloc(sizeof(PipelineContextReceiver));
  if (context == NULL)
    return NULL;
  context->config = config;
  context->queue = queue;
  context->file_descriptor = file_descriptor;
  context->ssl = ssl;
  protocol_session_init(&context->session, file_descriptor, file_descriptor);
  protocol_session_set_ssl(&context->session, ssl);
  context->receiver_done = false;
  atomic_init(&context->cancelled, false);
  int init = 0;
  if (mtx_init(&context->mutex, mtx_plain) != thrd_success)
    goto fail;
  init++;
  if (cnd_init(&context->condition_not_full) != thrd_success)
    goto fail;
  init++;
  if (cnd_init(&context->condition_not_empty) != thrd_success)
    goto fail;
  // cppcheck-suppress unreadVariable
  init++;
  return context;

fail:
  perror("Error initializing synchronization objects");
  if (init >= 3)
    cnd_destroy(&context->condition_not_empty);
  if (init >= 2)
    cnd_destroy(&context->condition_not_full);
  if (init >= 1)
    mtx_destroy(&context->mutex);
  free(context);
  return NULL;
}

void pipeline_context_receiver_destroy(PipelineContextReceiver* context) {
  config_delete(context->config);
  queue_destroy(context->queue);
  mtx_destroy(&context->mutex);
  cnd_destroy(&context->condition_not_full);
  cnd_destroy(&context->condition_not_empty);
  free(context);
}

static bool receiver_enqueue_file(File* file, void* context_pointer) {
  PipelineContextReceiver* context = context_pointer;
  if (queue_enqueue_multithreaded_cancel(context->queue, file, &context->mutex,
                                         &context->condition_not_empty,
                                         &context->condition_not_full, &context->cancelled))
    return true;
  file_destroy(file);
  return false;
}

static void receiver_thread_fail(PipelineContextReceiver* context) {
  mtx_lock(&context->mutex);
  atomic_store(&context->cancelled, true);
  context->receiver_done = true;
  cnd_broadcast(&context->condition_not_empty);
  cnd_broadcast(&context->condition_not_full);
  mtx_unlock(&context->mutex);
}

int receive_thread(void* pipeline_context) {
  PipelineContextReceiver* context = (PipelineContextReceiver*)pipeline_context;
  protocol_session_bind(&context->session);
  mtx_lock(&context->mutex);
  int file_descriptor = context->file_descriptor;
  const Config* config = context->config;
  mtx_unlock(&context->mutex);

  ReceiverSink sink = {receiver_enqueue_file, context, false, false};
  if (receiver_process((Config*)config, file_descriptor, &sink) != 0) {
    receiver_thread_fail(context);
    protocol_session_unbind();
    return thrd_error;
  }
  mtx_lock(&context->mutex);
  context->receiver_done = true;
  cnd_signal(&context->condition_not_empty);
  mtx_unlock(&context->mutex);
  protocol_session_unbind();
  return thrd_success;
}

int write_thread(void* pipeline_context) {
  PipelineContextReceiver* context = (PipelineContextReceiver*)pipeline_context;
  mtx_lock(&context->mutex);
  bool save_to_disk = context->config->save_to_disk;
  char* root_directory = str_dup(context->config->receive_root_directory);
  mtx_unlock(&context->mutex);

  while (true) {
    File* file =
        queue_dequeue_multithreaded(context->queue, &context->mutex, &context->condition_not_empty,
                                    &context->condition_not_full, &context->receiver_done);
    if (file == NULL) {
      free(root_directory);
      return thrd_success;
    }
    if (save_to_disk && !file_save_to_disk(root_directory, file, context->config)) {
      file_destroy(file);
      mtx_lock(&context->mutex);
      atomic_store(&context->cancelled, true);
      context->receiver_done = true;
      cnd_broadcast(&context->condition_not_full);
      cnd_broadcast(&context->condition_not_empty);
      mtx_unlock(&context->mutex);
      free(root_directory);
      return thrd_error;
    }
    file_destroy(file);
  }
}
