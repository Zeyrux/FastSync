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
  context->remove_source_files = NULL;
  context->total_files = 0;
  context->progress_bytes = 0;
  context->total_bytes = 0;
  context->sender_done = false;
  atomic_init(&context->cancelled, false);
  protocol_session_init(&context->allocation_session, -1, -1);
  protocol_session_set_max_alloc(&context->allocation_session, config->max_alloc);
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
  log_perror("Error initializing synchronization objects");
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
  if (context->remove_source_files)
    array_list_delete(context->remove_source_files);
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
  context->outcomes.entries = NULL;
  context->outcomes.count = 0;
  context->outcomes.capacity = 0;
  protocol_session_init(&context->session, file_descriptor, file_descriptor);
  protocol_session_set_ssl(&context->session, ssl);
  context->receiver_done = false;
  context->queued_bytes = 0;
  context->max_queue_bytes = 0;
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
  log_perror("Error initializing synchronization objects");
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
  receiver_outcomes_destroy(&context->outcomes);
  mtx_destroy(&context->mutex);
  cnd_destroy(&context->condition_not_full);
  cnd_destroy(&context->condition_not_empty);
  free(context);
}

void pipeline_context_receiver_set_queue_byte_limit(PipelineContextReceiver* context,
                                                    size_t max_bytes) {
  if (context == NULL)
    return;
  mtx_lock(&context->mutex);
  context->max_queue_bytes = max_bytes;
  context->queued_bytes = 0;
  cnd_broadcast(&context->condition_not_full);
  mtx_unlock(&context->mutex);
}

void pipeline_context_receiver_note_bytes_released(PipelineContextReceiver* context,
                                                   size_t released_bytes) {
  if (context == NULL || context->max_queue_bytes == 0 || released_bytes == 0)
    return;
  mtx_lock(&context->mutex);
  if (released_bytes >= context->queued_bytes)
    context->queued_bytes = 0;
  else
    context->queued_bytes -= released_bytes;
  cnd_signal(&context->condition_not_full);
  mtx_unlock(&context->mutex);
}

bool pipeline_context_receiver_enqueue_file(PipelineContextReceiver* context, File* file) {
  if (context == NULL || file == NULL)
    return false;
  size_t file_bytes = file->data ? file->data->size : 0;
  mtx_lock(&context->mutex);
  while (!atomic_load(&context->cancelled)) {
    bool blocked_by_count = queue_is_full(context->queue);
    bool blocked_by_budget = false;
    if (context->max_queue_bytes > 0) {
      size_t budget = context->max_queue_bytes;
      size_t used = context->queued_bytes;
      if (used >= budget) {
        blocked_by_budget = true;
      } else if (file_bytes > budget - used) {
        /* A single payload larger than the whole budget (not possible with
           the per-file receive cap) is only admitted to an empty pipeline so
           the wait can never deadlock. */
        blocked_by_budget = used != 0;
      }
    }
    if (!blocked_by_count && !blocked_by_budget)
      break;
    cnd_wait(&context->condition_not_full, &context->mutex);
  }
  if (atomic_load(&context->cancelled)) {
    mtx_unlock(&context->mutex);
    file_destroy(file);
    return false;
  }
  if (!queue_enqueue(context->queue, file)) {
    mtx_unlock(&context->mutex);
    file_destroy(file);
    return false;
  }
  context->queued_bytes += file_bytes;
  cnd_signal(&context->condition_not_empty);
  mtx_unlock(&context->mutex);
  return true;
}

static bool receiver_enqueue_file(File* file, void* context_pointer) {
  PipelineContextReceiver* context = (PipelineContextReceiver*)context_pointer;
  return pipeline_context_receiver_enqueue_file(context, file);
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

  ReceiverSink sink = {receiver_enqueue_file, context, false, false, NULL};
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
  protocol_session_bind(&context->session);
  mtx_lock(&context->mutex);
  bool save_to_disk = context->config->save_to_disk;
  char* root_directory = str_dup(context->config->receive_root_directory);
  mtx_unlock(&context->mutex);
  if (save_to_disk && !root_directory) {
    mtx_lock(&context->mutex);
    atomic_store(&context->cancelled, true);
    context->receiver_done = true;
    cnd_broadcast(&context->condition_not_full);
    cnd_broadcast(&context->condition_not_empty);
    mtx_unlock(&context->mutex);
    protocol_session_unbind();
    return thrd_error;
  }

  while (true) {
    File* file =
        queue_dequeue_multithreaded(context->queue, &context->mutex, &context->condition_not_empty,
                                    &context->condition_not_full, &context->receiver_done);
    if (file == NULL) {
      free(root_directory);
      protocol_session_unbind();
      return thrd_success;
    }
    size_t file_bytes = file->data ? file->data->size : 0;
    FileSaveResult result = FILE_SAVE_SKIPPED;
    if (save_to_disk) {
      result = file_save_to_disk_full(root_directory, file, context->config);
      if (result == FILE_SAVE_ERROR) {
        file_destroy(file);
        pipeline_context_receiver_note_bytes_released(context, file_bytes);
        mtx_lock(&context->mutex);
        atomic_store(&context->cancelled, true);
        context->receiver_done = true;
        cnd_broadcast(&context->condition_not_full);
        cnd_broadcast(&context->condition_not_empty);
        mtx_unlock(&context->mutex);
        free(root_directory);
        protocol_session_unbind();
        return thrd_error;
      }
    }
    /* Record the per-file outcome so a --remove-source-files sender learns
       which sources were actually written versus skipped on the receiver.
       Explicit directory entries have no source and are never acknowledged. */
    if (context->config->remove_source_files && !file->is_dir && !file->skip &&
        !receiver_outcomes_append(&context->outcomes, (unsigned char)result)) {
      file_destroy(file);
      pipeline_context_receiver_note_bytes_released(context, file_bytes);
      mtx_lock(&context->mutex);
      atomic_store(&context->cancelled, true);
      context->receiver_done = true;
      cnd_broadcast(&context->condition_not_full);
      cnd_broadcast(&context->condition_not_empty);
      mtx_unlock(&context->mutex);
      free(root_directory);
      protocol_session_unbind();
      return thrd_error;
    }
    file_destroy(file);
    pipeline_context_receiver_note_bytes_released(context, file_bytes);
  }
}
