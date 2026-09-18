#include "multiprocessing.h"

#include "array_list.h"
#include "chunk.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "file_receive.h"
#include "log.h"
#include "protocol.h"
#include "queue.h"
#include "utils.h"
#include <stdint.h>
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
  context->queued_bytes = 0;
  context->max_queue_bytes = 0;
  context->manifest = NULL;
  context->excluded_paths = NULL;
  context->size_skipped_paths = NULL;
  context->synced_dirs = NULL;
  context->plan_dirs = NULL;
  context->missing_args = NULL;
  context->scan_had_io_error = false;
  context->remove_source_files = NULL;
  context->early_delete = false;
  context->delete_plans = NULL;
  context->scan_stopped_early = false;
  context->total_files = 0;
  context->progress_bytes = 0;
  context->total_bytes = 0;
  memset(&context->stats, 0, sizeof(context->stats));
  context->sender_done = false;
  atomic_init(&context->cancelled, false);
  protocol_session_init(&context->allocation_session, -1, -1);
  protocol_session_set_max_alloc(&context->allocation_session, config->max_alloc);
  context->dir_entries = NULL;
  context->dir_entries_mutex_init = false;
  context->delete_limit = false;
  int init = 0;
  if (config->use_metadata) {
    context->dir_entries = array_list_create(file_destroy);
    if (!context->dir_entries)
      goto fail;
  }
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
  if (mtx_init(&context->dir_entries_mutex, mtx_plain) != thrd_success)
    goto fail;
  context->dir_entries_mutex_init = true;
  return context;

fail:
  log_perror("Error initializing synchronization objects");
  if (context->dir_entries_mutex_init)
    mtx_destroy(&context->dir_entries_mutex);
  if (context->dir_entries)
    array_list_delete(context->dir_entries);
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

void pipeline_context_sender_set_queue_byte_limit(PipelineContextSender* context,
                                                  size_t max_bytes) {
  if (context == NULL)
    return;
  mtx_lock(&context->mutex_loader);
  context->max_queue_bytes = max_bytes;
  context->queued_bytes = 0;
  cnd_broadcast(&context->condition_not_full_loader);
  mtx_unlock(&context->mutex_loader);
}

size_t pipeline_context_sender_chunk_bytes(const Chunk* chunk) {
  if (chunk == NULL || chunk->items == NULL)
    return 0;
  size_t total = 0;
  for (int i = 0; i < chunk->element_count; i++) {
    const File* file = chunk->items[i];
    if (file == NULL || file->data == NULL || file->data->data == NULL)
      continue;
    if (file->data->size > SIZE_MAX - total)
      return SIZE_MAX;
    total += file->data->size;
  }
  return total;
}

void pipeline_context_sender_note_bytes_released(PipelineContextSender* context,
                                                 size_t released_bytes) {
  if (context == NULL || context->max_queue_bytes == 0 || released_bytes == 0)
    return;
  mtx_lock(&context->mutex_loader);
  if (released_bytes >= context->queued_bytes)
    context->queued_bytes = 0;
  else
    context->queued_bytes -= released_bytes;
  cnd_signal(&context->condition_not_full_loader);
  mtx_unlock(&context->mutex_loader);
}

bool pipeline_context_sender_enqueue_chunk(PipelineContextSender* context, Chunk* chunk) {
  if (context == NULL || chunk == NULL)
    return false;
  size_t chunk_bytes = pipeline_context_sender_chunk_bytes(chunk);
  mtx_lock(&context->mutex_loader);
  while (!atomic_load(&context->cancelled)) {
    bool blocked_by_count = queue_is_full(context->queue_loader);
    bool blocked_by_budget = false;
    if (context->max_queue_bytes > 0) {
      size_t budget = context->max_queue_bytes;
      size_t used = context->queued_bytes;
      if (used >= budget) {
        blocked_by_budget = true;
      } else if (chunk_bytes > budget - used) {
        /* A single payload larger than the whole budget is only admitted to an
           empty pipeline so the wait can never deadlock. */
        blocked_by_budget = used != 0;
      }
    }
    if (!blocked_by_count && !blocked_by_budget)
      break;
    cnd_wait(&context->condition_not_full_loader, &context->mutex_loader);
  }
  if (atomic_load(&context->cancelled)) {
    mtx_unlock(&context->mutex_loader);
    chunk_destroy(chunk);
    return false;
  }
  if (!queue_enqueue(context->queue_loader, chunk)) {
    mtx_unlock(&context->mutex_loader);
    chunk_destroy(chunk);
    return false;
  }
  context->queued_bytes += chunk_bytes;
  cnd_signal(&context->condition_not_empty_loader);
  mtx_unlock(&context->mutex_loader);
  return true;
}

void pipeline_context_sender_destroy(PipelineContextSender* context) {
  /* `config` is borrowed: the caller retains ownership and frees it after the
     pipeline has been destroyed (the worker threads are already joined, so no
     config access can outlive this call). */
  if (context->manifest) {
    array_list_delete(context->manifest);
  }
  if (context->delete_plans)
    delete_plan_sender_destroy(context->delete_plans);
  if (context->excluded_paths)
    array_list_delete(context->excluded_paths);
  if (context->size_skipped_paths)
    array_list_delete(context->size_skipped_paths);
  if (context->synced_dirs)
    array_list_delete(context->synced_dirs);
  if (context->plan_dirs)
    array_list_delete(context->plan_dirs);
  if (context->missing_args)
    array_list_delete(context->missing_args);
  if (context->remove_source_files)
    array_list_delete(context->remove_source_files);
  if (context->dir_entries)
    array_list_delete(context->dir_entries);
  if (context->dir_entries_mutex_init)
    mtx_destroy(&context->dir_entries_mutex);
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
