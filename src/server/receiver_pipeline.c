#include "receiver_pipeline.h"

#include "log.h"
#include "protocol.h"
#include "queue.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <threads.h>

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
  dir_time_list_init(&context->dir_times);
  protocol_session_init(&context->session, file_descriptor, file_descriptor);
  protocol_session_set_ssl(&context->session, ssl);
  context->receiver_done = false;
  context->queued_bytes = 0;
  context->max_queue_bytes = 0;
  context->deferred_manifest = NULL;
  context->deferred_plans = NULL;
  context->delete_limit_reached = false;
  context->failed_entries = 0;
  memset(&context->stats, 0, sizeof(context->stats));
  context->would_delete = NULL;
  context->deleted_paths = NULL;
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
  context->would_delete = array_list_create(free);
  if (!context->would_delete)
    goto fail;
  /* The actually-removed path list is only needed to render rsync's
     `deleting PATH` lines, which the client requests via report_deletes
     (--info=del / -i / --out-format under --delete).  A plain --delete run must
     not allocate it or observe every removal. */
  if (config->report_deletes) {
    context->deleted_paths = array_list_create(free);
    if (!context->deleted_paths)
      goto fail;
  }
  return context;

fail:
  log_perror("Error initializing synchronization objects");
  if (init >= 3)
    cnd_destroy(&context->condition_not_empty);
  if (init >= 2)
    cnd_destroy(&context->condition_not_full);
  if (init >= 1)
    mtx_destroy(&context->mutex);
  /* Free every list that was already created before the failing allocation:
     `context` itself is freed below, so they would otherwise leak. */
  if (context->would_delete)
    array_list_delete(context->would_delete);
  if (context->deleted_paths)
    array_list_delete(context->deleted_paths);
  free(context);
  return NULL;
}

void pipeline_context_receiver_destroy(PipelineContextReceiver* context) {
  config_delete(context->config);
  if (context->deferred_manifest)
    delete_manifest_free(context->deferred_manifest);
  if (context->deferred_plans)
    delete_plan_session_destroy(context->deferred_plans);
  queue_destroy(context->queue);
  receiver_outcomes_destroy(&context->outcomes);
  dir_time_list_free(&context->dir_times);
  if (context->would_delete)
    array_list_delete(context->would_delete);
  if (context->deleted_paths)
    array_list_delete(context->deleted_paths);
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
  if (file && file->matched_bytes > 0) {
    mtx_lock(&context->mutex);
    context->stats.matched_data += file->matched_bytes;
    mtx_unlock(&context->mutex);
  }
  return pipeline_context_receiver_enqueue_file(context, file);
}

/* Early delete modes (--delete-before/--delete-during) commit the manifest
   inside receiver_process_pending on this thread; record a capped commit so
   server.c's terminal frame can report STATUS_DELETE_LIMIT.  The plain bool is
   safe: receive_thread writes it before the main thread joins the thread. */
static void receiver_pipeline_note_delete_limit(void* context_pointer) {
  PipelineContextReceiver* context = (PipelineContextReceiver*)context_pointer;
  context->delete_limit_reached = true;
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

  ReceiverSink sink = {receiver_enqueue_file,
                       context,
                       false,
                       false,
                       NULL,
                       receiver_pipeline_note_delete_limit,
                       &context->stats,
                       context->would_delete,
                       context->deleted_paths};
  if (receiver_process_pending((Config*)config, file_descriptor, &sink, &context->deferred_manifest,
                               &context->deferred_plans) != 0) {
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
    bool created = false;
    unsigned created_dirs = 0;
    /* Server-contacting --dry-run: never write.  The receiver thread does not
       enqueue anything on the dry-run path, but this keeps the writer thread
       provably mutation-free if a data frame ever reached it. */
    bool dry_run = context->config->dry_run;
    if (save_to_disk && !dry_run) {
      result =
          file_save_to_disk_full_ex(root_directory, file, context->config, &created, &created_dirs);
      if (result == FILE_SAVE_WRITTEN) {
        /* Protocol 2.28.0: fold the receiver-observed literal bytes and the
           created-entry type into the shared stats block under its mutex (the
           receive thread also writes stats.matched_data). */
        mtx_lock(&context->mutex);
        receiver_stats_note_saved(&context->stats, file, created, created_dirs);
        mtx_unlock(&context->mutex);
      }
      /* --devices parity: a device node that could not be mknod'ed is counted
         per-run but does NOT abort the transfer. */
      if (result == FILE_SAVE_FAILED) {
        mtx_lock(&context->mutex);
        context->failed_entries++;
        mtx_unlock(&context->mutex);
      }
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
    /* P7 Wave D: a directory's times are never applied inline (a later child
       write would clobber them); accumulate the metadata here and let the
       caller apply it once every writer has drained. */
    if (!dry_run && result != FILE_SAVE_ERROR && file->is_dir && file->metadata &&
        dir_metadata_should_capture(context->config) &&
        !dir_time_list_add(&context->dir_times, file->path, file->metadata, file->xattrs)) {
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
    /* Record the per-file outcome so a --remove-source-files sender learns
       which sources were actually written versus skipped on the receiver.
       Explicit directory entries and recreated device/special nodes have no
       source and are never acknowledged (mirrors receiver.c). */
    if (!dry_run && context->config->remove_source_files && !file->is_dir && !file->is_special &&
        !file->skip && !receiver_outcomes_append(&context->outcomes, (unsigned char)result)) {
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
