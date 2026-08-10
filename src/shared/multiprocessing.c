#include "multiprocessing.h"

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

static bool valid_batch_path(const char* path) {
  return path && path[0] != '\0' && path[0] != '/' && !has_path_traversal(path);
}

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

static bool receive_chunk_enqueue(int file_descriptor, PipelineContextReceiver* context) {
  Chunk* chunk = receive_chunk_data(file_descriptor, context->config);
  if (chunk == NULL)
    return false;

  for (int i = 0; i < chunk->element_count; i++) {
    File* file = chunk->items[i];
    chunk->items[i] = NULL;
    if (!queue_enqueue_multithreaded_cancel(context->queue, file, &context->mutex,
                                            &context->condition_not_empty,
                                            &context->condition_not_full, &context->cancelled)) {
      file_destroy(file);
      chunk_destroy(chunk);
      return false;
    }
  }
  chunk_destroy(chunk);
  return true;
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
#define RECEIVE_THREAD_FAIL()                                                                      \
  do {                                                                                             \
    receiver_thread_fail(context);                                                                 \
    return thrd_error;                                                                             \
  } while (0)
  PipelineContextReceiver* context = (PipelineContextReceiver*)pipeline_context;
  if (context->ssl)
    io_set_ssl(context->ssl);
  mtx_lock(&context->mutex);
  int file_descriptor = context->file_descriptor;
  const Config* config = context->config;
  mtx_unlock(&context->mutex);

  Status status;
  if (!receive_status(file_descriptor, &status))
    RECEIVE_THREAD_FAIL();
  while (status == STATUS_NEXT || status == STATUS_CHUNK || status == STATUS_CHECK ||
         status == STATUS_KEEPALIVE || status == STATUS_ABORT || status == STATUS_CHECK_BATCH) {
    if (status == STATUS_KEEPALIVE) {
      if (!send_status(file_descriptor, STATUS_KEEPALIVE))
        RECEIVE_THREAD_FAIL();
      goto next;
    }
    if (status == STATUS_ABORT) {
      log_message(LOG_LEVEL_INFO, "Received abort from client, cleaning up");
      RECEIVE_THREAD_FAIL();
    }
    if (status == STATUS_CHECK) {
      bool skipped;
      File* file = receive_incremental_check(file_descriptor, config, &skipped);
      if (!skipped) {
        if (file == NULL)
          RECEIVE_THREAD_FAIL();
        if (!queue_enqueue_multithreaded_cancel(
                context->queue, file, &context->mutex, &context->condition_not_empty,
                &context->condition_not_full, &context->cancelled)) {
          file_destroy(file);
          RECEIVE_THREAD_FAIL();
        }
      }
    } else if (status == STATUS_CHUNK) {
      if (!receive_chunk_enqueue(file_descriptor, context))
        RECEIVE_THREAD_FAIL();
    } else if (status == STATUS_CHECK_BATCH) {
      int count;
      if (config->checksum || !receive_int(file_descriptor, &count) || count < 0 ||
          count > MAX_MANIFEST_ENTRIES)
        RECEIVE_THREAD_FAIL();
      for (int i = 0; i < count; i++) {
        char* check_path = receive_str(file_descriptor);
        if (!check_path)
          RECEIVE_THREAD_FAIL();
        unsigned long long check_size;
        long long check_mtime;
        if (!receive_n_data(file_descriptor, &check_size, sizeof(check_size)) ||
            !receive_n_data(file_descriptor, &check_mtime, sizeof(check_mtime))) {
          free(check_path);
          RECEIVE_THREAD_FAIL();
        }
        if (!valid_batch_path(check_path)) {
          free(check_path);
          if (!send_status(file_descriptor, STATUS_ERROR))
            RECEIVE_THREAD_FAIL();
          RECEIVE_THREAD_FAIL();
        }
        char* full_path = path_cat(config->receive_root_directory, check_path);
        struct stat st;
        bool has_old = full_path && lstat(full_path, &st) == 0;
        bool match = has_old && (unsigned long long)st.st_size == check_size &&
                     (long long)st.st_mtime == check_mtime;
        if (!send_status(file_descriptor, match ? STATUS_OK : STATUS_NEXT))
          RECEIVE_THREAD_FAIL();
        free(full_path);
        free(check_path);
      }
      goto next;
    } else {
      File* file = file_receive(config, file_descriptor);
      if (file) {
        if (!queue_enqueue_multithreaded_cancel(
                context->queue, file, &context->mutex, &context->condition_not_empty,
                &context->condition_not_full, &context->cancelled)) {
          file_destroy(file);
          receiver_thread_fail(context);
          return thrd_error;
        }
      } else {
        log_message(LOG_LEVEL_ERROR, "Failed to receive file");
        RECEIVE_THREAD_FAIL();
      }
    }
  next:
    if (!receive_status(file_descriptor, &status))
      RECEIVE_THREAD_FAIL();
  }
  if (status == STATUS_MANIFEST) {
    if (receive_manifest(file_descriptor, config, &status) != 0)
      RECEIVE_THREAD_FAIL();
  }
  if (status != STATUS_FINISHED)
    RECEIVE_THREAD_FAIL();
  mtx_lock(&context->mutex);
  context->receiver_done = true;
  cnd_signal(&context->condition_not_empty);
  mtx_unlock(&context->mutex);
#undef RECEIVE_THREAD_FAIL
  return thrd_success;
}

int write_thread(void* pipeline_context) {
  PipelineContextReceiver* context = (PipelineContextReceiver*)pipeline_context;
  if (context->ssl)
    io_set_ssl(context->ssl);
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
