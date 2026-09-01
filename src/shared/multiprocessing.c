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
#include <sys/stat.h>

static bool valid_batch_path(const char* path) {
  return path && path[0] != '\0' && path[0] != '/' && !has_path_traversal(path);
}

static bool handle_batch_checks(int file_descriptor, const Config* config) {
  int count;
  if (config->checksum || !receive_int(file_descriptor, &count) || count < 0 ||
      count > MAX_MANIFEST_ENTRIES)
    return false;
  for (int i = 0; i < count; i++) {
    char* check_path = receive_str(file_descriptor);
    if (!check_path)
      return false;
    unsigned long long check_size;
    long long check_mtime;
    bool received = receive_n_data(file_descriptor, &check_size, sizeof(check_size)) &&
                    receive_n_data(file_descriptor, &check_mtime, sizeof(check_mtime));
    if (!received || !valid_batch_path(check_path)) {
      free(check_path);
      if (received)
        send_status(file_descriptor, STATUS_ERROR);
      return false;
    }
    char* full_path = path_cat(config->receive_root_directory, check_path);
    struct stat st;
    bool has_old = full_path && lstat(full_path, &st) == 0;
    bool match = has_old && (unsigned long long)st.st_size == check_size &&
                 (long long)st.st_mtime == check_mtime;
    bool sent = send_status(file_descriptor, match ? STATUS_OK : STATUS_NEXT);
    free(full_path);
    free(check_path);
    if (!sent)
      return false;
  }
  return true;
}

int receive_files_common(const Config* config, int file_descriptor, ReceivedFileHandler handler,
                         void* context, bool send_completion_status) {
  Status status;
  if (!receive_status(file_descriptor, &status))
    return -1;
  while (status == STATUS_NEXT || status == STATUS_CHUNK || status == STATUS_CHECK ||
         status == STATUS_KEEPALIVE || status == STATUS_ABORT || status == STATUS_CHECK_BATCH) {
    if (status == STATUS_KEEPALIVE) {
      if (!send_status(file_descriptor, STATUS_KEEPALIVE))
        return -1;
    } else if (status == STATUS_ABORT) {
      log_message(LOG_LEVEL_INFO, "Received abort from client, cleaning up");
      return -1;
    } else if (status == STATUS_CHECK_BATCH) {
      if (!handle_batch_checks(file_descriptor, config))
        return -1;
    } else {
      if (status == STATUS_CHUNK) {
        Chunk* chunk = receive_chunk_data(file_descriptor, config);
        if (!chunk)
          return -1;
        for (int i = 0; i < chunk->element_count; i++) {
          File* file = chunk->items[i];
          chunk->items[i] = NULL;
          if (!handler(file, context)) {
            file_destroy(file);
            chunk_destroy(chunk);
            return -1;
          }
        }
        chunk_destroy(chunk);
      } else {
        bool skipped = false;
        File* file = status == STATUS_CHECK
                         ? receive_incremental_check(file_descriptor, config, &skipped)
                         : file_receive(config, file_descriptor);
        if (!skipped) {
          if (!file || !handler(file, context)) {
            file_destroy(file);
            if (status == STATUS_NEXT)
              log_message(LOG_LEVEL_ERROR, "Failed to receive file");
            return -1;
          }
        }
      }
    }
    if (!receive_status(file_descriptor, &status))
      return -1;
  }
  if (status == STATUS_MANIFEST && receive_manifest(file_descriptor, config, &status) != 0)
    return -1;
  if (status != STATUS_FINISHED) {
    log_message(LOG_LEVEL_ERROR, "Did not receive FINISHED Status");
    if (send_completion_status)
      send_status(file_descriptor, STATUS_ERROR);
    return -1;
  }
  if (send_completion_status && !send_status(file_descriptor, STATUS_OK))
    return -1;
  return 0;
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

static bool enqueue_received_file(File* file, void* context) {
  PipelineContextReceiver* receiver = context;
  return queue_enqueue_multithreaded_cancel(receiver->queue, file, &receiver->mutex,
                                            &receiver->condition_not_empty,
                                            &receiver->condition_not_full, &receiver->cancelled);
}

int receive_thread(void* pipeline_context) {
  PipelineContextReceiver* context = (PipelineContextReceiver*)pipeline_context;
  if (context->ssl)
    io_set_ssl(context->ssl);
  mtx_lock(&context->mutex);
  int file_descriptor = context->file_descriptor;
  const Config* config = context->config;
  mtx_unlock(&context->mutex);

  int result = receive_files_common(config, file_descriptor, enqueue_received_file, context, false);
  mtx_lock(&context->mutex);
  if (result != 0)
    atomic_store(&context->cancelled, true);
  context->receiver_done = true;
  cnd_signal(&context->condition_not_empty);
  cnd_broadcast(&context->condition_not_full);
  mtx_unlock(&context->mutex);
  return result == 0 ? thrd_success : thrd_error;
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
