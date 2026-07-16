#include "multiprocessing.h"
#include "array_list.h"
#include "chunk.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "queue.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

PipelineContextSender *pipeline_context_sender_create(Config *config,
                                                      Queue *queue_scanner,
                                                      Queue *queue_loader) {
  PipelineContextSender *context = malloc(sizeof(PipelineContextSender));
  context->config = config;
  context->queue_scanner = queue_scanner;
  context->queue_loader = queue_loader;
  context->scanner_done = false;
  context->loader_done = false;
  if (mtx_init(&context->mutex_scanner, mtx_plain) != thrd_success ||
      cnd_init(&context->condition_not_full_scanner) != thrd_success ||
      cnd_init(&context->condition_not_empty_scanner) != thrd_success ||
      mtx_init(&context->mutex_loader, mtx_plain) != thrd_success ||
      cnd_init(&context->condition_not_full_loader) != thrd_success ||
      cnd_init(&context->condition_not_empty_loader) != thrd_success) {
    perror("Error initializing synchronization objects!");
    exit(EXIT_FAILURE);
  }
  return context;
}

void pipeline_context_sender_destroy(PipelineContextSender *context) {
  if (context->manifest) {
    for (int i = 0; i < context->manifest->size; i++)
      free(context->manifest->items[i]);
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
  free(context);
}

PipelineContextReceiver *pipeline_context_receiver_create(Config *config,
                                                          Queue *queue,
                                                          int file_descriptor) {
  PipelineContextReceiver *context = malloc(sizeof(PipelineContextReceiver));
  context->config = config;
  context->queue = queue;
  context->file_descriptor = file_descriptor;
  context->receiver_done = false;
  if (mtx_init(&context->mutex, mtx_plain) != thrd_success ||
      cnd_init(&context->condition_not_full) != thrd_success ||
      cnd_init(&context->condition_not_empty) != thrd_success) {
    perror("Error initializing synchronization objects!");
    exit(EXIT_FAILURE);
  }
  return context;
}

void pipeline_context_receiver_destroy(PipelineContextReceiver *context) {
  config_delete(context->config);
  queue_destroy(context->queue);
  mtx_destroy(&context->mutex);
  cnd_destroy(&context->condition_not_full);
  cnd_destroy(&context->condition_not_empty);
  free(context);
}

static void receive_chunk_enqueue(int file_descriptor,
                                  PipelineContextReceiver *context) {
  Data *chunk_data = receive_data(file_descriptor);
  Data *data_to_process = chunk_data;
  if (context->config->use_compression) {
    data_to_process = data_decompress(chunk_data);
    data_destroy(chunk_data);
  }
  Chunk *chunk = chunk_deserialize(data_to_process, context->config->use_metadata);
  data_destroy(data_to_process);
  if (chunk == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to deserialize chunk, skipping");
    return;
  }

  for (int i = 0; i < chunk->element_count; i++) {
    File *file = chunk->items[i];
    chunk->items[i] = NULL;
    queue_enqueue_multithreaded(context->queue, file, &context->mutex,
                                &context->condition_not_empty,
                                &context->condition_not_full);
  }
  chunk_destroy(chunk);
}

int receive_thread(void *pipeline_context) {
  PipelineContextReceiver *context =
      (PipelineContextReceiver *)pipeline_context;
  mtx_lock(&context->mutex);
  int file_descriptor = context->file_descriptor;
  Config *config = context->config;
  mtx_unlock(&context->mutex);

  Status status = receive_status(file_descriptor);
  while (status == STATUS_NEXT || status == STATUS_CHUNK) {
    if (status == STATUS_CHUNK) {
      receive_chunk_enqueue(file_descriptor, context);
    } else {
      File *file = file_receive(config, file_descriptor);
      queue_enqueue_multithreaded(context->queue, file, &context->mutex,
                                  &context->condition_not_empty,
                                  &context->condition_not_full);
    }
    status = receive_status(file_descriptor);
  }
  if (status == STATUS_MANIFEST) {
    int count = receive_int(file_descriptor);
    ArrayList *manifest = array_list_create(free);
    for (int i = 0; i < count; i++)
      array_list_add(manifest, receive_str(file_descriptor));
    delete_extras(context->config->receive_root_directory, manifest);
    for (int i = 0; i < manifest->size; i++)
      free(manifest->items[i]);
    array_list_delete(manifest);
    status = receive_status(file_descriptor);
  }
  mtx_lock(&context->mutex);
  context->receiver_done = true;
  cnd_signal(&context->condition_not_empty);
  mtx_unlock(&context->mutex);
  return thrd_success;
}

int write_thread(void *pipeline_context) {
  PipelineContextReceiver *context =
      (PipelineContextReceiver *)pipeline_context;
  mtx_lock(&context->mutex);
  bool save_to_disk = context->config->save_to_disk;
  char *root_directory = str_dup(context->config->receive_root_directory);
  mtx_unlock(&context->mutex);

  while (true) {
    File *file = queue_dequeue_multithreaded(
        context->queue, &context->mutex, &context->condition_not_empty,
        &context->condition_not_full, &context->receiver_done);
    if (file == NULL) {
      free(root_directory);
      return thrd_success;
    }
    if (save_to_disk) {
      char *disk_path = path_cat(root_directory, file->path);
      to_disk(disk_path, file->data->data, file->data->size);
      file_restore_metadata(disk_path, file->metadata);
      free(disk_path);
    }
    file_destroy(file);
  }
}
