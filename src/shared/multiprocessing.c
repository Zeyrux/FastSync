#include "multiprocessing.h"
#include "config.h"
#include "queue.h"
#include <stdio.h>
#include <stdlib.h>
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
