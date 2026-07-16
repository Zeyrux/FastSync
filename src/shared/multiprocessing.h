#ifndef MULTIPROCESSING_H
#define MULTIPROCESSING_H

#include <threads.h>

#include "config.h"
#include "file.h"
#include "queue.h"

typedef struct {
  Config *config;
  Queue *queue_scanner;
  mtx_t mutex_scanner;
  cnd_t condition_not_full_scanner;
  cnd_t condition_not_empty_scanner;
  bool scanner_done;
  Queue *queue_loader;
  mtx_t mutex_loader;
  cnd_t condition_not_full_loader;
  cnd_t condition_not_empty_loader;
  bool loader_done;
} PipelineContextSender;

typedef struct PipelineContextReceiver {
  Queue *queue;
  Config *config;
  int file_descriptor;
  mtx_t mutex;
  cnd_t condition_not_full;
  cnd_t condition_not_empty;
  bool receiver_done;
} PipelineContextReceiver;

PipelineContextSender *pipeline_context_sender_create(Config *config,
                                                      Queue *queue_scanner,
                                                      Queue *queue_loader);
void pipeline_context_sender_destroy(PipelineContextSender *context);
PipelineContextReceiver *pipeline_context_receiver_create(Config *config,
                                                          Queue *queue_receiver,
                                                          int file_descriptor);
void pipeline_context_receiver_destroy(PipelineContextReceiver *context);
int receive_thread(void *pipeline_context);
int write_thread(void *pipeline_context);
#endif
