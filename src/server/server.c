#include "chunk.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "multiprocessing.h"
#include "queue.h"
#include "socket.h"
#include "unistd.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

File *file_receive(Config *config, int file_descriptor) {
  char *path = (char *)receive_str(file_descriptor);
  File *file = file_create(path);
  free(path);
  if (config->use_metadata)
    file->metadata = file_receive_metadata(file_descriptor);
  Data *file_data = receive_data(file_descriptor);
  if (config->use_compression) {
    Data *file_data_uncompressed = data_decompress(file_data);
    data_destroy(file_data);
    file_data = file_data_uncompressed;
  }
  data_destroy(file->data);
  file->data = file_data;
  return file;
}

static void receive_chunk_enqueue(int file_descriptor, Config *config,
                                  PipelineContextReceiver *context) {
  (void)config;
  Data *chunk_data = receive_data(file_descriptor);
  Data *data_to_process = chunk_data;
  if (config->use_compression) {
    data_to_process = data_decompress(chunk_data);
    data_destroy(chunk_data);
  }
  Chunk *chunk = chunk_deserialize(data_to_process, config->use_metadata);
  data_destroy(data_to_process);

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
      receive_chunk_enqueue(file_descriptor, config, context);
    } else {
      File *file = file_receive(config, file_descriptor);
      queue_enqueue_multithreaded(context->queue, file, &context->mutex,
                                  &context->condition_not_empty,
                                  &context->condition_not_full);
    }
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

int receive_files(Config *config, int file_descriptor) {
  Status status = receive_status(file_descriptor);
  while (status == STATUS_NEXT || status == STATUS_CHUNK) {
    if (status == STATUS_CHUNK) {
      Data *chunk_data = receive_data(file_descriptor);
      Data *data_to_process = chunk_data;
      if (config->use_compression) {
        data_to_process = data_decompress(chunk_data);
        data_destroy(chunk_data);
      }
      Chunk *chunk = chunk_deserialize(data_to_process, config->use_metadata);
      data_destroy(data_to_process);

      for (int i = 0; i < chunk->element_count; i++) {
        if (config->save_to_disk) {
          char *disk_path = path_cat(config->receive_root_directory, chunk->items[i]->path);
          to_disk(disk_path, chunk->items[i]->data->data, chunk->items[i]->data->size);
          file_restore_metadata(disk_path, chunk->items[i]->metadata);
          free(disk_path);
        }
      }
      chunk_destroy(chunk);
    } else {
      File *file = file_receive(config, file_descriptor);
      if (config->save_to_disk) {
        char *disk_path = path_cat(config->receive_root_directory, file->path);
        to_disk(disk_path, file->data->data, file->data->size);
        file_restore_metadata(disk_path, file->metadata);
        free(disk_path);
      }
      file_destroy(file);
    }
    status = receive_status(file_descriptor);
  }
  if (status != STATUS_FINISHED) {
    log_message(LOG_LEVEL_ERROR, "Did not receive FINISHED Status");
    send_status(file_descriptor, STATUS_ERROR);
    return -1;
  }
  send_status(file_descriptor, STATUS_OK);
  return 0;
}

void handler(int file_descriptor) {
  Config *config = config_receive(file_descriptor);
  if (config->use_multithreading) {
    PipelineContextReceiver *context = pipeline_context_receiver_create(
        config, queue_create(100, file_destroy), file_descriptor);
    thrd_t receiver, writer;
    if (thrd_create(&receiver, receive_thread, context) != thrd_success ||
        thrd_create(&writer, write_thread, context) != thrd_success) {
      perror("Error creating Threads!");
      exit(EXIT_FAILURE);
    }
    thrd_join(receiver, NULL);
    thrd_join(writer, NULL);
    pipeline_context_receiver_destroy(context);
    send_status(file_descriptor, STATUS_OK);
  } else
    receive_files(config, file_descriptor);
  close(file_descriptor);
}

int main(int argc, char *argv[]) {
  if (argc > 1 && strcmp(argv[1], "--stdio") == 0) {
    io_set_fds(STDIN_FILENO, STDOUT_FILENO);
    handler(STDIN_FILENO);
    return 0;
  }
  Server *server = server_create(8080);
  server_listen(server, handler);
  server_delete(server);
  return 0;
}
