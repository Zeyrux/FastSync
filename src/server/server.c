#include "chunk.h"
#include "config.h"
#include "multiprocessing.h"
#include "queue.h"
#include "socket.h"
#include "unistd.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>

FileReceive *receive_file_receive(int file_descriptor) {
  char *path = (char *)receive_str(file_descriptor);
  printf("%s\n", path);
  DataFragment *file_data_fragment = receive_data(file_descriptor);
  FileReceive *file = file_receive_create(path, file_data_fragment);
  return file;
}

int receive_thread(void *pipeline_context) {
  PipelineContextReceiver *context =
      (PipelineContextReceiver *)pipeline_context;
  mtx_lock(&context->mutex);
  int file_descriptor = context->file_descriptor;
  mtx_unlock(&context->mutex);

  while (receive_status(file_descriptor) == NEXT) {
    FileReceive *file = receive_file_receive(file_descriptor);
    queue_enqueue_multithreaded(context->queue, file, &context->mutex,
                                &context->condition_not_empty,
                                &context->condition_not_full);
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
    FileReceive *file = queue_dequeue_multithreaded(
        context->queue, &context->mutex, &context->condition_not_empty,
        &context->condition_not_full, &context->receiver_done);
    if (file == NULL) {
      free(root_directory);
      return thrd_success;
    }
    if (save_to_disk)
      to_disk(path_cat(root_directory, file->path), file->data_fragment->data,
              file->data_fragment->size);
  }
}

int receive_files(Config *config, int file_descriptor) {
  Status status = receive_status(file_descriptor);
  while (status == NEXT) {
    FileReceive *file = receive_file_receive(file_descriptor);
    if (config->save_to_disk)
      to_disk(path_cat(config->receive_root_directory, file->path),
              file->data_fragment->data, file->data_fragment->size);
    file_receive_destroy(file);
    status = receive_status(file_descriptor);
  }
  if (status != FINISHED) {
    send_status(file_descriptor, ERROR);
    return -1;
  }
  send_status(file_descriptor, OK);
  return 0;
}

void handler(int file_descriptor) {
  Config *config = config_receive(file_descriptor);
  if (config->use_multithreading) {
    PipelineContextReceiver *context = pipeline_context_receiver_create(
        config, queue_create(100, file_receive_destroy), file_descriptor);
    thrd_t receiver, writer;
    if (thrd_create(&receiver, receive_thread, context) != thrd_success ||
        thrd_create(&writer, write_thread, context) != thrd_success) {
      perror("Error creating Threads!");
      exit(EXIT_FAILURE);
    }
    thrd_join(receiver, NULL);
    thrd_join(writer, NULL);
    pipeline_context_receiver_destroy(context);
  } else
    receive_files(config, file_descriptor);
  close(file_descriptor);
}

int main() {
  Server *server = server_create(8080);
  server_listen(server, handler);
  server_delete(server);
  return 0;
}
