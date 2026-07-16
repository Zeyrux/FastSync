#include "chunk.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "transport_tcp.h"
#include "unistd.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--stdio") == 0) {
      io_set_fds(STDIN_FILENO, STDOUT_FILENO);
      handler(STDIN_FILENO);
      return 0;
    } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
      set_log_level(LOG_LEVEL_DEBUG);
    }
  }
  Server *server = server_create(8080);
  server_listen(server, handler);
  server_delete(&server);
  return 0;
}
