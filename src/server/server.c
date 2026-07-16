#include "array_list.h"
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int receive_files(Config *config, int file_descriptor) {
  Status status;
  if (!receive_status(file_descriptor, &status)) return -1;
  while (status == STATUS_NEXT || status == STATUS_CHUNK) {
    if (status == STATUS_CHUNK) {
      Data *chunk_data = receive_data(file_descriptor);
      if (chunk_data == NULL) {
        log_message(LOG_LEVEL_ERROR, "Failed to receive chunk data");
        send_status(file_descriptor, STATUS_ERROR);
        return -1;
      }
      Data *data_to_process = chunk_data;
      if (config->use_compression) {
        data_to_process = data_decompress(chunk_data);
        data_destroy(chunk_data);
        if (data_to_process == NULL) {
          log_message(LOG_LEVEL_ERROR, "Failed to decompress chunk");
          send_status(file_descriptor, STATUS_ERROR);
          return -1;
        }
      }
      Chunk *chunk = chunk_deserialize(data_to_process, config->use_metadata);
      data_destroy(data_to_process);
      if (chunk == NULL) {
        log_message(LOG_LEVEL_ERROR, "Failed to deserialize chunk, skipping");
        send_status(file_descriptor, STATUS_ERROR);
        return -1;
      }

      for (int i = 0; i < chunk->element_count; i++) {
        if (config->save_to_disk) {
          char *disk_path = path_cat(config->receive_root_directory, chunk->items[i]->path);
          if (disk_path) {
            to_disk(disk_path, chunk->items[i]->data->data, chunk->items[i]->data->size);
            file_restore_metadata(disk_path, chunk->items[i]->metadata);
            free(disk_path);
          }
        }
      }
      chunk_destroy(chunk);
    } else {
      File *file = file_receive(config, file_descriptor);
      if (file == NULL) {
        log_message(LOG_LEVEL_ERROR, "Failed to receive file");
        send_status(file_descriptor, STATUS_ERROR);
        return -1;
      }
      if (config->save_to_disk) {
        char *disk_path = path_cat(config->receive_root_directory, file->path);
        if (disk_path) {
          to_disk(disk_path, file->data->data, file->data->size);
          file_restore_metadata(disk_path, file->metadata);
          free(disk_path);
        }
      }
      file_destroy(file);
    }
    if (!receive_status(file_descriptor, &status)) {
      send_status(file_descriptor, STATUS_ERROR);
      return -1;
    }
  }
  if (status == STATUS_MANIFEST) {
    int count;
    if (!receive_int(file_descriptor, &count)) return -1;
    ArrayList *manifest = array_list_create(free);
    if (manifest) {
      for (int i = 0; i < count; i++) {
        char *s = receive_str(file_descriptor);
        if (s) array_list_add(manifest, s);
      }
      fprintf(stderr, "Deleting files not in manifest...\n");
      delete_extras(config->receive_root_directory, manifest);
      array_list_delete(manifest);
    }
    if (!receive_status(file_descriptor, &status)) return -1;
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
  if (config == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to receive config");
    close(file_descriptor);
    return;
  }
  if (config->use_multithreading) {
    Queue *q = queue_create(100, file_destroy);
    if (q == NULL) {
      config_delete(config);
      close(file_descriptor);
      return;
    }
    PipelineContextReceiver *context = pipeline_context_receiver_create(
        config, q, file_descriptor);
    if (context == NULL) {
      queue_destroy(q);
      config_delete(config);
      close(file_descriptor);
      return;
    }
    thrd_t receiver, writer;
    if (thrd_create(&receiver, receive_thread, context) != thrd_success ||
        thrd_create(&writer, write_thread, context) != thrd_success) {
      perror("Error creating Threads");
      pipeline_context_receiver_destroy(context);
      close(file_descriptor);
      return;
    }
    thrd_join(receiver, NULL);
    thrd_join(writer, NULL);
    send_status(file_descriptor, STATUS_OK);
    pipeline_context_receiver_destroy(context);
  } else
    receive_files(config, file_descriptor);
  close(file_descriptor);
}

static Server *g_server = NULL;

static void cleanup(int sig) {
  (void)sig;
  if (g_server) {
    server_delete(&g_server);
  }
  _exit(0);
}

int main(int argc, char *argv[]) {
  signal(SIGPIPE, SIG_IGN);
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--stdio") == 0) {
      io_set_fds(STDIN_FILENO, STDOUT_FILENO);
      handler(STDIN_FILENO);
      return 0;
    } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
      set_log_level(LOG_LEVEL_DEBUG);
    }
  }
  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);
  g_server = server_create(8080);
  if (g_server == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to create server");
    return 1;
  }
  server_listen(g_server, handler);
  return 0;
}
