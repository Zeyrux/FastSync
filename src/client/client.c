#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include "chunk.h"
#include "config.h"
#include "log.h"
#include "multiprocessing.h"
#include "queue.h"
#include "scanner.h"
#include "socket.h"
#include "utils.h"
#include <dirent.h>

int send_chunk(Client *client, Chunk *chunk, bool use_compression) {
  if (use_compression) {
    Data *data = chunk_compress(chunk);
    send_data(client->file_descriptor, data->data, data->data_size);
  } else {
    for (int i = 0; i < chunk->element_count; i++) {
      send_status(client->file_descriptor, NEXT);
      File *file = chunk->items[i];
      send_str(client->file_descriptor, file->path);
      send_data(client->file_descriptor, file->data, file->stats.st_size);
    }
  }
  return 0;
}

int scan_directory_multithreaded(void *pipeline_context) {
  PipelineContextSender *context = (PipelineContextSender *)pipeline_context;
  mtx_lock(&context->mutex_scanner);
  DirectoryScanner *scanner =
      directory_scanner_create(context->config->send_directory);
  mtx_unlock(&context->mutex_scanner);

  Chunk *current_chunk;
  while ((current_chunk = directory_scanner_next(scanner)) != NULL)
    queue_enqueue_multithreaded(context->queue_scanner, current_chunk,
                                &context->mutex_scanner,
                                &context->condition_not_empty_scanner,
                                &context->condition_not_full_scanner);
  mtx_lock(&context->mutex_scanner);
  context->scanner_done = true;
  cnd_signal(&context->condition_not_empty_scanner);
  mtx_unlock(&context->mutex_scanner);

  directory_scanner_destroy(scanner);
  return thrd_success;
}

int load_files_multithreaded(void *pipeline_context) {
  PipelineContextSender *context = (PipelineContextSender *)pipeline_context;
  while (true) {
    Chunk *chunk = queue_dequeue_multithreaded(
        context->queue_scanner, &context->mutex_scanner,
        &context->condition_not_empty_scanner,
        &context->condition_not_full_scanner, &context->scanner_done);
    if (chunk == NULL) {
      mtx_lock(&context->mutex_loader);
      context->loader_done = true;
      cnd_signal(&context->condition_not_empty_loader);
      mtx_unlock(&context->mutex_loader);
      return thrd_success;
    }
    for (int i = 0; i < chunk->element_count; i++)
      file_load_data(chunk->items[i]);
    queue_enqueue_multithreaded(context->queue_loader, chunk,
                                &context->mutex_loader,
                                &context->condition_not_empty_loader,
                                &context->condition_not_full_loader);
  }
}

int send_chunks_multithreaded(void *pipeline_context) {
  PipelineContextSender *context = (PipelineContextSender *)pipeline_context;
  bool use_compression = context->config->use_compression;
  Client *client = client_create();
  client_connect(client, "127.0.0.1", 8080);
  config_send(client->file_descriptor, context->config);

  while (true) {
    Chunk *current_chunk = queue_dequeue_multithreaded(
        context->queue_loader, &context->mutex_loader,
        &context->condition_not_empty_loader,
        &context->condition_not_full_loader, &context->loader_done);
    if (current_chunk == NULL) {
      send_status(client->file_descriptor, FINISHED);
      client_disconnect(client);
      client_delete(client);
      return thrd_success;
    }
    if (send_chunk(client, current_chunk, use_compression) != 0) {
      perror("Something unexpected happend while sending the chunk");
      exit(EXIT_FAILURE);
    }
    chunk_destroy(current_chunk);
  }
}

int send_files(Config *config) {
  Client *client = client_create();
  client_connect(client, "127.0.0.1", 8080);
  config_send(client->file_descriptor, config);
  DirectoryScanner *scanner = directory_scanner_create(config->send_directory);
  Chunk *current_chunk;
  while ((current_chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < current_chunk->element_count; i++)
      file_load_data(current_chunk->items[i]);
    send_chunk(client, current_chunk, config->use_compression);
    chunk_destroy(current_chunk);
  }
  send_status(client->file_descriptor, FINISHED);
  if (receive_status(client->file_descriptor) != OK)
    return -1;
  printf("FINISHED");
  directory_scanner_destroy(scanner);
  client_disconnect(client);
  client_delete(client);
  return 0;
}

void handle_arg(char *argument_given, char *argument_to_set, bool *result,
                char *message) {
  if (strcmp(argument_given, argument_to_set) == 0) {
    *result = true;
    log_message(LOG_LEVEL_INFO, message);
  }
}

int send_files_multithreaded(Config *config) {
  PipelineContextSender *context =
      pipeline_context_sender_create(config, queue_create(100, chunk_destroy),
                                     queue_create(100, chunk_destroy));

  thrd_t scanner, loader, sender;
  if (thrd_create(&scanner, scan_directory_multithreaded, context) !=
          thrd_success ||
      thrd_create(&loader, load_files_multithreaded, context) != thrd_success ||
      thrd_create(&sender, send_chunks_multithreaded, context) !=
          thrd_success) {
    perror("Error creating threads.\n");
    return 1;
  }

  thrd_join(scanner, NULL);
  thrd_join(loader, NULL);
  thrd_join(sender, NULL);

  pipeline_context_sender_destroy(context);
  return 0;
}

// int send_files_multiprocessed(Config *config) {
//   int cores = sysconf(_SC_NPROCESSORS_ONLN);
//   int pid = fork();
//   if (pid == -1) {
//     perror("Error Forking!");
//     return 1;
//   } else if (pid == 0) {
//   }
//   for (int i = 0; i < cores; i++) {
//     int pid = fork();
//     if (pid == -1) {
//       perror("Error forking!");
//       return 1;
//     } else if (pid == 0) {
//     }
//   }
//   return 0;
// }

int main(int argc, char *argv[]) {
  Config *config = config_create(
      str_dup("1.0.0"), str_dup("/home/taptap/Nextcloud/Uni/moodle/MINT-Raum"),
      str_dup("./data_copied"), false, false, false, false, 1);
  for (int i = 1; i < argc; i++) {
    handle_arg(argv[i], "-m", &config->use_multithreading,
               "Enabled Multithreading");
    handle_arg(argv[i], "-s", &config->use_chunk_serialization,
               "Enabled Chunk Serialization");
    handle_arg(argv[i], "-c", &config->use_compression, "Enabled Compression");
  }

  if (config->use_multithreading)
    return send_files_multithreaded(config);
  // else if (config->use_multiprocessing)
  //   return send_files_multiprocessed(config);
  return send_files(config);
}
