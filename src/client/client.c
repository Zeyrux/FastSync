#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include "chunk.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "multiprocessing.h"
#include "queue.h"
#include "scanner.h"
#include "socket.h"
#include "utils.h"
#include <dirent.h>

int send_chunk(Client *client, Chunk *chunk, Config *config) {
  if (config->use_chunk_serialization) {
    send_status(client->file_descriptor, STATUS_CHUNK);
    Data *data;
    if (config->use_compression) {
      data = chunk_compress(chunk, config->compression_level, config->use_metadata);
    } else {
      for (int i = 0; i < chunk->element_count; i++)
        file_load_data(chunk->items[i]);
      data = chunk_serialize(chunk, config->use_metadata);
    }
    send_data(client->file_descriptor, data->data, data->size);
    data_destroy(data);
  } else if (config->use_sendfile && !config->use_compression) {
    for (int i = 0; i < chunk->element_count; i++) {
      send_status(client->file_descriptor, STATUS_NEXT);
      file_send_sendfile(chunk->items[i], client->file_descriptor, config->use_metadata);
    }
  } else {
    for (int i = 0; i < chunk->element_count; i++) {
      send_status(client->file_descriptor, STATUS_NEXT);
      File *file = chunk->items[i];
      if (config->use_compression) {
        Data *compressed_data =
            data_compress(file->data, config->compression_level);
        data_destroy(file->data);
        file->data = compressed_data;
      }
      file_send_single_calls(file, client->file_descriptor, config->use_metadata);
    }
  }
  return 0;
}

int scan_directory_multithreaded(void *pipeline_context) {
  PipelineContextSender *context = (PipelineContextSender *)pipeline_context;
  mtx_lock(&context->mutex_scanner);
  DirectoryScanner *scanner =
      directory_scanner_create(context->config->send_directory, context->config->use_metadata);
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
    if (!context->config->use_sendfile) {
      for (int i = 0; i < chunk->element_count; i++)
        file_load_data(chunk->items[i]);
    }
    queue_enqueue_multithreaded(context->queue_loader, chunk,
                                &context->mutex_loader,
                                &context->condition_not_empty_loader,
                                &context->condition_not_full_loader);
  }
}

int send_chunks_multithreaded(void *pipeline_context) {
  PipelineContextSender *context = (PipelineContextSender *)pipeline_context;
  Client *client;
  if (context->config->transport == TRANSPORT_SSH) {
    if (context->config->use_sendfile) {
      fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
      return 1;
    }
    client = client_connect_ssh(context->config->ssh_destination);
  } else {
    client = client_create();
    const char *env_ip = getenv("FASTSYNC_SERVER_IP");
    const char *ip = env_ip ? env_ip : "127.0.0.1";
    const char *env_port = getenv("FASTSYNC_SERVER_PORT");
    int port = env_port ? atoi(env_port) : 8080;
    client_connect(client, (char *)ip, port);
  }
  config_send(client->file_descriptor, context->config);

  while (true) {
    Chunk *current_chunk = queue_dequeue_multithreaded(
        context->queue_loader, &context->mutex_loader,
        &context->condition_not_empty_loader,
        &context->condition_not_full_loader, &context->loader_done);
    if (current_chunk == NULL) {
      send_status(client->file_descriptor, STATUS_FINISHED);
      if (receive_status(client->file_descriptor) != STATUS_OK) {
        client_disconnect(client);
        client_delete(client);
        return 1;
      }
      client_disconnect(client);
      client_delete(client);
      return thrd_success;
    }
    if (send_chunk(client, current_chunk, context->config) != 0) {
      perror("Something unexpected happend while sending the chunk");
      exit(EXIT_FAILURE);
    }
    chunk_destroy(current_chunk);
  }
}

int send_files(Config *config) {
  Client *client;
  if (config->transport == TRANSPORT_SSH) {
    if (config->use_sendfile) {
      fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
      return 1;
    }
    client = client_connect_ssh(config->ssh_destination);
  } else {
    client = client_create();
    const char *env_ip = getenv("FASTSYNC_SERVER_IP");
    const char *ip = env_ip ? env_ip : "127.0.0.1";
    const char *env_port = getenv("FASTSYNC_SERVER_PORT");
    int port = env_port ? atoi(env_port) : 8080;
    client_connect(client, (char *)ip, port);
  }
  config_send(client->file_descriptor, config);
  DirectoryScanner *scanner = directory_scanner_create(config->send_directory, config->use_metadata);
  Chunk *current_chunk;
  while ((current_chunk = directory_scanner_next(scanner)) != NULL) {
    if (!config->use_sendfile) {
      for (int i = 0; i < current_chunk->element_count; i++)
        file_load_data(current_chunk->items[i]);
    }
    send_chunk(client, current_chunk, config);
    chunk_destroy(current_chunk);
  }
  send_status(client->file_descriptor, STATUS_FINISHED);
  if (receive_status(client->file_descriptor) != STATUS_OK)
    return -1;
  directory_scanner_destroy(scanner);
  client_disconnect(client);
  client_delete(client);
  return 0;
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

static int is_remote_dest(const char *s) {
  const char *colon = strchr(s, ':');
  if (!colon) return 0;
  if (colon == s) return 0;
  for (const char *p = s; p < colon; p++) {
    if (*p == '/') return 0;
  }
  return 1;
}

static void print_usage(void) {
  printf("Usage:\n");
  printf("  fastsync [options] <source> <destination>\n");
  printf("  fastsync [options] --source-dir <src> --dest-dir <dst>\n");
  printf("\n");
  printf("Destination formats:\n");
  printf("  user@host:/path     SSH transport (rsync-style)\n");
  printf("  host:/path          SSH transport (current user)\n");
  printf("  /local/path         TCP transport (requires server on localhost:8080)\n");
  printf("\n");
  printf("Options:\n");
  printf("  -c [level]          Enable compression (level 1-22, default 5)\n");
  printf("  -m                  Enable multithreading\n");
  printf("  -s                  Enable chunk serialization\n");
  printf("  -f                  Enable sendfile (TCP only, not with -c or -s)\n");
  printf("  -M, --preserve      Preserve file metadata\n");
  printf("  --source-dir <path> Source directory\n");
  printf("  --dest-dir <path>   Destination directory\n");
  printf("  --save-to-disk      Write received files to disk\n");
  printf("  --help              Show this help\n");
}

int main(int argc, char *argv[]) {
  const char *env_source = getenv("FASTSYNC_SOURCE_DIR");
  const char *env_dest = getenv("FASTSYNC_DEST_DIR");
  const char *env_save = getenv("FASTSYNC_SAVE_TO_DISK");

  bool save_to_disk = false;
  if (env_save &&
      (strcmp(env_save, "true") == 0 || strcmp(env_save, "1") == 0)) {
    save_to_disk = true;
  }

  Config *config = config_create(str_dup("1.0.0"), NULL, NULL,
                                 save_to_disk, false, false, false, false, 5, 20, false);

  int positional_args[2];
  int positional_count = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      print_usage();
      return 0;
    } else if (strcmp(argv[i], "-c") == 0) {
      config->use_compression = true;
      log_message(LOG_LEVEL_INFO, "Enabled Compression");
      if (i + 1 < argc) {
        char *end_ptr;
        int level = strtol(argv[i + 1], &end_ptr, 10);
        if (*end_ptr == '\0') {
          config->compression_level = level;
          log_message(LOG_LEVEL_INFO, "Set Compression level to %d",
                      config->compression_level);
          i++;
        }
      }
    } else if (strcmp(argv[i], "--source-dir") == 0 && i + 1 < argc) {
      free(config->send_directory);
      config->send_directory = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--dest-dir") == 0 && i + 1 < argc) {
      free(config->receive_root_directory);
      config->receive_root_directory = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--save-to-disk") == 0) {
      config->save_to_disk = true;
    } else if (strcmp(argv[i], "-M") == 0 || strcmp(argv[i], "--preserve") == 0) {
      config->use_metadata = true;
      log_message(LOG_LEVEL_INFO, "Enabled metadata preservation");
    } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--sendfile") == 0) {
      config->use_sendfile = true;
      log_message(LOG_LEVEL_INFO, "Enabled sendfile");
    } else if (strcmp(argv[i], "-m") == 0) {
      config->use_multithreading = true;
      log_message(LOG_LEVEL_INFO, "Enabled Multithreading");
    } else if (strcmp(argv[i], "-s") == 0) {
      config->use_chunk_serialization = true;
      log_message(LOG_LEVEL_INFO, "Enabled Chunk Serialization");
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_usage();
      return 1;
    } else {
      if (positional_count < 2)
        positional_args[positional_count++] = i;
      else {
        fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
        print_usage();
        return 1;
      }
    }
  }

  if (positional_count == 2) {
    free(config->send_directory);
    config->send_directory = str_dup(argv[positional_args[0]]);
    free(config->receive_root_directory);
    config->receive_root_directory = str_dup(argv[positional_args[1]]);
    config->save_to_disk = true;

    if (is_remote_dest(config->receive_root_directory)) {
      config->transport = TRANSPORT_SSH;
      config->ssh_destination = str_dup(config->receive_root_directory);
    }
  } else if (positional_count == 1) {
    fprintf(stderr, "Error: missing destination argument\n");
    print_usage();
    return 1;
  } else {
    if (!config->send_directory) {
      config->send_directory =
          env_source ? str_dup((char *)env_source)
                     : str_dup("/home/taptap/Nextcloud/Uni/moodle/B. Schnor： "
                               "Konzepte Paralleler Programmierung, SoSe 2026");
    }
    if (!config->receive_root_directory) {
      config->receive_root_directory =
          env_dest ? str_dup((char *)env_dest) : str_dup("./data_copied");
    }
  }

  if (config->use_sendfile && (config->use_chunk_serialization || config->use_compression)) {
    fprintf(stderr, "Error: -f/--sendfile cannot be combined with -c (compression) or -s (chunk serialization)\n");
    return 1;
  }

  if (config->transport == TRANSPORT_SSH && config->use_sendfile) {
    fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
    return 1;
  }

  if (config->use_multithreading)
    return send_files_multithreaded(config);
  return send_files(config);
}
