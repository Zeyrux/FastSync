#include "client_send.h"
#include "array_list.h"
#include "chunk.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "scanner.h"
#include "transport_tcp.h"
#include "transport_ssh.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>

int send_chunk(Client *client, Chunk *chunk, Config *config) {
  if (config->use_chunk_serialization) {
    send_status(client->file_descriptor, STATUS_CHUNK);
    Data *data;
    if (config->use_compression) {
      data = chunk_compress(chunk, config->compression_level, config->use_metadata);
    } else {
      data = chunk_serialize(chunk, config->use_metadata);
    }
    send_data(client->file_descriptor, data);
    data_destroy(data);
  } else if (config->use_sendfile && !config->use_compression) {
    for (int i = 0; i < chunk->element_count; i++) {
      send_status(client->file_descriptor, STATUS_NEXT);
      file_send_sendfile(chunk->items[i], client->file_descriptor, config->use_metadata);
    }
  } else {
    for (int i = 0; i < chunk->element_count; i++) {
      send_status(client->file_descriptor, STATUS_NEXT);
      file_send_single_calls(chunk->items[i], client->file_descriptor,
                            config->use_metadata,
                            config->use_compression ? config->compression_level : 0);
    }
  }
  return 0;
}

static int send_chunks_multithreaded(void *pipeline_context) {
  PipelineContextSender *context = (PipelineContextSender *)pipeline_context;
  Client *client;
  if (context->config->transport == TRANSPORT_SSH) {
    if (context->config->use_sendfile) {
      fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
      return 1;
    }
    client = client_connect_ssh(context->config->ssh_destination, context->config->ssh_port);
  } else {
    client = client_create();
    client_connect(client, server_host, server_port);
  }
  config_send(client->file_descriptor, context->config);

  while (true) {
    Chunk *current_chunk = queue_dequeue_multithreaded(
        context->queue_loader, &context->mutex_loader,
        &context->condition_not_empty_loader,
        &context->condition_not_full_loader, &context->loader_done);
    if (current_chunk == NULL) {
      if (context->config->use_delete) {
        send_status(client->file_descriptor, STATUS_MANIFEST);
        send_int(client->file_descriptor, context->manifest->size);
        for (int i = 0; i < context->manifest->size; i++)
          send_str(client->file_descriptor,
                   (char *)context->manifest->items[i]);
      }
      send_status(client->file_descriptor, STATUS_FINISHED);
      int ok = receive_status(client->file_descriptor) == STATUS_OK;
      client_disconnect(client);
      client_delete(client);
      return ok ? thrd_success : thrd_error;
    }
    if (send_chunk(client, current_chunk, context->config) != 0) {
      perror("Something unexpected happend while sending the chunk");
      exit(EXIT_FAILURE);
    }
    chunk_destroy(current_chunk);
  }
}

static int scan_directory_multithreaded(void *pipeline_context) {
  PipelineContextSender *context = (PipelineContextSender *)pipeline_context;
  mtx_lock(&context->mutex_scanner);
  DirectoryScanner *scanner = directory_scanner_create(
      context->config->send_directory, context->config->use_metadata,
      context->config->chunk_size, context->config->exclude_patterns,
      context->config->exclude_count);
  mtx_unlock(&context->mutex_scanner);

  Chunk *current_chunk;
  while ((current_chunk = directory_scanner_next(scanner)) != NULL) {
    if (context->config->use_delete) {
      mtx_lock(&context->mutex_scanner);
      for (int i = 0; i < current_chunk->element_count; i++)
        array_list_add(context->manifest,
                       str_dup(current_chunk->items[i]->path));
      mtx_unlock(&context->mutex_scanner);
    }
    queue_enqueue_multithreaded(context->queue_scanner, current_chunk,
                                &context->mutex_scanner,
                                &context->condition_not_empty_scanner,
                                &context->condition_not_full_scanner);
  }
  mtx_lock(&context->mutex_scanner);
  context->scanner_done = true;
  cnd_signal(&context->condition_not_empty_scanner);
  mtx_unlock(&context->mutex_scanner);

  directory_scanner_destroy(scanner);
  return thrd_success;
}

static int load_files_multithreaded(void *pipeline_context) {
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

int send_files(Config *config) {
  if (config->dry_run) {
    DirectoryScanner *scanner = directory_scanner_create(
        config->send_directory, config->use_metadata, config->chunk_size,
        config->exclude_patterns, config->exclude_count);
    Chunk *chunk;
    int file_count = 0;
    unsigned long long total_bytes = 0;
    printf("Dry run: files to be transferred\n");
    while ((chunk = directory_scanner_next(scanner)) != NULL) {
      for (int i = 0; i < chunk->element_count; i++) {
        printf("  %s (%zu bytes)\n", chunk->items[i]->path,
               chunk->items[i]->data->size);
        total_bytes += chunk->items[i]->data->size;
        file_count++;
      }
      chunk_destroy(chunk);
    }
    directory_scanner_destroy(scanner);
    printf("Total: %d files, %.1f MB\n", file_count,
           total_bytes / 1048576.0);
    return 0;
  }

  Client *client;
  if (config->transport == TRANSPORT_SSH) {
    if (config->use_sendfile) {
      fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
      return 1;
    }
    client = client_connect_ssh(config->ssh_destination, config->ssh_port);
  } else {
    client = client_create();
    client_connect(client, server_host, server_port);
  }
  config_send(client->file_descriptor, config);
  DirectoryScanner *scanner = directory_scanner_create(
      config->send_directory, config->use_metadata, config->chunk_size,
      config->exclude_patterns, config->exclude_count);
  Chunk *current_chunk;
  unsigned long long total_bytes = 0;
  time_t last_progress = 0;
  time_t start = time(NULL);
  ArrayList *manifest = config->use_delete ? array_list_create(free) : NULL;
  while ((current_chunk = directory_scanner_next(scanner)) != NULL) {
    unsigned long long chunk_bytes = 0;
    for (int i = 0; i < current_chunk->element_count; i++) {
      chunk_bytes += current_chunk->items[i]->data->size;
      if (manifest)
        array_list_add(manifest, str_dup(current_chunk->items[i]->path));
    }
    if (!config->use_sendfile) {
      for (int i = 0; i < current_chunk->element_count; i++)
        file_load_data(current_chunk->items[i]);
    }
    send_chunk(client, current_chunk, config);
    if (config->show_progress) {
      total_bytes += chunk_bytes;
      time_t now = time(NULL);
      if (now - last_progress >= 1) {
        last_progress = now;
        double elapsed = difftime(now, start);
        double rate = elapsed > 0 ? total_bytes / (1048576.0 * elapsed) : 0;
        fprintf(stderr, "\rSent %.1f MB  (%.1f MB/s)  ", total_bytes / 1048576.0, rate);
        fflush(stderr);
      }
    }
    chunk_destroy(current_chunk);
  }
  if (config->use_delete) {
    send_status(client->file_descriptor, STATUS_MANIFEST);
    send_int(client->file_descriptor, manifest->size);
    for (int i = 0; i < manifest->size; i++)
      send_str(client->file_descriptor, (char *)manifest->items[i]);
    for (int i = 0; i < manifest->size; i++)
      free(manifest->items[i]);
    array_list_delete(manifest);
  }
  send_status(client->file_descriptor, STATUS_FINISHED);
  int ok = receive_status(client->file_descriptor) == STATUS_OK;
  if (config->show_progress) {
    double elapsed = difftime(time(NULL), start);
    double rate = elapsed > 0 ? total_bytes / (1048576.0 * elapsed) : 0;
    fprintf(stderr, "\rSent %.1f MB  (%.1f MB/s)  Done.\n", total_bytes / 1048576.0, rate);
  }
  directory_scanner_destroy(scanner);
  client_disconnect(client);
  client_delete(client);
  return ok ? 0 : -1;
}

int send_files_multithreaded(Config *config) {
  if (config->dry_run) {
    DirectoryScanner *scanner = directory_scanner_create(
        config->send_directory, config->use_metadata, config->chunk_size,
        config->exclude_patterns, config->exclude_count);
    Chunk *chunk;
    int file_count = 0;
    unsigned long long total_bytes = 0;
    printf("Dry run: files to be transferred\n");
    while ((chunk = directory_scanner_next(scanner)) != NULL) {
      for (int i = 0; i < chunk->element_count; i++) {
        printf("  %s (%zu bytes)\n", chunk->items[i]->path,
               chunk->items[i]->data->size);
        total_bytes += chunk->items[i]->data->size;
        file_count++;
      }
      chunk_destroy(chunk);
    }
    directory_scanner_destroy(scanner);
    printf("Total: %d files, %.1f MB\n", file_count,
           total_bytes / 1048576.0);
    return 0;
  }

  PipelineContextSender *context =
      pipeline_context_sender_create(config, queue_create(100, chunk_destroy),
                                     queue_create(100, chunk_destroy));
  if (config->use_delete)
    context->manifest = array_list_create(free);

  thrd_t scanner, loader, sender;
  if (thrd_create(&scanner, scan_directory_multithreaded, context) !=
          thrd_success ||
      thrd_create(&loader, load_files_multithreaded, context) != thrd_success ||
      thrd_create(&sender, send_chunks_multithreaded, context) !=
          thrd_success) {
    perror("Error creating threads.\n");
    return 1;
  }

  int sender_result;
  thrd_join(scanner, NULL);
  thrd_join(loader, NULL);
  thrd_join(sender, &sender_result);

  pipeline_context_sender_destroy(context);
  return sender_result == thrd_success ? 0 : -1;
}
