#include "client_send.h"
#include "array_list.h"
#include "chunk.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delta.h"
#include "file.h"
#include "metadata.h"
#include "log.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "scanner.h"
#include "transport_tcp.h"
#include "transport_ssh.h"
#include "transport_tls.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>

static int incremental_check(Client* client, File* file, DeltaSignature** out_sig) {
  *out_sig = NULL;
  if (!send_status(client->file_descriptor, STATUS_CHECK))
    return -1;
  if (!send_str(client->file_descriptor, file->path))
    return -1;
  unsigned long long fsize = file->data->size;
  long long mtime = file->metadata ? file->metadata->mtime_sec : 0;
  if (!send_n_data(client->file_descriptor, &fsize, sizeof(fsize)))
    return -1;
  if (!send_n_data(client->file_descriptor, &mtime, sizeof(mtime)))
    return -1;
  Status s;
  if (!receive_status(client->file_descriptor, &s))
    return -1;
  if (s == STATUS_ERROR) {
    log_message(LOG_LEVEL_ERROR, "Server reported error for file");
    return -1;
  }
  if (s == STATUS_OK)
    return 1;
  if (s == STATUS_DELTA_SIGNATURE) {
    Data* sig_data = receive_data(client->file_descriptor);
    if (!sig_data)
      return -1;
    DeltaSignature* sig = delta_signature_deserialize(sig_data);
    data_destroy(sig_data);
    if (!sig)
      return -1;
    *out_sig = sig;
    return 2;
  }
  if (s != STATUS_NEXT) {
    log_message(LOG_LEVEL_ERROR, "Unexpected server status");
    return -1;
  }
  return 0;
}

static int send_delta(Client* client, File* file, DeltaSignature* sig, Config* config) {
  Delta* delta = delta_compute(file->data->data, file->data->size, sig, config->delta_block_size);
  if (!delta)
    return 1;

  if (!delta_is_worthwhile(delta, file->data->size)) {
    delta_destroy(delta);
    if (!send_status(client->file_descriptor, STATUS_NEXT))
      return -1;
    return 1;
  }

  Data* delta_data = delta_serialize(delta);
  delta_destroy(delta);
  if (!delta_data)
    return -1;

  Data* to_send = delta_data;
  if (config->use_compression) {
    to_send = data_compress(delta_data, config->compression_level);
    data_destroy(delta_data);
    if (!to_send)
      return -1;
  }

  bool ok = send_status(client->file_descriptor, STATUS_DELTA_DATA) &&
            send_data(client->file_descriptor, to_send);

  if (ok && config->use_metadata)
    ok = metadata_send(client->file_descriptor, file->metadata);

  data_destroy(to_send);
  return ok ? 0 : -1;
}

typedef bool (*file_send_fn)(File*, int, bool, int, bool);

// Send a single file directly (non-incremental path).
static bool send_file_direct(File* file, int fd, bool use_metadata, int compression_level) {
  if (!send_status(fd, STATUS_NEXT))
    return false;
  return file_send_single_calls(file, fd, use_metadata, compression_level, true);
}

// Send a single file directly via sendfile (non-incremental path).
static bool send_file_direct_sendfile(File* file, int fd, bool use_metadata) {
  if (!send_status(fd, STATUS_NEXT))
    return false;
  return file_send_sendfile(file, fd, use_metadata, 0, true);
}

// Process one file in a chunk: either via incremental check or direct send.
// Returns 0 on success, 1 if skipped (incremental match), -1 on error.
static int send_single_file(Client* client, File* file, Config* config, bool use_incremental,
                            bool use_sendfile) {
  int compression_level = config->use_compression ? config->compression_level : 0;

  if (!use_incremental) {
    if (use_sendfile) {
      return send_file_direct_sendfile(file, client->file_descriptor, config->use_metadata) ? 0
                                                                                            : -1;
    }
    return send_file_direct(file, client->file_descriptor, config->use_metadata, compression_level)
               ? 0
               : -1;
  }

  // Incremental path: use sendfile for the actual data if enabled and no compression
  if (use_sendfile) {
    DeltaSignature* sig = NULL;
    int rc = incremental_check(client, file, &sig);
    if (rc == 1) {
      delta_signature_destroy(sig);
      return 1;
    }
    if (rc < 0) {
      delta_signature_destroy(sig);
      return -1;
    }
    // rc == 0 or rc == 2 (delta not possible with sendfile)
    delta_signature_destroy(sig);
    // Fall through: send full file via sendfile (pass 0 for compression_level)
    if (!file_send_sendfile(file, client->file_descriptor, config->use_metadata, 0, false))
      return -1;
    return 0;
  }

  // Incremental path with single_calls (supports compression and delta)
  file_send_fn send_fn = (file_send_fn)file_send_single_calls;
  DeltaSignature* sig = NULL;
  int rc = incremental_check(client, file, &sig);
  if (rc < 0) {
    delta_signature_destroy(sig);
    return -1;
  }
  if (rc == 1) {
    delta_signature_destroy(sig);
    return 1;
  }
  if (rc == 2 && config->use_delta) {
    int drc = send_delta(client, file, sig, config);
    delta_signature_destroy(sig);
    if (drc == 0)
      return 0;
    if (drc < 0)
      return -1;
  } else {
    delta_signature_destroy(sig);
  }
  if (!send_fn(file, client->file_descriptor, config->use_metadata, compression_level, false))
    return -1;
  return 0;
}

int send_chunk(Client* client, Chunk* chunk, Config* config) {
  if (config->use_chunk_serialization) {
    if (!send_status(client->file_descriptor, STATUS_CHUNK))
      return -1;
    Data* data;
    if (config->use_compression) {
      data = chunk_compress(chunk, config->compression_level, config->use_metadata);
    } else {
      data = chunk_serialize(chunk, config->use_metadata);
    }
    if (data == NULL)
      return -1;
    if (!send_data(client->file_descriptor, data)) {
      data_destroy(data);
      return -1;
    }
    data_destroy(data);
    return 0;
  }

  bool use_sendfile = config->use_sendfile && !config->use_compression;
  for (int i = 0; i < chunk->element_count; i++) {
    int rc =
        send_single_file(client, chunk->items[i], config, config->use_incremental, use_sendfile);
    if (rc == 1)
      continue;
    if (rc < 0)
      return -1;
  }
  return 0;
}

static int send_chunks_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  Client* client;
  if (context->config->transport == TRANSPORT_SSH) {
    if (context->config->use_sendfile) {
      fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
      return 1;
    }
    client = client_connect_ssh(context->config->ssh_destination, context->config->ssh_port);
  } else if (context->config->use_tls) {
    client = client_create();
    if (!client || !client_connect_tls(client, context->config->server_host,
                                       context->config->server_port, context->config->tls_cert,
                                       context->config->tls_key, context->config->tls_ca)) {
      if (client)
        client_delete(client);
      fprintf(stderr, "Error: could not connect to server via TLS\n");
      return thrd_error;
    }
  } else {
    client = client_create();
    if (!client ||
        !client_connect(client, context->config->server_host, context->config->server_port)) {
      if (client)
        client_delete(client);
      fprintf(stderr, "Error: could not connect to server\n");
      return thrd_error;
    }
  }
  if (!config_send(client->file_descriptor, context->config)) {
    client_disconnect(client);
    client_delete(client);
    return thrd_error;
  }

  while (true) {
    Chunk* current_chunk = queue_dequeue_multithreaded(
        context->queue_loader, &context->mutex_loader, &context->condition_not_empty_loader,
        &context->condition_not_full_loader, &context->loader_done);
    if (current_chunk == NULL) {
      if (context->config->use_delete) {
        send_status(client->file_descriptor, STATUS_MANIFEST);
        send_int(client->file_descriptor, context->manifest->size);
        for (int i = 0; i < context->manifest->size; i++)
          send_str(client->file_descriptor, (char*)context->manifest->items[i]);
      }
      send_status(client->file_descriptor, STATUS_FINISHED);
      Status s;
      int ok = receive_status(client->file_descriptor, &s) && s == STATUS_OK;
      client_disconnect(client);
      client_delete(client);
      return ok ? thrd_success : thrd_error;
    }
    if (send_chunk(client, current_chunk, context->config) != 0) {
      fprintf(stderr, "Error: unexpected error while sending chunk\n");
      client_disconnect(client);
      client_delete(client);
      return thrd_error;
    }
    chunk_destroy(current_chunk);
  }
}

static int scan_directory_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  mtx_lock(&context->mutex_scanner);
  DirectoryScanner* scanner = directory_scanner_create(
      context->config->send_directory, context->config->use_metadata, context->config->chunk_size,
      context->config->exclude_patterns, context->config->exclude_count,
      context->config->include_patterns, context->config->include_count, context->config->max_size,
      context->config->min_size);
  mtx_unlock(&context->mutex_scanner);

  Chunk* current_chunk;
  while ((current_chunk = directory_scanner_next(scanner)) != NULL) {
    if (context->config->use_delete) {
      mtx_lock(&context->mutex_scanner);
      for (int i = 0; i < current_chunk->element_count; i++) {
        const char* p = current_chunk->items[i]->path;
        if (*p == '/')
          p++;
        array_list_add(context->manifest, str_dup(p));
      }
      mtx_unlock(&context->mutex_scanner);
    }
    queue_enqueue_multithreaded(context->queue_scanner, current_chunk, &context->mutex_scanner,
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

static int load_files_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  while (true) {
    Chunk* chunk = queue_dequeue_multithreaded(
        context->queue_scanner, &context->mutex_scanner, &context->condition_not_empty_scanner,
        &context->condition_not_full_scanner, &context->scanner_done);
    if (chunk == NULL) {
      mtx_lock(&context->mutex_loader);
      context->loader_done = true;
      cnd_signal(&context->condition_not_empty_loader);
      mtx_unlock(&context->mutex_loader);
      return thrd_success;
    }
    if (!context->config->use_sendfile) {
      for (int i = 0; i < chunk->element_count; i++) {
        if (!file_load_data(chunk->items[i])) {
          log_message(LOG_LEVEL_ERROR, "Failed to load file data, skipping");
          file_destroy(chunk->items[i]);
          chunk->items[i] = NULL;
        }
      }
    }
    queue_enqueue_multithreaded(context->queue_loader, chunk, &context->mutex_loader,
                                &context->condition_not_empty_loader,
                                &context->condition_not_full_loader);
  }
}

int send_files(Config* config) {
  if (config->dry_run) {
    DirectoryScanner* scanner = directory_scanner_create(
        config->send_directory, config->use_metadata, config->chunk_size, config->exclude_patterns,
        config->exclude_count, config->include_patterns, config->include_count, config->max_size,
        config->min_size);
    Chunk* chunk;
    int file_count = 0;
    unsigned long long total_bytes = 0;
    printf("Dry run: files to be transferred\n");
    while ((chunk = directory_scanner_next(scanner)) != NULL) {
      for (int i = 0; i < chunk->element_count; i++) {
        printf("  %s (%zu bytes)\n", chunk->items[i]->path, chunk->items[i]->data->size);
        total_bytes += chunk->items[i]->data->size;
        file_count++;
      }
      chunk_destroy(chunk);
    }
    directory_scanner_destroy(scanner);
    printf("Total: %d files, %.1f MB\n", file_count, total_bytes / 1048576.0);
    return 0;
  }

  Client* client;
  if (config->transport == TRANSPORT_SSH) {
    if (config->use_sendfile) {
      fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
      return 1;
    }
    client = client_connect_ssh(config->ssh_destination, config->ssh_port);
    if (!client)
      return 1;
  } else if (config->use_tls) {
    client = client_create();
    if (!client || !client_connect_tls(client, config->server_host, config->server_port,
                                       config->tls_cert, config->tls_key, config->tls_ca)) {
      if (client)
        client_delete(client);
      fprintf(stderr, "Error: could not connect to server via TLS\n");
      return 1;
    }
  } else {
    client = client_create();
    if (!client || !client_connect(client, config->server_host, config->server_port)) {
      if (client)
        client_delete(client);
      fprintf(stderr, "Error: could not connect to server\n");
      return 1;
    }
  }
  if (!config_send(client->file_descriptor, config)) {
    client_disconnect(client);
    client_delete(client);
    return 1;
  }
  DirectoryScanner* scanner = directory_scanner_create(
      config->send_directory, config->use_metadata, config->chunk_size, config->exclude_patterns,
      config->exclude_count, config->include_patterns, config->include_count, config->max_size,
      config->min_size);
  Chunk* current_chunk;
  unsigned long long total_bytes = 0;
  time_t last_progress = 0;
  time_t start = time(NULL);
  ArrayList* manifest = config->use_delete ? array_list_create(free) : NULL;
  while ((current_chunk = directory_scanner_next(scanner)) != NULL) {
    unsigned long long chunk_bytes = 0;
    for (int i = 0; i < current_chunk->element_count; i++) {
      chunk_bytes += current_chunk->items[i]->data->size;
      if (manifest) {
        const char* p = current_chunk->items[i]->path;
        if (*p == '/')
          p++;
        array_list_add(manifest, str_dup(p));
      }
    }
    if (!config->use_sendfile) {
      for (int i = 0; i < current_chunk->element_count; i++) {
        if (!file_load_data(current_chunk->items[i])) {
          log_message(LOG_LEVEL_ERROR, "Failed to load file data");
          continue;
        }
      }
    }
    if (send_chunk(client, current_chunk, config) != 0) {
      log_message(LOG_LEVEL_ERROR, "Failed to send chunk");
      chunk_destroy(current_chunk);
      break;
    }
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
      send_str(client->file_descriptor, (char*)manifest->items[i]);
    array_list_delete(manifest);
  }
  send_status(client->file_descriptor, STATUS_FINISHED);
  Status s;
  int ok = receive_status(client->file_descriptor, &s) && s == STATUS_OK;
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

int send_files_multithreaded(Config* config) {
  if (config->dry_run) {
    DirectoryScanner* scanner = directory_scanner_create(
        config->send_directory, config->use_metadata, config->chunk_size, config->exclude_patterns,
        config->exclude_count, config->include_patterns, config->include_count, config->max_size,
        config->min_size);
    Chunk* chunk;
    int file_count = 0;
    unsigned long long total_bytes = 0;
    printf("Dry run: files to be transferred\n");
    while ((chunk = directory_scanner_next(scanner)) != NULL) {
      for (int i = 0; i < chunk->element_count; i++) {
        printf("  %s (%zu bytes)\n", chunk->items[i]->path, chunk->items[i]->data->size);
        total_bytes += chunk->items[i]->data->size;
        file_count++;
      }
      chunk_destroy(chunk);
    }
    directory_scanner_destroy(scanner);
    printf("Total: %d files, %.1f MB\n", file_count, total_bytes / 1048576.0);
    return 0;
  }

  Queue* q1 = queue_create(100, chunk_destroy);
  Queue* q2 = queue_create(100, chunk_destroy);
  if (!q1 || !q2) {
    if (q1)
      queue_destroy(q1);
    if (q2)
      queue_destroy(q2);
    return 1;
  }
  PipelineContextSender* context = pipeline_context_sender_create(config, q1, q2);
  if (!context) {
    queue_destroy(q1);
    queue_destroy(q2);
    return 1;
  }
  if (config->use_delete)
    context->manifest = array_list_create(free);

  thrd_t scanner, loader, sender;
  if (thrd_create(&scanner, scan_directory_multithreaded, context) != thrd_success ||
      thrd_create(&loader, load_files_multithreaded, context) != thrd_success ||
      thrd_create(&sender, send_chunks_multithreaded, context) != thrd_success) {
    perror("Error creating threads.\n");
    pipeline_context_sender_destroy(context);
    return 1;
  }

  int sender_result;
  thrd_join(scanner, NULL);
  thrd_join(loader, NULL);
  thrd_join(sender, &sender_result);

  pipeline_context_sender_destroy(context);
  return sender_result == thrd_success ? 0 : -1;
}
