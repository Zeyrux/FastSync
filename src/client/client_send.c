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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>

static volatile sig_atomic_t g_abort_requested = 0;
static int g_abort_fd = -1;

static void handle_sigint(int sig) {
  (void)sig;
  g_abort_requested = 1;
}

#define KEEPALIVE_INTERVAL 30

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

static bool batch_incremental_check(Client* client, ArrayList* files) {
  if (!send_status(client->file_descriptor, STATUS_CHECK_BATCH))
    return false;
  if (!send_int(client->file_descriptor, files->size))
    return false;
  for (int i = 0; i < files->size; i++) {
    File* file = (File*)files->items[i];
    if (!send_str(client->file_descriptor, file->path))
      return false;
    unsigned long long fsize = file->data ? file->data->size : 0;
    long long mtime = file->metadata ? file->metadata->mtime_sec : 0;
    if (!send_n_data(client->file_descriptor, &fsize, sizeof(fsize)))
      return false;
    if (!send_n_data(client->file_descriptor, &mtime, sizeof(mtime)))
      return false;
  }
  for (int i = 0; i < files->size; i++) {
    Status s;
    if (!receive_status(client->file_descriptor, &s))
      return false;
    File* file = (File*)files->items[i];
    if (s == STATUS_OK)
      file->skip = true;
    else if (s == STATUS_ERROR)
      return false;
  }
  return true;
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

  if (file->skip)
    return 1;

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
    // rc == 0: unchanged file, skip
    // rc == 2: server sent delta signature but sendfile doesn't support delta
    delta_signature_destroy(sig);
    if (rc == 2) {
      // Server is waiting for STATUS_NEXT after delta handshake
      if (!send_status(client->file_descriptor, STATUS_NEXT))
        return -1;
    }
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
    // rc == 2 can happen if server sends STATUS_DELTA_SIGNATURE but
    // use_delta is false on the client side. Send STATUS_NEXT to
    // tell the server to proceed with the full file transfer.
    if (rc == 2) {
      if (!send_status(client->file_descriptor, STATUS_NEXT))
        return -1;
    }
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

  g_abort_fd = client->file_descriptor;
  time_t last_activity = time(NULL);
  while (true) {
    if (g_abort_requested) {
      send_status(client->file_descriptor, STATUS_ABORT);
      client_disconnect(client);
      client_delete(client);
      return thrd_error;
    }
    time_t now = time(NULL);
    if (now - last_activity >= KEEPALIVE_INTERVAL) {
      if (!send_status(client->file_descriptor, STATUS_KEEPALIVE)) {
        client_disconnect(client);
        client_delete(client);
        return thrd_error;
      }
      Status s;
      if (!receive_status(client->file_descriptor, &s)) {
        client_disconnect(client);
        client_delete(client);
        return thrd_error;
      }
      last_activity = now;
    }
    Chunk* current_chunk = queue_dequeue_multithreaded(
        context->queue_loader, &context->mutex_loader, &context->condition_not_empty_loader,
        &context->condition_not_full_loader, &context->loader_done);
    if (current_chunk == NULL) {
      if (context->config->use_delete) {
        if (!send_status(client->file_descriptor, STATUS_MANIFEST))
          goto send_fail;
        if (!send_int(client->file_descriptor, context->manifest->size))
          goto send_fail;
        for (int i = 0; i < context->manifest->size; i++) {
          if (!send_str(client->file_descriptor, (char*)context->manifest->items[i]))
            goto send_fail;
        }
      }
      if (!send_status(client->file_descriptor, STATUS_FINISHED))
        goto send_fail;
      Status s;
      int ok = receive_status(client->file_descriptor, &s) && s == STATUS_OK;
      client_disconnect(client);
      client_delete(client);
      return ok ? thrd_success : thrd_error;

    send_fail:
      client_disconnect(client);
      client_delete(client);
      return thrd_error;
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
      context->config->min_size, context->config->max_depth);
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
        config->min_size, config->max_depth);
    Chunk* chunk;
    int file_count = 0;
    unsigned long long total_bytes = 0;
    if (!config->quiet)
      printf("Dry run: files to be transferred\n");
    while ((chunk = directory_scanner_next(scanner)) != NULL) {
      for (int i = 0; i < chunk->element_count; i++) {
        if (!config->quiet)
          printf("  %s (%zu bytes)\n", chunk->items[i]->path, chunk->items[i]->data->size);
        total_bytes += chunk->items[i]->data->size;
        file_count++;
      }
      chunk_destroy(chunk);
    }
    directory_scanner_destroy(scanner);
    if (!config->quiet)
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

  g_abort_fd = client->file_descriptor;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_sigint;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  DirectoryScanner* scanner = directory_scanner_create(
      config->send_directory, config->use_metadata, config->chunk_size, config->exclude_patterns,
      config->exclude_count, config->include_patterns, config->include_count, config->max_size,
      config->min_size, config->max_depth);
  ArrayList* all_files = array_list_create(NULL);
  ArrayList* manifest = config->use_delete ? array_list_create(free) : NULL;
  Chunk* current_chunk;
  while ((current_chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < current_chunk->element_count; i++) {
      File* f = current_chunk->items[i];
      array_list_add(all_files, f);
      current_chunk->items[i] = NULL;
      if (manifest) {
        const char* p = f->path;
        if (*p == '/')
          p++;
        array_list_add(manifest, str_dup(p));
      }
    }
    chunk_destroy(current_chunk);
  }
  directory_scanner_destroy(scanner);
  scanner = NULL;

  bool batch_ok = true;
  if (config->use_incremental && all_files->size > 0) {
    if (!batch_incremental_check(client, all_files)) {
      log_message(LOG_LEVEL_ERROR, "Batch incremental check failed");
      batch_ok = false;
    }
  }

  unsigned long long total_bytes = 0;
  time_t last_progress = 0;
  time_t last_activity = 0;
  time_t start = time(NULL);
  bool use_sendfile = config->use_sendfile && !config->use_compression;
  for (int i = 0; i < all_files->size; i++) {
    File* file = (File*)all_files->items[i];
    if (file->skip)
      continue;
    if (g_abort_requested) {
      send_status(client->file_descriptor, STATUS_ABORT);
      batch_ok = false;
      break;
    }
    time_t now = time(NULL);
    if (now - last_activity >= KEEPALIVE_INTERVAL) {
      if (!send_status(client->file_descriptor, STATUS_KEEPALIVE)) {
        batch_ok = false;
        break;
      }
      Status s;
      if (!receive_status(client->file_descriptor, &s)) {
        batch_ok = false;
        break;
      }
      last_activity = now;
    }
    int compression_level = config->use_compression ? config->compression_level : 0;
    if (!send_status(client->file_descriptor, STATUS_NEXT)) {
      batch_ok = false;
      break;
    }
    if (use_sendfile) {
      if (!file_send_sendfile(file, client->file_descriptor, config->use_metadata, 0, true)) {
        log_message(LOG_LEVEL_ERROR, "Failed to send file via sendfile");
        batch_ok = false;
        break;
      }
    } else {
      if (!file_load_data(file)) {
        log_message(LOG_LEVEL_ERROR, "Failed to load file data");
        continue;
      }
      if (!file_send_single_calls(file, client->file_descriptor, config->use_metadata,
                                  compression_level, true)) {
        log_message(LOG_LEVEL_ERROR, "Failed to send file");
        batch_ok = false;
        break;
      }
    }
    total_bytes += file->data ? file->data->size : 0;
    if (config->show_progress) {
      if (now - last_progress >= 1) {
        last_progress = now;
        double elapsed = difftime(now, start);
        double rate = elapsed > 0 ? total_bytes / (1048576.0 * elapsed) : 0;
        fprintf(stderr, "\rSent %.1f MB  (%.1f MB/s)  ", total_bytes / 1048576.0, rate);
        fflush(stderr);
      }
    }
  }

  if (batch_ok && config->use_delete && manifest) {
    if (!send_status(client->file_descriptor, STATUS_MANIFEST))
      batch_ok = false;
    else if (!send_int(client->file_descriptor, manifest->size))
      batch_ok = false;
    else {
      for (int i = 0; i < manifest->size && batch_ok; i++) {
        if (!send_str(client->file_descriptor, (char*)manifest->items[i]))
          batch_ok = false;
      }
    }
  }
  array_list_delete(manifest);

  if (batch_ok && !send_status(client->file_descriptor, STATUS_FINISHED))
    batch_ok = false;
  Status s;
  int ok = 0;
  if (batch_ok)
    ok = receive_status(client->file_descriptor, &s) && s == STATUS_OK;
  if (config->show_progress) {
    double elapsed = difftime(time(NULL), start);
    double rate = elapsed > 0 ? total_bytes / (1048576.0 * elapsed) : 0;
    fprintf(stderr, "\rSent %.1f MB  (%.1f MB/s)  Done.\n", total_bytes / 1048576.0, rate);
  }
  for (int i = 0; i < all_files->size; i++)
    file_destroy(all_files->items[i]);
  array_list_delete(all_files);
  client_disconnect(client);
  client_delete(client);
  return (batch_ok && ok) ? 0 : -1;
}

int send_files_multithreaded(Config* config) {
  time_t start_time = time(NULL);
  if (config->dry_run) {
    DirectoryScanner* scanner = directory_scanner_create(
        config->send_directory, config->use_metadata, config->chunk_size, config->exclude_patterns,
        config->exclude_count, config->include_patterns, config->include_count, config->max_size,
        config->min_size, config->max_depth);
    Chunk* chunk;
    int file_count = 0;
    unsigned long long total_bytes = 0;
    if (!config->quiet)
      printf("Dry run: files to be transferred\n");
    while ((chunk = directory_scanner_next(scanner)) != NULL) {
      for (int i = 0; i < chunk->element_count; i++) {
        if (!config->quiet)
          printf("  %s (%zu bytes)\n", chunk->items[i]->path, chunk->items[i]->data->size);
        total_bytes += chunk->items[i]->data->size;
        file_count++;
      }
      chunk_destroy(chunk);
    }
    directory_scanner_destroy(scanner);
    if (!config->quiet)
      printf("Total: %d files, %.1f MB\n", file_count, total_bytes / 1048576.0);
    return 0;
  }

  int qsize = config->queue_size > 0 ? config->queue_size : 100;
  Queue* q1 = queue_create(qsize, chunk_destroy);
  Queue* q2 = queue_create(qsize, chunk_destroy);
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

  if (config->stats && !config->quiet) {
    double elapsed = difftime(time(NULL), start_time);
    printf("\nTransfer statistics:\n");
    printf("  Elapsed time: %.1f sec\n", elapsed);
  }

  pipeline_context_sender_destroy(context);
  return sender_result == thrd_success ? 0 : -1;
}
