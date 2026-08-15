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
#include <unistd.h>

#define STREAM_THRESHOLD (64ULL * 1024 * 1024)

/* Forward declaration for progress-reporting thread used in multithreaded send. */
static int progress_thread_fn(void* arg);

static ScannerOptions scanner_options_from_config(const Config* config, int num_threads) {
  ScannerOptions options = {
      config->use_metadata,  config->chunk_size,        config->exclude_patterns,
      config->exclude_count, config->include_patterns,  config->include_count,
      config->max_size,      config->min_size,          config->max_depth,
      num_threads,           config->follow_symlinks,   config->copy_links,
      config->safe_links,    config->copy_unsafe_links, config->checksum};
  return options;
}

/* Select the configured transport for both transfer execution paths. */
static Client* connect_transfer_client(const Config* config) {
  if (config->transport == TRANSPORT_SSH) {
    if (config->use_sendfile) {
      fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
      return NULL;
    }
    return client_connect_ssh(config->ssh_destination, config->ssh_port,
                              config->fastsync_server_path);
  }

  Client* client = client_create();
  if (!client)
    return NULL;
  bool connected;
  if (config->use_tls) {
    connected = client_connect_tls(client, config->server_host, config->server_port,
                                   config->tls_cert, config->tls_key, config->tls_ca);
  } else {
    connected = client_connect(client, config->server_host, config->server_port);
  }
  if (!connected) {
    client_delete(client);
    return NULL;
  }
  return client;
}

static void disconnect_transfer_client(Client* client) {
  if (!client)
    return;
  client_disconnect(client);
  client_delete(client);
}

static ArrayList* create_transfer_manifest(const Config* config) {
  return config->use_delete ? array_list_create(free) : NULL;
}

static bool add_chunk_to_manifest(ArrayList* manifest, const Chunk* chunk) {
  if (!manifest)
    return true;
  for (int i = 0; i < chunk->element_count; i++) {
    const char* path = chunk->items[i]->path;
    if (*path == '/')
      path++;
    char* entry = str_dup(path);
    if (!entry) {
      log_message(LOG_LEVEL_ERROR, "Failed to allocate manifest entry");
      return false;
    }
    if (!array_list_add(manifest, entry)) {
      free(entry);
      return false;
    }
  }
  return true;
}

static bool finalize_transfer(Client* client) {
  Status status;
  return send_status(client->file_descriptor, STATUS_FINISHED) &&
         receive_status(client->file_descriptor, &status) && status == STATUS_OK;
}

static void mark_sender_done(PipelineContextSender* context) {
  mtx_lock(&context->mutex_progress);
  context->sender_done = true;
  mtx_unlock(&context->mutex_progress);
}

static void pipeline_cancel(PipelineContextSender* context) {
  mtx_lock(&context->mutex_scanner);
  mtx_lock(&context->mutex_loader);
  atomic_store(&context->cancelled, true);
  context->scanner_done = true;
  context->loader_done = true;
  cnd_broadcast(&context->condition_not_full_scanner);
  cnd_broadcast(&context->condition_not_empty_scanner);
  cnd_broadcast(&context->condition_not_full_loader);
  cnd_broadcast(&context->condition_not_empty_loader);
  mtx_unlock(&context->mutex_loader);
  mtx_unlock(&context->mutex_scanner);
}

/* Print dry-run manifest showing files that would be transferred. Returns 0 on success. */
static int send_dry_run_manifest(const Config* config) {
  ScannerOptions options = scanner_options_from_config(config, 0);
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &options);
  if (!scanner)
    return -1;
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

/* Send the delete manifest (list of files) to the server. Returns 0 on success, -1 on failure. */
static int send_delete_manifest(int fd, ArrayList* manifest) {
  if (!send_status(fd, STATUS_MANIFEST))
    return -1;
  if (!send_int(fd, manifest->size))
    return -1;
  for (int i = 0; i < manifest->size; i++) {
    if (!send_str(fd, (char*)manifest->items[i]))
      return -1;
  }
  return 0;
}

static int incremental_check(Client* client, File* file, const Config* config,
                             DeltaSignature** out_sig) {
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
  if (config->checksum) {
    uint64_t checksum;
    if (!file_checksum(file, &checksum) ||
        !send_n_data(client->file_descriptor, &checksum, sizeof(checksum)))
      return -1;
  }
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
  if (!delta) {
    if (!send_status(client->file_descriptor, STATUS_NEXT))
      return -1;
    return 1;
  }

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
    int rc = incremental_check(client, file, config, &sig);
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
  int rc = incremental_check(client, file, config, &sig);
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

  for (int i = 0; i < chunk->element_count; i++) {
    File* f = chunk->items[i];
    if (f == NULL)
      continue;
    bool stream = f->data->data == NULL && f->data->size > 0;
    bool use_sendfile = (config->use_sendfile && !config->use_compression) || stream;
    int rc = send_single_file(client, f, config, config->use_incremental, use_sendfile);
    if (rc == 1)
      continue;
    if (rc < 0)
      return -1;
  }
  return 0;
}

static int send_chunks_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  Client* client = connect_transfer_client(context->config);
  if (!client) {
    if (context->config->transport == TRANSPORT_TCP)
      fprintf(stderr, "Error: could not connect to server%s\n",
              context->config->use_tls ? " via TLS" : "");
    mark_sender_done(context);
    return thrd_error;
  }
  ProtocolSession session;
  protocol_session_init(&session, client->file_descriptor, client->file_descriptor);
  protocol_session_set_ssl(&session, (SSL*)client->ssl);
  protocol_session_bind(&session);
  if (!config_send(client->file_descriptor, context->config)) {
    disconnect_transfer_client(client);
    mark_sender_done(context);
    protocol_session_unbind();
    return thrd_error;
  }

  while (true) {
    Chunk* current_chunk = queue_dequeue_multithreaded(
        context->queue_loader, &context->mutex_loader, &context->condition_not_empty_loader,
        &context->condition_not_full_loader, &context->loader_done);
    if (current_chunk == NULL) {
      if (context->config->use_delete) {
        if (send_delete_manifest(client->file_descriptor, context->manifest) != 0)
          goto send_fail;
      }
      bool ok = finalize_transfer(client);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return ok ? thrd_success : thrd_error;

    send_fail:
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
    if (send_chunk(client, current_chunk, context->config) != 0) {
      fprintf(stderr, "Error: unexpected error while sending chunk\n");
      chunk_destroy(current_chunk);
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
    if (context->config->show_progress) {
      unsigned long long chunk_bytes = 0;
      for (int i = 0; i < current_chunk->element_count; i++) {
        if (current_chunk->items[i] && current_chunk->items[i]->data)
          chunk_bytes += current_chunk->items[i]->data->size;
      }
      mtx_lock(&context->mutex_progress);
      context->progress_bytes += chunk_bytes;
      mtx_unlock(&context->mutex_progress);
    }
    chunk_destroy(current_chunk);
  }
}

static int scan_directory_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  ScannerOptions options = scanner_options_from_config(context->config, 4);
  ParallelScanner* scanner =
      parallel_scanner_create_with_options(context->config->send_directory, &options);

  Chunk* current_chunk;
  if (scanner == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to create parallel scanner");
    pipeline_cancel(context);
    return thrd_error;
  }
  while ((current_chunk = parallel_scanner_next(scanner)) != NULL) {
    if (context->config->use_delete) {
      mtx_lock(&context->mutex_scanner);
      bool manifest_ok = add_chunk_to_manifest(context->manifest, current_chunk);
      mtx_unlock(&context->mutex_scanner);
      if (!manifest_ok) {
        pipeline_cancel(context);
        chunk_destroy(current_chunk);
        parallel_scanner_destroy(scanner);
        return thrd_error;
      }
    }
    if (!queue_enqueue_multithreaded_cancel(
            context->queue_scanner, current_chunk, &context->mutex_scanner,
            &context->condition_not_empty_scanner, &context->condition_not_full_scanner,
            &context->cancelled)) {
      chunk_destroy(current_chunk);
      pipeline_cancel(context);
      parallel_scanner_destroy(scanner);
      return thrd_error;
    }
  }
  if (parallel_scanner_failed(scanner)) {
    parallel_scanner_destroy(scanner);
    mtx_lock(&context->mutex_scanner);
    context->scanner_done = true;
    cnd_broadcast(&context->condition_not_empty_scanner);
    cnd_broadcast(&context->condition_not_full_scanner);
    mtx_unlock(&context->mutex_scanner);
    pipeline_cancel(context);
    return thrd_error;
  }
  mtx_lock(&context->mutex_scanner);
  context->scanner_done = true;
  cnd_signal(&context->condition_not_empty_scanner);
  mtx_unlock(&context->mutex_scanner);

  parallel_scanner_destroy(scanner);
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
        File* f = chunk->items[i];
        if (f->data->size > STREAM_THRESHOLD)
          continue;
        if (!file_load_data(f)) {
          log_message(LOG_LEVEL_ERROR, "Failed to load file data");
          chunk_destroy(chunk);
          pipeline_cancel(context);
          return thrd_error;
        }
      }
    }
    if (!queue_enqueue_multithreaded_cancel(context->queue_loader, chunk, &context->mutex_loader,
                                            &context->condition_not_empty_loader,
                                            &context->condition_not_full_loader,
                                            &context->cancelled)) {
      chunk_destroy(chunk);
      atomic_store(&context->cancelled, true);
      cnd_broadcast(&context->condition_not_full_loader);
      cnd_broadcast(&context->condition_not_empty_loader);
      return thrd_error;
    }
  }
}

/* Progress-reporting thread for multithreaded send. Runs in parallel with
   the scanner/loader/sender threads and prints periodic progress to stderr. */
static int progress_thread_fn(void* arg) {
  PipelineContextSender* context = (PipelineContextSender*)arg;
  time_t last_progress = 0;
  time_t start = time(NULL);

  while (true) {
    mtx_lock(&context->mutex_progress);
    bool done = context->sender_done;
    unsigned long long total = context->progress_bytes;
    mtx_unlock(&context->mutex_progress);

    if (done) {
      time_t now = time(NULL);
      double elapsed = difftime(now, start);
      double rate = elapsed > 0.0 ? total / (1048576.0 * elapsed) : 0.0;
      fprintf(stderr, "\rSent %.1f MB  (%.1f MB/s)  Done.\n", total / 1048576.0, rate);
      break;
    }

    time_t now = time(NULL);
    if (now - last_progress >= 1) {
      last_progress = now;
      double elapsed = difftime(now, start);
      double rate = elapsed > 0.0 ? total / (1048576.0 * elapsed) : 0.0;
      fprintf(stderr, "\rSent %.1f MB  (%.1f MB/s)  ", total / 1048576.0, rate);
      fflush(stderr);
    }

    struct timespec ts = {0, 100 * 1000000L}; /* 100 ms */
    thrd_sleep(&ts, NULL);
  }
  return thrd_success;
}

int send_files(Config* config) {
  if (config->dry_run)
    return send_dry_run_manifest(config);

  Client* client = connect_transfer_client(config);
  if (!client) {
    if (config->transport == TRANSPORT_TCP)
      fprintf(stderr, "Error: could not connect to server%s\n", config->use_tls ? " via TLS" : "");
    return 1;
  }
  ProtocolSession session;
  protocol_session_init(&session, client->file_descriptor, client->file_descriptor);
  protocol_session_set_ssl(&session, (SSL*)client->ssl);
  protocol_session_bind(&session);
  if (!config_send(client->file_descriptor, config)) {
    disconnect_transfer_client(client);
    protocol_session_unbind();
    return 1;
  }
  ScannerOptions scanner_options = scanner_options_from_config(config, 0);
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &scanner_options);
  Chunk* current_chunk;
  unsigned long long total_bytes = 0;
  int total_files = 0;
  time_t last_progress = 0;
  time_t start = time(NULL);
  ArrayList* manifest = create_transfer_manifest(config);
  if (!scanner || (config->use_delete && !manifest)) {
    if (scanner)
      directory_scanner_destroy(scanner);
    if (manifest)
      array_list_delete(manifest);
    disconnect_transfer_client(client);
    protocol_session_unbind();
    return 1;
  }
  while ((current_chunk = directory_scanner_next(scanner)) != NULL) {
    unsigned long long chunk_bytes = 0;
    for (int i = 0; i < current_chunk->element_count; i++) {
      chunk_bytes += current_chunk->items[i]->data->size;
      total_files++;
    }
    if (!add_chunk_to_manifest(manifest, current_chunk)) {
      chunk_destroy(current_chunk);
      goto send_fail;
    }
    if (!config->use_sendfile) {
      for (int i = 0; i < current_chunk->element_count; i++) {
        File* f = current_chunk->items[i];
        if (f->data->size > STREAM_THRESHOLD)
          continue;
        if (!file_load_data(f)) {
          log_message(LOG_LEVEL_ERROR, "Failed to load file data");
          chunk_destroy(current_chunk);
          goto send_fail;
        }
      }
    }
    if (send_chunk(client, current_chunk, config) != 0) {
      log_message(LOG_LEVEL_ERROR, "Failed to send chunk");
      chunk_destroy(current_chunk);
      if (manifest)
        array_list_delete(manifest);
      manifest = NULL;
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
  if (directory_scanner_failed(scanner) || (config->use_delete && manifest == NULL))
    goto send_fail;
  if (config->use_delete) {
    if (send_delete_manifest(client->file_descriptor, manifest) != 0) {
      array_list_delete(manifest);
      goto send_fail;
    }
    array_list_delete(manifest);
    manifest = NULL;
  }
  bool ok = finalize_transfer(client);
  double elapsed_total = difftime(time(NULL), start);
  if (config->show_progress) {
    double rate = elapsed_total > 0 ? total_bytes / (1048576.0 * elapsed_total) : 0;
    fprintf(stderr, "\rSent %.1f MB  (%.1f MB/s)  Done.\n", total_bytes / 1048576.0, rate);
  }
  if (config->stats) {
    double rate = elapsed_total > 0 ? total_bytes / (1048576.0 * elapsed_total) : 0;
    fprintf(stderr, "Stats: %d files, %.1f MB, %.1f MB/s\n", total_files, total_bytes / 1048576.0,
            rate);
  }
  directory_scanner_destroy(scanner);
  disconnect_transfer_client(client);
  protocol_session_unbind();
  return ok ? 0 : 1;

send_fail:
  if (manifest)
    array_list_delete(manifest);
  directory_scanner_destroy(scanner);
  disconnect_transfer_client(client);
  protocol_session_unbind();
  return 1;
}

int send_files_multithreaded(Config* config) {
  if (config->dry_run)
    return send_dry_run_manifest(config);

  long pages = sysconf(_SC_AVPHYS_PAGES);
  long page_size = sysconf(_SC_PAGE_SIZE);
  unsigned long long available_memory =
      pages > 0 && page_size > 0 ? (unsigned long long)pages * (unsigned long long)page_size
                                 : 512ULL * 1024 * 1024;
  unsigned long long avg_file_size = 1024 * 1024;
  int qsize = (int)(available_memory / avg_file_size);
  if (qsize < 10)
    qsize = 10;
  if (qsize > 1000)
    qsize = 1000;

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
    context->manifest = create_transfer_manifest(config);

  thrd_t scanner, loader, sender;
  bool scanner_created = false;
  bool loader_created = false;
  bool sender_created = false;

  scanner_created = (thrd_create(&scanner, scan_directory_multithreaded, context) == thrd_success);
  if (scanner_created)
    loader_created = (thrd_create(&loader, load_files_multithreaded, context) == thrd_success);
  if (scanner_created && loader_created)
    sender_created = (thrd_create(&sender, send_chunks_multithreaded, context) == thrd_success);

  if (!scanner_created || !loader_created || !sender_created) {
    perror("Error creating threads.\n");
    pipeline_cancel(context);
    mtx_lock(&context->mutex_progress);
    context->sender_done = true;
    mtx_unlock(&context->mutex_progress);
    if (sender_created)
      thrd_join(sender, NULL);
    if (loader_created)
      thrd_join(loader, NULL);
    if (scanner_created)
      thrd_join(scanner, NULL);
    pipeline_context_sender_destroy(context);
    return 1;
  }

  thrd_t progress;
  bool progress_created = false;
  if (config->show_progress) {
    progress_created = (thrd_create(&progress, progress_thread_fn, context) == thrd_success);
    if (!progress_created) {
      perror("Error creating progress thread.\n");
      /* Non-fatal; continue without progress reporting */
    }
  }

  int sender_result;
  thrd_join(scanner, NULL);
  thrd_join(loader, NULL);
  thrd_join(sender, &sender_result);

  if (progress_created) {
    /* Signal progress thread to exit if it hasn't already */
    mtx_lock(&context->mutex_progress);
    context->sender_done = true;
    mtx_unlock(&context->mutex_progress);
    thrd_join(progress, NULL);
  }

  pipeline_context_sender_destroy(context);
  return sender_result == thrd_success ? 0 : 1;
}
