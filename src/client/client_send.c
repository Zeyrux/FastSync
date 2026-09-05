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
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define STREAM_THRESHOLD (64ULL * 1024 * 1024)

/* Forward declaration for progress-reporting thread used in multithreaded send. */
static int progress_thread_fn(void* arg);

static const char* display_bytes(unsigned long long bytes, bool human_readable, char* buffer,
                                 size_t buffer_size) {
  if (human_readable && format_human_bytes(bytes, buffer, buffer_size))
    return buffer;
  snprintf(buffer, buffer_size, "%.1f MB", bytes / 1048576.0);
  return buffer;
}

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
      log_message(LOG_LEVEL_ERROR, "-f/--sendfile is not supported with SSH transport");
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
    client_disconnect(client);
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

typedef struct {
  char* path;
  dev_t device;
  ino_t inode;
} SourceFile;

static void source_file_destroy(void* item) {
  SourceFile* source = item;
  if (source) {
    free(source->path);
    free(source);
  }
}

/* Remove only the same regular source file that was sent. */
static void remove_transferred_sources(const Config* config, ArrayList* paths) {
  if (!config->remove_source_files || !paths)
    return;
  for (int i = 0; i < paths->size; i++) {
    SourceFile* source = paths->items[i];
    const char* slash = strrchr(source->path, '/');
    const char* leaf = slash ? slash + 1 : source->path;
    char parent[PATH_MAX];
    if (slash) {
      size_t parent_length = (size_t)(slash - source->path);
      if (parent_length == 0)
        parent_length = 1;
      if (parent_length >= sizeof(parent))
        continue;
      memcpy(parent, source->path, parent_length);
      parent[parent_length] = '\0';
    } else {
      (void)snprintf(parent, sizeof(parent), ".");
    }

    int dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
      continue;
    struct stat st;
    if (fstatat(dirfd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode) ||
        st.st_dev != source->device || st.st_ino != source->inode) {
      close(dirfd);
      continue;
    }
    if (unlinkat(dirfd, leaf, 0) != 0)
      log_message(LOG_LEVEL_WARNING, "Could not remove source file %s", source->path);
    close(dirfd);
  }
}

static SourceFile* source_file_create(const File* file) {
  if (!file || !file->path)
    return NULL;
  struct stat st;
  if (lstat(file->path, &st) != 0 || !S_ISREG(st.st_mode))
    return NULL;
  SourceFile* source = malloc(sizeof(*source));
  if (!source)
    return NULL;
  source->path = str_dup(file->path);
  source->device = st.st_dev;
  source->inode = st.st_ino;
  if (!source->path) {
    source_file_destroy(source);
    return NULL;
  }
  return source;
}

static bool remember_source_file(ArrayList* paths, const File* file) {
  if (!paths || !file || !file->path)
    return true;
  SourceFile* source = source_file_create(file);
  if (!source)
    return true;
  if (!array_list_add(paths, source)) {
    source_file_destroy(source);
    return false;
  }
  return true;
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
  char size_buffer[32];
  if (!config->quiet)
    printf("Dry run: files to be transferred\n");
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count; i++) {
      if (!config->quiet) {
        char* escaped_path = output_escape(chunk->items[i]->path, config->eight_bit_output);
        if (!escaped_path) {
          chunk_destroy(chunk);
          directory_scanner_destroy(scanner);
          return -1;
        }
        if (config->human_readable)
          printf("  %s (%s)\n", escaped_path,
                 display_bytes(chunk->items[i]->data->size, true, size_buffer, sizeof(size_buffer)));
        else
          printf("  %s (%zu bytes)\n", escaped_path, chunk->items[i]->data->size);
        free(escaped_path);
      }
      total_bytes += chunk->items[i]->data->size;
      file_count++;
    }
    chunk_destroy(chunk);
  }
  directory_scanner_destroy(scanner);
  if (!config->quiet) {
    if (config->human_readable)
      printf("Total: %d files, %s\n", file_count,
             display_bytes(total_bytes, true, size_buffer, sizeof(size_buffer)));
    else
      printf("Total: %d files, %.1f MB\n", file_count, total_bytes / 1048576.0);
  }
  return 0;
}

/* Send the delete manifest (list of files) to the server. Returns 0 on success, -1 on failure. */
static int send_delete_manifest(int fd, ArrayList* manifest) {
  if (!manifest)
    return -1;
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
  long long mtime_nsec = file->metadata ? file->metadata->mtime_nsec : 0;
  if (!send_n_data(client->file_descriptor, &fsize, sizeof(fsize)))
    return -1;
  if (!send_n_data(client->file_descriptor, &mtime, sizeof(mtime)))
    return -1;
  if (!send_n_data(client->file_descriptor, &mtime_nsec, sizeof(mtime_nsec)))
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
    if (!sig_data) {
      send_status(client->file_descriptor, STATUS_ERROR);
      return -1;
    }
    DeltaSignature* sig = delta_signature_deserialize(sig_data);
    data_destroy(sig_data);
    if (!sig) {
      send_status(client->file_descriptor, STATUS_ERROR);
      return -1;
    }
    *out_sig = sig;
    return 2;
  }
  if (s != STATUS_NEXT) {
    log_message(LOG_LEVEL_ERROR, "Unexpected server status");
    send_status(client->file_descriptor, STATUS_ERROR);
    return -1;
  }
  return 0;
}

static int send_delta(Client* client, File* file, DeltaSignature* sig, Config* config) {
  Delta* delta = delta_compute(file->data->data, file->data->size, sig, config->delta_block_size);
  /* The receiver is blocked after sending the signature.  Every local
     fallback therefore needs the explicit NEXT response before full data. */
  if (!delta)
    return send_status(client->file_descriptor, STATUS_NEXT) ? 1 : -1;

  if (!delta_is_worthwhile(delta, file->data->size)) {
    delta_destroy(delta);
    if (!send_status(client->file_descriptor, STATUS_NEXT))
      return -1;
    return 1;
  }

  Data* delta_data = delta_serialize(delta);
  delta_destroy(delta);
  if (!delta_data)
    return send_status(client->file_descriptor, STATUS_NEXT) ? 1 : -1;

  Data* to_send = delta_data;
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  if (config->use_compression && !compression_should_skip_with_suffixes(
                                     file->path, config->skip_compress_suffixes, skip_count)) {
    to_send = data_compress_with_threads(delta_data, config->compression_level,
                                         config->compression_threads);
    data_destroy(delta_data);
    if (!to_send)
      return send_status(client->file_descriptor, STATUS_NEXT) ? 1 : -1;
  }

  bool ok = send_status(client->file_descriptor, STATUS_DELTA_DATA) &&
            send_data(client->file_descriptor, to_send);

  if (ok && config->use_metadata)
    ok = metadata_send(client->file_descriptor, file->metadata);

  data_destroy(to_send);
  return ok ? 0 : -1;
}

// Send a single file directly (non-incremental path).
static bool send_file_direct(File* file, int fd, bool use_metadata, int compression_level,
                             const Config* config) {
  if (!send_status(fd, STATUS_NEXT))
    return false;
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  return file_send_single_calls_with_skip(file, fd, use_metadata, compression_level, true,
                                          config->skip_compress_suffixes, skip_count,
                                          config->compression_threads);
}

// Send a single file directly via sendfile (non-incremental path).
static bool send_file_direct_sendfile(File* file, int fd, bool use_metadata, const Config* config) {
  if (!send_status(fd, STATUS_NEXT))
    return false;
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  return file_send_sendfile_with_skip(file, fd, use_metadata, 0, true,
                                      config->skip_compress_suffixes, skip_count,
                                      config->compression_threads);
}

// Process one file in a chunk: either via incremental check or direct send.
// Returns 0 on success, 1 if skipped (incremental match), -1 on error.
static int send_single_file(Client* client, File* file, Config* config, bool use_incremental,
                            bool use_sendfile) {
  int compression_level = config->use_compression ? config->compression_level : 0;

  if (!use_incremental) {
    if (use_sendfile) {
      return send_file_direct_sendfile(file, client->file_descriptor, config->use_metadata, config)
                 ? 0
                 : -1;
    }
    return send_file_direct(file, client->file_descriptor, config->use_metadata, compression_level,
                            config)
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
    int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
    if (!file_send_sendfile_with_skip(file, client->file_descriptor, config->use_metadata, 0, false,
                                      config->skip_compress_suffixes, skip_count,
                                      config->compression_threads))
      return -1;
    return 0;
  }

  // Incremental path with single_calls (supports compression and delta)
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
  if (rc == 2 && config->use_delta && !config->whole_file) {
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
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  if (!file_send_single_calls_with_skip(file, client->file_descriptor, config->use_metadata,
                                        compression_level, false, config->skip_compress_suffixes,
                                        skip_count, config->compression_threads))
    return -1;
  return 0;
}

static int send_chunk_with_removal(Client* client, Chunk* chunk, Config* config,
                                   ArrayList* remove_sources) {
  if (config->use_chunk_serialization) {
    if (remove_sources) {
      for (int i = 0; i < chunk->element_count; i++) {
        if (!remember_source_file(remove_sources, chunk->items[i]))
          return -1;
      }
    }
    if (!send_status(client->file_descriptor, STATUS_CHUNK))
      return -1;
    Data* data;
    if (config->use_compression) {
      data = chunk_compress_with_threads(chunk, config->compression_level, config->use_metadata,
                                         config->compression_threads);
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
    bool use_sendfile =
        (config->use_sendfile && !config->use_compression) || (stream && !config->use_compression);
    SourceFile* source = remove_sources ? source_file_create(f) : NULL;
    int rc = send_single_file(client, f, config, config->use_incremental, use_sendfile);
    if (rc == 1) {
      source_file_destroy(source);
      continue;
    }
    if (rc < 0) {
      source_file_destroy(source);
      return -1;
    }
    if (source && !array_list_add(remove_sources, source)) {
      source_file_destroy(source);
      return -1;
    }
  }
  return 0;
}

int send_chunk(Client* client, Chunk* chunk, Config* config) {
  return send_chunk_with_removal(client, chunk, config, NULL);
}

static int send_chunks_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  Client* client = connect_transfer_client(context->config);
  if (!client) {
    if (context->config->transport == TRANSPORT_TCP)
      log_message(LOG_LEVEL_ERROR, "could not connect to server%s",
                  context->config->use_tls ? " via TLS" : "");
    pipeline_cancel(context);
    mark_sender_done(context);
    return thrd_error;
  }
  ProtocolSession session;
  protocol_session_init(&session, client->file_descriptor, client->file_descriptor);
  protocol_session_set_ssl(&session, (SSL*)client->ssl);
  protocol_session_bind(&session);
  if (!config_send(client->file_descriptor, context->config)) {
    pipeline_cancel(context);
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
      if (atomic_load(&context->cancelled)) {
        pipeline_cancel(context);
        disconnect_transfer_client(client);
        mark_sender_done(context);
        protocol_session_unbind();
        return thrd_error;
      }
      if (context->config->use_delete) {
        if (send_delete_manifest(client->file_descriptor, context->manifest) != 0)
          goto send_fail;
      }
      bool ok = finalize_transfer(client);
      if (ok)
        remove_transferred_sources(context->config, context->remove_source_files);
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
    if (send_chunk_with_removal(client, current_chunk, context->config,
                                context->remove_source_files) != 0) {
      log_message(LOG_LEVEL_ERROR, "unexpected error while sending chunk");
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
        if (f->data->size > STREAM_THRESHOLD && !context->config->use_compression)
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
      pipeline_cancel(context);
      return thrd_error;
    }
  }
}

/* Print a one-line transfer progress report to stderr. `suffix` ends the
   line (e.g. "Done.\n") or is "" for in-place refresh. Shared by the
   single-threaded loop and the multithreaded progress thread. */
static void print_transfer_progress(unsigned long long total_bytes, time_t start,
                                    const char* suffix, bool human_readable) {
  double elapsed = difftime(time(NULL), start);
  double rate = elapsed > 0.0 ? total_bytes / (1048576.0 * elapsed) : 0.0;
  if (human_readable) {
    char total_buffer[32];
    char rate_buffer[32];
    fprintf(stderr, "\rSent %s  (%s/s)  %s",
            display_bytes(total_bytes, true, total_buffer, sizeof(total_buffer)),
            display_bytes((unsigned long long)(rate * 1048576.0), true, rate_buffer,
                          sizeof(rate_buffer)),
            suffix);
  } else {
    fprintf(stderr, "\rSent %.1f MB  (%.1f MB/s)  %s", total_bytes / 1048576.0, rate, suffix);
  }
  fflush(stderr);
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
      print_transfer_progress(total, start, "Done.\n", context->config->human_readable);
      break;
    }

    time_t now = time(NULL);
    if (now - last_progress >= 1) {
      last_progress = now;
      print_transfer_progress(total, start, "", context->config->human_readable);
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
      log_message(LOG_LEVEL_ERROR, "could not connect to server%s",
                  config->use_tls ? " via TLS" : "");
    return 1;
  }
  ProtocolSession session;
  protocol_session_init(&session, client->file_descriptor, client->file_descriptor);
  protocol_session_set_ssl(&session, (SSL*)client->ssl);
  protocol_session_bind(&session);
  int ret = 1;
  DirectoryScanner* scanner = NULL;
  ArrayList* manifest = NULL;
  ArrayList* remove_sources = NULL;
  if (!config_send(client->file_descriptor, config))
    goto send_fail;
  ScannerOptions scanner_options = scanner_options_from_config(config, 0);
  scanner = directory_scanner_create_with_options(config->send_directory, &scanner_options);
  manifest = create_transfer_manifest(config);
  if (config->remove_source_files)
    remove_sources = array_list_create(source_file_destroy);
  if (!scanner || (config->use_delete && !manifest) ||
      (config->remove_source_files && !remove_sources))
    goto send_fail;
  Chunk* current_chunk;
  unsigned long long total_bytes = 0;
  int total_files = 0;
  time_t last_progress = 0;
  time_t start = time(NULL);
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
      bool load_ok = true;
      for (int i = 0; i < current_chunk->element_count; i++) {
        File* f = current_chunk->items[i];
        if (f->data->size > STREAM_THRESHOLD && !config->use_compression)
          continue;
        if (!file_load_data(f)) {
          log_message(LOG_LEVEL_ERROR, "Failed to load file data");
          load_ok = false;
          break;
        }
      }
      if (!load_ok) {
        chunk_destroy(current_chunk);
        goto send_fail;
      }
    }
    if (send_chunk_with_removal(client, current_chunk, config, remove_sources) != 0) {
      log_message(LOG_LEVEL_ERROR, "Failed to send chunk");
      chunk_destroy(current_chunk);
      if (manifest)
        array_list_delete(manifest);
      manifest = NULL;
      break;
    }
    total_bytes += chunk_bytes;
    if (config->show_progress && !config->quiet) {
      time_t now = time(NULL);
      if (now - last_progress >= 1) {
        last_progress = now;
        print_transfer_progress(total_bytes, start, "", config->human_readable);
      }
    }
    chunk_destroy(current_chunk);
  }
  if (directory_scanner_failed(scanner) || (config->use_delete && manifest == NULL))
    goto send_fail;
  if (config->use_delete) {
    if (send_delete_manifest(client->file_descriptor, manifest) != 0) {
      array_list_delete(manifest);
      manifest = NULL;
      goto send_fail;
    }
    array_list_delete(manifest);
    manifest = NULL;
  }
  bool ok = finalize_transfer(client);
  if (ok)
    remove_transferred_sources(config, remove_sources);
  if (config->show_progress && !config->quiet)
    print_transfer_progress(total_bytes, start, "Done.\n", config->human_readable);
  if (config->stats && !config->quiet) {
    double elapsed_total = difftime(time(NULL), start);
    double rate = elapsed_total > 0 ? total_bytes / (1048576.0 * elapsed_total) : 0;
    if (config->human_readable) {
      char total_buffer[32];
      char rate_buffer[32];
      fprintf(stderr, "Stats: %d files, %s, %s/s\n", total_files,
              display_bytes(total_bytes, true, total_buffer, sizeof(total_buffer)),
              display_bytes((unsigned long long)(rate * 1048576.0), true, rate_buffer,
                            sizeof(rate_buffer)));
    } else {
      fprintf(stderr, "Stats: %d files, %.1f MB, %.1f MB/s\n", total_files, total_bytes / 1048576.0,
              rate);
    }
  }
  ret = ok ? 0 : 1;

send_fail:
  /* Single cleanup path for all exits. The manifest is intentionally deleted
     here even on success without --delete, fixing a pre-existing leak. */
  if (manifest)
    array_list_delete(manifest);
  if (remove_sources)
    array_list_delete(remove_sources);
  if (scanner)
    directory_scanner_destroy(scanner);
  disconnect_transfer_client(client);
  protocol_session_unbind();
  return ret;
}

int send_files_multithreaded(Config** config_ptr) {
  if (!config_ptr || !*config_ptr)
    return 1;
  Config* config = *config_ptr;
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
  *config_ptr = NULL; /* context now owns config through all remaining paths */
  if (config->use_delete)
    context->manifest = array_list_create(free);
  if (config->remove_source_files)
    context->remove_source_files = array_list_create(source_file_destroy);
  if ((config->use_delete && !context->manifest) ||
      (config->remove_source_files && !context->remove_source_files)) {
    pipeline_context_sender_destroy(context);
    return 1;
  }

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
    log_perror("Error creating threads");
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
  if (config->show_progress && !config->quiet) {
    progress_created = (thrd_create(&progress, progress_thread_fn, context) == thrd_success);
    if (!progress_created) {
      log_perror("Error creating progress thread");
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
