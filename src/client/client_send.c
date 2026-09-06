#include "client_send.h"
#include "array_list.h"
#include "change_list.h"
#include "chunk.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delta.h"
#include "file.h"
#include "file_list.h"
#include "filter.h"
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

/* Compiled scanner inputs that are shared read-only across scanner instances
 * and, in -m mode, across worker threads. `base_filters` owns the compiled
 * command-line + -C rules; the FileListSet allow-set lives in the Config. */
typedef struct {
  ScannerOptions options;
  FilterRuleList* base_filters; /* owned; may be NULL */
} PreparedScanner;

/* Build the scanner options for one scan. Returns false and logs on failure. */
static bool prepare_scanner(const Config* config, int num_threads, PreparedScanner* out) {
  if (!out)
    return false;
  out->base_filters = NULL;
  memset(&out->options, 0, sizeof(out->options));

  int rule_count = config->filters ? config->filters->size : 0;
  const char** texts = NULL;
  if (rule_count > 0) {
    texts = malloc((size_t)rule_count * sizeof(char*));
    if (!texts) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed for filter rules");
      return false;
    }
    for (int i = 0; i < rule_count; i++)
      texts[i] = (const char*)config->filters->items[i];
  }
  if (rule_count > 0 || config->cvs_exclude) {
    char err[160];
    out->base_filters = filter_base_build(texts, rule_count, config->cvs_exclude, err, sizeof(err));
    free(texts);
    if (!out->base_filters) {
      log_message(LOG_LEVEL_ERROR, "invalid filter rule: %s", err);
      return false;
    }
  } else {
    free(texts);
  }

  ScannerOptions* options = &out->options;
  options->use_metadata = config->use_metadata;
  options->chunk_size = config->chunk_size;
  options->exclude_patterns = config->exclude_patterns;
  options->exclude_count = config->exclude_count;
  options->include_patterns = config->include_patterns;
  options->include_count = config->include_count;
  options->max_size = config->max_size;
  options->min_size = config->min_size;
  options->max_depth = config->max_depth;
  options->num_threads = num_threads;
  options->follow_symlinks = config->follow_symlinks;
  options->copy_links = config->copy_links;
  options->safe_links = config->safe_links;
  options->copy_unsafe_links = config->copy_unsafe_links;
  options->checksum = config->checksum;
  options->one_file_system = config->one_file_system;
  options->file_list = (const FileListSet*)config->files_from_set;
  options->base_filters = out->base_filters;
  options->per_dir_filters = config->per_dir_filter;
  return true;
}

static void prepared_scanner_destroy(PreparedScanner* prepared) {
  if (!prepared)
    return;
  filter_rule_list_free(prepared->base_filters);
  prepared->base_filters = NULL;
}

/* --files-from semantics: every listed entry must resolve under the source
 * root, otherwise rsync reports a hard error instead of silently transferring
 * nothing. An empty list is also an error. An entry of "." (the whole tree)
 * and listed-but-empty directories are valid. Runs before any transfer so the
 * failure is surfaced uniformly in the single-threaded, -m, dry-run and
 * --list-only paths. */
static bool files_from_list_valid(const Config* config) {
  const FileListSet* set = (const FileListSet*)config->files_from_set;
  if (!set)
    return true;
  if (!config->send_directory) {
    log_message(LOG_LEVEL_ERROR, "--files-from requires a source directory");
    return false;
  }
  if (set->count == 0) {
    log_message(LOG_LEVEL_ERROR, "--files-from file '%s' contains no entries; nothing to transfer",
                config->files_from ? config->files_from : "");
    return false;
  }
  for (int i = 0; i < set->count; i++) {
    const char* entry = set->entries[i];
    if (entry[0] == '\0')
      continue; /* "." == list the whole tree */
    char* full = path_cat(config->send_directory, entry);
    if (!full) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed while validating --files-from");
      return false;
    }
    struct stat st;
    if (lstat(full, &st) != 0) {
      log_message(LOG_LEVEL_ERROR, "--files-from entry '%s' not found in source '%s'", entry,
                  config->send_directory);
      free(full);
      return false;
    }
    free(full);
  }
  return true;
}

/* Select the configured transport for both transfer execution paths. */
static Client* connect_transfer_client(const Config* config) {
  if (config->transport == TRANSPORT_SSH) {
    if (config->use_sendfile) {
      log_message(LOG_LEVEL_ERROR, "-f/--sendfile is not supported with SSH transport");
      return NULL;
    }
    return client_connect_ssh(config->ssh_destination, config->ssh_port,
                              config->fastsync_server_path, config->old_args);
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

/* (finalize_transfer is defined after the SourceFile helpers below.) */

typedef struct SourceFile {
  char* path;
  dev_t device;
  ino_t inode;
  bool skipped; /* receiver reported the file was not written */
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
    if (source->skipped)
      continue;
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
  source->skipped = false;
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

/* Send the final STATUS_FINISHED frame and await the receiver's verdict.
   When --remove-source-files is active the receiver acknowledges each data
   file it processed, in send order: STATUS_NEXT means the file was written,
   STATUS_OK means the file was skipped/unchanged.  Skipped sources are marked
   so the later removal pass keeps them. */
static bool finalize_transfer(Client* client, const Config* config, ArrayList* remove_sources) {
  if (!send_status(client->file_descriptor, STATUS_FINISHED))
    return false;
  if (config->remove_source_files && remove_sources) {
    for (int i = 0; i < remove_sources->size; i++) {
      Status per_file;
      if (!receive_status(client->file_descriptor, &per_file))
        return false;
      if (per_file == STATUS_ERROR)
        return false;
      if (per_file == STATUS_OK) {
        ((SourceFile*)remove_sources->items[i])->skipped = true;
      } else if (per_file != STATUS_NEXT) {
        log_message(LOG_LEVEL_ERROR, "Unexpected per-file status from receiver");
        return false;
      }
    }
  }
  Status status;
  return receive_status(client->file_descriptor, &status) && status == STATUS_OK;
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
  if (!files_from_list_valid(config))
    return -1;
  PreparedScanner prepared;
  if (!prepare_scanner(config, 0, &prepared))
    return -1;
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner) {
    prepared_scanner_destroy(&prepared);
    return -1;
  }
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
          prepared_scanner_destroy(&prepared);
          return -1;
        }
        if (config->human_readable)
          printf(
              "  %s (%s)\n", escaped_path,
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
  prepared_scanner_destroy(&prepared);
  if (!config->quiet) {
    if (config->human_readable)
      printf("Total: %d files, %s\n", file_count,
             display_bytes(total_bytes, true, size_buffer, sizeof(size_buffer)));
    else
      printf("Total: %d files, %.1f MB\n", file_count, total_bytes / 1048576.0);
  }
  return 0;
}

typedef struct {
  char* path;
  mode_t mode;
  unsigned long long size;
  time_t mtime;
} ListEntry;

static void list_entries_destroy(ListEntry* entries, size_t count) {
  if (entries == NULL)
    return;
  for (size_t i = 0; i < count; i++)
    free(entries[i].path);
  free(entries);
}

static int compare_list_entries(const void* left, const void* right) {
  const ListEntry* a = (const ListEntry*)left;
  const ListEntry* b = (const ListEntry*)right;
  return strcmp(a->path, b->path);
}

/* --list-only: print an ls-style listing of the files that WOULD be
 * transferred and exit without contacting the server or writing anything.
 * Directory lines are not printed because the scanner only yields regular
 * transfer candidates. Returns 0 on success, 1 on error. */
static int send_list_only(const Config* config) {
  if (!files_from_list_valid(config))
    return 1;
  PreparedScanner prepared;
  if (!prepare_scanner(config, 0, &prepared))
    return 1;
  prepared.options.use_metadata = true; /* capture mode + mtime for the listing */
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner) {
    prepared_scanner_destroy(&prepared);
    return 1;
  }
  ListEntry* entries = NULL;
  size_t count = 0;
  size_t capacity = 0;
  Chunk* chunk;
  bool oom = false;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count; i++) {
      File* f = chunk->items[i];
      if (f == NULL)
        continue;
      if (count == capacity) {
        size_t new_capacity = capacity > 0 ? capacity * 2 : 64;
        if (new_capacity <= capacity) {
          oom = true;
          break;
        }
        ListEntry* grown = realloc(entries, new_capacity * sizeof(ListEntry));
        if (!grown) {
          oom = true;
          break;
        }
        entries = grown;
        capacity = new_capacity;
      }
      char* path = str_dup(f->path);
      if (!path) {
        oom = true;
        break;
      }
      mode_t mode = 0;
      time_t mtime = 0;
      if (f->metadata != NULL) {
        mode = f->metadata->mode;
        mtime = f->metadata->mtime_sec;
      } else {
        struct stat st;
        if (stat(f->path, &st) == 0) {
          mode = st.st_mode;
          mtime = st.st_mtime;
        }
      }
      entries[count].path = path;
      entries[count].mode = mode;
      entries[count].mtime = mtime;
      entries[count].size = f->data != NULL ? f->data->size : 0;
      count++;
    }
    chunk_destroy(chunk);
    if (oom)
      break;
  }
  bool failed = oom || directory_scanner_failed(scanner);
  directory_scanner_destroy(scanner);
  prepared_scanner_destroy(&prepared);
  if (failed) {
    list_entries_destroy(entries, count);
    if (oom)
      log_message(LOG_LEVEL_ERROR, "memory allocation failed while listing");
    return 1;
  }
  if (count > 1)
    qsort(entries, count, sizeof(ListEntry), compare_list_entries);
  for (size_t i = 0; i < count; i++) {
    char* line = change_render_list_line(entries[i].mode, entries[i].size, entries[i].mtime,
                                         entries[i].path);
    if (line != NULL) {
      char* escaped = output_escape(line, config->eight_bit_output);
      printf("%s\n", escaped != NULL ? escaped : line);
      free(escaped);
      free(line);
    }
  }
  list_entries_destroy(entries, count);
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
  log_info_message(LOG_INFO_COPY, "Transferring %s", file->path);

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
      log_info_message(LOG_INFO_SKIP, "Skipping unchanged %s", file->path);
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
    log_info_message(LOG_INFO_SKIP, "Skipping unchanged %s", file->path);
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
    for (int i = 0; i < chunk->element_count; i++) {
      if (chunk->items[i] != NULL)
        change_emit_file_sent(config, chunk->items[i]);
    }
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
    change_emit_file_sent(config, f);
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
      bool ok = finalize_transfer(client, context->config, context->remove_source_files);
      if (ok)
        remove_transferred_sources(context->config, context->remove_source_files);
      mtx_lock(&context->mutex_progress);
      int total_files = context->total_files;
      unsigned long long total_bytes = context->total_bytes;
      mtx_unlock(&context->mutex_progress);
      if (context->config->stats)
        fprintf(stderr, "Stats: %d files, %.1f MB\n", total_files, total_bytes / 1048576.0);
      log_info_message(LOG_INFO_STATS, "Transfer summary: %d files, %.1f MB", total_files,
                       total_bytes / 1048576.0);
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
    unsigned long long chunk_bytes = 0;
    int chunk_files = 0;
    for (int i = 0; i < current_chunk->element_count; i++) {
      if (current_chunk->items[i] && current_chunk->items[i]->data) {
        chunk_files++;
        chunk_bytes += current_chunk->items[i]->data->size;
      }
    }
    mtx_lock(&context->mutex_progress);
    context->total_files += chunk_files;
    context->total_bytes += chunk_bytes;
    context->progress_bytes = context->total_bytes;
    mtx_unlock(&context->mutex_progress);
    chunk_destroy(current_chunk);
  }
}

static int scan_directory_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  protocol_session_bind(&context->allocation_session);
  PreparedScanner prepared;
  if (!prepare_scanner(context->config, 4, &prepared)) {
    pipeline_cancel(context);
    protocol_session_unbind();
    return thrd_error;
  }
  ParallelScanner* scanner = parallel_scanner_create_with_options(
      context->config->send_directory, &prepared.options, &context->allocation_session);

  Chunk* current_chunk;
  if (scanner == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to create parallel scanner");
    pipeline_cancel(context);
    prepared_scanner_destroy(&prepared);
    protocol_session_unbind();
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
        prepared_scanner_destroy(&prepared);
        protocol_session_unbind();
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
      prepared_scanner_destroy(&prepared);
      protocol_session_unbind();
      return thrd_error;
    }
  }
  if (parallel_scanner_failed(scanner)) {
    parallel_scanner_destroy(scanner);
    prepared_scanner_destroy(&prepared);
    mtx_lock(&context->mutex_scanner);
    context->scanner_done = true;
    cnd_broadcast(&context->condition_not_empty_scanner);
    cnd_broadcast(&context->condition_not_full_scanner);
    mtx_unlock(&context->mutex_scanner);
    pipeline_cancel(context);
    protocol_session_unbind();
    return thrd_error;
  }
  mtx_lock(&context->mutex_scanner);
  context->scanner_done = true;
  cnd_signal(&context->condition_not_empty_scanner);
  mtx_unlock(&context->mutex_scanner);

  parallel_scanner_destroy(scanner);
  prepared_scanner_destroy(&prepared);
  protocol_session_unbind();
  return thrd_success;
}

static int load_files_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  protocol_session_bind(&context->allocation_session);
  while (true) {
    Chunk* chunk = queue_dequeue_multithreaded(
        context->queue_scanner, &context->mutex_scanner, &context->condition_not_empty_scanner,
        &context->condition_not_full_scanner, &context->scanner_done);
    if (chunk == NULL) {
      mtx_lock(&context->mutex_loader);
      context->loader_done = true;
      cnd_signal(&context->condition_not_empty_loader);
      mtx_unlock(&context->mutex_loader);
      protocol_session_unbind();
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
          protocol_session_unbind();
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
      protocol_session_unbind();
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
  if (config->list_only)
    return send_list_only(config);
  if (config->dry_run)
    return send_dry_run_manifest(config);
  if (!files_from_list_valid(config))
    return 1;

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
  PreparedScanner prepared;
  memset(&prepared, 0, sizeof(prepared));
  if (!config_send(client->file_descriptor, config))
    goto send_fail;
  if (!prepare_scanner(config, 0, &prepared))
    goto send_fail;
  scanner = directory_scanner_create_with_options(config->send_directory, &prepared.options);
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
  bool ok = finalize_transfer(client, config, remove_sources);
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
  log_info_message(LOG_INFO_STATS, "Transfer summary: %d files, %.1f MB", total_files,
                   total_bytes / 1048576.0);
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
  prepared_scanner_destroy(&prepared);
  disconnect_transfer_client(client);
  protocol_session_unbind();
  return ret;
}

int send_files_multithreaded(Config** config_ptr) {
  if (!config_ptr || !*config_ptr)
    return 1;
  Config* config = *config_ptr;
  if (config->list_only)
    return send_list_only(config);
  if (config->dry_run)
    return send_dry_run_manifest(config);
  if (!files_from_list_valid(config))
    return 1;

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
