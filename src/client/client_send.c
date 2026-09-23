#include "client_send.h"
#include "client_send_internal.h"
#include "array_list.h"
#include "batch.h"
#include "change_list.h"
#include "charset.h"
#include "chunk.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delete_plan.h"
#include "delta.h"
#include "file.h"
#include "file_list.h"
#include "filter.h"
#include "format.h"
#include "hardlink.h"
#include "metadata.h"
#include "motd.h"
#include "log.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "scanner.h"
#include "stop_condition.h"
#include "transport_tcp.h"
#include "transport_ssh.h"
#include "transport_tls.h"
#include "utils.h"
#include "xattr.h"
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

/* Aggregate loaded payload bytes the sender may buffer across the loader queue
   and the chunk in flight.  Sending one chunk adds up to ~2 * MAX_CHUNK_SIZE of
   transient serialize/compress buffers on top of the queued payloads, so this
   ceiling keeps total pipeline memory within MAX_CONNECTION_MEMORY (mirrors the
   receiver's RECEIVER_QUEUE_MAX_BYTES). */
#define SENDER_QUEUE_MAX_BYTES (MAX_CONNECTION_MEMORY - 2 * MAX_CHUNK_SIZE)

/* rsync's --ignore-errors semantics: an I/O error during the transfer normally
 * suppresses deletion entirely ("IO error encountered -- skipping file
 * deletion"); --ignore-errors lets the deletion run anyway.  FastSync always
 * continues past an unreadable subdirectory so the readable tree transfers, and
 * always reports the partial transfer (exit 23); this only decides whether the
 * deletion phase is skipped.  Returns true when deletion may proceed. */
bool ignore_errors_allows_delete(const Config* config, bool had_io_error) {
  return !had_io_error || (config && config->ignore_errors);
}

/* Read the daemon's MOTD frame and, unless --no-motd, display it on stdout.
 *
 * The daemon sends the MOTD as the first thing after the config-frame STATUS_OK
 * on a host::module/path connection (rsync semantics), so this runs immediately
 * after config_send succeeds.  The frame is ALWAYS consumed for a daemon
 * connection -- even with --no-motd -- so the byte stream stays in sync; the
 * flag only suppresses the display.  A non-daemon (local TCP / SSH) connection
 * has no MOTD frame.  The text is rendered through motd_render so a hostile
 * server cannot inject terminal escape sequences.  A read failure is not fatal
 * here: the transfer that follows surfaces the real connection error. */
void receive_daemon_motd(Client* client, const Config* config) {
  if (!config->module || config->module[0] == '\0')
    return;
  char* motd = motd_receive(client->file_descriptor);
  if (!motd)
    return;
  if (!config->no_motd && motd[0] != '\0') {
    char* rendered = motd_render(motd, config->eight_bit_output);
    if (rendered) {
      fputs(rendered, stdout);
      size_t length = strlen(rendered);
      if (length == 0 || rendered[length - 1] != '\n')
        fputc('\n', stdout);
      fflush(stdout);
      free(rendered);
    }
  }
  free(motd);
}

/* Select the configured transport for both transfer execution paths. */
Client* connect_transfer_client(const Config* config) {
  if (config->transport == TRANSPORT_SSH) {
    if (config->use_sendfile) {
      log_message(LOG_LEVEL_ERROR, "--sendfile is not supported with SSH transport");
      return NULL;
    }
    return client_connect_ssh(config->ssh_destination, config->ssh_port,
                              config->fastsync_server_path, config->rsh_command,
                              config->blocking_io, config->remote_options,
                              config->remote_option_count);
  }

  Client* client = client_create();
  if (!client)
    return NULL;
  /* Socket/connect concerns that never cross the wire: --address (source bind),
   * -4/-6 (family pinning), and --sockopts.  Passed straight to the TCP layer. */
  TcpConnectOptions connect_opts;
  connect_opts.bind_address = config->address;
  connect_opts.family = tcp_connect_family(config->ipv4, config->ipv6);
  connect_opts.sockopts = config->sockopts;
  connect_opts.sockopt_count = config->sockopt_count;
  bool connected;
  if (config->use_tls) {
    connected =
        client_connect_tls_ex(client, config->server_host, config->server_port, config->tls_cert,
                              config->tls_key, config->tls_ca, &connect_opts);
  } else {
    connected = client_connect_ex(client, config->server_host, config->server_port, &connect_opts);
  }
  if (!connected) {
    client_disconnect(client);
    client_delete(client);
    return NULL;
  }
  return client;
}

void disconnect_transfer_client(Client* client) {
  if (!client)
    return;
  /* --stderr=client: push any diagnostics logged during the transfer to the
     peer before the socket closes; once deactivated, later messages fall back
     to local output instead of being lost. */
  client_flush_client_messages(client->file_descriptor);
  client_messages_activate(false);
  client_disconnect(client);
  client_delete(client);
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
    if (unlinkat(dirfd, leaf, 0) != 0) {
      char* escaped_path = output_escape(source->path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING, "Could not remove source file %s",
                  escaped_path ? escaped_path : "<allocation failed>");
      free(escaped_path);
    } else if (info_flag_enabled(config, LOG_INFO_REMOVE) && !config->quiet) {
      /* rsync's --info=remove line: the transfer-relative name. */
      const char* rel = delete_display_path(config, source->path);
      char* escaped = output_escape(rel, config->eight_bit_output);
      printf("sender removed %s\n", escaped ? escaped : rel);
      free(escaped);
      fflush(stdout);
    }
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
   so the later removal pass keeps them.  `partial_out` is set when the receiver
   reported STATUS_PARTIAL (a per-entry receiver failure): the transfer is
   otherwise complete, so successfully stored sources are still removed and the
   caller exits 23 (rsync's partial transfer) instead of a fatal non-zero. */
static bool finalize_transfer(Client* client, const Config* config, ArrayList* remove_sources,
                              bool* delete_limit_out, bool* partial_out, ReceiverStats* stats_out) {
  if (delete_limit_out)
    *delete_limit_out = false;
  if (partial_out)
    *partial_out = false;
  /* --stderr=client: the receiver consumes frames until it reads
     STATUS_FINISHED, after which it no longer reads.  Flush every diagnostic
     queued during the transfer here -- the last frame boundary at which the
     peer is still reading -- so nothing is stranded in the queue. */
  client_flush_client_messages(client->file_descriptor);
  if (!send_status(client->file_descriptor, STATUS_FINISHED))
    return false;
  /* Past STATUS_FINISHED the receiver has stopped reading, so any diagnostic
     logged from here on (notably the STATUS_PARTIAL warning below) can no
     longer be forwarded.  Deactivate the channel so those messages fall back
     to local output instead of being queued for a closed peer and lost. */
  client_messages_activate(false);
  /* The receiver emits its optional wire-stats frame (protocol 2.25.0) FIRST,
     then any per-file --remove-source-files acks, then the terminal status. */
  Status status;
  if (!receive_status(client->file_descriptor, &status))
    return false;
  if (status == STATUS_STATS) {
    ReceiverStats scratch;
    log_debug_message(LOG_DEBUG_RECV, "recv: receiver stats");
    /* A real --info=del run carries the actually-removed paths in the stats
       frame's path list; collect and print them in rsync's format. */
    ArrayList* deleted = config->report_deletes ? array_list_create(free) : NULL;
    if (config->report_deletes && !deleted)
      return false;
    if (!receive_stats_record(client->file_descriptor, stats_out ? stats_out : &scratch, deleted)) {
      array_list_delete(deleted);
      return false;
    }
    if (deleted) {
      print_delete_reports(config, deleted);
      array_list_delete(deleted);
    }
    if (!receive_status(client->file_descriptor, &status))
      return false;
  }
  if (config->remove_source_files && remove_sources && remove_sources->size > 0) {
    for (int i = 0; i < remove_sources->size; i++) {
      if (i > 0 && !receive_status(client->file_descriptor, &status))
        return false;
      if (status == STATUS_ERROR) {
        log_server_rejection("Receiver reported a per-file error");
        return false;
      }
      if (status == STATUS_OK) {
        ((SourceFile*)remove_sources->items[i])->skipped = true;
      } else if (status != STATUS_NEXT) {
        log_message(LOG_LEVEL_ERROR, "Unexpected per-file status from receiver");
        return false;
      }
    }
    if (!receive_status(client->file_descriptor, &status))
      return false;
  }
  /* A capped --max-delete commit is a successful transfer that the client must
     report with rsync's exit code 25 (not an error). */
  if (status == STATUS_DELETE_LIMIT) {
    log_message(LOG_LEVEL_ERROR,
                "Deletions stopped due to --max-delete limit; some deletions were skipped");
    if (delete_limit_out)
      *delete_limit_out = true;
    return true;
  }
  /* A per-entry receiver failure the receiver chose to continue past is a
     rsync PARTIAL transfer: everything else succeeded and the stored sources
     may be removed, but the client must exit 23. */
  if (status == STATUS_PARTIAL) {
    log_message(LOG_LEVEL_WARNING,
                "some files could not be transferred (see the server log for details)");
    if (partial_out)
      *partial_out = true;
    return true;
  }
  if (status != STATUS_OK) {
    log_server_rejection("Receiver reported transfer failure");
    return false;
  }
  return true;
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

int incremental_check(Client* client, File* file, const Config* config, DeltaSignature** out_sig,
                      unsigned long long* resume_offset) {
  *out_sig = NULL;
  if (resume_offset)
    *resume_offset = 0;
  if (!send_status(client->file_descriptor, STATUS_CHECK))
    return -1;
  if (!send_wire_str(client->file_descriptor, file_wire_path(file)))
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
  /* The whole-file digest (negotiated --checksum-choice algorithm and
   * --checksum-seed) is only needed when it drives a decision: --checksum's
   * per-file quick check, or a --verify-basis content equality.  Under the
   * default metadata quick-check the receiver never reads it, so the sender
   * skips the full-file read/hash exactly as rsync does for a plain
   * --link-dest run. */
  if (config->checksum || config->verify_basis) {
    uint8_t digest[CHECKSUM_MAX_DIGEST_LEN];
    size_t digest_len = 0;
    if (!file_checksum(file, (ChecksumAlgo)config->checksum_algo, config->checksum_seed, digest,
                       sizeof(digest), &digest_len))
      return -1;
    log_debug_message(LOG_DEBUG_HASH, "hash: %s (algo %d)", file_wire_path(file),
                      config->checksum_algo);
    uint8_t wire_len = (uint8_t)digest_len;
    if (!send_n_data(client->file_descriptor, &wire_len, sizeof(wire_len)) ||
        !send_n_data(client->file_descriptor, digest, wire_len))
      return -1;
  }
  /* Basis directories: the receiver materializes a hit from the basis without a
   * data frame, so it would otherwise only have the basis inode's metadata.
   * Transmit the SOURCE metadata with the check (rsync's copy-then-fix) so a
   * --copy-dest hit / --link-dest copy fallback applies the source's
   * attributes.  Symmetric with incremental_check_receive_request. */
  if (config_has_basis(config) && config->use_metadata) {
    if (!metadata_send(client->file_descriptor, file->metadata))
      return -1;
  }
  Status s;
  if (!receive_status(client->file_descriptor, &s))
    return -1;
  /* Output parity: when dest-info reporting is negotiated the receiver sends
   * the pre-transfer destination snapshot BEFORE its ordinary verdict.  Consume
   * it here so the following status read stays in sync. */
  if (config->report_dest_info) {
    if (s != STATUS_DEST_INFO ||
        !format_dest_state_receive(client->file_descriptor, &file->dest_state)) {
      log_message(LOG_LEVEL_ERROR, "Unexpected reply to the destination-state report");
      send_status(client->file_descriptor, STATUS_ERROR);
      return -1;
    }
    if (!receive_status(client->file_descriptor, &s))
      return -1;
  }
  if (s == STATUS_ERROR) {
    log_server_rejection("Server reported error for file");
    return -1;
  }
  log_debug_message(LOG_DEBUG_RECV, "recv: check reply for %s", file_wire_path(file));
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
    log_debug_message(LOG_DEBUG_RECV, "recv: delta signature for %s (%u blocks)",
                      file_wire_path(file), sig->block_count);
    *out_sig = sig;
    return 2;
  }
  if (s == STATUS_APPEND) {
    /* --append / --append-verify tail resume: the receiver found an existing
       destination SHORTER than the source and wants only the tail from this
       offset (the bytes it already holds). */
    unsigned long long offset;
    if (!receive_n_data(client->file_descriptor, &offset, sizeof(offset))) {
      send_status(client->file_descriptor, STATUS_ERROR);
      return -1;
    }
    if (resume_offset)
      *resume_offset = offset;
    return 3;
  }
  /* Server-contacting --dry-run: the receiver decided the file is not up to
     date and answered "would transfer" WITHOUT expecting any data.  Treat it as
     the dry-run code ONLY when this session actually requested dry-run.  A
     hostile/buggy peer that emits it outside dry-run is a protocol error: fail
     closed (and send STATUS_ERROR) rather than fall through to the normal path,
     which would transmit file data the receiver is not reading and desync. */
  if (s == STATUS_DRY_RUN_TRANSFER) {
    if (config->dry_run)
      return 4;
    log_message(LOG_LEVEL_ERROR, "Unexpected DRY_RUN_TRANSFER status outside a --dry-run session");
    send_status(client->file_descriptor, STATUS_ERROR);
    return -1;
  }
  if (s != STATUS_NEXT) {
    log_server_rejection("Unexpected server status");
    send_status(client->file_descriptor, STATUS_ERROR);
    return -1;
  }
  return 0;
}

static int send_delta(Client* client, File* file, DeltaSignature* sig, Config* config) {
  Delta* delta = delta_compute_seeded(file->data->data, file->data->size, sig,
                                      config->delta_block_size, (uint32_t)config->checksum_seed);
  log_debug_message(LOG_DEBUG_HASH, "deltasum: %s", file_wire_path(file));
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

  if (ok && config->use_xattrs)
    ok = xattr_send(client->file_descriptor, file->xattrs);

  data_destroy(to_send);
  return ok ? 0 : -1;
}

/* --append / --append-verify tail resume.  The receiver learned the existing
 * destination is SHORTER than the source and replied STATUS_APPEND with the
 * resume offset (prefix bytes it already holds).  For plain --append we send
 * the tail immediately (the prefix is not content-verified, matching rsync).
 * For --append-verify we first send the source prefix xxHash64; the receiver
 * compares it to the retained prefix and replies STATUS_APPEND_OK (send the
 * tail) or STATUS_NEXT (prefix mismatch -> full transfer, never corrupt).
 * Returns 0 on success, 1 when a full transfer was done instead, -1 on error. */
static int send_append(const Client* client, File* file, Config* config,
                       unsigned long long offset) {
  int fd = client->file_descriptor;
  if (file->data->data == NULL && !file_load_data(file)) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  const unsigned long long fsize = file->data->size;
  if (offset >= fsize) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  size_t off = (size_t)offset;
  size_t tail_len = (size_t)(fsize - off);
  int compression_level = config->use_compression ? config->compression_level : 0;
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  bool compress = compression_level > 0 &&
                  !compression_should_skip_with_suffixes(file->path, config->skip_compress_suffixes,
                                                         skip_count);

  /* --append-verify: exchange the source prefix checksum and await the verdict. */
  if (config->append_verify) {
    uint64_t prefix_hash = delta_xxhash64(file->data->data, off);
    if (!send_status(fd, STATUS_APPEND_SIG) || !send_n_data(fd, &prefix_hash, sizeof(prefix_hash)))
      return -1;
    Status resp;
    if (!receive_status(fd, &resp))
      return -1;
    if (resp == STATUS_NEXT) {
      /* Retained prefix does not match the source: fall back to the atomic full
         transfer (byte-identical, never a corrupt prefix+tail blend). */
      int rc = file_send_single_calls_with_skip(file, fd, config->use_metadata, compression_level,
                                                false, config->skip_compress_suffixes, skip_count,
                                                config->compression_threads, config->use_xattrs)
                   ? 1
                   : -1;
      return rc;
    }
    if (resp != STATUS_APPEND_OK) {
      log_server_rejection("Unexpected append-verify response");
      send_status(fd, STATUS_ERROR);
      return -1;
    }
  }

  if (!send_status(fd, STATUS_APPEND_DATA)) {
    return -1;
  }
  if (config->use_metadata && !metadata_send(fd, file->metadata)) {
    return -1;
  }
  if (config->use_xattrs && !xattr_send(fd, file->xattrs)) {
    return -1;
  }
  bool ok;
  if (compress) {
    /* Compression needs an owned copy of the tail to compress. */
    Data* tail = data_create_empty(tail_len);
    if (!tail) {
      send_status(fd, STATUS_ERROR);
      return -1;
    }
    memcpy(tail->data, (const char*)file->data->data + off, tail_len);
    Data* comp = data_compress_with_threads(tail, compression_level, config->compression_threads);
    data_destroy(tail);
    if (!comp) {
      send_status(fd, STATUS_ERROR);
      return -1;
    }
    ok = send_data(fd, comp);
    data_destroy(comp);
  } else {
    /* Uncompressed: send directly from the source buffer (no per-file copy;
       send_data is synchronous, so the view outlives the call). */
    Data tail_view;
    tail_view.data = (char*)file->data->data + off;
    tail_view.size = tail_len;
    tail_view.protocol_charge = 0;
    tail_view.owner = NULL;
    ok = send_data(fd, &tail_view);
  }
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
                                          config->compression_threads, config->use_xattrs);
}

/* Transmit one explicit directory entry (--dirs): a STATUS_MKDIR frame whose
   payload is the destination path and, when metadata is negotiated, the
   directory's metadata frame.  The receiver validates the path, creates the
   directory under the receive root, and (metadata case) defers applying its
   times to the end of the transfer so -O/--omit-dir-times is honored. */
static bool send_directory_entry(const Client* client, File* file, const Config* config) {
  if (!file || !file_wire_path(file))
    return false;
  int fd = client->file_descriptor;
  if (!send_status(fd, STATUS_MKDIR))
    return false;
  /* Output parity (protocol 2.30.0): when report_dest_info is negotiated every
     STATUS_MKDIR body is prefixed with a probe flag (1 = probe only, 0 = a real
     create), so the receiver knows whether to expect the metadata/xattr block. */
  if (config->report_dest_info && !send_int(fd, 0))
    return false;
  if (!send_wire_str(fd, file_wire_path(file)))
    return false;
  if (config->use_metadata && !metadata_send(fd, file->metadata))
    return false;
  /* Directory xattrs/ACLs (-X/-A) ride the same trailing block as regular files
     when the xattr transport was negotiated. */
  if (config->use_xattrs && !xattr_send(fd, file->xattrs))
    return false;
  /* The receiver answers with the directory's pre-transfer destination state
     BEFORE creating it, so the sender can render rsync's `.d..t......` versus
     `cd+++++++++` and suppress an unchanged directory. */
  if (config->report_dest_info) {
    Status status;
    if (!receive_status(fd, &status) || status != STATUS_DEST_INFO ||
        !format_dest_state_receive(fd, &file->dest_state)) {
      log_message(LOG_LEVEL_ERROR, "Unexpected reply to the directory destination-state report");
      return false;
    }
  }
  return true;
}

/* P7 Wave D: transmit every captured source directory's metadata in terminal
   STATUS_DIR_TIMES frames (count, then (path, metadata) pairs) after all file
   data and the optional delete manifest.  The receiver applies them at the END
   of its own transfer (after deletion and --delay-updates publication) so a
   directory's mtime is not clobbered by writing its children.  A non-metadata
   transfer (or an empty set) sends nothing, keeping the stream byte-identical.

   The receiver rejects a frame whose count exceeds MAX_MANIFEST_ENTRIES, so a
   huge tree is CHUNKED into repeated frames of at most that many entries each
   (the receiver's loop handles repeated STATUS_DIR_TIMES frames).  Every frame
   stays within the receiver's bound, and a frame that would exceed it is never
   emitted. */
static bool send_dir_times(const Client* client, const Config* config, ArrayList* dir_entries) {
  if (!client || !config || !dir_metadata_should_capture(config) || !dir_entries ||
      dir_entries->size == 0)
    return true;
  int fd = client->file_descriptor;
  int index = 0;
  while (index < dir_entries->size) {
    int remaining = dir_entries->size - index;
    int chunk = remaining > MAX_MANIFEST_ENTRIES ? MAX_MANIFEST_ENTRIES : remaining;
    if (!send_status(fd, STATUS_DIR_TIMES) || !send_int(fd, chunk))
      return false;
    for (int i = 0; i < chunk; i++) {
      File* file = (File*)dir_entries->items[index + i];
      if (!file || !file_wire_path(file))
        return false;
      if (!send_wire_str(fd, file_wire_path(file)) || !metadata_send(fd, file->metadata))
        return false;
      /* Directory xattrs/ACLs travel with the deferred directory metadata. */
      if (config->use_xattrs && !xattr_send(fd, file->xattrs))
        return false;
    }
    index += chunk;
  }
  return true;
}

/* Transmit one symlink entry: a STATUS_SYMLINK frame carrying the destination
 * path, the (sender-munged, if --munge-links) target string, and metadata when
 * negotiated.  The receiver unmunges the target and creates the symlink beneath
 * its root.  Symlinks never need an incremental check or data payload. */
static bool send_symlink_entry(const Client* client, File* file, const Config* config) {
  if (!file || !file_wire_path(file) || !file->symlink_target)
    return false;
  int fd = client->file_descriptor;
  if (!send_status(fd, STATUS_SYMLINK) || !send_wire_str(fd, file_wire_path(file)) ||
      !send_wire_str(fd, file->symlink_target))
    return false;
  if (config->use_metadata && !metadata_send(fd, file->metadata))
    return false;
  /* Symlink xattrs/ACLs (-X/-A) ride the same trailing block as regular files
     and directories when the xattr transport was negotiated. */
  if (config->use_xattrs && !xattr_send(fd, file->xattrs))
    return false;
  /* The receiver answers with the symlink's pre-transfer destination state
     (including whether the on-disk link target already matches) BEFORE creating
     it, so the sender can render rsync's `cLc........` / `.L..t......` and
     suppress an unchanged symlink. */
  if (config->report_dest_info) {
    Status status;
    if (!receive_status(fd, &status) || status != STATUS_DEST_INFO ||
        !format_dest_state_receive(fd, &file->dest_state)) {
      log_message(LOG_LEVEL_ERROR, "Unexpected reply to the symlink destination-state report");
      return false;
    }
  }
  return true;
}

// Send a single file directly via sendfile (non-incremental path).
static bool send_file_direct_sendfile(File* file, int fd, bool use_metadata, const Config* config) {
  if (!send_status(fd, STATUS_NEXT))
    return false;
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  return file_send_sendfile_with_skip(file, fd, use_metadata, 0, true,
                                      config->skip_compress_suffixes, skip_count,
                                      config->compression_threads, config->use_xattrs);
}

// Process one file in a chunk: either via incremental check or direct send.
// Returns 0 on success, 1 if skipped (incremental match), -1 on error.
static int send_single_file(Client* client, File* file, Config* config, bool use_incremental,
                            bool use_sendfile) {
  int compression_level = config->use_compression ? config->compression_level : 0;
  log_info_message(LOG_INFO_COPY, "Transferring %s", file->path);
  log_debug_message(LOG_DEBUG_SEND, "send: %s", file_wire_path(file));

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
    unsigned long long resume_offset = 0;
    int rc = incremental_check(client, file, config, &sig, &resume_offset);
    if (rc == 1) {
      log_info_message(LOG_INFO_SKIP, "Skipping unchanged %s", file->path);
      delta_signature_destroy(sig);
      return 1;
    }
    if (rc < 0) {
      delta_signature_destroy(sig);
      return -1;
    }
    // rc == 3: append resume (tail-only) -- send_append uses the data path.
    if (rc == 3) {
      delta_signature_destroy(sig);
      int arc = send_append(client, file, config, resume_offset);
      if (arc == 1) {
        log_info_message(LOG_INFO_COPY, "Append prefix mismatch; full transfer of %s", file->path);
        return 0;
      }
      return arc == 0 ? 0 : -1;
    }
    // rc == 4: the receiver answered DRY_RUN_TRANSFER, which is only valid in
    // incremental_check's dedicated dry-run consumer.  send_single_file never
    // runs a dry-run session, so this is a protocol error: abort instead of
    // falling through and sending data the receiver is not reading.
    if (rc == 4) {
      log_message(LOG_LEVEL_ERROR, "Receiver answered DRY_RUN_TRANSFER in a non-dry-run transfer");
      delta_signature_destroy(sig);
      send_status(client->file_descriptor, STATUS_ERROR);
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
                                      config->compression_threads, config->use_xattrs))
      return -1;
    return 0;
  }

  // Incremental path with single_calls (supports compression and delta)
  DeltaSignature* sig = NULL;
  unsigned long long resume_offset = 0;
  int rc = incremental_check(client, file, config, &sig, &resume_offset);
  if (rc < 0) {
    delta_signature_destroy(sig);
    return -1;
  }
  if (rc == 1) {
    log_info_message(LOG_INFO_SKIP, "Skipping unchanged %s", file->path);
    delta_signature_destroy(sig);
    return 1;
  }
  if (rc == 3) {
    /* --append / --append-verify tail resume.  send_append reports 1 when the
       verified prefix mismatched and a full transfer was sent instead. */
    delta_signature_destroy(sig);
    int arc = send_append(client, file, config, resume_offset);
    if (arc == 1) {
      log_info_message(LOG_INFO_COPY, "Append prefix mismatch; full transfer of %s", file->path);
      return 0;
    }
    return arc == 0 ? 0 : -1;
  }
  if (rc == 4) {
    /* See the sendfile branch above: DRY_RUN_TRANSFER is only valid in the
       dedicated dry-run consumer, never in the normal per-file send path. */
    log_message(LOG_LEVEL_ERROR, "Receiver answered DRY_RUN_TRANSFER in a non-dry-run transfer");
    delta_signature_destroy(sig);
    send_status(client->file_descriptor, STATUS_ERROR);
    return -1;
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
                                        skip_count, config->compression_threads,
                                        config->use_xattrs))
    return -1;
  return 0;
}

/* Sendfile calls a blocking open() on the source (file_send_sendfile_with_skip
 * -> file_open_for_read), which never returns for a FIFO/device with no writer.
 * Only a regular file may take the zero-copy sendfile path; a non-regular source
 * (FIFO/device copied by --copy-devices) must use the buffered, size-bounded
 * read path instead.  `stat` follows symlinks, so a dereferenced symlink to a
 * regular file keeps the sendfile fast path. */
static bool source_is_regular_file(const File* file) {
  if (!file || !file->path)
    return false;
  struct stat st;
  return stat(file->path, &st) == 0 && S_ISREG(st.st_mode);
}

/* True when an over-threshold source will be sent by STREAMING from disk rather
 * than loaded into memory: either the zero-copy sendfile path (no compression)
 * or the sender-side streaming compressor (zstd/zlib, when this file is not on
 * the --skip-compress list).  Otherwise the loader must materialize it. */
static bool loader_can_stream(const Config* config, const File* file) {
  if (!config || !file || !file->data || file->data->size <= STREAM_THRESHOLD)
    return false;
  if (!config->use_compression)
    return true;
  if (!compression_stream_compress_supported(compression_get_algo()) ||
      config->compression_level <= 0)
    return false;
  int skip_count = config->skip_compress_set ? config->skip_compress_count : -1;
  return !compression_should_skip_with_suffixes(file->path, config->skip_compress_suffixes,
                                                skip_count);
}

static int send_chunk_with_removal(Client* client, Chunk* chunk, Config* config,
                                   ArrayList* remove_sources, TransferStats* stats) {
  /* --stderr=client: this is a frame boundary, so forward any diagnostics the
     scanner/log emitted since the previous chunk before the next frame. */
  client_flush_client_messages(client->file_descriptor);
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
      if (chunk->items[i] == NULL)
        continue;
      transfer_stats_note_entry(stats, chunk->items[i]);
      /* Output parity: probe each entry's ancestor directories' destination
         state before emitting its itemize line, exactly as the non-serialized
         loop does.  Without this, dest_state.known stays false and -i/-P
         renders an existing dir/symlink as created instead of `.d..t...` (or
         suppressing it). */
      if (!client_change_probe_ancestors(config, chunk->items[i], client->file_descriptor))
        return -1;
      /* The chunk-serialization path emits no --progress name lines, so only
         feed -i/--out-format its ancestor directory lines here. */
      if (config->itemize_changes || config->out_format != NULL)
        client_change_emit_ancestors(config, chunk->items[i]);
      if (chunk->items[i]->is_dir) {
        change_emit_dir_sent(config, chunk->items[i]);
        client_change_mark_dir(config, chunk->items[i]);
      } else {
        change_emit_file_sent(config, chunk->items[i]);
      }
      if (!chunk->items[i]->is_dir)
        transfer_stats_note_transferred(stats, chunk->items[i]);
    }
    return 0;
  }

  for (int i = 0; i < chunk->element_count; i++) {
    File* f = chunk->items[i];
    if (f == NULL)
      continue;
    transfer_stats_note_entry(stats, f);
    /* Output parity: probe this entry's ancestor directories' destination state
       before the entry (or the first child below them) is sent, while the
       receiver has not yet created them implicitly. */
    if (!client_change_probe_ancestors(config, f, client->file_descriptor))
      return -1;
    if (f->is_dir) {
      /* Explicit directory entry (--dirs): a MKDIR frame carrying the
         destination path (and metadata when negotiated).  Directories have no
         source to remove and no incremental check. */
      if (!send_directory_entry(client, f, config))
        return -1;
      client_change_emit_ancestors(config, f);
      change_emit_dir_sent(config, f);
      client_change_mark_dir(config, f);
      client_progress_name(config, f);
      continue;
    }
    /* --hard-links/-H sibling: a later member of a hard-link group that has no
       data (its payload lives in the first member).  Transmit a dedicated
       STATUS_HARDLINK frame carrying the first member's destination-relative
       wire path so the receiver links this entry to that installed file. */
    if (f->link_group != 0 && !f->link_first && f->hardlink_target != NULL) {
      if (!send_status(client->file_descriptor, STATUS_HARDLINK) ||
          !send_wire_str(client->file_descriptor, file_wire_path(f)) ||
          !send_int(client->file_descriptor, f->link_group) ||
          !send_wire_str(client->file_descriptor, f->hardlink_target))
        return -1;
      client_change_emit_ancestors(config, f);
      change_emit_file_sent(config, f);
      client_progress_name(config, f);
      continue;
    }
    /* Symlink entry (-l / -k keep-as-symlink): only the target rides the wire. */
    if (f->is_symlink) {
      if (!send_symlink_entry(client, f, config))
        return -1;
      client_change_emit_ancestors(config, f);
      change_emit_file_sent(config, f);
      client_progress_name(config, f);
      continue;
    }
    /* --devices/--specials: a device/special node is recreated on the receiver,
       not transferred as content.  Send the dedicated STATUS_SPECIAL frame. */
    if (f->is_special) {
      if (!file_send_special(f, client->file_descriptor, config->use_metadata))
        return -1;
      client_change_emit_ancestors(config, f);
      change_emit_file_sent(config, f);
      client_progress_name(config, f);
      continue;
    }
    bool stream = f->data->data == NULL && f->data->size > 0;
    bool use_sendfile = ((config->use_sendfile && !config->use_compression) ||
                         (stream && !config->use_compression)) &&
                        source_is_regular_file(f);
    SourceFile* source = remove_sources ? source_file_create(f) : NULL;
    unsigned long long bytes_before = protocol_bytes_written();
    unsigned long long read_before = protocol_bytes_read();
    int rc = send_single_file(client, f, config, config->use_incremental, use_sendfile);
    if (rc == 1) {
      source_file_destroy(source);
      change_emit_file_uptodate(config, f);
      client_progress_uptodate(config, f);
      continue;
    }
    if (rc < 0) {
      source_file_destroy(source);
      return -1;
    }
    transfer_stats_note_transferred(stats, f);
    client_change_emit_ancestors(config, f);
    change_emit_file_sent_bytes(config, f, protocol_bytes_written() - bytes_before,
                                protocol_bytes_read() - read_before);
    client_progress_file(config, f);
    if (source && !array_list_add(remove_sources, source)) {
      source_file_destroy(source);
      return -1;
    }
  }
  return 0;
}

static int send_chunks_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  time_t start = time(NULL);
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
  protocol_session_set_io_timeout(&session, context->config->timeout);
  protocol_session_set_ssl(&session, (SSL*)client->ssl);
  protocol_session_bind(&session);
  client_messages_activate(true);
  if (!config_send(client->file_descriptor, context->config)) {
    pipeline_cancel(context);
    disconnect_transfer_client(client);
    mark_sender_done(context);
    protocol_session_unbind();
    return thrd_error;
  }
  receive_daemon_motd(client, context->config);
  if (context->early_delete) {
    /* The keep-set manifest was prebuilt by a path-only pre-scan.  Transmit it
       and wait for the receiver to delete extras before streaming any data. */
    if (!send_delete_manifest_early(client, context->manifest, context->excluded_paths,
                                    context->size_skipped_paths, context->missing_args,
                                    context->synced_dirs, context->per_dir_rules)) {
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
  } else if (context->delete_plans) {
    /* --delete-during/--delete-delay: transmit the COMPLETE per-directory plan
       set before any data, so a mid-transfer abort has already applied every
       planned removal exactly like rsync's generator (which runs ahead of its
       throttled sender).  A completed run is unaffected. */
    if (delete_plan_send_all(client->file_descriptor, context->delete_plans, context->plan_dirs) !=
        0) {
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
  }

  client_progress_begin(context->config);
  while (true) {
    /* Graceful abort (Ctrl-C/SIGTERM): tell the receiver to clean up instead of
       dying abruptly.  Best-effort: a failed send just means the peer is gone.
       Only reached while the session is active (config_send already succeeded). */
    if (client_abort_pending()) {
      log_info_message(LOG_INFO_MISC,
                       "Abort requested; sending STATUS_ABORT to server and disconnecting");
      send_status(client->file_descriptor, STATUS_ABORT);
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
    /* Phase 6: stop-elegantly at the next chunk boundary once the --stop-after
       / --stop-at deadline has passed.  Everything already sent is finalized by
       the completion tail below; the run still returns success. */
    if (stop_condition_reached(&context->stop_condition)) {
      log_info_message(LOG_INFO_MISC,
                       "Stop deadline reached; stopping transfer at the next chunk boundary");
      context->scan_stopped_early = true;
      pipeline_cancel(context);
      break;
    }
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
      break;
    }
    if (send_chunk_with_removal(client, current_chunk, context->config,
                                context->remove_source_files, &context->stats) != 0) {
      log_message(LOG_LEVEL_ERROR, "unexpected error while sending chunk");
      chunk_destroy(current_chunk);
      pipeline_cancel(context);
      disconnect_transfer_client(client);
      mark_sender_done(context);
      protocol_session_unbind();
      return thrd_error;
    }
    /* Payload bytes this chunk was charged for on the loader's byte budget.
       Computed before destruction and released after the memory is actually
       freed, so a loader blocked on the budget wakes only once room exists. */
    size_t queued_payload = pipeline_context_sender_chunk_bytes(current_chunk);
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
    pipeline_context_sender_note_bytes_released(context, queued_payload);
  }

  /* Completion tail: reached on natural exhaustion or an early stop deadline.
     A deadline that cut the scan short leaves an incomplete keep-set manifest;
     transmitting it would make the receiver --delete the unscanned source
     mirrors (data loss), so it is deliberately suppressed.  Suppressing it also
     means the manifest (which the scanner thread may still be appending) is
     never read here on the early-stop path, so no scanner synchronization is
     required to enter the tail. */
  context->scan_stopped_early =
      context->scan_stopped_early || stop_condition_reached(&context->stop_condition);
  if (context->scan_stopped_early) {
    if (context->config->use_delete || context->config->delete_missing_args)
      log_message(LOG_LEVEL_WARNING,
                  "transfer stopped early (stop deadline); skipping --delete keep-set so "
                  "unscanned source mirrors are not deleted");
    else
      log_message(LOG_LEVEL_WARNING, "transfer stopped early (stop deadline)");
  } else if (context->config->use_delete && !context->early_delete && !context->delete_plans &&
             !context->delete_suppressed) {
    /* Empty keep-set + scan I/O error must not delete the whole destination
       (the source may not be genuinely empty -- see send_files). */
    bool empty_io;
    mtx_lock(&context->mutex_scanner);
    empty_io = context->scan_had_io_error && context->manifest && context->manifest->size == 0;
    mtx_unlock(&context->mutex_scanner);
    if (empty_io) {
      log_message(LOG_LEVEL_ERROR,
                  "source scan hit an I/O error before finding any file; refusing to delete "
                  "with an empty keep-set (--delete)");
      goto send_fail;
    }
    /* rsync default: an I/O error suppresses deletion unless --ignore-errors.
       The keep-set manifest is not sent, so the receiver removes nothing. */
    mtx_lock(&context->mutex_scanner);
    bool scan_io_now = context->scan_had_io_error;
    mtx_unlock(&context->mutex_scanner);
    if (!ignore_errors_allows_delete(context->config, scan_io_now)) {
      log_message(LOG_LEVEL_WARNING, "IO error encountered -- skipping file deletion");
    } else if (send_delete_manifest(client->file_descriptor, context->manifest,
                                    context->excluded_paths, context->size_skipped_paths,
                                    context->missing_args, context->synced_dirs,
                                    context->per_dir_rules) != 0) {
      goto send_fail;
    }
  } else if (context->config->delete_missing_args && !context->early_delete &&
             !context->delete_suppressed && !context->delete_plans) {
    /* --delete-missing-args without --delete: no keep-set is built, but the
       exact-delete paths still ride the same manifest frame (commit once the
       transfer succeeded). */
    if (send_delete_manifest(client->file_descriptor, NULL, NULL, NULL, context->missing_args, NULL,
                             NULL) != 0)
      goto send_fail;
  }
  /* P7 Wave D: transmit the captured directory times last.  The scanner thread
     (and all parallel workers) has been joined before scanner_done was set, so
     the list is complete and race-free; on an early stop the list may be
     incomplete and is deliberately not sent. */
  client_change_emit_pending_dirs(context->config, client->file_descriptor);
  if (!context->scan_stopped_early &&
      !send_dir_times(client, context->config, context->dir_entries))
    goto send_fail;
  bool delete_limit = false;
  bool partial = false;
  ReceiverStats recv_stats;
  memset(&recv_stats, 0, sizeof(recv_stats));
  client_flush_client_messages(client->file_descriptor);
  bool ok = finalize_transfer(client, context->config, context->remove_source_files, &delete_limit,
                              &partial, &recv_stats);
  context->delete_limit = delete_limit;
  context->partial = partial;
  if (!ok && context->config->use_delete)
    log_message(LOG_LEVEL_ERROR,
                "server reported a deletion failure (--delete); see the server log for the reason");
  if (ok)
    remove_transferred_sources(context->config, context->remove_source_files);
  context->stats.flist_dir +=
      dir_count_for_stats(context->config, context->dir_entries, &context->dir_count);
  report_transfer_stats(context->config, &context->stats, start, &recv_stats);
  log_info_message(LOG_INFO_STATS, "Transfer summary: %llu files, %.1f MB",
                   context->stats.transferred_regular,
                   (double)context->stats.transferred_file_size / (double)BYTES_PER_MIB);
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

/* Scan thread of the -m pipeline.  --dirs disables recursive traversal (the
   transfer is a small set of explicit directory/file entries), so it uses the
   sequential scanner rather than spawning worker threads. */
static int scan_directory_multithreaded(void* pipeline_context) {
  PipelineContextSender* context = (PipelineContextSender*)pipeline_context;
  protocol_session_bind(&context->allocation_session);
  if (context->prescan_chunks != NULL) {
    /* --delete-before replays the pre-scan that built the early keep-set as the
       data pass (rsync builds one file list).  Feed the retained chunks straight
       into the pipeline instead of re-reading the source, so a file created
       after the pre-scan is neither transferred nor kept.  The chunk also
       carries the directory times captured by that scan (there is no later
       scan), so no scanner is created here. */
    bool failed = false;
    for (int i = 0; i < context->prescan_chunks->size; i++) {
      Chunk* chunk = (Chunk*)context->prescan_chunks->items[i];
      /* Move ownership out of the retained list so a cleanup here never
         double-frees a chunk the queue now owns. */
      context->prescan_chunks->items[i] = NULL;
      if (chunk == NULL)
        continue;
      if (!queue_enqueue_multithreaded_cancel(
              context->queue_scanner, chunk, &context->mutex_scanner,
              &context->condition_not_empty_scanner, &context->condition_not_full_scanner,
              &context->cancelled)) {
        chunk_destroy(chunk);
        failed = true;
        break;
      }
    }
    mtx_lock(&context->mutex_scanner);
    context->scanner_done = true;
    cnd_broadcast(&context->condition_not_empty_scanner);
    cnd_broadcast(&context->condition_not_full_scanner);
    mtx_unlock(&context->mutex_scanner);
    if (failed) {
      pipeline_cancel(context);
      protocol_session_unbind();
      return thrd_error;
    }
    protocol_session_unbind();
    return thrd_success;
  }
  PreparedScanner prepared;
  /* -j/--threads=N sizes the parallel scanner's worker pool; 0 (bare -j) lets
   * the scanner apply its built-in default. */
  if (!prepare_scanner(context->config, context->config->scanner_threads, &prepared)) {
    pipeline_cancel(context);
    protocol_session_unbind();
    return thrd_error;
  }
  prepared.options.stop_condition = &context->stop_condition;
  /* P7 Wave D: the recursive scan feeds the shared directory-time list; the
     parallel workers append under the context's dedicated mutex. */
  prepared.options.dir_entries = context->dir_entries;
  prepared.options.dir_entries_mutex = &context->dir_entries_mutex;
  prepared.options.dir_count = context->config->stats ? &context->dir_count : NULL;
  if (!append_implied_dir_times(context->config, context->dir_entries)) {
    pipeline_cancel(context);
    protocol_session_unbind();
    return thrd_error;
  }
  /* The keep-set manifest for the late modes is built from this data pass, so
     the parallel scanner records the protected excluded prefixes and the
     synchronized directories here (the size-prune protection is collected in
     every mode).  The early modes already transmitted the pre-scan keep-set and
     its protected lists, so the data pass must not append to them again. */
  if (!context->early_delete && !context->delete_plans) {
    prepared.options.excluded_paths = context->excluded_paths;
    prepared.options.per_dir_rules = context->per_dir_rules;
    /* The root marker for a full recursive transfer is already in the list; do
       not let the scanner append every directory to it. */
    if (context->config->files_from_set != NULL)
      prepared.options.synced_dirs = context->synced_dirs;
  }
  if (!context->delete_plans)
    prepared.options.size_skipped_paths = context->size_skipped_paths;
  bool dirs_mode = prepared.options.dirs;
  /* -H also selects the sequential scanner (see the comment at the branch),
   * so the loop below must choose the scanner by which object exists, not by
   * --dirs alone. */
  bool use_dscanner = dirs_mode || prepared.options.hardlinks;
  DirectoryScanner* dscanner = NULL;
  ParallelScanner* scanner = NULL;
  /* --hard-links/-H forces the sequential scanner even in -m mode: a hard-link
     group's first member must be emitted before any of its siblings so the
     receiver always links to an already-installed first member.  The parallel
     scanner hands different subdirectories to different worker threads, which
     can reorder a group whose members span directories. */
  if (use_dscanner) {
    dscanner =
        directory_scanner_create_with_options(context->config->send_directory, &prepared.options);
  } else {
    scanner = parallel_scanner_create_with_options(context->config->send_directory,
                                                   &prepared.options, &context->allocation_session);
  }
  if (dscanner == NULL && scanner == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to create scanner");
    pipeline_cancel(context);
    prepared_scanner_destroy(&prepared);
    protocol_session_unbind();
    return thrd_error;
  }
  bool failed = false;
  Chunk* current_chunk;
  while (1) {
    if (use_dscanner)
      current_chunk = directory_scanner_next(dscanner);
    else
      current_chunk = parallel_scanner_next(scanner);
    if (current_chunk == NULL) {
      failed = use_dscanner ? directory_scanner_failed(dscanner) : parallel_scanner_failed(scanner);
      break;
    }
    if (context->config->use_delete && !context->early_delete && !context->delete_plans &&
        !context->delete_suppressed) {
      mtx_lock(&context->mutex_scanner);
      bool manifest_ok = add_chunk_to_manifest(context->manifest, current_chunk);
      mtx_unlock(&context->mutex_scanner);
      if (!manifest_ok) {
        failed = true;
        chunk_destroy(current_chunk);
        break;
      }
    }
    if (!queue_enqueue_multithreaded_cancel(
            context->queue_scanner, current_chunk, &context->mutex_scanner,
            &context->condition_not_empty_scanner, &context->condition_not_full_scanner,
            &context->cancelled)) {
      chunk_destroy(current_chunk);
      failed = true;
      break;
    }
  }
  /* Capture the scanner results BEFORE destroying the scanner objects (the
     io_error flag lives on the scanner, so reading it after destroy would be a
     use-after-free). */
  bool had_io = use_dscanner ? directory_scanner_had_io_error(dscanner)
                             : parallel_scanner_had_io_error(scanner);
  if (use_dscanner)
    directory_scanner_destroy(dscanner);
  else
    parallel_scanner_destroy(scanner);
  if (failed) {
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
  /* --ignore-errors: an unreadable subdirectory was skipped (workers recorded
     io_error, not failure); the deletion still runs but the run reports it. */
  if (had_io) {
    mtx_lock(&context->mutex_scanner);
    context->scan_had_io_error = true;
    mtx_unlock(&context->mutex_scanner);
  }
  mtx_lock(&context->mutex_scanner);
  context->scanner_done = true;
  cnd_signal(&context->condition_not_empty_scanner);
  mtx_unlock(&context->mutex_scanner);

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
        if (loader_can_stream(context->config, f))
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
    if (!pipeline_context_sender_enqueue_chunk(context, chunk)) {
      pipeline_cancel(context);
      protocol_session_unbind();
      return thrd_error;
    }
  }
}

/* Phase 6 residual-batch (client-only).  --write-batch=FILE / --only-write-batch
 * emit a self-contained single-file batch of a whole source tree from a
 * deterministic separate scan pass.  Each chunk's file images are fully loaded
 * into memory (so chunk_serialize sees complete content, matching the -s wire
 * codec byte-for-byte) and written to FILE as a length-prefixed record.  The
 * batch never crosses the wire and needs no server.  Returns 0 on success. */
int write_batch_from_source(const Config* config, const char* batch_path) {
  if (!config || !batch_path || !config->send_directory)
    return 1;
  PreparedScanner prepared;
  memset(&prepared, 0, sizeof(prepared));
  if (!prepare_scanner(config, 0, &prepared))
    return 1;
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner) {
    prepared_scanner_destroy(&prepared);
    return 1;
  }
  int fd = open(batch_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    log_perror("could not create batch file");
    directory_scanner_destroy(scanner);
    prepared_scanner_destroy(&prepared);
    return 1;
  }
  bool ok = batch_write_header(fd, config);
  Chunk* chunk;
  while (ok && (chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count && ok; i++) {
      File* f = chunk->items[i];
      if (f == NULL || f->data == NULL)
        continue;
      if (f->data->size > 0 && f->data->data == NULL && !file_load_data(f)) {
        char* escaped_path = output_escape(f->path ? f->path : "", log_get_8_bit_output());
        log_message(LOG_LEVEL_ERROR, "batch: failed to load data for %s",
                    escaped_path ? escaped_path : "<allocation failed>");
        free(escaped_path);
        ok = false;
        break;
      }
    }
    if (ok)
      ok = batch_write_chunk(fd, chunk);
    chunk_destroy(chunk);
  }
  if (ok && directory_scanner_failed(scanner))
    ok = false;
  if (directory_scanner_had_io_error(scanner))
    log_message(LOG_LEVEL_WARNING, "batch: source scan hit an unreadable directory");
  close(fd);
  directory_scanner_destroy(scanner);
  prepared_scanner_destroy(&prepared);
  if (!ok && batch_path[0] != '\0')
    unlink(batch_path); /* never leave a partial batch behind */
  return ok ? 0 : 1;
}

/* Apply a batch FILE to DEST_ROOT (client-only, no server).  Returns 0 on
 * success; a malformed/truncated/oversized record or an apply error fails the
 * whole apply. */
int apply_batch_to_dest(const Config* config, const char* batch_path, const char* dest_root) {
  if (!batch_path || !dest_root)
    return 1;
  int fd = open(batch_path, O_RDONLY);
  if (fd < 0) {
    log_perror("could not open batch file");
    return 1;
  }
  int rc = batch_read_apply(fd, config, dest_root);
  close(fd);
  return rc;
}

/* Resources and phase state threaded through the single-threaded send path.
 * The send_files_* helpers populate it incrementally and send_files_cleanup
 * releases every owned field; the members mirror the locals of the original
 * monolithic send_files, so ownership and destruction order are unchanged. */
typedef struct {
  Client* client;
  DirectoryScanner* scanner;
  ArrayList* manifest;
  /* --delete-before: the pre-scan that built the keep-set, retained as the data
     pass's file list (owning Chunk*; consumed chunks are NULLed as they are
     sent).  NULL in every other mode, where the data pass scans normally. */
  ArrayList* prescan_chunks;
  DeletePlanSender* plan_sender;
  ArrayList* remove_sources;
  ArrayList* dir_entries;
  atomic_ullong dir_count;
  ArrayList* excluded;
  ArrayList* size_skipped;
  ArrayList* synced_dirs;
  ArrayList* plan_dirs;
  ArrayList* missing_args;
  /* Per-directory filter rules compiled by the scan (protocol 2.30.0). */
  FilterRuleList* per_dir_rules;
  PreparedScanner prepared;
  StopCondition stop;
  TransferStats transfer_stats;
  time_t start;
  bool delete_early;
  bool delete_per_dir;
  bool had_scan_io;
  bool scan_stopped_early;
  unsigned long long per_dir_non_dir_count;
} SendFilesState;

/* Post-connect setup: negotiate the protocol, consume the daemon MOTD, build
 * the scanner and allocate the delete/keep-set/remove-source list containers. */
static bool send_files_prepare(Config* config, SendFilesState* state) {
  Client* client = state->client;
  if (!config_send(client->file_descriptor, config))
    return false;
  receive_daemon_motd(client, config);
  if (!prepare_scanner(config, 0, &state->prepared))
    return false;
  if (dir_metadata_should_capture(config)) {
    state->dir_entries = array_list_create(file_destroy);
    if (!state->dir_entries)
      return false;
    if (!append_implied_dir_times(config, state->dir_entries))
      return false;
  }
  if (config->remove_source_files)
    state->remove_sources = array_list_create(source_file_destroy);
  if (config->remove_source_files && !state->remove_sources)
    return false;
  /* Unless --delete-excluded opts out, collect the paths the source scan prunes
     by user-selection rules so the receiver protects their destination mirrors
     from --delete (rsync's default).  Only scans that build the keep-set get the
     sink attached (prescan for early timing, the streaming data pass otherwise). */
  if (config->use_delete) {
    if (!config->delete_excluded) {
      state->excluded = array_list_create(free);
      if (!state->excluded)
        return false;
      state->prepared.options.excluded_paths = state->excluded;
    }
    state->size_skipped = array_list_create(free);
    state->synced_dirs = array_list_create(free);
    state->per_dir_rules = filter_rule_list_create();
    if (!state->size_skipped || !state->synced_dirs || !state->per_dir_rules)
      return false;
    state->prepared.options.size_skipped_paths = state->size_skipped;
    state->prepared.options.per_dir_rules = state->per_dir_rules;
    /* Only a --files-from subset confines the extras walk to the directories
       the scan synchronized; a full recursive transfer deletes throughout the
       receive root, so mark the root itself (the "." sentinel) and let the
       scanner record nothing extra. */
    if (config->files_from_set == NULL) {
      char* root_marker = delete_scope_root_marker(config);
      if (!root_marker || !array_list_add(state->synced_dirs, root_marker)) {
        free(root_marker);
        return false;
      }
    } else {
      state->prepared.options.synced_dirs = state->synced_dirs;
    }
  }
  return true;
}

/* Delete-timing pre-pass.  The late-timing modes (--delete-after/--delete-commit)
 * build the manifest while streaming (handled by the run/finalize phases);
 * --delete-before sends a whole-tree keep-set up front, and --delete-during/
 * --delete-delay build the complete per-directory plan set up front (paths only)
 * and transmit it all before the first data frame, so a mid-transfer abort has
 * already applied every planned removal. */
static bool send_files_prepare_delete(Config* config, SendFilesState* state) {
  Client* client = state->client;
  if (state->delete_early) {
    /* Pass 1: collect the complete keep-set (paths only, no data loaded) and
       transmit it now, before any file data.  The receiver removes extras and
       acks; the transfer aborts here if the deletion could not commit.  The
       scanned chunks are retained so the data pass can replay this exact list
       instead of re-reading the source (rsync builds one file list and never
       transfers a file created after it). */
    ArrayList* early_manifest = array_list_create(free);
    ArrayList* prescan_chunks = array_list_create(chunk_destroy);
    if (!early_manifest || !prescan_chunks) {
      array_list_delete(early_manifest);
      array_list_delete(prescan_chunks);
      return false;
    }
    /* No later scan runs for --delete-before, so this pass must also capture the
       deferred directory times and the --stats directory count. */
    state->prepared.options.dir_entries = state->dir_entries;
    state->prepared.options.dir_count = config->stats ? &state->dir_count : NULL;
    bool prescan_ok = scan_paths_only(config, &state->prepared.options, early_manifest, NULL,
                                      &state->had_scan_io, NULL, prescan_chunks, true);
    bool early_ok = false;
    bool skip_delete = false;
    if (prescan_ok) {
      /* A scan that hit an I/O error and produced NO keep entries is ambiguous
         (the source may not be genuinely empty -- part of it was unreadable),
         and an empty keep-set would delete the whole destination.  Refuse to
         delete; the genuine-empty-source case has no io_error and still sends
         its (empty) keep-set. */
      if (state->had_scan_io && early_manifest->size == 0) {
        log_message(LOG_LEVEL_ERROR,
                    "source scan hit an I/O error before finding any file; refusing to delete "
                    "with an empty keep-set (--delete)");
        prescan_ok = false;
      } else if (!ignore_errors_allows_delete(config, state->had_scan_io)) {
        /* rsync default: an I/O error suppresses deletion unless
           --ignore-errors.  Skip the manifest; the transfer still proceeds. */
        log_message(LOG_LEVEL_WARNING, "IO error encountered -- skipping file deletion");
        skip_delete = true;
      } else {
        early_ok = send_delete_manifest_early(client, early_manifest, state->excluded,
                                              state->size_skipped, state->missing_args,
                                              state->synced_dirs, state->per_dir_rules);
      }
    }
    array_list_delete(early_manifest);
    /* The keep-set (and its protected prefixes and synchronized directories) are
       already on the wire; the data pass must not append to those lists again. */
    state->prepared.options.excluded_paths = NULL;
    state->prepared.options.size_skipped_paths = NULL;
    state->prepared.options.synced_dirs = NULL;
    state->prepared.options.per_dir_rules = NULL;
    if (!prescan_ok || (!early_ok && !skip_delete)) {
      array_list_delete(prescan_chunks);
      return false;
    }
    /* Adopt the captured scan as the data pass's file list (including when an
       I/O error suppressed only the deletion: the list is still complete). */
    state->prescan_chunks = prescan_chunks;
  } else if (state->delete_per_dir) {
    /* --delete-during/--delete-delay: build one plan per source directory from a
       path-only pre-scan and transmit the COMPLETE plan set now, before any data,
       so every planned removal has already been applied when a later transfer
       phase fails -- exactly like rsync's generator, whose deletion list runs
       ahead of its throttled sender.  A completed run is unaffected. */
    state->plan_sender = delete_plan_sender_create();
    state->plan_dirs = array_list_create(free);
    if (!state->plan_sender || !state->plan_dirs)
      return false;
    state->prepared.options.plan_dirs = state->plan_dirs;
    bool prescan_ok =
        scan_paths_only(config, &state->prepared.options, NULL, state->plan_sender,
                        &state->had_scan_io, &state->per_dir_non_dir_count, NULL, false);
    bool plans_ok = false;
    bool skip_delete = false;
    if (prescan_ok) {
      const char* walk_root = delete_plan_walk_root(config, state->synced_dirs);
      const ArrayList* scope =
          config->files_from_set ? state->synced_dirs : (walk_root ? state->synced_dirs : NULL);
      delete_plan_sender_finalize(state->plan_sender, scope, walk_root);
      delete_plan_sender_set_config(state->plan_sender, state->excluded, state->size_skipped,
                                    state->missing_args, state->per_dir_rules);
      if (state->had_scan_io && delete_plan_sender_empty(state->plan_sender)) {
        log_message(LOG_LEVEL_ERROR,
                    "source scan hit an I/O error before finding any file; refusing to delete "
                    "with an empty keep-set (--delete)");
        prescan_ok = false;
      } else if (!ignore_errors_allows_delete(config, state->had_scan_io)) {
        /* rsync default: an I/O error suppresses deletion unless
           --ignore-errors.  Drop the plans; the transfer still proceeds. */
        log_message(LOG_LEVEL_WARNING, "IO error encountered -- skipping file deletion");
        delete_plan_sender_destroy(state->plan_sender);
        state->plan_sender = NULL;
        array_list_delete(state->plan_dirs);
        state->plan_dirs = NULL;
        skip_delete = true;
      } else {
        plans_ok = delete_plan_send_all(client->file_descriptor, state->plan_sender,
                                        state->plan_dirs) == 0;
      }
    }
    state->prepared.options.excluded_paths = NULL;
    state->prepared.options.size_skipped_paths = NULL;
    state->prepared.options.synced_dirs = NULL;
    state->prepared.options.plan_dirs = NULL;
    state->prepared.options.per_dir_rules = NULL;
    if (!prescan_ok || (!plans_ok && !skip_delete))
      return false;
  } else if (config->use_delete) {
    state->manifest = array_list_create(free);
    if (!state->manifest)
      return false;
  }
  return true;
}

/* Streaming run phase: pre-count progress, arm the stop deadline, scan the
 * source and transmit every chunk.  Returns false on a fatal error (the caller
 * runs the shared cleanup). */
static bool send_files_run(Config* config, SendFilesState* state) {
  Client* client = state->client;
  /* --progress needs the file-list total; -i/--out-format needs the directory
     entries.  Either way one paths-only pre-count supplies both, and a
     --delete-during/--delete-delay pre-scan is reused when present. */
  if (progress_requested(config) || config->itemize_changes || config->out_format != NULL)
    client_progress_prepare(config, state->plan_dirs, state->per_dir_non_dir_count);
  /* Phase 6: compute the client-only stop deadline once at transfer start.  The
     early-delete pre-scan above deliberately ignores it so the keep-set (and
     its committed deletion) is always complete and correct. */
  struct timespec now_mono;
  if (clock_gettime(CLOCK_MONOTONIC, &now_mono) != 0) {
    now_mono.tv_sec = 0;
    now_mono.tv_nsec = 0;
  }
  state->stop = stop_condition_make(config->stop_after_mins > 0, config->stop_after_mins,
                                    config->cli.stop_at_set, config->stop_at, now_mono);
  state->prepared.options.stop_condition = &state->stop;
  /* --delete-before reuses the pre-scan that built the keep-set as the data
     pass's file list, so a source file created after that scan is neither
     transferred nor kept (rsync builds one file list).  That pre-scan captured
     the deferred directory times and the --stats directory count because no
     later scan runs; every other mode opens a fresh data scanner here. */
  if (state->prescan_chunks == NULL) {
    state->prepared.options.dir_entries = state->dir_entries;
    state->prepared.options.dir_count = config->stats ? &state->dir_count : NULL;
    state->scanner =
        directory_scanner_create_with_options(config->send_directory, &state->prepared.options);
    if (!state->scanner)
      return false;
  }

  Chunk* current_chunk;
  int prescan_index = 0;
  memset(&state->transfer_stats, 0, sizeof(state->transfer_stats));
  state->start = time(NULL);
  client_progress_begin(config);
  /* True when the stop deadline cut the scan short so the keep-set manifest is
     only a prefix of the source. */
  bool send_failed = false;
  while (true) {
    if (state->prescan_chunks != NULL) {
      if (prescan_index >= state->prescan_chunks->size)
        break;
      /* Move ownership out of the retained list so chunk_destroy below (and the
         cleanup tail for an early exit) never double-frees it. */
      current_chunk = (Chunk*)state->prescan_chunks->items[prescan_index];
      state->prescan_chunks->items[prescan_index] = NULL;
      prescan_index++;
    } else {
      current_chunk = directory_scanner_next(state->scanner);
      if (current_chunk == NULL)
        break;
    }
    /* Graceful abort (Ctrl-C/SIGTERM): notify the receiver and clean up.  The
       session is active (config_send already succeeded); a send failure here is
       fine because the client is exiting anyway. */
    if (client_abort_pending()) {
      log_info_message(LOG_INFO_MISC, "Abort requested; sending STATUS_ABORT to server");
      chunk_destroy(current_chunk);
      send_status(client->file_descriptor, STATUS_ABORT);
      return false;
    }
    /* Phase 6: stop-elegantly at the next chunk boundary once the deadline has
       passed.  The scanner may also have stopped early itself; either way the
       completion tail below keeps everything already sent. */
    if (stop_condition_reached(&state->stop)) {
      chunk_destroy(current_chunk);
      log_info_message(LOG_INFO_MISC,
                       "Stop deadline reached; stopping transfer at the next chunk boundary");
      state->scan_stopped_early = true;
      break;
    }
    if (state->manifest && !add_chunk_to_manifest(state->manifest, current_chunk)) {
      chunk_destroy(current_chunk);
      return false;
    }
    if (!config->use_sendfile) {
      bool load_ok = true;
      for (int i = 0; i < current_chunk->element_count; i++) {
        File* f = current_chunk->items[i];
        if (loader_can_stream(config, f))
          continue;
        if (!file_load_data(f)) {
          log_message(LOG_LEVEL_ERROR, "Failed to load file data");
          load_ok = false;
          break;
        }
      }
      if (!load_ok) {
        chunk_destroy(current_chunk);
        return false;
      }
    }
    if (send_chunk_with_removal(client, current_chunk, config, state->remove_sources,
                                &state->transfer_stats) != 0) {
      log_message(LOG_LEVEL_ERROR, "Failed to send chunk");
      chunk_destroy(current_chunk);
      send_failed = true;
      break;
    }
    chunk_destroy(current_chunk);
  }
  return !send_failed;
}

/* Completion tail: send the late delete manifest and captured directory times,
 * finalize the receiver handshake, remove transferred sources and report stats.
 * Returns the rsync-compatible exit code. */
static int send_files_finalize(const Config* config, SendFilesState* state) {
  Client* client = state->client;
  /* A --delete-before run replays the pre-scan and owns no data scanner; its
     I/O-error verdict was already recorded by that pre-scan. */
  if (state->scanner != NULL) {
    if (directory_scanner_failed(state->scanner))
      return 1;
    if (directory_scanner_had_io_error(state->scanner))
      state->had_scan_io = true;
  }
  /* An abort that arrived after the last chunk must still stop the completion
     tail (manifest/finalize) rather than let it run to success. */
  if (client_abort_pending()) {
    log_info_message(LOG_INFO_MISC, "Abort requested; sending STATUS_ABORT to server");
    send_status(client->file_descriptor, STATUS_ABORT);
    return 1;
  }
  /* Phase 6: the scanner may have stopped early (returning NULL without a
     failure) as soon as the deadline passed, so reflect that here too.  A
     deadline that cut the scan short leaves an incomplete keep-set; transmitting
     it would make the receiver --delete the unscanned source mirrors (data
     loss), so the late delete manifest is suppressed below. */
  state->scan_stopped_early = state->scan_stopped_early || stop_condition_reached(&state->stop);
  if (state->scan_stopped_early) {
    if (config->use_delete || config->delete_missing_args)
      log_message(LOG_LEVEL_WARNING,
                  "transfer stopped early (stop deadline); skipping --delete keep-set so "
                  "unscanned source mirrors are not deleted");
    else
      log_message(LOG_LEVEL_WARNING, "transfer stopped early (stop deadline)");
  } else {
    if (state->had_scan_io && state->manifest && state->manifest->size == 0) {
      /* A scan that hit an I/O error and produced no keep entries is ambiguous;
         an empty keep-set would delete the whole destination.  Refuse to delete
         (see the early-timing comment above). */
      log_message(LOG_LEVEL_ERROR,
                  "source scan hit an I/O error before finding any file; refusing to delete with "
                  "an empty keep-set (--delete)");
      return 1;
    }
    /* rsync default: a scan I/O error suppresses deletion unless
       --ignore-errors, even in the late (commit) modes.  Drop the keep-set so
       the receiver removes nothing; the readable tree still transferred. */
    bool late_delete = (state->manifest || config->delete_missing_args) && !state->delete_early &&
                       !state->delete_per_dir;
    if (late_delete && !ignore_errors_allows_delete(config, state->had_scan_io)) {
      log_message(LOG_LEVEL_WARNING, "IO error encountered -- skipping file deletion");
      if (state->manifest) {
        array_list_delete(state->manifest);
        state->manifest = NULL;
      }
    } else if (late_delete) {
      /* Late (commit) ordering: all file data is out; transmit the manifest so
         the receiver commits the extras walk (--delete) and/or the
         --delete-missing-args exact-path deletions only after the transfer
         succeeds.  In the early modes (--delete-before) and the per-directory
         modes the deletion already went out with the data, so nothing is
         re-sent here. */
      if (send_delete_manifest(client->file_descriptor, state->manifest, state->excluded,
                               state->size_skipped, state->missing_args, state->synced_dirs,
                               state->per_dir_rules) != 0) {
        if (state->manifest) {
          array_list_delete(state->manifest);
          state->manifest = NULL;
        }
        return 1;
      }
      if (state->manifest) {
        array_list_delete(state->manifest);
        state->manifest = NULL;
      }
    }
  }
  /* Output parity: report changed directories that had no transferred child
     before the deferred directory times are applied (so the probe still sees
     their pre-transfer state). */
  client_change_emit_pending_dirs(config, client->file_descriptor);
  /* P7 Wave D: every directory has now been traversed (or the scan stopped
     early), so transmit the captured directory times last.  The receiver defers
     applying them until after its own deletion/publication phase. */
  if (!send_dir_times(client, config, state->dir_entries))
    return 1;
  bool delete_limit = false;
  bool partial = false;
  ReceiverStats recv_stats;
  memset(&recv_stats, 0, sizeof(recv_stats));
  client_flush_client_messages(client->file_descriptor);
  bool ok = finalize_transfer(client, config, state->remove_sources, &delete_limit, &partial,
                              &recv_stats);
  if (!ok && config->use_delete)
    log_message(LOG_LEVEL_ERROR,
                "server reported a deletion failure (--delete); see the server log for the reason");
  if (ok)
    remove_transferred_sources(config, state->remove_sources);
  /* A recursive -a scan has no directory entries in its chunks; account them
     from the scanner's captured directory list (present whenever a directory
     attribute is preserved, e.g. -a/-t/-p).  The -d generator counts its
     explicit directory entries inline instead. */
  state->transfer_stats.flist_dir +=
      dir_count_for_stats(config, state->dir_entries, &state->dir_count);
  report_transfer_stats(config, &state->transfer_stats, state->start, &recv_stats);
  log_info_message(LOG_INFO_STATS, "Transfer summary: %llu files, %.1f MB",
                   state->transfer_stats.transferred_regular,
                   (double)state->transfer_stats.transferred_file_size / (double)BYTES_PER_MIB);
  /* A skipped source entry (--ignore-errors past an unreadable directory, or a
     dereferenced symlink with no referent) makes rsync report a partial
     transfer (exit 23), as does a receiver per-entry failure (STATUS_PARTIAL).
     A --max-delete-capped commit is a successful transfer that rsync reports
     with exit code 25. */
  if (!ok)
    return 1;
  if (state->had_scan_io || partial)
    return 23;
  return delete_limit ? 25 : 0;
}

/* Single cleanup path for all exits.  The manifest is intentionally deleted
 * here even on success without --delete, fixing a pre-existing leak. */
static void send_files_cleanup(SendFilesState* state) {
  if (state->manifest)
    array_list_delete(state->manifest);
  if (state->prescan_chunks)
    array_list_delete(state->prescan_chunks);
  if (state->plan_sender)
    delete_plan_sender_destroy(state->plan_sender);
  if (state->excluded)
    array_list_delete(state->excluded);
  if (state->size_skipped)
    array_list_delete(state->size_skipped);
  if (state->synced_dirs)
    array_list_delete(state->synced_dirs);
  if (state->plan_dirs)
    array_list_delete(state->plan_dirs);
  if (state->missing_args)
    array_list_delete(state->missing_args);
  if (state->per_dir_rules)
    filter_rule_list_free(state->per_dir_rules);
  if (state->remove_sources)
    array_list_delete(state->remove_sources);
  if (state->dir_entries)
    array_list_delete(state->dir_entries);
  if (state->scanner)
    directory_scanner_destroy(state->scanner);
  prepared_scanner_destroy(&state->prepared);
  client_progress_cleanup();
  disconnect_transfer_client(state->client);
  protocol_session_unbind();
  client_set_abort_armed(false);
}

static int send_files_impl(Config* config);

int send_files(Config* config) {
  /* Install the --stderr=client sink for the whole run (it only queues while a
     session is live) and release its queue on every return path. */
  client_messages_install();
  int rc = send_files_impl(config);
  client_messages_end();
  return rc;
}

static int send_files_impl(Config* config) {
  if (config->list_only)
    return send_list_only(config);
  if (config->dry_run)
    return dry_run_targets_server(config) ? send_dry_run_remote(config)
                                          : send_dry_run_manifest(config);
  SendFilesState state;
  memset(&state, 0, sizeof(state));
  atomic_init(&state.dir_count, 0);
  state.delete_early = config->use_delete && config_delete_timing_early(config);
  /* --delete-during/--delete-delay use per-directory plans for every transfer
     shape.  For -d/--dirs the generator records only the directories whose
     direct children it actually enumerated, so the plan removes extras directly
     inside a listed directory while an untraversed (kept) subdirectory is
     shielded -- rsync's `-d DIR/ --delete`. */
  state.delete_per_dir = config->use_delete && config_delete_timing_per_dir(config);
  int skipped = 0;
  if (config->delete_missing_args) {
    state.missing_args = array_list_create(free);
    if (!state.missing_args)
      return 1;
  }
  if (!files_from_list_check(config, state.missing_args, &skipped)) {
    if (state.missing_args)
      array_list_delete(state.missing_args);
    return 1;
  }

  /* From here on a server session may be live, so Ctrl-C/SIGTERM should set the
     abort flag (and be forwarded as STATUS_ABORT) instead of terminating. */
  client_set_abort_armed(true);
  Client* client = connect_transfer_client(config);
  if (!client) {
    if (config->transport == TRANSPORT_TCP)
      log_message(LOG_LEVEL_ERROR, "could not connect to server%s",
                  config->use_tls ? " via TLS" : "");
    if (state.missing_args)
      array_list_delete(state.missing_args);
    return 1;
  }
  state.client = client;
  ProtocolSession session;
  protocol_session_init(&session, client->file_descriptor, client->file_descriptor);
  protocol_session_set_io_timeout(&session, config->timeout);
  protocol_session_set_ssl(&session, (SSL*)client->ssl);
  protocol_session_bind(&session);
  client_messages_activate(true);

  int ret = 1;
  if (!send_files_prepare(config, &state))
    goto send_fail;
  if (!send_files_prepare_delete(config, &state))
    goto send_fail;
  if (!send_files_run(config, &state))
    goto send_fail;
  ret = send_files_finalize(config, &state);

send_fail:
  send_files_cleanup(&state);
  return ret;
}

static int send_files_multithreaded_impl(Config* config);

int send_files_multithreaded(Config* config) {
  client_messages_install();
  int rc = send_files_multithreaded_impl(config);
  client_messages_end();
  return rc;
}

static int send_files_multithreaded_impl(Config* config) {
  if (!config)
    return 1;
  if (config->list_only)
    return send_list_only(config);
  if (config->dry_run)
    return dry_run_targets_server(config) ? send_dry_run_remote(config)
                                          : send_dry_run_manifest(config);
  ArrayList* missing_args = NULL;
  int skipped = 0;
  if (config->delete_missing_args) {
    missing_args = array_list_create(free);
    if (!missing_args)
      return 1;
  }
  if (!files_from_list_check(config, missing_args, &skipped)) {
    if (missing_args)
      array_list_delete(missing_args);
    return 1;
  }

  /* Armed only once a session may go live (see send_files). */
  client_set_abort_armed(true);

  long pages = sysconf(_SC_AVPHYS_PAGES);
  long page_size = sysconf(_SC_PAGE_SIZE);
  unsigned long long available_memory =
      pages > 0 && page_size > 0 ? (unsigned long long)pages * (unsigned long long)page_size
                                 : 512ULL * 1024 * 1024;
  /* Size the chunk queues from the actual chunk size rather than a fixed 1 MiB
     average: a chunk holds roughly `chunk_size` bytes of file data, so counting
     chunks at 1 MiB over-estimated the queue capacity by up to 10x.  The byte
     budget below is the authoritative bound; this count keeps the unloaded
     chunks waiting in the scanner queue bounded too. */
  unsigned long long chunk_size = config->chunk_size > 0 ? config->chunk_size : DEFAULT_CHUNK_SIZE;
  int qsize = (int)(available_memory / chunk_size);
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
    if (missing_args)
      array_list_delete(missing_args);
    return 1;
  }
  context->missing_args = missing_args;
  missing_args = NULL; /* owned by the context from here on */
  pipeline_context_sender_set_queue_byte_limit(context, SENDER_QUEUE_MAX_BYTES);
  /* The context borrows `config`; the caller (main) still owns and frees it. */
  struct timespec now_mono;
  if (clock_gettime(CLOCK_MONOTONIC, &now_mono) != 0) {
    now_mono.tv_sec = 0;
    now_mono.tv_nsec = 0;
  }
  context->stop_condition =
      stop_condition_make(config->stop_after_mins > 0, config->stop_after_mins,
                          config->cli.stop_at_set, config->stop_at, now_mono);
  bool collect_excluded = config->use_delete && !config->delete_excluded;
  unsigned long long pre_scan_non_dir = 0;
  if (config->use_delete) {
    if (collect_excluded) {
      context->excluded_paths = array_list_create(free);
      if (!context->excluded_paths) {
        pipeline_context_sender_destroy(context);
        return 1;
      }
    }
    /* Size-pruned mirrors stay protected under every mode (even
       --delete-excluded); synchronized directories confine the walk.  A full
       recursive transfer marks the receive root itself (".") so the walk is not
       confined; only a --files-from subset records concrete directories. */
    context->size_skipped_paths = array_list_create(free);
    context->synced_dirs = array_list_create(free);
    context->per_dir_rules = filter_rule_list_create();
    if (!context->size_skipped_paths || !context->synced_dirs || !context->per_dir_rules) {
      pipeline_context_sender_destroy(context);
      return 1;
    }
    if (config->files_from_set == NULL) {
      char* root_marker = delete_scope_root_marker(config);
      if (!root_marker || !array_list_add(context->synced_dirs, root_marker)) {
        free(root_marker);
        pipeline_context_sender_destroy(context);
        return 1;
      }
    }
    /* --delete-during/--delete-delay use per-directory plans for every transfer
       shape.  The -d/--dirs generator records only the directories whose direct
       children it enumerated, so extras directly inside a listed directory are
       removed while an untraversed (kept) subdirectory is shielded. */
    bool per_dir = config_delete_timing_per_dir(config);
    if (config_delete_timing_early(config) || per_dir) {
      /* --delete-before / --delete-during / --delete-delay: build the keep-set
         (paths only, nothing loaded or sent) up front so the sender thread can
         transmit it before/with the data.  The path-only pre-scan also fills the
         protected excluded prefixes and synchronized directories. */
      PreparedScanner prepared;
      memset(&prepared, 0, sizeof(prepared));
      bool prepared_ok = prepare_scanner(config, config->scanner_threads, &prepared);
      if (prepared_ok) {
        if (context->excluded_paths)
          prepared.options.excluded_paths = context->excluded_paths;
        prepared.options.size_skipped_paths = context->size_skipped_paths;
        prepared.options.per_dir_rules = context->per_dir_rules;
        /* The root marker for a full recursive transfer is already in the list;
           only a --files-from subset needs the scanner to record directories. */
        if (config->files_from_set != NULL)
          prepared.options.synced_dirs = context->synced_dirs;
      }
      if (per_dir) {
        context->delete_plans = delete_plan_sender_create();
        context->plan_dirs = array_list_create(free);
        prepared_ok = prepared_ok && context->delete_plans != NULL && context->plan_dirs != NULL;
        if (prepared_ok)
          prepared.options.plan_dirs = context->plan_dirs;
      } else {
        /* --delete-before: retain the pre-scan chunks as the pipeline's data
           pass (rsync's single file list) so a source file created after the
           scan is not transferred.  No later scan runs, so this pass must also
           capture the deferred directory times and the --stats directory
           count. */
        context->manifest = array_list_create(free);
        context->prescan_chunks = array_list_create(chunk_destroy);
        prepared_ok = prepared_ok && context->manifest != NULL && context->prescan_chunks != NULL;
        if (prepared_ok) {
          prepared.options.dir_entries = context->dir_entries;
          prepared.options.dir_entries_mutex = &context->dir_entries_mutex;
          prepared.options.dir_count = config->stats ? &context->dir_count : NULL;
          if (!append_implied_dir_times(config, context->dir_entries))
            prepared_ok = false;
        }
      }
      bool prebuilt =
          prepared_ok &&
          scan_paths_only(config, &prepared.options, context->manifest, context->delete_plans,
                          &context->scan_had_io_error, &pre_scan_non_dir, context->prescan_chunks,
                          context->prescan_chunks != NULL);
      prepared_scanner_destroy(&prepared);
      if (per_dir && prebuilt) {
        const char* walk_root = delete_plan_walk_root(config, context->synced_dirs);
        const ArrayList* scope = config->files_from_set ? context->synced_dirs
                                                        : (walk_root ? context->synced_dirs : NULL);
        delete_plan_sender_finalize(context->delete_plans, scope, walk_root);
        delete_plan_sender_set_config(context->delete_plans, context->excluded_paths,
                                      context->size_skipped_paths, context->missing_args,
                                      context->per_dir_rules);
      }
      bool empty = per_dir
                       ? (context->delete_plans && delete_plan_sender_empty(context->delete_plans))
                       : (context->manifest && context->manifest->size == 0);
      if (prebuilt && context->scan_had_io_error && empty) {
        /* Empty keep-set + scan I/O error: refusing an empty keep-set would
           have deleted the whole destination (see send_files). */
        log_message(LOG_LEVEL_ERROR,
                    "source scan hit an I/O error before finding any file; refusing to delete "
                    "with an empty keep-set (--delete)");
        prebuilt = false;
      }
      if (!prebuilt) {
        pipeline_context_sender_destroy(context);
        return 1;
      }
      if (context->scan_had_io_error && !ignore_errors_allows_delete(config, true)) {
        /* rsync default: an I/O error suppresses deletion unless
           --ignore-errors.  Drop the prebuilt keep-set so nothing is sent; the
           data pass still transfers the readable tree and exits 23. */
        log_message(LOG_LEVEL_WARNING, "IO error encountered -- skipping file deletion");
        if (context->manifest) {
          array_list_delete(context->manifest);
          context->manifest = NULL;
        }
        if (context->delete_plans) {
          delete_plan_sender_destroy(context->delete_plans);
          context->delete_plans = NULL;
        }
        if (context->plan_dirs) {
          array_list_delete(context->plan_dirs);
          context->plan_dirs = NULL;
        }
        /* A later --delete pass must not try to rebuild/send a keep-set. */
        context->delete_suppressed = true;
      } else if (!per_dir) {
        context->early_delete = true;
      }
    } else {
      context->manifest = array_list_create(free);
      if (!context->manifest) {
        pipeline_context_sender_destroy(context);
        return 1;
      }
    }
  }
  if (config->remove_source_files)
    context->remove_source_files = array_list_create(source_file_destroy);
  if ((config->use_delete && !context->manifest && !context->delete_plans &&
       !context->delete_suppressed) ||
      (config->remove_source_files && !context->remove_source_files)) {
    pipeline_context_sender_destroy(context);
    return 1;
  }
  /* --progress/--info=progress: pre-count the file list for rsync's to-chk
     denominator; -i/--out-format: pre-count the directory entries.  One pass
     supplies both, reusing a --delete-during/--delete-delay pre-scan when one
     already ran. */
  if (progress_requested(config) || config->itemize_changes || config->out_format != NULL)
    client_progress_prepare(config, context->plan_dirs, pre_scan_non_dir);

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
    client_progress_cleanup();
    return 1;
  }

  int sender_result;
  thrd_join(scanner, NULL);
  thrd_join(loader, NULL);
  thrd_join(sender, &sender_result);

  bool scan_io;
  mtx_lock(&context->mutex_scanner);
  scan_io = context->scan_had_io_error;
  mtx_unlock(&context->mutex_scanner);
  bool sender_ok = sender_result == thrd_success;
  bool delete_limit = context->delete_limit;
  bool partial = context->partial;
  /* A skipped source entry (--ignore-errors past an unreadable directory, or a
     dereferenced symlink with no referent) makes rsync report a partial
     transfer (exit 23), as does a receiver per-entry failure (STATUS_PARTIAL).
     A --max-delete-capped commit is a successful transfer that rsync reports
     with exit code 25. */
  pipeline_context_sender_destroy(context);
  client_progress_cleanup();
  client_set_abort_armed(false);
  if (!sender_ok)
    return 1;
  if (scan_io || partial)
    return 23;
  return delete_limit ? 25 : 0;
}
