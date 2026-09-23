#include "client_send_internal.h"
#include "array_list.h"
#include "change_list.h"
#include "charset.h"
#include "config.h"
#include "data.h"
#include "delta.h"
#include "file.h"
#include "format.h"
#include "log.h"
#include "protocol.h"
#include "scanner.h"
#include "transport_tls.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* True when --dry-run should contact a receiver rather than running the
 * client-side local manifest.  Any target a real run would reach over the wire
 * selects the server-contacting path: a remote (SSH host:path), a daemon
 * (host::module/path), an explicit --server-host, --server-port/--port, TLS, or
 * a source-bind --address.  A plain local destination (none of these) keeps the
 * original client-side behavior, which never dials the default 127.0.0.1:8080. */
bool dry_run_targets_server(const Config* config) {
  if (!config)
    return false;
  if (config->transport == TRANSPORT_SSH)
    return true;
  if (config->module && config->module[0] != '\0')
    return true;
  if (config->cli.server_host_set || config->cli.server_port_set)
    return true;
  if (config->use_tls)
    return true;
  if (config->address != NULL)
    return true;
  return false;
}

bool add_chunk_to_manifest(ArrayList* manifest, const Chunk* chunk) {
  if (!manifest)
    return true;
  for (int i = 0; i < chunk->element_count; i++) {
    const char* path = file_wire_path(chunk->items[i]);
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

/* Print dry-run manifest showing files that would be transferred. Returns 0 on success. */
int send_dry_run_manifest(const Config* config) {
  int skipped = 0;
  ArrayList* missing_dest = NULL;
  if (config->delete_missing_args) {
    missing_dest = array_list_create(free);
    if (!missing_dest)
      return -1;
  }
  if (!files_from_list_check(config, missing_dest, &skipped)) {
    if (missing_dest)
      array_list_delete(missing_dest);
    return -1;
  }
  PreparedScanner prepared;
  if (!prepare_scanner(config, 0, &prepared)) {
    if (missing_dest)
      array_list_delete(missing_dest);
    return -1;
  }
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner) {
    prepared_scanner_destroy(&prepared);
    if (missing_dest)
      array_list_delete(missing_dest);
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
        char* escaped_path =
            output_escape(file_wire_path(chunk->items[i]), config->eight_bit_output);
        if (!escaped_path) {
          chunk_destroy(chunk);
          directory_scanner_destroy(scanner);
          prepared_scanner_destroy(&prepared);
          if (missing_dest)
            array_list_delete(missing_dest);
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
  /* --delete-missing-args: the missing entries' destination mirrors render as
     would-be deletions (rsync's dry-run also lists its *deleting lines). */
  if (missing_dest && !config->quiet) {
    for (int i = 0; i < missing_dest->size; i++) {
      char* escaped = output_escape((char*)missing_dest->items[i], config->eight_bit_output);
      printf("  %s (missing; would be deleted)\n", escaped ? escaped : "<allocation failed>");
      free(escaped);
    }
  }
  if (missing_dest)
    array_list_delete(missing_dest);
  if (!config->quiet) {
    if (config->human_readable)
      printf("Total: %d files, %s\n", file_count,
             display_bytes(total_bytes, true, size_buffer, sizeof(size_buffer)));
    else
      printf("Total: %d files, %.1f MB\n", file_count, (double)total_bytes / (double)BYTES_PER_MIB);
  }
  return 0;
}

typedef struct {
  char* name; /* transfer-relative name ("" == the source root) */
  mode_t mode;
  unsigned long long size;
  time_t mtime;
  long mtime_nsec;
  bool is_dir;
  bool is_symlink;
  char* link_target;
} ListEntry;

static void list_entries_destroy(ListEntry* entries, size_t count) {
  if (entries == NULL)
    return;
  for (size_t i = 0; i < count; i++) {
    free(entries[i].name);
    free(entries[i].link_target);
  }
  free(entries);
}

static int compare_list_entries(const void* left, const void* right) {
  const ListEntry* a = (const ListEntry*)left;
  const ListEntry* b = (const ListEntry*)right;
  return strcmp(a->name, b->name);
}

/* Relative path of an entry below `root` ("" for the root itself).  Mirrors
 * change_list's relative_name for list-only rendering. */
static char* list_relative_name(const char* root, const char* full) {
  if (root == NULL || full == NULL)
    return str_dup(full != NULL ? full : "");
  size_t root_len = strlen(root);
  while (root_len > 1 && root[root_len - 1] == '/')
    root_len--;
  if (strncmp(root, full, root_len) == 0) {
    if (full[root_len] == '\0')
      return str_dup("");
    if (full[root_len] == '/')
      return str_dup(full + root_len + 1);
  }
  return str_dup(full);
}

/* --list-only: print an ls-style listing of the entries that WOULD be
 * transferred and exit without contacting the server or writing anything.
 * Names are transfer-relative (rsync prints `a.txt`, `sub/b.txt`, `.`) and
 * directory entries are included.  Returns 0 on success, 1 on error. */
int send_list_only(const Config* config) {
  int skipped = 0;
  if (!files_from_list_check(config, NULL, &skipped))
    return 1;
  PreparedScanner prepared;
  if (!prepare_scanner(config, 0, &prepared))
    return 1;
  prepared.options.use_metadata = true; /* capture mode + mtime for the listing */
  prepared.options.list_dirs = true;
  DirectoryScanner* scanner =
      directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner) {
    prepared_scanner_destroy(&prepared);
    return 1;
  }
  ListEntry* entries = NULL;
  size_t count = 0;
  size_t capacity = 0;
  bool oom = false;

  /* rsync lists the source root itself (as ".").  Only when the source is a
   * directory and no --files-from subset is in effect. */
  if (config->files_from_set == NULL && config->send_directory != NULL) {
    struct stat st;
    if (stat(config->send_directory, &st) == 0 && S_ISDIR(st.st_mode)) {
      capacity = 64;
      entries = calloc(capacity, sizeof(ListEntry));
      if (entries == NULL) {
        oom = true;
      } else if ((entries[0].name = str_dup("")) == NULL) {
        /* A NULL name would be dereferenced by qsort/render: fail the listing. */
        oom = true;
      } else {
        entries[0].mode = st.st_mode;
        entries[0].mtime = st.st_mtime;
        entries[0].mtime_nsec = st.st_mtim.tv_nsec;
        entries[0].size = (unsigned long long)st.st_size;
        entries[0].is_dir = true;
        count = 1;
      }
    }
  }

  Chunk* chunk;
  while (!oom && (chunk = directory_scanner_next(scanner)) != NULL) {
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
        memset(entries + capacity, 0, (new_capacity - capacity) * sizeof(ListEntry));
        capacity = new_capacity;
      }
      char* name = list_relative_name(config->send_directory, file_wire_path(f));
      if (!name) {
        oom = true;
        break;
      }
      mode_t mode = 0;
      time_t mtime = 0;
      long mtime_nsec = 0;
      if (f->metadata != NULL) {
        mode = f->metadata->mode;
        mtime = f->metadata->mtime_sec;
        mtime_nsec = f->metadata->mtime_nsec;
      } else {
        struct stat st;
        if (lstat(f->path, &st) == 0) {
          mode = st.st_mode;
          mtime = st.st_mtime;
          mtime_nsec = st.st_mtim.tv_nsec;
        }
      }
      entries[count].name = name;
      entries[count].mode = mode;
      entries[count].mtime = mtime;
      entries[count].mtime_nsec = mtime_nsec;
      if (f->is_symlink)
        entries[count].size = f->symlink_target != NULL ? strlen(f->symlink_target) : 0;
      else if (f->is_dir) {
        struct stat dir_st;
        entries[count].size = stat(f->path, &dir_st) == 0 ? (unsigned long long)dir_st.st_size : 0;
      } else
        entries[count].size = f->data != NULL ? f->data->size : 0;
      entries[count].is_dir = f->is_dir;
      entries[count].is_symlink = f->is_symlink;
      entries[count].link_target =
          f->is_symlink && f->symlink_target ? str_dup(f->symlink_target) : NULL;
      count++;
    }
    chunk_destroy(chunk);
  }
  bool failed = oom || directory_scanner_failed(scanner) || directory_scanner_had_io_error(scanner);
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
    ChangeEvent event;
    memset(&event, 0, sizeof(event));
    event.name = entries[i].name;
    event.path = entries[i].name;
    event.mode = entries[i].mode;
    event.size = entries[i].size;
    event.mtime_sec = entries[i].mtime;
    event.mtime_nsec = entries[i].mtime_nsec;
    event.is_directory = entries[i].is_dir;
    event.is_symlink = entries[i].is_symlink;
    event.symlink_target = entries[i].link_target;
    char* line = change_render_list_line(config, &event);
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

/* Send the delete manifest to the server.  Returns 0 on success, -1 on
   failure.  It carries FOUR path sections (keep-set paths, protected excluded
   prefixes, --delete-missing-args exact-delete paths, and the destination-
   relative directories the sender synchronized this run) followed by the
   protocol-2.30.0 per-directory filter-rule block (`per_dir_rules`, the rules
   the scan compiled from each directory's merge files).
   When --delete-excluded is given `protected` is empty: excluded destination
   mirrors are then ordinary extras and are removed.  When
   --delete-missing-args is active `missing_args` holds the destination mirrors
   of missing --files-from entries: each is an explicit receiver-side deletion
   request, independent of the extras walk.  `synced_dirs` confines the extras
   walk to entries directly inside a synchronized directory.  A NULL
   keep-set / protected / missing / dirs list transmits an empty section.  All
   four sections are unbounded on the sender; the receiver enforces
   MAX_MANIFEST_ENTRIES per section and a single MAX_MANIFEST_BYTES budget
   shared across the sections, rejecting (with STATUS_ERROR) an over-budget
   frame.  A heavily filtered source whose exclusion list is large therefore
   fails the run cleanly on the receiver rather than being truncated. */
int send_delete_manifest(int fd, ArrayList* manifest, ArrayList* protected_prefixes,
                         ArrayList* size_skipped, ArrayList* missing_args, ArrayList* synced_dirs,
                         const FilterRuleList* per_dir_rules) {
  if (!send_status(fd, STATUS_MANIFEST))
    return -1;
  int keep_count = manifest ? manifest->size : 0;
  if (!send_int(fd, keep_count))
    return -1;
  for (int i = 0; i < keep_count; i++) {
    if (!send_wire_str(fd, (char*)manifest->items[i]))
      return -1;
  }
  /* The receiver has ONE protected-prefix section; filter-excluded prefixes
     (dropped under --delete-excluded) and size-pruned prefixes (always
     protected) are concatenated into it. */
  int protected_count =
      (protected_prefixes ? protected_prefixes->size : 0) + (size_skipped ? size_skipped->size : 0);
  if (!send_int(fd, protected_count))
    return -1;
  if (protected_prefixes) {
    for (int i = 0; i < protected_prefixes->size; i++) {
      if (!send_wire_str(fd, (char*)protected_prefixes->items[i]))
        return -1;
    }
  }
  if (size_skipped) {
    for (int i = 0; i < size_skipped->size; i++) {
      if (!send_wire_str(fd, (char*)size_skipped->items[i]))
        return -1;
    }
  }
  int missing_count = missing_args ? missing_args->size : 0;
  if (!send_int(fd, missing_count))
    return -1;
  for (int i = 0; i < missing_count; i++) {
    if (!send_wire_str(fd, (char*)missing_args->items[i]))
      return -1;
  }
  int dirs_count = synced_dirs ? synced_dirs->size : 0;
  if (!send_int(fd, dirs_count))
    return -1;
  for (int i = 0; i < dirs_count; i++) {
    if (!send_wire_str(fd, (char*)synced_dirs->items[i]))
      return -1;
  }
  /* Protocol 2.30.0: the receiver-side per-directory filter rules discovered by
     the sender's scan, so the whole-tree commit walker can shield a
     destination-only entry that matches only a per-directory merge rule. */
  if (!delete_filter_dir_rules_send(fd, per_dir_rules))
    return -1;
  return 0;
}

/* Transmit the keep-set manifest and wait for the receiver's verdict.  Used by
   --delete-before/--delete-during, where the extras are removed on the receiver
   BEFORE the first byte of file data is sent: the receiver acknowledges with
   STATUS_OK once the bounded delete committed, or STATUS_ERROR if it could not
   (in which case the sender aborts without streaming any data).  The ACK may
   take much longer than an ordinary per-message round trip because the receiver
   performs the whole bounded deletion walk (up to MAX_SERVER_DELETE_COUNT
   unlinks) before replying, so the wait uses a generous explicit deadline
   instead of the default 60 s receive window. */
#define DELETE_ACK_TIMEOUT_SEC 3600
/* While waiting for the (potentially slow) receiver-side deletion, send a
 * STATUS_KEEPALIVE at most this often so the connection is demonstrably alive
 * and neither side's per-message timeout trips. */
#define DELETE_ACK_KEEPALIVE_SEC 10

bool send_delete_manifest_early(Client* client, ArrayList* manifest, ArrayList* protected_prefixes,
                                ArrayList* size_skipped, ArrayList* missing_args,
                                ArrayList* synced_dirs, const FilterRuleList* per_dir_rules) {
  if (!client || !manifest)
    return false;
  if (send_delete_manifest(client->file_descriptor, manifest, protected_prefixes, size_skipped,
                           missing_args, synced_dirs, per_dir_rules) != 0)
    return false;
  Status ack;
  /* The wait is long (up to an hour) and runs inline on this thread: a helper
   * thread would race the non-thread-safe protocol send path, so keepalives are
   * emitted from this wait loop itself.  A Ctrl-C/SIGTERM abort flag also ends
   * the wait; the caller then best-effort sends STATUS_ABORT. */
  if (!receive_status_keepalive(client->file_descriptor, &ack, DELETE_ACK_TIMEOUT_SEC,
                                DELETE_ACK_KEEPALIVE_SEC, client_abort_pending)) {
    /* A Ctrl-C/SIGTERM abort ends the wait above; tell the receiver before the
       caller tears the connection down (best-effort). */
    if (client_abort_pending()) {
      log_info_message(LOG_INFO_MISC,
                       "Abort requested while awaiting delete ack; sending STATUS_ABORT");
      send_status(client->file_descriptor, STATUS_ABORT);
    }
    return false;
  }
  if (ack != STATUS_OK) {
    log_server_rejection("Server failed to delete files before the transfer");
    return false;
  }
  return true;
}

/* Server-contacting --dry-run.  Connects to the configured remote/daemon and
 * runs the normal per-file incremental decision WITHOUT transmitting any file
 * data: the receiver (which also sees dry_run=true on the wire) answers
 * STATUS_OK for an up-to-date file and STATUS_DRY_RUN_TRANSFER for a file it
 * would otherwise write, mutating nothing on either side.  The would-transfer
 * set and the same trailer as the local dry-run are printed.  A
 * --compare-dest exact basis hit with no destination copy is reported as a
 * skip by the receiver.
 *
 * Only regular files take the receiver-consulted check; directory / symlink /
 * special / hard-link-sibling entries have no per-file content check, so they
 * are reported conservatively as would-transfer and their frames are never
 * sent (which is what keeps the receiver mutation-free).  --delete* is
 * deliberately NOT transmitted in dry-run, so no deletion can occur; the
 * would-delete manifest report is a documented follow-up.
 *
 * Returns 0 on success, 1 on error. */
int send_dry_run_remote(Config* config) {
  int from_skipped = 0;
  ArrayList* missing_args = NULL;
  if (config->delete_missing_args) {
    missing_args = array_list_create(free);
    if (!missing_args)
      return 1;
  }
  if (!files_from_list_check(config, missing_args, &from_skipped)) {
    if (missing_args)
      array_list_delete(missing_args);
    return 1;
  }
  if (missing_args)
    array_list_delete(missing_args);
  /* A live session may follow, so arm graceful abort handling. */
  client_set_abort_armed(true);
  Client* client = connect_transfer_client(config);
  if (!client) {
    if (config->transport == TRANSPORT_TCP)
      log_message(LOG_LEVEL_ERROR, "could not connect to server%s",
                  config->use_tls ? " via TLS" : "");
    client_set_abort_armed(false);
    return 1;
  }
  ProtocolSession session;
  protocol_session_init(&session, client->file_descriptor, client->file_descriptor);
  protocol_session_set_io_timeout(&session, config->timeout);
  protocol_session_set_ssl(&session, (SSL*)client->ssl);
  protocol_session_bind(&session);

  int ret = 1;
  time_t dry_start = time(NULL);
  ReceiverStats dry_stats;
  memset(&dry_stats, 0, sizeof(dry_stats));
  PreparedScanner prepared;
  memset(&prepared, 0, sizeof(prepared));
  DirectoryScanner* scanner = NULL;
  ArrayList* dry_manifest = NULL;
  ArrayList* dry_dirs = NULL;
  ArrayList* dry_excluded = NULL;
  ArrayList* dry_size_skipped = NULL;
  FilterRuleList* dry_per_dir = NULL;
  if (!config_send(client->file_descriptor, config))
    goto dry_fail;
  receive_daemon_motd(client, config);
  if (!prepare_scanner(config, 0, &prepared))
    goto dry_fail;
  /* -n --delete: build the same keep-set manifest, protected prefixes, and
     synchronized-directory scope a real run would send, so the receiver's
     read-only extras walk enumerates exactly the deletions a real run makes. */
  if (config->use_delete) {
    dry_manifest = array_list_create(free);
    dry_dirs = array_list_create(free);
    dry_size_skipped = array_list_create(free);
    dry_per_dir = filter_rule_list_create();
    if (!dry_manifest || !dry_dirs || !dry_size_skipped || !dry_per_dir)
      goto dry_fail;
    prepared.options.per_dir_rules = dry_per_dir;
    if (!config->delete_excluded) {
      dry_excluded = array_list_create(free);
      if (!dry_excluded)
        goto dry_fail;
      prepared.options.excluded_paths = dry_excluded;
    }
    prepared.options.size_skipped_paths = dry_size_skipped;
    /* A --files-from subset confines the extras walk to the directories the
       scan synchronized; a full recursive transfer marks the root itself. */
    if (config->files_from_set == NULL) {
      char* root_marker = delete_scope_root_marker(config);
      if (!root_marker || !array_list_add(dry_dirs, root_marker)) {
        free(root_marker);
        goto dry_fail;
      }
    } else {
      prepared.options.synced_dirs = dry_dirs;
    }
  }
  scanner = directory_scanner_create_with_options(config->send_directory, &prepared.options);
  if (!scanner)
    goto dry_fail;

  int file_count = 0;
  unsigned long long total_bytes = 0;
  char size_buffer[32];
  if (!config->quiet)
    printf("Dry run: files to be transferred\n");
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    if (dry_manifest && !add_chunk_to_manifest(dry_manifest, chunk)) {
      chunk_destroy(chunk);
      goto dry_fail;
    }
    for (int i = 0; i < chunk->element_count; i++) {
      File* f = chunk->items[i];
      if (!f)
        continue;
      unsigned long long fsize = f->data ? f->data->size : 0;
      bool would;
      if (f->is_dir || f->is_symlink || f->is_special ||
          (f->link_group != 0 && !f->link_first && f->hardlink_target != NULL)) {
        /* No receiver-side content check exists for these frame types; a real
           run would (re)create them, so report would-transfer and send no
           frame (the receiver must stay mutation-free). */
        would = true;
      } else if (fsize > MAX_RECEIVE_WHOLE_FILE_SIZE && !config->use_incremental &&
                 !config_has_basis(config)) {
        /* A non-incremental run streams a >whole-file-limit source without the
           STATUS_CHECK handshake, so no read-only receiver decision is possible
           (and none is needed: a real run would transfer it). */
        would = true;
      } else {
        DeltaSignature* sig = NULL;
        unsigned long long resume_offset = 0;
        int rc = incremental_check(client, f, config, &sig, &resume_offset);
        delta_signature_destroy(sig);
        if (rc < 0) {
          chunk_destroy(chunk);
          goto dry_fail;
        }
        if (rc == 1)
          continue; /* up to date; nothing to report */
        if (rc != 4) {
          log_message(LOG_LEVEL_ERROR, "Unexpected receiver reply during dry-run");
          chunk_destroy(chunk);
          goto dry_fail;
        }
        would = true;
      }
      if (would) {
        if (!config->quiet) {
          char* escaped_path = output_escape(file_wire_path(f), config->eight_bit_output);
          if (!escaped_path) {
            chunk_destroy(chunk);
            goto dry_fail;
          }
          if (config->human_readable)
            printf("  %s (%s)\n", escaped_path,
                   display_bytes(fsize, true, size_buffer, sizeof(size_buffer)));
          else
            printf("  %s (%llu bytes)\n", escaped_path, fsize);
          free(escaped_path);
        }
        total_bytes += fsize;
        file_count++;
      }
    }
    chunk_destroy(chunk);
  }
  bool io_error = directory_scanner_had_io_error(scanner);
  if (directory_scanner_failed(scanner))
    goto dry_fail;
  if (io_error)
    log_message(LOG_LEVEL_WARNING, "source scan hit an unreadable directory");
  /* Send the keep-set manifest (no data frames) so the receiver can enumerate
     the destination extras; an early-timing delete ACKs before it will accept
     the terminal FINISHED. */
  bool early_delete = config->use_delete && config_delete_timing_early(config);
  if (dry_manifest) {
    if (send_delete_manifest(client->file_descriptor, dry_manifest, dry_excluded, dry_size_skipped,
                             NULL, dry_dirs, dry_per_dir) != 0)
      goto dry_fail;
    if (early_delete) {
      Status ack;
      if (!receive_status_keepalive(client->file_descriptor, &ack, DELETE_ACK_TIMEOUT_SEC,
                                    DELETE_ACK_KEEPALIVE_SEC, client_abort_pending) ||
          ack != STATUS_OK)
        goto dry_fail;
    }
  }
  /* Terminate the stream so the receiver emits its success frame; no data frame
     is ever sent in dry-run. */
  if (!send_status(client->file_descriptor, STATUS_FINISHED))
    goto dry_fail;
  Status status;
  if (!receive_status(client->file_descriptor, &status))
    goto dry_fail;
  if (status == STATUS_STATS) {
    ArrayList* would_delete = array_list_create(free);
    if (!would_delete)
      goto dry_fail;
    if (!receive_stats_record(client->file_descriptor, &dry_stats, would_delete)) {
      array_list_delete(would_delete);
      goto dry_fail;
    }
    print_delete_reports(config, would_delete);
    array_list_delete(would_delete);
    if (!receive_status(client->file_descriptor, &status))
      goto dry_fail;
  }
  if (status != STATUS_OK)
    goto dry_fail;
  if (!config->quiet) {
    if (config->human_readable)
      printf("Total: %d files, %s\n", file_count,
             display_bytes(total_bytes, true, size_buffer, sizeof(size_buffer)));
    else
      printf("Total: %d files, %.1f MB\n", file_count, (double)total_bytes / (double)BYTES_PER_MIB);
  }
  {
    TransferStats dry_transfer;
    memset(&dry_transfer, 0, sizeof(dry_transfer));
    dry_transfer.flist_reg = (unsigned long long)file_count;
    dry_transfer.total_file_size = total_bytes;
    dry_transfer.transferred_regular = (unsigned long long)file_count;
    dry_transfer.transferred_file_size = total_bytes;
    dry_transfer.literal_data = total_bytes;
    report_transfer_stats(config, &dry_transfer, dry_start, &dry_stats);
  }
  ret = io_error ? 1 : 0;

dry_fail:
  if (dry_manifest)
    array_list_delete(dry_manifest);
  if (dry_dirs)
    array_list_delete(dry_dirs);
  if (dry_excluded)
    array_list_delete(dry_excluded);
  if (dry_size_skipped)
    array_list_delete(dry_size_skipped);
  if (dry_per_dir)
    filter_rule_list_free(dry_per_dir);
  if (scanner)
    directory_scanner_destroy(scanner);
  prepared_scanner_destroy(&prepared);
  disconnect_transfer_client(client);
  protocol_session_unbind();
  client_set_abort_armed(false);
  return ret;
}
