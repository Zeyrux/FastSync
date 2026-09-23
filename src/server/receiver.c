#include "receiver.h"

#include "charset.h"
#include "chunk.h"
#include "config.h"
#include "delete_plan.h"
#include "delay_updates.h"
#include "file.h"
#include "file_receive.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

bool receiver_outcomes_append(ReceiverOutcomes* outcomes, unsigned char code) {
  if (!outcomes)
    return false;
  if (outcomes->count == outcomes->capacity) {
    size_t new_capacity = outcomes->capacity == 0 ? 64 : outcomes->capacity * 2;
    if (new_capacity < outcomes->capacity)
      return false;
    unsigned char* grown = realloc(outcomes->entries, new_capacity);
    if (!grown)
      return false;
    outcomes->entries = grown;
    outcomes->capacity = new_capacity;
  }
  outcomes->entries[outcomes->count++] = code;
  return true;
}

void receiver_outcomes_destroy(ReceiverOutcomes* outcomes) {
  if (!outcomes)
    return;
  free(outcomes->entries);
  outcomes->entries = NULL;
  outcomes->count = 0;
  outcomes->capacity = 0;
}

/* End-of-transfer success frame.  When --remove-source-files was negotiated
   each processed data file is acknowledged first (STATUS_NEXT = written,
   STATUS_OK = skipped) so the sender never removes a source the receiver did
   not actually store.  The frame ends with `final_status` (STATUS_OK, or
   STATUS_DELETE_LIMIT when a --max-delete commit was capped). */
bool receiver_send_final_success(int fd, const Config* config, const ReceiverOutcomes* outcomes,
                                 Status final_status) {
  if (!config->remove_source_files)
    return send_status(fd, final_status);
  size_t count = outcomes ? outcomes->count : 0;
  for (size_t i = 0; i < count; i++) {
    Status per_file;
    if (outcomes->entries[i] == FILE_SAVE_WRITTEN)
      per_file = STATUS_NEXT;
    else if (outcomes->entries[i] == FILE_SAVE_FAILED)
      per_file = STATUS_ERROR;
    else
      per_file = STATUS_OK;
    if (!send_status(fd, per_file))
      return false;
  }
  return send_status(fd, final_status);
}

bool receiver_send_stats_frame(int fd, const Config* config, const ReceiverStats* stats,
                               const struct ArrayList* would_delete,
                               const struct ArrayList* deleted_paths) {
  if (!config->report_stats)
    return true;
  ReceiverStats local;
  memset(&local, 0, sizeof(local));
  const ReceiverStats* out = stats ? stats : &local;
  /* The path list carries the dry-run would-delete set for a -n run and the
     actually-removed set for a real --info=del run. */
  const struct ArrayList* paths =
      config->dry_run ? would_delete : (config->report_deletes ? deleted_paths : NULL);
  size_t count = paths ? (size_t)paths->size : 0;
  if (count > (size_t)MAX_MANIFEST_ENTRIES)
    count = MAX_MANIFEST_ENTRIES;
  ReceiverStats record = *out;
  record.would_delete_count = count;
  if (!send_status(fd, STATUS_STATS) || !format_stats_send(fd, &record) ||
      !send_int(fd, (int)count))
    return false;
  for (size_t i = 0; i < count; i++) {
    const char* path = (const char*)paths->items[i];
    if (!send_wire_str(fd, path ? path : ""))
      return false;
  }
  return true;
}

/* Add a delete commit's tally to the sink's end-of-transfer wire counters (when
   the sink reports them).  Runs on the receiving thread, so no locking. */
static void receiver_tally_deleted(const ReceiverSink* sink, size_t deleted) {
  if (sink && sink->stats && deleted > 0)
    sink->stats->deleted_files += deleted;
}

/* Observer for --info=del/--stats: record each truly-removed destination-
   relative path (when the context carries a path list) and tally it by type
   (when it carries a stats record), so the terminal STATUS_STATS frame can list
   the paths and render rsync's per-type `Number of deleted files` breakdown.  A
   failed append is best-effort (the deletion already happened; output is
   cosmetic).  Shared by the single-threaded receiver and the -m pipeline's
   deferred commit. */
void receiver_record_deleted_path(void* context, const char* rel_path, DeleteEntryType type) {
  ReceiverDeleteContext* del = context;
  if (!del || !rel_path)
    return;
  if (del->stats) {
    switch (type) {
    case DELETE_ENTRY_DIR:
      del->stats->deleted_dir++;
      break;
    case DELETE_ENTRY_LINK:
      del->stats->deleted_link++;
      break;
    case DELETE_ENTRY_SPECIAL:
      del->stats->deleted_special++;
      break;
    default:
      del->stats->deleted_reg++;
      break;
    }
  }
  ArrayList* paths = del->deleted_paths;
  if (!paths)
    return;
  /* Bound the retained list like the keep-set manifest: only MAX_MANIFEST_ENTRIES
     paths are ever transmitted in the terminal STATUS_STATS frame, so recording
     more only grows memory.  A hostile/huge deletion set is therefore capped. */
  if ((size_t)paths->size >= (size_t)MAX_MANIFEST_ENTRIES)
    return;
  char* copy = str_dup(rel_path);
  if (copy && !array_list_add(paths, copy))
    free(copy);
}

/* Install the delete observer (and its context) for one commit when the sink
   carries a stats record or a path list.  Returns NULL when neither is needed,
   so the delete engines skip the observer entirely. */
static DeletePathObserver receiver_delete_observer(const ReceiverSink* sink,
                                                   ReceiverDeleteContext* del) {
  del->stats = sink ? sink->stats : NULL;
  del->deleted_paths = sink ? sink->deleted_paths : NULL;
  return (del->stats || del->deleted_paths) ? receiver_record_deleted_path : NULL;
}

static bool receiver_process_chunk(Chunk* chunk, const ReceiverSink* sink) {
  if (!chunk || !sink || !sink->store_file)
    return false;
  for (int i = 0; i < chunk->element_count; i++) {
    File* file = chunk->items[i];
    if (!file) {
      chunk_destroy(chunk);
      return false;
    }
    chunk->items[i] = NULL;
    if (!sink->store_file(file, sink->context)) {
      chunk_destroy(chunk);
      return false;
    }
  }
  chunk_destroy(chunk);
  return true;
}

/* P7 Wave D: read one STATUS_DIR_TIMES frame (a count followed by that many
 * (path, metadata) directory entries) and route every entry through the regular
 * store_file sink.  A dir-time entry is RECORD-ONLY (file->dir_time_only): the
 * sink accumulates its metadata for end-of-transfer application but creates
 * nothing, so an empty/pruned source directory is never resurrected.  A large
 * tree arrives as repeated frames, each bounded by MAX_MANIFEST_ENTRIES; a
 * malformed count or entry is a hard error. */
static bool receiver_process_dir_times(int fd, const Config* config, const ReceiverSink* sink) {
  int count;
  if (!receive_int(fd, &count) || count < 0 || count > MAX_MANIFEST_ENTRIES)
    return false;
  for (int i = 0; i < count; i++) {
    File* dir = file_receive_dir_time(fd, config);
    if (!dir || !sink->store_file(dir, sink->context))
      return false;
  }
  return true;
}

static bool receiver_process_batch(Config* config, int file_descriptor) {
  int count;
  if (config->checksum || !receive_int(file_descriptor, &count) || count < 0 ||
      count > MAX_MANIFEST_ENTRIES)
    return false;
  for (int i = 0; i < count; i++) {
    char* check_path = receive_wire_str(file_descriptor);
    if (!check_path)
      return false;
    unsigned long long check_size;
    long long check_mtime;
    long long check_mtime_nsec;
    if (!receive_n_data(file_descriptor, &check_size, sizeof(check_size)) ||
        !receive_n_data(file_descriptor, &check_mtime, sizeof(check_mtime)) ||
        !receive_n_data(file_descriptor, &check_mtime_nsec, sizeof(check_mtime_nsec)) ||
        check_mtime_nsec < 0 || check_mtime_nsec >= 1000000000LL) {
      free(check_path);
      send_status(file_descriptor, STATUS_ERROR);
      return false;
    }
    /* --trust-sender: accept a ``..``/absolute check path (a trusted sender's
         odd-but-legit entry) and defer containment to the secure stat below;
         an empty path is still always rejected. */
    if (check_path[0] == '\0' ||
        (!file_get_trust_sender() && !utils_valid_batch_path(check_path))) {
      free(check_path);
      send_status(file_descriptor, STATUS_ERROR);
      return false;
    }
    if (check_size > MAX_RECEIVE_WHOLE_FILE_SIZE) {
      free(check_path);
      send_status(file_descriptor, STATUS_ERROR);
      return false;
    }
    char* full_path = path_cat(config->receive_root_directory, check_path);
    if (!full_path) {
      free(check_path);
      send_status(file_descriptor, STATUS_ERROR);
      return false;
    }
    struct stat st;
    bool has_old = file_stat_secure(full_path, &st);
    long long old_mtime_nsec = 0;
    if (has_old) {
#ifdef __linux__
      old_mtime_nsec = st.st_mtim.tv_nsec;
#endif
    }
    bool match = !config->ignore_times && has_old && (unsigned long long)st.st_size == check_size &&
                 metadata_mtime_matches(st.st_mtime, old_mtime_nsec, (time_t)check_mtime,
                                        (long)check_mtime_nsec, config->modify_window);
    bool sent = send_status(file_descriptor, match ? STATUS_OK : STATUS_NEXT);
    free(full_path);
    free(check_path);
    if (!sent)
      return false;
  }
  return true;
}

/* ---- Anti-slowloris connection bounds ----
 * A legitimate transfer either streams data frames continuously or, when it
 * must pause, sends STATUS_KEEPALIVE so the peer sees the connection is alive.
 * An attacker can therefore squat on a connection slot indefinitely by sending
 * only keepalives under the per-message timeout.  Two CLOCK_MONOTONIC bounds
 * defeat that without ever punishing a real transfer:
 *
 *   MAX_SESSION_IDLE_SEC (1 h): the longest a stream may make no forward
 *     progress.  Data/status frames count as progress and refresh the timer;
 *     keepalives do not.  One hour is far longer than any real pause between
 *     data frames, yet small enough to reap a slowloris well before the 24 h
 *     session cap.
 *
 *   MAX_SESSION_WALL_SEC (24 h): an absolute ceiling on one connection's
 *     lifetime as defense-in-depth against a trickle of progress frames that
 *     resets the idle timer just below its limit.  Larger than any plausible
 *     single transfer while still bounding resource occupancy.
 *
 * Both are wall-clock deltas, so the per-message poll timeout (60 s by default,
 * or --timeout) can never fool them, and both the single-threaded and the -m
 * receiver paths (receiver_process_pending) share the same logic. */
#define MAX_SESSION_IDLE_SEC 3600u
#define MAX_SESSION_WALL_SEC 86400u

static unsigned int g_max_session_idle_sec = MAX_SESSION_IDLE_SEC;
static unsigned int g_max_session_wall_sec = MAX_SESSION_WALL_SEC;

void receiver_set_time_limits(unsigned int idle_sec, unsigned int wall_sec) {
  g_max_session_idle_sec = idle_sec;
  g_max_session_wall_sec = wall_sec;
}

void receiver_reset_time_limits(void) {
  g_max_session_idle_sec = MAX_SESSION_IDLE_SEC;
  g_max_session_wall_sec = MAX_SESSION_WALL_SEC;
}

bool receiver_time_limit_exceeded(const struct timespec* session_start,
                                  const struct timespec* last_progress,
                                  const struct timespec* now) {
  if (!session_start || !last_progress || !now)
    return false;
  if (now->tv_sec - session_start->tv_sec >= (time_t)g_max_session_wall_sec)
    return true;
  if (now->tv_sec - last_progress->tv_sec >= (time_t)g_max_session_idle_sec)
    return true;
  return false;
}

/* A frame proves forward progress only when it cannot be fabricated for free.
 * KEEPALIVE/ABORT are pure liveness, and CHECK_BATCH/DIR_TIMES may carry zero
 * entries, so a peer must not be able to hold a connection slot forever by
 * merely emitting empty frames. */
static bool status_counts_as_progress(Status status) {
  switch (status) {
  case STATUS_KEEPALIVE:
  case STATUS_ABORT:
  case STATUS_CHECK_BATCH:
  case STATUS_DIR_TIMES:
  case STATUS_CLIENT_MSG:
    return false;
  default:
    return true;
  }
}

/* Refresh the progress timestamp for a forward-moving frame and enforce the
 * bounds above.  Returns false when the connection must be dropped; the
 * terminal STATUS_ERROR is sent only when the sink owns error reporting (the
 * -m sink sets send_error=false so the main thread emits exactly one). */
static bool receiver_note_status(const struct timespec* session_start,
                                 struct timespec* last_progress, Status status, int file_descriptor,
                                 const ReceiverSink* sink) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    now = *last_progress;
  if (status_counts_as_progress(status))
    *last_progress = now;
  if (!receiver_time_limit_exceeded(session_start, last_progress, &now))
    return true;
  log_message(LOG_LEVEL_ERROR,
              "Receive session exceeded its time bound (idle %us / total %us); aborting connection",
              g_max_session_idle_sec, g_max_session_wall_sec);
  if (!sink || sink->send_error)
    send_status(file_descriptor, STATUS_ERROR);
  return false;
}

int receiver_process(Config* config, int file_descriptor, const ReceiverSink* sink) {
  return receiver_process_pending_ctx(config, file_descriptor, sink, NULL, NULL, NULL);
}

int receiver_process_pending(Config* config, int file_descriptor, const ReceiverSink* sink,
                             DeleteManifest** pending_manifest, DeletePlanSession** pending_plans) {
  return receiver_process_pending_ctx(config, file_descriptor, sink, pending_manifest,
                                      pending_plans, NULL);
}

/* Per-connection state threaded through the status handlers below.  The parked
   keep-set / per-directory session live here so one teardown helper can release
   them on every exit path. */
typedef struct {
  Config* config;
  int fd;
  const ReceiverSink* sink;
  DeleteManifest** pending_manifest;
  DeletePlanSession** pending_plans;
  /* Parked keep-set for the late/commit timing.  Every exit path frees it
     exactly once; the only exception is the successful FINISHED handoff, which
     transfers ownership to *pending_manifest (used by the -m receiver). */
  DeleteManifest* deferred_manifest;
  /* Per-directory delete session for --delete-during/--delete-delay.  During the
     loop it applies plans inline (during) or snapshots their extras (delay); on
     a successful FINISHED it is either committed here or handed to
     *pending_plans so the -m caller commits after its disk writer drained. */
  DeletePlanSession* plan_session;
  /* Observer context for the per-directory delete session, which outlives the
     frame handler; must stay alive until the session commits.  For a session
     handed to the caller (pending_plans) this points at a caller-owned
     long-lived context; otherwise it points at an internal stack context. */
  ReceiverDeleteContext* delete_ctx;
  bool early_delete;
  bool per_dir_delete;
  bool delete_limit_noted;
} ReceiverPendingState;

/* Outcome of one frame handler.  NEXT reads the following status frame; FAIL
   tears the connection down without a peer STATUS_ERROR; ERROR tears it down
   and (when the sink owns error reporting) emits STATUS_ERROR. */
typedef enum {
  RECEIVER_STEP_NEXT,
  RECEIVER_STEP_FAIL,
  RECEIVER_STEP_ERROR,
} ReceiverStep;

static ReceiverStep receiver_handle_keepalive(ReceiverPendingState* state) {
  if (!send_status(state->fd, STATUS_KEEPALIVE))
    return RECEIVER_STEP_FAIL;
  return RECEIVER_STEP_NEXT;
}

/* rsync --stderr=client: a client diagnostic forwarded over the wire.  Read the
 * bounded string and log it through the normal destination/level gate.  The
 * body is peer-controlled text: log_client_message() escapes every
 * non-printable byte (newlines, CR, ANSI ESC, ...) before writing, so a hostile
 * client cannot forge log lines or inject terminal control sequences.  A
 * malformed string (over-long or embedded NUL) is a framing error and tears the
 * connection down. */
static ReceiverStep receiver_handle_client_msg(ReceiverPendingState* state) {
  char* message = receive_str(state->fd);
  if (!message)
    return RECEIVER_STEP_FAIL;
  if (message[0] != '\0')
    log_client_message(message);
  free(message);
  return RECEIVER_STEP_NEXT;
}

static ReceiverStep receiver_handle_abort(ReceiverPendingState* state) {
  (void)state;
  log_message(LOG_LEVEL_INFO, "Received abort from client, cleaning up");
  return RECEIVER_STEP_FAIL;
}

static ReceiverStep receiver_handle_check(ReceiverPendingState* state) {
  bool skipped = false;
  bool would_transfer = false;
  File* file = receive_incremental_check_ex(state->fd, state->config, &skipped, &would_transfer);
  if (state->config->dry_run) {
    /* Server-contacting --dry-run: the reply has already been sent
       (STATUS_OK = up to date, STATUS_DRY_RUN_TRANSFER = would transfer) and
       nothing may be stored.  Both flags false means a genuine protocol
       error (STATUS_ERROR already sent or sent by receive_error below). */
    if (!skipped && !would_transfer)
      return RECEIVER_STEP_ERROR;
  } else if (!skipped && (!file || !state->sink->store_file(file, state->sink->context))) {
    return RECEIVER_STEP_ERROR;
  }
  return RECEIVER_STEP_NEXT;
}

static ReceiverStep receiver_handle_chunk(ReceiverPendingState* state) {
  Chunk* chunk = receive_chunk_data(state->fd, state->config);
  if (!chunk || !receiver_process_chunk(chunk, state->sink))
    return RECEIVER_STEP_ERROR;
  return RECEIVER_STEP_NEXT;
}

static ReceiverStep receiver_handle_check_batch(ReceiverPendingState* state) {
  if (!receiver_process_batch(state->config, state->fd))
    return RECEIVER_STEP_FAIL;
  return RECEIVER_STEP_NEXT;
}

/* Probe a destination entry's pre-transfer state for the output-parity
   dest-info report (protocol 2.30.0).  `wire_path` is the destination-relative
   path; `incoming_target` is non-NULL only for a symlink probe, in which case
   the on-disk link target is compared with the target the receiver is about to
   store (after --munge-links).  The final component is never followed and the
   parent walk is confined below the receive root.  Returns false only on an
   allocation/secure-walk failure; a missing entry is reported as existed=false. */
static bool receiver_probe_dest_state(const Config* config, const char* wire_path,
                                      const char* incoming_target, OutputDestState* out) {
  memset(out, 0, sizeof(*out));
  out->known = true;
  if (!config || !wire_path || wire_path[0] == '\0')
    return false;
  char* full = path_cat(config->receive_root_directory, wire_path);
  if (!full)
    return false;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(full, &leaf, false);
  free(full);
  if (parent_fd < 0) {
    /* A missing/unreachable parent means the entry cannot exist yet. */
    free(leaf);
    return true;
  }
  struct stat st;
  if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0) {
    out->existed = true;
    out->size = (unsigned long long)st.st_size;
    out->mtime_sec = (long long)st.st_mtime;
#ifdef __linux__
    out->mtime_nsec = st.st_mtim.tv_nsec;
#endif
    out->mode = (uint32_t)st.st_mode;
    out->uid = (int32_t)st.st_uid;
    out->gid = (int32_t)st.st_gid;
    if (incoming_target && S_ISLNK(st.st_mode)) {
      char target_buf[PATH_MAX];
      ssize_t n = readlinkat(parent_fd, leaf, target_buf, sizeof(target_buf) - 1);
      if (n >= 0) {
        target_buf[n] = '\0';
        char* expected =
            config->munge_links ? file_symlink_munge(incoming_target) : str_dup(incoming_target);
        if (expected) {
          out->target_matches = strcmp(target_buf, expected) == 0;
          free(expected);
        }
      }
    }
  }
  close(parent_fd);
  free(leaf);
  return true;
}

static ReceiverStep receiver_handle_mkdir(ReceiverPendingState* state) {
  const Config* config = state->config;
  int fd = state->fd;
  if (config->report_dest_info) {
    int probe = 0;
    if (!receive_int(fd, &probe) || (probe != 0 && probe != 1))
      return RECEIVER_STEP_FAIL;
    if (probe) {
      /* Probe-only frame: report the destination state and create nothing. */
      char* path = receive_wire_str(fd);
      if (!path || path[0] == '\0' || (!file_get_trust_sender() && has_path_traversal(path))) {
        free(path);
        send_status(fd, STATUS_ERROR);
        return RECEIVER_STEP_FAIL;
      }
      OutputDestState info;
      bool ok = receiver_probe_dest_state(config, path, NULL, &info);
      free(path);
      if (!ok || !send_status(fd, STATUS_DEST_INFO) || !format_dest_state_send(fd, &info))
        return RECEIVER_STEP_FAIL;
      return RECEIVER_STEP_NEXT;
    }
  }
  File* dir = file_receive_directory(fd, config);
  if (!dir)
    return RECEIVER_STEP_ERROR;
  if (config->report_dest_info) {
    OutputDestState info;
    bool ok = receiver_probe_dest_state(config, file_wire_path(dir), NULL, &info);
    if (!ok || !send_status(fd, STATUS_DEST_INFO) || !format_dest_state_send(fd, &info)) {
      file_destroy(dir);
      return RECEIVER_STEP_FAIL;
    }
  }
  if (!state->sink->store_file(dir, state->sink->context))
    return RECEIVER_STEP_ERROR;
  return RECEIVER_STEP_NEXT;
}

static ReceiverStep receiver_handle_dir_times(const ReceiverPendingState* state) {
  if (!receiver_process_dir_times(state->fd, state->config, state->sink))
    return RECEIVER_STEP_ERROR;
  return RECEIVER_STEP_NEXT;
}

static ReceiverStep receiver_handle_hardlink(ReceiverPendingState* state) {
  File* file = file_receive_hardlink(state->fd);
  if (!file || !state->sink->store_file(file, state->sink->context))
    return RECEIVER_STEP_ERROR;
  return RECEIVER_STEP_NEXT;
}

static ReceiverStep receiver_handle_symlink(ReceiverPendingState* state) {
  const Config* config = state->config;
  File* sym = file_receive_symlink(state->fd, config);
  if (!sym)
    return RECEIVER_STEP_ERROR;
  if (config->report_dest_info) {
    OutputDestState info;
    bool ok = receiver_probe_dest_state(config, file_wire_path(sym), sym->symlink_target, &info);
    if (!ok || !send_status(state->fd, STATUS_DEST_INFO) ||
        !format_dest_state_send(state->fd, &info)) {
      file_destroy(sym);
      return RECEIVER_STEP_FAIL;
    }
  }
  if (!state->sink->store_file(sym, state->sink->context))
    return RECEIVER_STEP_ERROR;
  return RECEIVER_STEP_NEXT;
}

static ReceiverStep receiver_handle_special(ReceiverPendingState* state) {
  File* file = file_receive_special(state->fd);
  if (!file || !state->sink->store_file(file, state->sink->context))
    return RECEIVER_STEP_ERROR;
  return RECEIVER_STEP_NEXT;
}

static ReceiverStep receiver_handle_manifest(ReceiverPendingState* state) {
  Config* config = state->config;
  int fd = state->fd;
  const ReceiverSink* sink = state->sink;
  DeleteManifest* manifest = receive_manifest_entries(fd);
  if (!manifest)
    return RECEIVER_STEP_FAIL; /* receive_manifest_entries already sent STATUS_ERROR */
  if (config->dry_run) {
    /* Server-contacting --dry-run mutates nothing, so a keep-set manifest
       is consumed and discarded.  The early-delete mode still needs its ACK
       so a sender blocked on the delete handshake is not left hanging.
       When would-delete reporting is armed, enumerate (read-only) the
       destination extras so the terminal STATUS_STATS frame can list them. */
    if (config->use_delete && sink->would_delete) {
      size_t count = 0;
      if (!manifest_would_delete_list(config, manifest, sink->would_delete, &count))
        log_message(LOG_LEVEL_WARNING, "dry-run: could not enumerate would-delete paths");
    }
    delete_manifest_free(manifest);
    if (state->early_delete && !send_status(fd, STATUS_OK))
      return RECEIVER_STEP_FAIL;
    return RECEIVER_STEP_NEXT;
  }
  if (state->early_delete) {
    /* --delete-before: the whole-tree manifest is authoritative the moment
       it arrives, before any file data.  Delete now and acknowledge so the
       sender only starts streaming once the deletion committed (or failed).
       A later transfer failure does not restore these deletions.  A
       --max-delete-capped commit still succeeds and the transfer proceeds;
       the terminal success frame reports the cap. */
    size_t deleted = 0;
    ReceiverDeleteContext delctx;
    DeletePathObserver observer = receiver_delete_observer(sink, &delctx);
    DeleteCommitResult deletion =
        (config->use_delete || config->delete_missing_args)
            ? manifest_delete_all_observed(config, manifest, &deleted, observer, &delctx)
            : DELETE_COMMIT_OK;
    receiver_tally_deleted(sink, deleted);
    delete_manifest_free(manifest);
    if (deletion == DELETE_COMMIT_ERROR) {
      send_status(fd, STATUS_ERROR);
      return RECEIVER_STEP_FAIL;
    }
    if (deletion == DELETE_COMMIT_LIMIT_REACHED && sink->note_delete_limit)
      sink->note_delete_limit(sink->context);
    if (!send_status(fd, STATUS_OK))
      return RECEIVER_STEP_FAIL;
  } else if (config->use_delete || config->delete_missing_args) {
    /* Plain --delete / --delete-after and the --delete-missing-args
       exact-path deletions: hold the manifest and commit it only after
       STATUS_FINISHED.  The per-directory modes never send this frame. */
    if (state->deferred_manifest) {
      log_message(LOG_LEVEL_ERROR, "Received a second delete manifest");
      delete_manifest_free(state->deferred_manifest);
      state->deferred_manifest = NULL;
      delete_manifest_free(manifest);
      send_status(fd, STATUS_ERROR);
      return RECEIVER_STEP_FAIL;
    }
    state->deferred_manifest = manifest;
  } else {
    delete_manifest_free(manifest);
  }
  return RECEIVER_STEP_NEXT;
}

static ReceiverStep receiver_handle_delete_plan(ReceiverPendingState* state) {
  Config* config = state->config;
  int fd = state->fd;
  const ReceiverSink* sink = state->sink;
  if (!state->per_dir_delete) {
    log_message(LOG_LEVEL_ERROR, "Received a per-directory delete plan without a per-dir "
                                 "delete timing");
    send_status(fd, STATUS_ERROR);
    return RECEIVER_STEP_FAIL;
  }
  if (!state->plan_session) {
    state->plan_session = delete_plan_session_create(config);
    if (state->plan_session && (sink->stats || sink->deleted_paths))
      delete_plan_session_set_delete_observer(state->plan_session, receiver_record_deleted_path,
                                              state->delete_ctx);
  }
  if (!state->plan_session || delete_plan_session_receive(state->plan_session, config, fd) != 0)
    return RECEIVER_STEP_FAIL;
  if (delete_plan_session_limit_reached(state->plan_session) && !state->delete_limit_noted &&
      sink->note_delete_limit) {
    sink->note_delete_limit(sink->context);
    state->delete_limit_noted = true;
  }
  return RECEIVER_STEP_NEXT;
}

static ReceiverStep receiver_handle_file(ReceiverPendingState* state) {
  File* file = file_receive(state->config, state->fd);
  if (!file) {
    log_message(LOG_LEVEL_ERROR, "Failed to receive file");
    return RECEIVER_STEP_ERROR;
  }
  if (!state->sink->store_file(file, state->sink->context))
    return RECEIVER_STEP_ERROR;
  return RECEIVER_STEP_NEXT;
}

/* One dispatch per admitted frame type; STATUS_NEXT (and any other
   data-bearing status) falls through to the regular file receiver. */
static ReceiverStep receiver_dispatch_status(ReceiverPendingState* state, Status status) {
  switch (status) {
  case STATUS_KEEPALIVE:
    return receiver_handle_keepalive(state);
  case STATUS_CLIENT_MSG:
    return receiver_handle_client_msg(state);
  case STATUS_ABORT:
    return receiver_handle_abort(state);
  case STATUS_CHECK:
    return receiver_handle_check(state);
  case STATUS_CHUNK:
    return receiver_handle_chunk(state);
  case STATUS_CHECK_BATCH:
    return receiver_handle_check_batch(state);
  case STATUS_MKDIR:
    return receiver_handle_mkdir(state);
  case STATUS_DIR_TIMES:
    return receiver_handle_dir_times(state);
  case STATUS_HARDLINK:
    return receiver_handle_hardlink(state);
  case STATUS_SYMLINK:
    return receiver_handle_symlink(state);
  case STATUS_SPECIAL:
    return receiver_handle_special(state);
  case STATUS_MANIFEST:
    return receiver_handle_manifest(state);
  case STATUS_DELETE_PLAN:
    return receiver_handle_delete_plan(state);
  default:
    return receiver_handle_file(state);
  }
}

/* Release the parked keep-set / per-directory session exactly once on every
   failure exit.  Never commit a deletion for a failed stream. */
static void receiver_drop_pending(ReceiverPendingState* state) {
  if (state->deferred_manifest) {
    delete_manifest_free(state->deferred_manifest);
    state->deferred_manifest = NULL;
  }
  if (state->plan_session) {
    delete_plan_session_destroy(state->plan_session);
    state->plan_session = NULL;
  }
}

/* Runs the whole receive loop.  The delete manifest may legitimately arrive
   either FIRST (--delete-before / --delete-during: the sender transmits the
   validated keep-set before any file data) or LAST (--delete-after /
   --delete-commit / --delete-delay: the manifest closes the data stream).  In
   the early modes the receiver deletes as soon as the manifest has been read
   and acknowledges with STATUS_OK so the sender only starts streaming once the
   deletion has committed (or failed); in the late modes the manifest is held
   and the deletion is committed only after the terminal STATUS_FINISHED proves
   the whole transfer succeeded.  A plain --delete defaults to the per-directory
   delete-during plan mode (no manifest at all).  See the per-frame handlers
   above for how the -m receiver defers that commit until its disk writer has
   drained. */
int receiver_process_pending_ctx(Config* config, int file_descriptor, const ReceiverSink* sink,
                                 DeleteManifest** pending_manifest,
                                 DeletePlanSession** pending_plans,
                                 ReceiverDeleteContext* observer_ctx) {
  Status status;
  if (!receive_status(file_descriptor, &status))
    return -1;
  /* Wall-clock (=CLOCK_MONOTONIC) anti-slowloris bookkeeping.  session_start is
   * fixed for the whole connection; last_progress is refreshed by every frame
   * that is not a keepalive/abort. */
  struct timespec session_start;
  struct timespec last_progress;
  clock_gettime(CLOCK_MONOTONIC, &session_start);
  last_progress = session_start;
  if (!receiver_note_status(&session_start, &last_progress, status, file_descriptor, sink))
    return -1;
  /* A per-directory delete session handed to the caller outlives this stack
     frame, so its observer context must be caller-owned (observer_ctx); only
     the default inline-commit case may use the stack context. */
  ReceiverDeleteContext local_ctx;
  ReceiverDeleteContext* delete_ctx = observer_ctx ? observer_ctx : &local_ctx;
  delete_ctx->stats = sink ? sink->stats : NULL;
  delete_ctx->deleted_paths = sink ? sink->deleted_paths : NULL;
  ReceiverPendingState state = {
      .config = config,
      .fd = file_descriptor,
      .sink = sink,
      .pending_manifest = pending_manifest,
      .pending_plans = pending_plans,
      .deferred_manifest = NULL,
      .plan_session = NULL,
      .delete_ctx = delete_ctx,
      .early_delete = config_delete_timing_early(config),
      .per_dir_delete = config_delete_timing_per_dir(config),
      .delete_limit_noted = false,
  };
  bool notify_peer = false;
  while (status == STATUS_NEXT || status == STATUS_CHUNK || status == STATUS_CHECK ||
         status == STATUS_KEEPALIVE || status == STATUS_ABORT || status == STATUS_CHECK_BATCH ||
         status == STATUS_MKDIR || status == STATUS_MANIFEST || status == STATUS_HARDLINK ||
         status == STATUS_SYMLINK || status == STATUS_SPECIAL || status == STATUS_DIR_TIMES ||
         status == STATUS_DELETE_PLAN || status == STATUS_CLIENT_MSG) {
    ReceiverStep step = receiver_dispatch_status(&state, status);
    if (step == RECEIVER_STEP_FAIL)
      goto fail;
    if (step == RECEIVER_STEP_ERROR)
      goto receive_error;
    if (!receive_status(file_descriptor, &status))
      goto receive_error;
    if (!receiver_note_status(&session_start, &last_progress, status, file_descriptor, sink))
      goto fail;
  }
  if (status != STATUS_FINISHED) {
    log_message(LOG_LEVEL_ERROR, "Did not receive FINISHED Status");
    goto receive_error;
  }
  /* --delay-updates: publish every staged file BEFORE the deferred delete
     commit, matching rsync's --delete-after ordering (all updates land first,
     then extras are removed).  The single-threaded receiver stores files
     synchronously, so every staged file is complete here.  The -m receiver
     hands both publication and deletion to its caller via
     pending_manifest/pending_plans; that caller publishes first, after its disk
     writer has drained. */
  bool handoff = state.pending_manifest != NULL || state.pending_plans != NULL;
  if (!handoff && !config->dry_run && config->delay_updates && config->delay_context) {
    if (!delay_updates_publish(config->delay_context, config)) {
      send_status(file_descriptor, STATUS_ERROR);
      goto fail;
    }
  }
  /* Commit-style (late) deletion: every data frame has been received and the
     sender proved the whole tree with STATUS_FINISHED.  The single-threaded
     receiver stores files synchronously, so everything is on disk here (and a
     --delay-updates run has already published above).  The -m receiver passes
     `pending_manifest` because its disk writer may still be draining; the
     caller commits after the writer has joined so no extra file is removed
     unless the transfer is known to have succeeded. */
  if (state.deferred_manifest) {
    if (state.pending_manifest) {
      *state.pending_manifest = state.deferred_manifest;
      state.deferred_manifest = NULL;
    } else {
      size_t deleted = 0;
      DeletePathObserver observer = receiver_delete_observer(sink, state.delete_ctx);
      DeleteCommitResult deletion = manifest_delete_all_observed(
          config, state.deferred_manifest, &deleted, observer, state.delete_ctx);
      receiver_tally_deleted(sink, deleted);
      delete_manifest_free(state.deferred_manifest);
      state.deferred_manifest = NULL;
      if (deletion == DELETE_COMMIT_ERROR) {
        send_status(file_descriptor, STATUS_ERROR);
        goto fail;
      }
      if (deletion == DELETE_COMMIT_LIMIT_REACHED && sink->note_delete_limit)
        sink->note_delete_limit(sink->context);
    }
  }
  /* Per-directory deletion: --delete-during already applied each plan inline, so
     this only finishes the missing-args deletions; --delete-delay committed
     nothing yet and applies its decompressed snapshot here.  The -m receiver
     hands the session to its caller instead, which commits after the disk
     writer drained. */
  if (state.plan_session) {
    if (sink->stats || sink->deleted_paths)
      delete_plan_session_set_delete_observer(state.plan_session, receiver_record_deleted_path,
                                              state.delete_ctx);
    if (state.pending_plans) {
      *state.pending_plans = state.plan_session;
      state.plan_session = NULL;
    } else if (config->dry_run) {
      /* Central dry-run no-op: never commit a deletion for a -n run. */
      delete_plan_session_destroy(state.plan_session);
      state.plan_session = NULL;
    } else {
      DeleteCommitResult deletion = delete_plan_session_commit(state.plan_session, config);
      bool limit = delete_plan_session_limit_reached(state.plan_session);
      receiver_tally_deleted(sink, delete_plan_session_deleted(state.plan_session));
      delete_plan_session_destroy(state.plan_session);
      state.plan_session = NULL;
      if (deletion == DELETE_COMMIT_ERROR) {
        send_status(file_descriptor, STATUS_ERROR);
        goto fail;
      }
      if (limit && !state.delete_limit_noted && sink->note_delete_limit)
        sink->note_delete_limit(sink->context);
    }
  }
  if (sink->send_success) {
    if (sink->send_success_frame) {
      if (!sink->send_success_frame(file_descriptor, sink->context))
        goto fail;
    } else if (!send_status(file_descriptor, STATUS_OK)) {
      goto fail;
    }
  }
  return 0;

receive_error:
  notify_peer = true;
fail:
  /* Failure exits that must not (or already did) report a STATUS_ERROR.  The
     parked keep-set/session is dropped: never commit a deletion for a failed
     stream. */
  receiver_drop_pending(&state);
  if (notify_peer && sink->send_error)
    send_status(file_descriptor, STATUS_ERROR);
  return -1;
}

/* ---- Single-threaded sink (used by receiver_receive_files) ---- */

typedef struct {
  Config* config;
  ReceiverOutcomes outcomes;
  /* P7 Wave D: directory metadata accumulated during the stream, applied only
     after the whole transfer (and its delete/publication phases) has run so a
     child write never clobbers a directory mtime. */
  DirTimeList dir_times;
  /* Set when a --max-delete commit was capped; the terminal frame then carries
     STATUS_DELETE_LIMIT so the sender exits 25 like rsync. */
  bool delete_limit_reached;
  /* End-of-transfer wire counters (protocol 2.25.0) and the -n/--dry-run
     --delete would-delete path list collected while processing the manifest. */
  ReceiverStats stats;
  ArrayList* would_delete;
  /* --info=del: actually-removed paths collected during the delete commit. */
  ArrayList* deleted_paths;
  /* Per-run count of entries that failed to materialize without aborting the
     stream (currently ONLY a --devices mknod EPERM/EACCES).  A nonzero count
     makes the terminal frame carry a non-OK status so the client exits
     non-zero, matching rsync's continue-and-exit-partial behavior. */
  size_t failed_entries;
} ReceiverSaveContext;

static bool receiver_save_file(File* file, void* context_pointer) {
  ReceiverSaveContext* context = context_pointer;
  FileSaveResult result = FILE_SAVE_ERROR;
  bool created = false;
  unsigned created_dirs = 0;
  if (context->config->dry_run) {
    /* Defense in depth: a dry-run receiver mutates nothing even if a data
       frame reaches the sink (the sender is not supposed to send one). */
    result = FILE_SAVE_SKIPPED;
  } else if (!context->config->save_to_disk) {
    /* Nothing is stored; report the file as not-written so a
       --remove-source-files sender keeps its source. */
    result = FILE_SAVE_SKIPPED;
  } else {
    result = file_save_to_disk_full_ex(context->config->receive_root_directory, file,
                                       context->config, &created, &created_dirs);
  }
  /* Wire-stats tally: bytes reconstructed from the basis file (delta matches)
     count as matched data in the end-of-transfer report. */
  if (result != FILE_SAVE_ERROR && file->matched_bytes > 0)
    context->stats.matched_data += file->matched_bytes;
  /* --devices parity: a device node the receiver could not mknod (EPERM/EACCES)
     is counted per-run but does not abort the transfer.  The terminal frame
     turns a nonzero count into a non-OK status so the client exits non-zero. */
  if (result == FILE_SAVE_FAILED)
    context->failed_entries++;
  /* Protocol 2.28.0: receiver-observed literal bytes and the created-entry
     breakdown (regular/dir/link/special) for the `--stats` report. */
  if (result == FILE_SAVE_WRITTEN)
    receiver_stats_note_saved(&context->stats, file, created, created_dirs);
  /* A directory's metadata is deferred, never applied inline: collect it now
     and apply it at the end.  -O/--omit-dir-times and --preserve_perms/-times
     are honored by dir_metadata_list_apply's caller (see
     receiver_send_success_frame). */
  if (result != FILE_SAVE_ERROR && file->is_dir && file->metadata &&
      dir_metadata_should_capture(context->config) &&
      !dir_time_list_add(&context->dir_times, file->path, file->metadata, file->xattrs)) {
    file_destroy(file);
    return false;
  }
  /* A dry-run receiver mutates nothing AND records no per-file outcomes: a
     hostile dry-run client that streamed data frames anyway must not be able to
     grow `outcomes` without bound (receiver_outcomes_append reallocs uncharged)
     or force a per-frame ack. */
  if (!context->config->dry_run && result != FILE_SAVE_ERROR &&
      context->config->remove_source_files && !file->is_dir && !file->is_special && !file->skip &&
      !receiver_outcomes_append(&context->outcomes, (unsigned char)result)) {
    file_destroy(file);
    return false;
  }
  file_destroy(file);
  return result != FILE_SAVE_ERROR;
}

static void receiver_note_delete_limit(void* context_pointer) {
  ReceiverSaveContext* context = context_pointer;
  context->delete_limit_reached = true;
}

/* Terminal status for a run.  A capped --delete limit wins (rsync exit 25);
   otherwise any per-entry failure (for example an unprivileged --devices
   mknod) makes the terminal frame STATUS_PARTIAL so the client exits 23
   (rsync's "partial transfer due to error") while still removing the sources
   it successfully transferred under --remove-source-files.  A fatal stream
   error keeps STATUS_ERROR (a non-23 exit).  A clean run keeps STATUS_OK. */
static Status receiver_final_status(bool delete_limit_reached, size_t failed_entries) {
  if (delete_limit_reached)
    return STATUS_DELETE_LIMIT;
  return failed_entries > 0 ? STATUS_PARTIAL : STATUS_OK;
}

static bool receiver_send_success_frame(int fd, void* context_pointer) {
  ReceiverSaveContext* context = context_pointer;
  if (context->failed_entries > 0)
    log_message(LOG_LEVEL_WARNING,
                "%zu entr%s failed to materialize; continuing (partial transfer)",
                context->failed_entries, context->failed_entries == 1 ? "y" : "ies");
  Status final_status =
      receiver_final_status(context->delete_limit_reached, context->failed_entries);
  if (!receiver_send_stats_frame(fd, context->config, &context->stats, context->would_delete,
                                 context->deleted_paths))
    return false;
  /* Server-contacting --dry-run: nothing was staged or written, so there is
     nothing to publish and no directory times to stamp. */
  if (context->config->dry_run)
    return receiver_send_final_success(fd, context->config, &context->outcomes, final_status);
  /* P7 Wave D: every child is now written and the --delay-updates publication
     (done in receiver_process before the delete commit) plus the deferred
     deletion have both committed, so it is finally safe to stamp directory
     times. */
  dir_metadata_list_apply(&context->dir_times, context->config->receive_root_directory,
                          context->config);
  return receiver_send_final_success(fd, context->config, &context->outcomes, final_status);
}

int receiver_receive_files(Config* config, int file_descriptor) {
  ReceiverSaveContext context = {.config = config, .outcomes = {0}};
  dir_time_list_init(&context.dir_times);
  context.would_delete = array_list_create(free);
  /* report_deletes (--info=del / -i / --out-format under --delete) is the only
     reason to retain the actually-removed paths; a plain --delete must not
     str_dup every removal.  NULL is handled by every consumer. */
  context.deleted_paths = config->report_deletes ? array_list_create(free) : NULL;
  if (!context.would_delete || (config->report_deletes && !context.deleted_paths)) {
    array_list_delete(context.would_delete);
    array_list_delete(context.deleted_paths);
    return -1;
  }
  ReceiverSink sink = {receiver_save_file,
                       &context,
                       true,
                       true,
                       receiver_send_success_frame,
                       receiver_note_delete_limit,
                       &context.stats,
                       context.would_delete,
                       context.deleted_paths};
  int ret = receiver_process(config, file_descriptor, &sink);
  if (ret != 0 && config->delay_updates && config->delay_context)
    delay_updates_cleanup(config->delay_context);
  receiver_outcomes_destroy(&context.outcomes);
  dir_time_list_free(&context.dir_times);
  array_list_delete(context.would_delete);
  array_list_delete(context.deleted_paths);
  return ret;
}
