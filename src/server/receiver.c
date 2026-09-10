#include "receiver.h"

#include "charset.h"
#include "chunk.h"
#include "config.h"
#include "delay_updates.h"
#include "file.h"
#include "file_receive.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"
#include <stdlib.h>
#include <sys/stat.h>

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
   not actually store.  The frame always ends with a plain STATUS_OK. */
bool receiver_send_final_success(int fd, const Config* config, const ReceiverOutcomes* outcomes) {
  if (!config->remove_source_files)
    return send_status(fd, STATUS_OK);
  size_t count = outcomes ? outcomes->count : 0;
  for (size_t i = 0; i < count; i++) {
    Status per_file = outcomes->entries[i] == FILE_SAVE_WRITTEN ? STATUS_NEXT : STATUS_OK;
    if (!send_status(fd, per_file))
      return false;
  }
  return send_status(fd, STATUS_OK);
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

int receiver_process(Config* config, int file_descriptor, const ReceiverSink* sink) {
  return receiver_process_pending(config, file_descriptor, sink, NULL);
}

/* Runs the whole receive loop.  The delete manifest may legitimately arrive
   either FIRST (--delete-before / --delete-during: the sender transmits the
   validated keep-set before any file data) or LAST (plain --delete /
   --delete-after / --delete-delay: the manifest closes the data stream).  In
   the early modes the receiver deletes as soon as the manifest has been read
   and acknowledges with STATUS_OK so the sender only starts streaming once the
   deletion has committed (or failed); in the late modes the manifest is held
   and the deletion is committed only after the terminal STATUS_FINISHED proves
   the whole transfer succeeded.  See receiver_process_pending() for how the -m
   receiver defers that commit until its disk writer has drained. */
int receiver_process_pending(Config* config, int file_descriptor, const ReceiverSink* sink,
                             DeleteManifest** pending_manifest) {
  Status status;
  if (!receive_status(file_descriptor, &status))
    return -1;
  bool early_delete = config_delete_timing_early(config);
  /* Parked keep-set for the late/commit timing.  Every exit path below frees it
     exactly once; the only exception is the successful FINISHED handoff, which
     transfers ownership to *pending_manifest (used by the -m receiver). */
  DeleteManifest* deferred_manifest = NULL;
  while (status == STATUS_NEXT || status == STATUS_CHUNK || status == STATUS_CHECK ||
         status == STATUS_KEEPALIVE || status == STATUS_ABORT || status == STATUS_CHECK_BATCH ||
         status == STATUS_MKDIR || status == STATUS_MANIFEST || status == STATUS_HARDLINK ||
         status == STATUS_SYMLINK || status == STATUS_SPECIAL) {
    if (status == STATUS_KEEPALIVE) {
      if (!send_status(file_descriptor, STATUS_KEEPALIVE))
        goto fail;
      goto next_status;
    }
    if (status == STATUS_ABORT) {
      log_message(LOG_LEVEL_INFO, "Received abort from client, cleaning up");
      goto fail;
    }
    if (status == STATUS_CHECK) {
      bool skipped;
      File* file = receive_incremental_check(file_descriptor, config, &skipped);
      if (!skipped && (!file || !sink->store_file(file, sink->context)))
        goto receive_error;
    } else if (status == STATUS_CHUNK) {
      Chunk* chunk = receive_chunk_data(file_descriptor, config);
      if (!chunk || !receiver_process_chunk(chunk, sink))
        goto receive_error;
    } else if (status == STATUS_CHECK_BATCH) {
      if (!receiver_process_batch(config, file_descriptor))
        goto fail;
      goto next_status;
    } else if (status == STATUS_MKDIR) {
      File* dir = file_receive_directory(file_descriptor);
      if (!dir || !sink->store_file(dir, sink->context))
        goto receive_error;
    } else if (status == STATUS_HARDLINK) {
      File* file = file_receive_hardlink(file_descriptor);
      if (!file || !sink->store_file(file, sink->context))
        goto receive_error;
    } else if (status == STATUS_SYMLINK) {
      File* sym = file_receive_symlink(file_descriptor, config);
      if (!sym || !sink->store_file(sym, sink->context))
        goto receive_error;
    } else if (status == STATUS_SPECIAL) {
      File* file = file_receive_special(file_descriptor);
      if (!file || !sink->store_file(file, sink->context))
        goto receive_error;
    } else if (status == STATUS_MANIFEST) {
      DeleteManifest* manifest = receive_manifest_entries(file_descriptor);
      if (!manifest)
        goto fail; /* receive_manifest_entries already sent STATUS_ERROR */
      if (early_delete) {
        /* --delete-before / --delete-during: the manifest is authoritative the
           moment it arrives, before any file data.  Delete now and acknowledge
           so the sender only starts streaming once the deletion committed (or
           failed).  This is the rsync delete-before/delete-during window: a
           later transfer failure does not restore these deletions. */
        bool deletion_ok = (config->use_delete || config->delete_missing_args)
                               ? manifest_delete_all(config, manifest)
                               : true;
        delete_manifest_free(manifest);
        if (!deletion_ok) {
          send_status(file_descriptor, STATUS_ERROR);
          goto fail;
        }
        if (!send_status(file_descriptor, STATUS_OK))
          goto fail;
      } else if (config->use_delete || config->delete_missing_args) {
        /* Plain --delete / --delete-after / --delete-delay and the
           --delete-missing-args exact-path deletions: hold the manifest and
           commit it only after STATUS_FINISHED. */
        if (deferred_manifest) {
          log_message(LOG_LEVEL_ERROR, "Received a second delete manifest");
          delete_manifest_free(deferred_manifest);
          deferred_manifest = NULL;
          delete_manifest_free(manifest);
          send_status(file_descriptor, STATUS_ERROR);
          goto fail;
        }
        deferred_manifest = manifest;
      } else {
        delete_manifest_free(manifest);
      }
      goto next_status;
    } else {
      File* file = file_receive(config, file_descriptor);
      if (!file) {
        log_message(LOG_LEVEL_ERROR, "Failed to receive file");
        goto receive_error;
      }
      if (!sink->store_file(file, sink->context))
        goto receive_error;
    }
  next_status:
    if (!receive_status(file_descriptor, &status))
      goto receive_error;
  }
  if (status != STATUS_FINISHED) {
    log_message(LOG_LEVEL_ERROR, "Did not receive FINISHED Status");
    goto receive_error;
  }
  /* Commit-style (late) deletion: every data frame has been received and the
     sender proved the whole tree with STATUS_FINISHED.  The single-threaded
     receiver stores files synchronously, so everything is on disk here and the
     deletion can be committed before the --delay-updates publication in
     send_success (the walker skips the staging dir, so staged files are never
     treated as extras).  The -m receiver passes `pending_manifest` because its
     disk writer may still be draining; the caller commits after the writer has
     joined so no extra file is removed unless the transfer is known to have
     succeeded. */
  if (deferred_manifest) {
    if (pending_manifest) {
      *pending_manifest = deferred_manifest;
      deferred_manifest = NULL;
    } else {
      bool deletion_ok = manifest_delete_all(config, deferred_manifest);
      delete_manifest_free(deferred_manifest);
      deferred_manifest = NULL;
      if (!deletion_ok) {
        send_status(file_descriptor, STATUS_ERROR);
        goto fail;
      }
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

fail:
  /* Failure exits that must not (or already did) report a STATUS_ERROR.  The
     parked keep-set is dropped: never commit a deletion for a failed stream. */
  if (deferred_manifest) {
    delete_manifest_free(deferred_manifest);
    deferred_manifest = NULL;
  }
  return -1;

receive_error:
  if (deferred_manifest) {
    delete_manifest_free(deferred_manifest);
    deferred_manifest = NULL;
  }
  if (sink->send_error)
    send_status(file_descriptor, STATUS_ERROR);
  return -1;
}

/* ---- Single-threaded sink (used by receiver_receive_files) ---- */

typedef struct {
  Config* config;
  ReceiverOutcomes outcomes;
} ReceiverSaveContext;

static bool receiver_save_file(File* file, void* context_pointer) {
  ReceiverSaveContext* context = context_pointer;
  FileSaveResult result = FILE_SAVE_ERROR;
  if (!context->config->save_to_disk) {
    /* Nothing is stored; report the file as not-written so a
       --remove-source-files sender keeps its source. */
    result = FILE_SAVE_SKIPPED;
  } else {
    result = file_save_to_disk_full(context->config->receive_root_directory, file, context->config);
  }
  if (result != FILE_SAVE_ERROR && context->config->remove_source_files && !file->is_dir &&
      !file->is_special && !file->skip &&
      !receiver_outcomes_append(&context->outcomes, (unsigned char)result)) {
    file_destroy(file);
    return false;
  }
  file_destroy(file);
  return result != FILE_SAVE_ERROR;
}

static bool receiver_send_success_frame(int fd, void* context_pointer) {
  ReceiverSaveContext* context = context_pointer;
  /* --delay-updates: the whole protocol stream (including manifest/delete
     handling, which ran inside receiver_process) has succeeded and every
     staged file was fully written.  Publish them atomically now, before the
     success/outcome frame tells a --remove-source-files sender it may delete
     its sources. */
  if (context->config->delay_updates && context->config->delay_context) {
    if (!delay_updates_publish(context->config->delay_context, context->config)) {
      send_status(fd, STATUS_ERROR);
      return false;
    }
  }
  return receiver_send_final_success(fd, context->config, &context->outcomes);
}

int receiver_receive_files(Config* config, int file_descriptor) {
  ReceiverSaveContext context = {.config = config, .outcomes = {0}};
  ReceiverSink sink = {receiver_save_file, &context, true, true, receiver_send_success_frame};
  int ret = receiver_process(config, file_descriptor, &sink);
  if (ret != 0 && config->delay_updates && config->delay_context)
    delay_updates_cleanup(config->delay_context);
  receiver_outcomes_destroy(&context.outcomes);
  return ret;
}
