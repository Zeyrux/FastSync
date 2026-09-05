#include "receiver.h"

#include "chunk.h"
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
    char* check_path = receive_str(file_descriptor);
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
    if (!utils_valid_batch_path(check_path)) {
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
  Status status;
  if (!receive_status(file_descriptor, &status))
    return -1;
  while (status == STATUS_NEXT || status == STATUS_CHUNK || status == STATUS_CHECK ||
         status == STATUS_KEEPALIVE || status == STATUS_ABORT || status == STATUS_CHECK_BATCH) {
    if (status == STATUS_KEEPALIVE) {
      if (!send_status(file_descriptor, STATUS_KEEPALIVE))
        return -1;
      goto next;
    }
    if (status == STATUS_ABORT) {
      log_message(LOG_LEVEL_INFO, "Received abort from client, cleaning up");
      return -1;
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
        return -1;
      goto next;
    } else {
      File* file = file_receive(config, file_descriptor);
      if (!file) {
        log_message(LOG_LEVEL_ERROR, "Failed to receive file");
        goto receive_error;
      }
      if (!sink->store_file(file, sink->context))
        goto receive_error;
    }
  next:
    if (!receive_status(file_descriptor, &status))
      goto receive_error;
  }
  if (status == STATUS_MANIFEST && receive_manifest(file_descriptor, config, &status) != 0)
    return -1;
  if (status != STATUS_FINISHED) {
    log_message(LOG_LEVEL_ERROR, "Did not receive FINISHED Status");
    goto receive_error;
  }
  if (sink->send_success) {
    if (sink->send_success_frame) {
      if (!sink->send_success_frame(file_descriptor, sink->context))
        return -1;
    } else if (!send_status(file_descriptor, STATUS_OK)) {
      return -1;
    }
  }
  return 0;

receive_error:
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
  if (result != FILE_SAVE_ERROR && context->config->remove_source_files &&
      !receiver_outcomes_append(&context->outcomes, (unsigned char)result)) {
    file_destroy(file);
    return false;
  }
  file_destroy(file);
  return result != FILE_SAVE_ERROR;
}

static bool receiver_send_success_frame(int fd, void* context_pointer) {
  ReceiverSaveContext* context = context_pointer;
  return receiver_send_final_success(fd, context->config, &context->outcomes);
}

int receiver_receive_files(Config* config, int file_descriptor) {
  ReceiverSaveContext context = {.config = config, .outcomes = {0}};
  ReceiverSink sink = {receiver_save_file, &context, true, true, receiver_send_success_frame};
  int ret = receiver_process(config, file_descriptor, &sink);
  receiver_outcomes_destroy(&context.outcomes);
  return ret;
}
