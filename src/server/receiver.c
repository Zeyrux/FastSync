#include "receiver.h"

#include "chunk.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"
#include <stdlib.h>
#include <sys/stat.h>

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
    if (check_size > MAX_RECEIVE_FILE_SIZE) {
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
    bool match =
        !config->ignore_times && has_old && (unsigned long long)st.st_size == check_size &&
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
  if (sink->send_success && !send_status(file_descriptor, STATUS_OK))
    return -1;
  return 0;

receive_error:
  if (sink->send_error)
    send_status(file_descriptor, STATUS_ERROR);
  return -1;
}

static bool receiver_save_file(File* file, void* context) {
  Config* config = context;
  bool success =
      !config->save_to_disk || file_save_to_disk(config->receive_root_directory, file, config);
  file_destroy(file);
  return success;
}

int receiver_receive_files(Config* config, int file_descriptor) {
  ReceiverSink sink = {receiver_save_file, config, true, true};
  return receiver_process(config, file_descriptor, &sink);
}
