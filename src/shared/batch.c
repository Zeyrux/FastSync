#include "batch.h"
#include "data.h"
#include "file.h"
#include "file_receive.h"
#include "identity.h"
#include "log.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Serialization metadata mode for the batch stream, captured from the config at
 * batch_write_header time.  The header persists it into the file so a batch is
 * self-describing about whether per-entry metadata was CAPTURED in the stream:
 * batch_read_apply re-reads it from the file (not from the reading config) to
 * decode the chunk records correctly.  Which attributes are actually APPLIED,
 * however, comes from the INVOKING process's per-attribute config (the
 * FileAttrPolicy and the dir-metadata gate), so a batch written with -M is NOT
 * automatically applied identically by an invoking process with a different
 * -p/-t/-o/-g: --read-batch must be invoked with the same -p/-t/-o/-g as the
 * write side (rsync requires the same options).  The batch driver is a single
 * sequential scan pass within one thread, so this module-level flag is safe. */
static bool batch_metadata_mode = false;

static bool write_all_bytes(int fd, const void* data, size_t size) {
  const unsigned char* p = (const unsigned char*)data;
  size_t done = 0;
  while (done < size) {
    ssize_t n = write(fd, p + done, size - done);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    done += (size_t)n;
  }
  return true;
}

bool batch_write_header(int fd, const Config* config) {
  if (fd < 0)
    return false;
  batch_metadata_mode = config != NULL && config->use_metadata;
  if (!write_all_bytes(fd, BATCH_MAGIC, BATCH_MAGIC_LEN))
    return false;
  unsigned char version = BATCH_FORMAT_VERSION;
  if (!write_all_bytes(fd, &version, 1))
    return false;
  unsigned char mode = batch_metadata_mode ? 1 : 0;
  return write_all_bytes(fd, &mode, 1);
}

bool batch_write_chunk(int fd, Chunk* chunk) {
  if (fd < 0 || chunk == NULL)
    return false;
  Data* serialized = chunk_serialize(chunk, batch_metadata_mode);
  if (serialized == NULL)
    return false;
  bool ok = false;
  unsigned long long length = (unsigned long long)serialized->size;
  if (length > BATCH_MAX_RECORD) {
    log_message(LOG_LEVEL_ERROR, "batch: record size %llu exceeds the %llu-byte cap", length,
                (unsigned long long)BATCH_MAX_RECORD);
  } else if (write_all_bytes(fd, &length, sizeof(length)) &&
             (length == 0 || write_all_bytes(fd, serialized->data, (size_t)length))) {
    ok = true;
  }
  data_destroy(serialized);
  return ok;
}

/* Read exactly `size` bytes.  Returns true on success.  On reaching EOF, sets
 * *clean_eof only when no bytes had been read yet (a clean boundary) and returns
 * that value, so a truncated record (EOF mid-read) yields false. */
static bool read_exact(int fd, void* data, size_t size, bool* clean_eof) {
  unsigned char* p = (unsigned char*)data;
  size_t done = 0;
  while (done < size) {
    ssize_t n = read(fd, p + done, size - done);
    if (n < 0 && errno == EINTR)
      continue;
    if (n == 0) {
      if (clean_eof)
        *clean_eof = done == 0;
      return done == 0;
    }
    if (n < 0)
      return false;
    done += (size_t)n;
  }
  if (clean_eof)
    *clean_eof = false;
  return true;
}

int batch_read_apply(int fd, const Config* config, const char* dest_root) {
  if (fd < 0 || dest_root == NULL || dest_root[0] == '\0')
    return -1;

  /* Directory metadata is deferred to the end of the apply (a child write would
   * otherwise clobber its parent's mtime/mode).  The batch header's single
   * metadata bit only says whether metadata is present in the stream; which
   * attributes are APPLIED comes from the invoking process's config, so
   * --read-batch must be invoked with the same -p/-t/-o/-g as the write side
   * (rsync requires the same options).  The identity snapshot is activated so
   * -o/-g and the explicit ownership flags can apply. */
  DirTimeList dir_times;
  dir_time_list_init(&dir_times);
  int result = -1;
  if (!identity_set_active(config)) {
    log_message(LOG_LEVEL_ERROR, "batch: could not activate the identity policy");
    goto done;
  }

  char magic[BATCH_MAGIC_LEN];
  bool eof = false;
  if (!read_exact(fd, magic, BATCH_MAGIC_LEN, &eof) || eof ||
      memcmp(magic, BATCH_MAGIC, BATCH_MAGIC_LEN) != 0) {
    log_message(LOG_LEVEL_ERROR, "batch: malformed header (bad magic)");
    goto done;
  }
  unsigned char version;
  if (!read_exact(fd, &version, 1, &eof) || eof || version != BATCH_FORMAT_VERSION) {
    log_message(LOG_LEVEL_ERROR, "batch: malformed header (bad or missing format version)");
    goto done;
  }
  unsigned char mode;
  if (!read_exact(fd, &mode, 1, &eof) || eof || (mode != 0 && mode != 1)) {
    log_message(LOG_LEVEL_ERROR, "batch: malformed header (bad metadata flag)");
    goto done;
  }
  bool use_metadata = mode == 1;

  while (1) {
    unsigned long long length;
    if (!read_exact(fd, &length, sizeof(length), &eof)) {
      log_message(LOG_LEVEL_ERROR, "batch: truncated length prefix");
      goto done;
    }
    if (eof)
      break; /* clean end of stream */
    if (length == 0 || length > BATCH_MAX_RECORD) {
      log_message(LOG_LEVEL_ERROR, "batch: rejected record length %llu (valid range 1..%llu)",
                  length, (unsigned long long)BATCH_MAX_RECORD);
      goto done;
    }
    char* record = (char*)malloc((size_t)length);
    if (record == NULL) {
      log_message(LOG_LEVEL_ERROR, "batch: could not allocate a %llu-byte record", length);
      goto done;
    }
    if (!read_exact(fd, record, (size_t)length, &eof) || eof) {
      log_message(LOG_LEVEL_ERROR, "batch: truncated chunk record");
      free(record);
      goto done;
    }
    Data* data = data_create(record, (size_t)length);
    if (data == NULL)
      goto done; /* data_create frees `record` on failure */
    Chunk* chunk = chunk_deserialize(data, use_metadata);
    data_destroy(data);
    if (chunk == NULL) {
      log_message(LOG_LEVEL_ERROR, "batch: rejected malformed chunk record");
      goto done;
    }
    for (int i = 0; i < chunk->element_count; i++) {
      File* file = chunk->items[i];
      chunk->items[i] = NULL;
      if (file == NULL)
        continue;
      FileSaveResult save = file_save_to_disk_full(dest_root, file, config);
      /* Accumulate directory metadata (when it applies) before the File is
       * destroyed; applied once the whole stream has been consumed. */
      if (save != FILE_SAVE_ERROR && file->is_dir && file->metadata &&
          dir_metadata_should_capture(config) &&
          !dir_time_list_add(&dir_times, file->path, file->metadata, file->xattrs)) {
        file_destroy(file);
        chunk_destroy(chunk);
        goto done;
      }
      file_destroy(file);
      if (save == FILE_SAVE_ERROR) {
        chunk_destroy(chunk);
        goto done;
      }
    }
    chunk_destroy(chunk);
  }
  dir_metadata_list_apply(&dir_times, dest_root, config);
  result = 0;

done:
  identity_clear_active();
  dir_time_list_free(&dir_times);
  return result;
}
