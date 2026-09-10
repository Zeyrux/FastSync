#include "batch.h"
#include "data.h"
#include "file.h"
#include "file_receive.h"
#include "log.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Serialization metadata mode for the batch stream, captured from the config at
 * batch_write_header time.  The header persists it into the file so a batch is
 * self-describing: batch_read_apply re-reads it from the file (not from the
 * reading config), so a batch written with -M is applied identically by an
 * invoking process regardless of its own -M setting.  The batch driver is a
 * single sequential scan pass within one thread, so this module-level flag is
 * safe. */
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

  char magic[BATCH_MAGIC_LEN];
  bool eof = false;
  if (!read_exact(fd, magic, BATCH_MAGIC_LEN, &eof) || eof ||
      memcmp(magic, BATCH_MAGIC, BATCH_MAGIC_LEN) != 0) {
    log_message(LOG_LEVEL_ERROR, "batch: malformed header (bad magic)");
    return -1;
  }
  unsigned char version;
  if (!read_exact(fd, &version, 1, &eof) || eof || version != BATCH_FORMAT_VERSION) {
    log_message(LOG_LEVEL_ERROR, "batch: malformed header (bad or missing format version)");
    return -1;
  }
  unsigned char mode;
  if (!read_exact(fd, &mode, 1, &eof) || eof || (mode != 0 && mode != 1)) {
    log_message(LOG_LEVEL_ERROR, "batch: malformed header (bad metadata flag)");
    return -1;
  }
  bool use_metadata = mode == 1;

  while (1) {
    unsigned long long length;
    if (!read_exact(fd, &length, sizeof(length), &eof)) {
      log_message(LOG_LEVEL_ERROR, "batch: truncated length prefix");
      return -1;
    }
    if (eof)
      break; /* clean end of stream */
    if (length == 0 || length > BATCH_MAX_RECORD) {
      log_message(LOG_LEVEL_ERROR, "batch: rejected record length %llu (valid range 1..%llu)",
                  length, (unsigned long long)BATCH_MAX_RECORD);
      return -1;
    }
    char* record = (char*)malloc((size_t)length);
    if (record == NULL) {
      log_message(LOG_LEVEL_ERROR, "batch: could not allocate a %llu-byte record", length);
      return -1;
    }
    if (!read_exact(fd, record, (size_t)length, &eof)) {
      log_message(LOG_LEVEL_ERROR, "batch: truncated chunk record");
      free(record);
      return -1;
    }
    Data* data = data_create(record, (size_t)length);
    if (data == NULL)
      return -1; /* data_create frees `record` on failure */
    Chunk* chunk = chunk_deserialize(data, use_metadata);
    data_destroy(data);
    if (chunk == NULL) {
      log_message(LOG_LEVEL_ERROR, "batch: rejected malformed chunk record");
      return -1;
    }
    for (int i = 0; i < chunk->element_count; i++) {
      File* file = chunk->items[i];
      chunk->items[i] = NULL;
      if (file == NULL)
        continue;
      FileSaveResult result = file_save_to_disk_full(dest_root, file, config);
      file_destroy(file);
      if (result == FILE_SAVE_ERROR) {
        chunk_destroy(chunk);
        return -1;
      }
    }
    chunk_destroy(chunk);
  }
  return 0;
}