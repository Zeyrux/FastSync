#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array_list.h"
#include "charset.h"
#include "chunk.h"
#include "compression.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"

/* Maximum individual file data size within a chunk (64 MB) */
#define MAX_FILE_DATA_SIZE (64ULL * 1024 * 1024)
#define MAX_FILES_PER_CHUNK 65536U

Chunk* chunk_create(File** items, int element_count) {
  if (element_count < 0 || (element_count > 0 && items == NULL))
    return NULL;
  Chunk* chunk = (Chunk*)protocol_alloc(sizeof(Chunk));
  if (chunk == NULL) {
    log_perror("ERROR: Could not allocate memory for chunk structure");
    return NULL;
  }

  if (element_count == 0) {
    chunk->items = NULL;
  } else {
    if ((size_t)element_count > SIZE_MAX / sizeof(File*)) {
      free(chunk);
      return NULL;
    }
    chunk->items = (File**)protocol_alloc((size_t)element_count * sizeof(File*));
    if (chunk->items == NULL) {
      free(chunk);
      return NULL;
    }
  }

  for (int i = 0; i < element_count; i++) {
    chunk->items[i] = items[i];
  }
  chunk->element_count = element_count;
  return chunk;
}

void chunk_destroy(void* item) {
  if (item == NULL) {
    return;
  }
  Chunk* chunk = (Chunk*)item;
  for (int i = 0; i < chunk->element_count; ++i) {
    if (chunk->items[i] != NULL) {
      file_destroy(chunk->items[i]);
    }
  }
  free(chunk->items);
  free(chunk);
}

/* --iconv: a chunk blob carries wire-charset path/target bytes.  Encode the
 * sender-side path (a no-op copy when iconv is disabled) so the blob is in the
 * same charset as every other wire string. */
static char* chunk_encode_wire(const char* path) {
  if (!charset_wire_active())
    return str_dup(path);
  return charset_wire_apply(path);
}

static unsigned long long per_file_serialize_size(File* file, bool use_metadata) {
  unsigned long long size = sizeof(size_t);
  char* wire_path = chunk_encode_wire(file_wire_path(file));
  if (!wire_path)
    return 0;
  size_t path_len = strlen(wire_path);
  free(wire_path);
  unsigned long long metadata_size =
      use_metadata ? sizeof(int) + (file->metadata ? FILE_METADATA_WIRE_SIZE : 0) : 0;
  if ((unsigned long long)path_len > ULLONG_MAX - size)
    return 0;
  size += path_len;
  if (metadata_size > ULLONG_MAX - size)
    return 0;
  size += metadata_size;
  /* Entry type marker: 0 = regular file, 1 = explicit directory entry,
     2 = symlink entry (carries its target string), 3 = special/device node
     (recreated by the receiver). */
  if (sizeof(int) > ULLONG_MAX - size)
    return 0;
  size += sizeof(int);
  /* A special node also carries its rdev major/minor. */
  if (file->is_special) {
    if (2 * sizeof(int32_t) > ULLONG_MAX - size)
      return 0;
    size += 2 * sizeof(int32_t);
  }
  if (sizeof(size_t) > ULLONG_MAX - size)
    return 0;
  size += sizeof(size_t);
  if ((unsigned long long)file->data->size > ULLONG_MAX - size)
    return 0;
  size += file->data->size;
  /* Symlink entries append the target string (length-prefixed). */
  if (file->is_symlink) {
    char* wire_target = chunk_encode_wire(file->symlink_target ? file->symlink_target : "");
    if (!wire_target)
      return 0;
    size_t target_len = strlen(wire_target);
    free(wire_target);
    if (sizeof(size_t) > ULLONG_MAX - size)
      return 0;
    size += sizeof(size_t);
    if ((unsigned long long)target_len > ULLONG_MAX - size)
      return 0;
    size += target_len;
  }
  return size;
}

Data* chunk_serialize(Chunk* chunk, bool use_metadata) {
  if (!chunk || chunk->element_count < 0 || (chunk->element_count > 0 && chunk->items == NULL))
    return NULL;
  unsigned long long data_size = 0;
  for (int i = 0; i < chunk->element_count; i++) {
    if (!chunk->items[i] || !chunk->items[i]->path || !chunk->items[i]->data ||
        (chunk->items[i]->data->size > 0 && !chunk->items[i]->data->data) ||
        chunk->items[i]->path[0] == '\0' || has_path_traversal(chunk->items[i]->path) ||
        (file_wire_path(chunk->items[i]))[0] == '\0')
      return NULL;
    unsigned long long file_size = per_file_serialize_size(chunk->items[i], use_metadata);
    if (file_size == 0 || file_size > ULLONG_MAX - data_size || data_size + file_size > SIZE_MAX)
      return NULL;
    data_size += file_size;
  }
  Data* data = data_create_empty(data_size);
  if (data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Could not allocate memory for chunk serialization");
    return NULL;
  }
  char* data_pointer = data->data;
  for (int i = 0; i < chunk->element_count; i++) {
    File* file = chunk->items[i];
    char* wire_path = chunk_encode_wire(file_wire_path(file));
    if (wire_path == NULL) {
      data_destroy(data);
      return NULL;
    }
    size_t path_len = strlen(wire_path);
    memcpy(data_pointer, &path_len, sizeof(size_t));
    data_pointer += sizeof(size_t);
    memcpy(data_pointer, wire_path, path_len);
    data_pointer += path_len;
    free(wire_path);

    int entry_type = file->is_dir ? 1 : (file->is_symlink ? 2 : (file->is_special ? 3 : 0));
    memcpy(data_pointer, &entry_type, sizeof(int));
    data_pointer += sizeof(int);

    if (file->is_special) {
      int32_t special_major = file->rdev_major;
      int32_t special_minor = file->rdev_minor;
      memcpy(data_pointer, &special_major, sizeof(special_major));
      data_pointer += sizeof(special_major);
      memcpy(data_pointer, &special_minor, sizeof(special_minor));
      data_pointer += sizeof(special_minor);
    }

    if (use_metadata)
      metadata_to_buf(&data_pointer, file->metadata);

    size_t file_data_size = file->data->size;
    memcpy(data_pointer, &file_data_size, sizeof(size_t));
    data_pointer += sizeof(size_t);
    if (file_data_size > 0)
      memcpy(data_pointer, file->data->data, file_data_size);
    data_pointer += file_data_size;

    if (file->is_symlink) {
      char* wire_target = chunk_encode_wire(file->symlink_target ? file->symlink_target : "");
      if (wire_target == NULL) {
        data_destroy(data);
        return NULL;
      }
      size_t target_len = strlen(wire_target);
      memcpy(data_pointer, &target_len, sizeof(size_t));
      data_pointer += sizeof(size_t);
      if (target_len > 0)
        memcpy(data_pointer, wire_target, target_len);
      data_pointer += target_len;
      free(wire_target);
    }
  }
  return data;
}

Chunk* chunk_deserialize(Data* data, bool use_metadata) {
  if (!data || (!data->data && data->size != 0))
    return NULL;
  ArrayList* files = array_list_create(file_destroy);
  if (files == NULL)
    return NULL;
  char* data_pointer = data->data;
  size_t remaining_size = data->size;
  /* The element currently being parsed is owned by `files` only after the
   * array_list_add() at the end of the iteration; until then the error
   * epilogue destroys it directly.  Keeping this one pointer nulled after the
   * hand-off makes the single cleanup path correct for every failure. */
  File* file = NULL;

  while (remaining_size > 0) {
    if ((unsigned int)files->size >= MAX_FILES_PER_CHUNK) {
      log_message(LOG_LEVEL_ERROR, "Chunk contains too many files");
      goto error;
    }
    if (remaining_size < sizeof(size_t)) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for path length");
      goto error;
    }

    size_t path_len;
    memcpy(&path_len, data_pointer, sizeof(size_t));
    data_pointer += sizeof(size_t);
    remaining_size -= sizeof(size_t);

    if (path_len > SIZE_MAX - 1 || remaining_size < path_len) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for path");
      goto error;
    }

    char* path = protocol_alloc(path_len + 1);
    if (path == NULL) {
      log_perror("Could not allocate memory for file path");
      goto error;
    }
    memcpy(path, data_pointer, path_len);
    path[path_len] = '\0';
    if (memchr(path, '\0', path_len) != NULL) {
      free(path);
      goto error;
    }
    data_pointer += path_len;
    remaining_size -= path_len;

    /* --iconv: the blob holds the wire charset; translate it to the receiver's
       local charset before validation and creation so the destination gets the
       local name.  A name that cannot be decoded fails the file cleanly. */
    if (charset_wire_active()) {
      char* local_path = charset_wire_apply(path);
      free(path);
      if (local_path == NULL) {
        log_message(LOG_LEVEL_ERROR,
                    "--iconv: received chunk file name cannot be converted to the local charset");
        goto error;
      }
      path = local_path;
      path_len = strlen(path);
    }

    if (path_len == 0 || has_path_traversal(path)) {
      free(path);
      goto error;
    }

    file = file_create(path);
    free(path);
    if (file == NULL)
      goto error;

    if (remaining_size < sizeof(int)) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for entry type");
      goto error;
    }
    int entry_type;
    memcpy(&entry_type, data_pointer, sizeof(int));
    if (entry_type != 0 && entry_type != 1 && entry_type != 2 && entry_type != 3) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: bad entry type");
      goto error;
    }
    file->is_dir = entry_type == 1;
    file->is_symlink = entry_type == 2;
    file->is_special = entry_type == 3;
    data_pointer += sizeof(int);
    remaining_size -= sizeof(int);

    if (file->is_special) {
      if (remaining_size < 2 * (int32_t)sizeof(int32_t)) {
        log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for special rdev");
        goto error;
      }
      int32_t special_major, special_minor;
      memcpy(&special_major, data_pointer, sizeof(special_major));
      data_pointer += sizeof(special_major);
      memcpy(&special_minor, data_pointer, sizeof(special_minor));
      data_pointer += sizeof(special_minor);
      remaining_size -= 2 * sizeof(int32_t);
      /* Reject an out-of-range/negative rdev here as a malformed chunk (the
         same 0xffff / 0x00ffffff bounds file_special_rdev_valid uses), so a
         bogus large-but-positive rdev is refused cleanly instead of being
         deferred to the creation site where it would abort after the frame. */
      if (special_major < 0 || special_minor < 0 || special_major > 0xffff ||
          special_minor > 0x00ffffff) {
        log_message(LOG_LEVEL_ERROR, "Invalid chunk format: out-of-range special rdev");
        goto error;
      }
      file->rdev_major = special_major;
      file->rdev_minor = special_minor;
    }

    if (use_metadata) {
      if (remaining_size < sizeof(int)) {
        log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for metadata");
        goto error;
      }
      /* Peek at the present flag to determine the total record size before
         decoding.  metadata_from_buf() independently bounds-checks every read
         against remaining_size, so a short body can never over-read. */
      int present_flag;
      memcpy(&present_flag, data_pointer, sizeof(int));
      if ((present_flag != 0 && present_flag != 1) ||
          (present_flag == 1 && remaining_size < sizeof(int) + FILE_METADATA_WIRE_SIZE)) {
        log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for metadata body");
        goto error;
      }
      file->metadata = metadata_from_buf((const uint8_t*)data_pointer, remaining_size);
      size_t metadata_consumed = sizeof(int);
      if (present_flag == 1) {
        if (file->metadata == NULL)
          goto error;
        metadata_consumed += FILE_METADATA_WIRE_SIZE;
      }
      data_pointer += metadata_consumed;
      remaining_size -= metadata_consumed;
    }

    if (remaining_size < sizeof(size_t)) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for data size");
      goto error;
    }

    size_t file_data_size;
    memcpy(&file_data_size, data_pointer, sizeof(size_t));
    data_pointer += sizeof(size_t);
    remaining_size -= sizeof(size_t);

    if (remaining_size < file_data_size) {
      log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for file content");
      goto error;
    }

    // Reject individual file data larger than the maximum allowed size.
    if (file_data_size > MAX_FILE_DATA_SIZE) {
      log_message(LOG_LEVEL_ERROR, "File data size %zu exceeds maximum %llu", file_data_size,
                  (unsigned long long)MAX_FILE_DATA_SIZE);
      goto error;
    }

    size_t allocation_size = file_data_size > 0 ? file_data_size : 1;
    void* file_data = protocol_alloc(allocation_size);
    if (file_data == NULL) {
      log_perror("Could not allocate memory for file data");
      goto error;
    }
    memcpy(file_data, data_pointer, file_data_size);
    Data* replacement = data_create(file_data, file_data_size);
    if (replacement == NULL)
      goto error;
    data_destroy(file->data);
    file->data = replacement;
    data_pointer += file_data_size;
    remaining_size -= file_data_size;

    if (file->is_symlink) {
      if (remaining_size < sizeof(size_t)) {
        log_message(LOG_LEVEL_ERROR, "Invalid chunk format: not enough data for symlink target");
        goto error;
      }
      size_t target_len;
      memcpy(&target_len, data_pointer, sizeof(size_t));
      data_pointer += sizeof(size_t);
      remaining_size -= sizeof(size_t);
      if (target_len == 0 || remaining_size < target_len) {
        log_message(LOG_LEVEL_ERROR, "Invalid chunk format: bad symlink target");
        goto error;
      }
      char* target = protocol_alloc(target_len + 1);
      if (!target) {
        log_perror("Could not allocate memory for symlink target");
        goto error;
      }
      memcpy(target, data_pointer, target_len);
      target[target_len] = '\0';
      if (memchr(target, '\0', target_len) != NULL) {
        free(target);
        goto error;
      }
      /* The symlink target also rides the wire charset; decode it to the local
         charset like the path (a target is a path). */
      if (charset_wire_active()) {
        char* local_target = charset_wire_apply(target);
        free(target);
        if (local_target == NULL) {
          log_message(LOG_LEVEL_ERROR,
                      "--iconv: received chunk symlink target cannot be converted to the local "
                      "charset");
          goto error;
        }
        target = local_target;
      }
      file->symlink_target = target;
      data_pointer += target_len;
      remaining_size -= target_len;
    }

    if (!array_list_add(files, file))
      goto error;
    file = NULL;
  }

  File** file_array = (File**)array_list_to_array(files);
  if (files->size > 0 && file_array == NULL)
    goto error;
  Chunk* chunk = chunk_create(file_array, files->size);
  free(file_array);
  if (chunk == NULL)
    goto error;
  files->item_destroyer = NULL;
  array_list_delete(files);
  return chunk;

error:
  if (file)
    file_destroy(file);
  array_list_delete(files);
  return NULL;
}

Data* chunk_compress(Chunk* chunk, int compression_level, bool use_metadata) {
  return chunk_compress_with_threads(chunk, compression_level, use_metadata, 0);
}

Data* chunk_compress_with_threads(Chunk* chunk, int compression_level, bool use_metadata,
                                  int compression_threads) {
  log_message(LOG_LEVEL_DEBUG, "Starting to compress chunk");
  Data* serialized = chunk_serialize(chunk, use_metadata);
  if (serialized == NULL)
    return NULL;
  Data* compressed = data_compress_with_threads(serialized, compression_level, compression_threads);
  data_destroy(serialized);
  if (compressed == NULL)
    return NULL;
  log_debug_message(LOG_DEBUG_PACK, "Chunk successfully compressed");
  return compressed;
}

Chunk* receive_chunk_data(int fd, const Config* config) {
  Data* chunk_data = receive_data_limited(fd, MAX_CHUNK_SIZE);
  if (chunk_data == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to receive chunk data");
    return NULL;
  }
  Data* data_to_process = chunk_data;
  if (config->use_compression) {
    data_to_process = data_decompress_limited(chunk_data, MAX_CHUNK_SIZE);
    data_destroy(chunk_data);
    if (data_to_process == NULL) {
      log_message(LOG_LEVEL_ERROR, "Failed to decompress chunk");
      return NULL;
    }
  }

  // Reject chunks larger than the maximum allowed size to prevent OOM.
  if (data_to_process->size > MAX_CHUNK_SIZE) {
    log_message(LOG_LEVEL_ERROR, "Chunk size %zu exceeds maximum %llu", data_to_process->size,
                (unsigned long long)MAX_CHUNK_SIZE);
    data_destroy(data_to_process);
    return NULL;
  }

  Chunk* chunk = chunk_deserialize(data_to_process, config->use_metadata);
  data_destroy(data_to_process);
  if (chunk == NULL)
    log_message(LOG_LEVEL_ERROR, "Failed to deserialize chunk, skipping");
  return chunk;
}
