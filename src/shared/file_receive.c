#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "array_list.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delta.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"

#define MAX_SERVER_DELETE_COUNT 100000U
#define MAX_FILE_DATA_SIZE MAX_RECEIVE_FILE_SIZE

bool file_save_to_disk(const char* root_directory, const File* file, const Config* config) {
  bool backup_enabled = config && config->backup;
  bool inplace = config && config->inplace;
  bool sparse = config && config->preserve_sparse;
  const char* backup_suffix = (config && config->suffix) ? config->suffix : "~";
  const char* backup_dir = (config && config->backup_dir) ? config->backup_dir : NULL;
  const char* partial_dir = (config && config->partial_dir) ? config->partial_dir : NULL;
  char *confined_backup = NULL, *confined_partial = NULL, *disk_path = NULL;
  char *backup_path = NULL, *parent_copy = NULL;

  if (!file || !file->path || !file->data || (file->data->size != 0 && !file->data->data) ||
      has_path_traversal(file->path) ||
      (backup_enabled &&
       (!backup_suffix || backup_suffix[0] == '\0' || strchr(backup_suffix, '/') != NULL ||
        strcmp(backup_suffix, ".") == 0 || strcmp(backup_suffix, "..") == 0))) {
    log_message(LOG_LEVEL_ERROR, "Invalid file or path received");
    return false;
  }

  /* These options arrive from the client.  They are names below the server
     root, never independent filesystem roots. */
  if ((backup_dir && (backup_dir[0] == '/' || has_path_traversal(backup_dir))) ||
      (partial_dir && (partial_dir[0] == '/' || has_path_traversal(partial_dir))))
    return false;
  if (backup_dir && !(confined_backup = path_cat(root_directory, backup_dir)))
    return false;
  if (partial_dir && !(confined_partial = path_cat(root_directory, partial_dir))) {
    free(confined_backup);
    return false;
  }

  const char* actual_root =
      (partial_dir && config && config->partial) ? confined_partial : root_directory;
  disk_path = path_cat(actual_root, file->path);
  if (disk_path == NULL) {
    free(confined_backup);
    free(confined_partial);
    return false;
  }

  /* --update is receiver-side policy: never replace a newer destination. */
  if (config && config->update) {
    struct stat destination_stat;
    if (file_stat_secure(disk_path, &destination_stat) && file->metadata &&
        destination_stat.st_mtime > file->metadata->mtime_sec) {
      free(confined_backup);
      free(confined_partial);
      free(disk_path);
      return true;
    }
  }

  if (backup_enabled) {
    struct stat backup_stat;
    if (file_stat_secure(disk_path, &backup_stat)) {
      if (backup_dir) {
        backup_path = path_cat(confined_backup, file->path);
      } else {
        size_t path_len = strlen(disk_path);
        size_t suffix_len = strlen(backup_suffix);
        if (path_len > SIZE_MAX - suffix_len - 1)
          goto fail;
        backup_path = malloc(path_len + suffix_len + 1);
        if (backup_path) {
          memcpy(backup_path, disk_path, path_len);
          memcpy(backup_path + path_len, backup_suffix, suffix_len + 1);
        }
      }
      if (!backup_path)
        goto fail;
      parent_copy = str_dup(backup_path);
      if (!parent_copy || !file_ensure_directory_secure(dirname(parent_copy)))
        goto fail;
      free(parent_copy);
      parent_copy = NULL;
      if (!file_rename_secure(disk_path, backup_path))
        goto fail;
      free(backup_path);
      backup_path = NULL;
    }
  }

  bool ok = file_to_disk_secure_with_fsync(disk_path, file->data->data, file->data->size, inplace,
                                           sparse, file->metadata, config && config->use_fsync);
  free(parent_copy);
  free(backup_path);
  free(confined_backup);
  free(confined_partial);
  free(disk_path);
  return ok;

fail:
  free(parent_copy);
  free(backup_path);
  free(confined_backup);
  free(confined_partial);
  free(disk_path);
  return false;
}

static File* receive_delta_file(int fd, const Config* config, const char* check_path,
                                void* old_data, unsigned long long old_size, bool* failed) {
  if (!old_data)
    return NULL;

  DeltaSignature* sig = delta_signature_create(old_data, old_size, config->delta_block_size);
  if (!sig) {
    free(old_data);
    *failed = true;
    return NULL;
  }

  Data* sig_data = delta_signature_serialize(sig);
  if (!sig_data) {
    delta_signature_destroy(sig);
    free(old_data);
    *failed = true;
    return NULL;
  }

  bool sig_sent = send_status(fd, STATUS_DELTA_SIGNATURE) && send_data(fd, sig_data);
  data_destroy(sig_data);

  if (!sig_sent) {
    delta_signature_destroy(sig);
    free(old_data);
    *failed = true;
    return NULL;
  }

  Status resp;
  if (!receive_status(fd, &resp)) {
    delta_signature_destroy(sig);
    free(old_data);
    *failed = true;
    return NULL;
  }

  if (resp == STATUS_DELTA_DATA) {
    Data* delta_data = receive_data_limited(fd, MAX_RECEIVE_FILE_SIZE);
    if (!delta_data) {
      delta_signature_destroy(sig);
      free(old_data);
      *failed = true;
      return NULL;
    }

    Data* raw_delta = delta_data;
    if (config->use_compression) {
      raw_delta = data_decompress_limited(delta_data, MAX_RECEIVE_FILE_SIZE);
      data_destroy(delta_data);
      if (!raw_delta) {
        free(old_data);
        delta_signature_destroy(sig);
        *failed = true;
        return NULL;
      }
    }

    Delta* delta = delta_deserialize(raw_delta);
    data_destroy(raw_delta);
    if (!delta) {
      free(old_data);
      delta_signature_destroy(sig);
      *failed = true;
      return NULL;
    }

    uint64_t new_size = delta->new_file_size;
    if (new_size > MAX_RECEIVE_FILE_SIZE || new_size > SIZE_MAX) {
      delta_destroy(delta);
      free(old_data);
      delta_signature_destroy(sig);
      send_status(fd, STATUS_ERROR);
      return NULL;
    }
    void* new_data = delta_apply(old_data, old_size, delta, config->delta_block_size);
    delta_destroy(delta);

    if (!new_data) {
      free(old_data);
      delta_signature_destroy(sig);
      *failed = true;
      return NULL;
    }

    File* file = file_create(check_path);
    if (!file) {
      free(new_data);
      free(old_data);
      delta_signature_destroy(sig);
      *failed = true;
      return NULL;
    }

    if (config->use_metadata) {
      int meta_ok = 1;
      file->metadata = metadata_receive(fd, &meta_ok);
      if (!meta_ok) {
        file_destroy(file);
        free(new_data);
        free(old_data);
        delta_signature_destroy(sig);
        *failed = true;
        return NULL;
      }
    }

    Data* replacement = data_create(new_data, (size_t)new_size);
    if (replacement == NULL) {
      file_destroy(file);
      free(old_data);
      delta_signature_destroy(sig);
      send_status(fd, STATUS_ERROR);
      return NULL;
    }
    data_destroy(file->data);
    file->data = replacement;

    free(old_data);
    delta_signature_destroy(sig);
    return file;
  }

  if (resp == STATUS_NEXT) {
    delta_signature_destroy(sig);
    free(old_data);

    File* file = file_create(check_path);
    if (!file) {
      *failed = true;
      return NULL;
    }

    if (config->use_metadata) {
      int meta_ok = 1;
      file->metadata = metadata_receive(fd, &meta_ok);
      if (!meta_ok) {
        file_destroy(file);
        *failed = true;
        return NULL;
      }
    }

    Data* file_data = receive_data_limited(fd, MAX_RECEIVE_FILE_SIZE);
    if (file_data == NULL) {
      file_destroy(file);
      *failed = true;
      return NULL;
    }

    if (config->use_compression) {
      Data* uncompressed = data_decompress_limited(file_data, MAX_RECEIVE_FILE_SIZE);
      data_destroy(file_data);
      if (uncompressed == NULL) {
        file_destroy(file);
        *failed = true;
        return NULL;
      }
      if (uncompressed->size > MAX_FILE_DATA_SIZE) {
        data_destroy(uncompressed);
        file_destroy(file);
        send_status(fd, STATUS_ERROR);
        return NULL;
      }
      file_data = uncompressed;
    }

    data_destroy(file->data);
    file->data = file_data;
    return file;
  }

  delta_signature_destroy(sig);
  free(old_data);
  send_status(fd, STATUS_ERROR);
  *failed = true;
  return NULL;
}

File* receive_incremental_check(int fd, const Config* config, bool* skipped) {
  if (!config || !skipped) {
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  *skipped = false;
  char* check_path = receive_str(fd);
  if (check_path == NULL) {
    return NULL;
  }

  unsigned long long check_size;
  long long check_mtime;
  uint64_t check_checksum = 0;
  if (!receive_n_data(fd, &check_size, sizeof(check_size)) ||
      !receive_n_data(fd, &check_mtime, sizeof(check_mtime))) {
    free(check_path);
    return NULL;
  }
  if (config->checksum && !receive_n_data(fd, &check_checksum, sizeof(check_checksum))) {
    free(check_path);
    return NULL;
  }

  if (check_size > MAX_RECEIVE_FILE_SIZE) {
    free(check_path);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }

  if (has_path_traversal(check_path)) {
    char* escaped_path = output_escape(check_path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Path traversal detected: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    free(check_path);
    return NULL;
  }

  char* full_path = path_cat(config->receive_root_directory, check_path);
  if (!full_path) {
    free(check_path);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  struct stat st;
  bool has_old_file = false;
  int old_fd = -1;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(full_path, &leaf, false);
  if (parent_fd >= 0) {
    old_fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    free(leaf);
    close(parent_fd);
    has_old_file = old_fd >= 0 && fstat(old_fd, &st) == 0 && S_ISREG(st.st_mode);
  }
  unsigned long long old_size = has_old_file ? (unsigned long long)st.st_size : 0;
  void* old_data = NULL;
  if (has_old_file && old_size > 0 && old_size <= MAX_RECEIVE_FILE_SIZE && old_size <= SIZE_MAX) {
    old_data = malloc((size_t)old_size);
    if (old_data) {
      size_t got = 0;
      while (got < (size_t)old_size) {
        ssize_t n = read(old_fd, (char*)old_data + got, (size_t)old_size - got);
        if (n <= 0) {
          free(old_data);
          old_data = NULL;
          break;
        }
        got += (size_t)n;
      }
    }
  }
  if (old_fd >= 0) {
    close(old_fd);
  }

  bool match = has_old_file && (unsigned long long)st.st_size == check_size;
  if (match && config->checksum) {
    uint64_t old_checksum = old_size == 0 ? delta_xxhash64("", 0) : 0;
    if (old_data)
      old_checksum = delta_xxhash64(old_data, (size_t)old_size);
    match = (old_size == 0 || old_data) && old_checksum == check_checksum;
    free(old_data);
    old_data = NULL;
  } else if (match) {
    match = (long long)st.st_mtime == check_mtime;
  }

  if (match) {
    free(old_data);
    if (!send_status(fd, STATUS_OK)) {
      free(full_path);
      free(check_path);
      return NULL;
    }
    free(full_path);
    free(check_path);
    *skipped = true;
    return NULL;
  }

  bool try_delta = config->use_delta && !config->whole_file && has_old_file && old_data != NULL &&
                   delta_should_attempt(old_size, check_size, config->delta_max_file_size);

  if (try_delta) {
    bool delta_failed = false;
    File* delta_file =
        receive_delta_file(fd, config, check_path, old_data, old_size, &delta_failed);
    old_data = NULL; /* receive_delta_file consumes the snapshot on every path */
    if (delta_file) {
      free(full_path);
      free(check_path);
      return delta_file;
    }
    if (delta_failed) {
      free(full_path);
      free(check_path);
      return NULL;
    }
    free(old_data);
    old_data = NULL;
    try_delta = false;
  }

  if (!try_delta) {
    if (!send_status(fd, STATUS_NEXT)) {
      free(full_path);
      free(check_path);
      return NULL;
    }
  }

  File* file = file_create(check_path);
  free(check_path);
  free(full_path);
  if (file == NULL) {
    return NULL;
  }

  if (config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(fd, &meta_ok);
    if (!meta_ok) {
      file_destroy(file);
      return NULL;
    }
  }

  Data* file_data = receive_data_limited(fd, MAX_RECEIVE_FILE_SIZE);
  if (file_data == NULL) {
    file_destroy(file);
    return NULL;
  }

  if (config->use_compression) {
    Data* uncompressed = data_decompress_limited(file_data, MAX_RECEIVE_FILE_SIZE);
    data_destroy(file_data);
    if (uncompressed == NULL) {
      file_destroy(file);
      return NULL;
    }
    if (uncompressed->size > MAX_FILE_DATA_SIZE) {
      data_destroy(uncompressed);
      file_destroy(file);
      send_status(fd, STATUS_ERROR);
      return NULL;
    }
    file_data = uncompressed;
  }

  data_destroy(file->data);
  file->data = file_data;
  return file;
}

File* file_receive(const Config* config, int file_descriptor) {
  char* path = receive_str(file_descriptor);
  if (path == NULL)
    return NULL;
  if (path[0] == '\0' || has_path_traversal(path)) {
    char* escaped_path = output_escape(path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid received file path: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    free(path);
    return NULL;
  }
  File* file = file_create(path);
  free(path);
  if (file == NULL)
    return NULL;
  if (config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(file_descriptor, &meta_ok);
    if (!meta_ok) {
      file_destroy(file);
      return NULL;
    }
  }
  Data* file_data = receive_data_limited(file_descriptor, MAX_RECEIVE_FILE_SIZE);
  if (file_data == NULL) {
    file_destroy(file);
    return NULL;
  }
  if (config->use_compression && !compression_should_skip(file->path)) {
    Data* file_data_uncompressed = data_decompress_limited(file_data, MAX_RECEIVE_FILE_SIZE);
    data_destroy(file_data);
    if (file_data_uncompressed == NULL) {
      file_destroy(file);
      return NULL;
    }
    if (file_data_uncompressed->size > MAX_FILE_DATA_SIZE) {
      data_destroy(file_data_uncompressed);
      file_destroy(file);
      return NULL;
    }
    file_data = file_data_uncompressed;
  }
  data_destroy(file->data);
  file->data = file_data;
  return file;
}

int receive_manifest(int fd, const Config* config, int* next_status) {
  if (!config) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  int received_status = STATUS_ERROR;
  int* status_out = next_status ? next_status : &received_status;
  int count;
  if (!receive_int(fd, &count)) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  if (count < 0 || count > MAX_MANIFEST_ENTRIES) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  ArrayList* manifest = array_list_create(free);
  if (!manifest) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  size_t manifest_bytes = 0;
  for (int i = 0; i < count; i++) {
    char* s = receive_str(fd);
    size_t entry_size = s ? strlen(s) : 0;
    if (!s || s[0] == '\0' || s[0] == '/' || has_path_traversal(s) ||
        entry_size > MAX_MANIFEST_BYTES - manifest_bytes ||
        (manifest_bytes += entry_size) > MAX_MANIFEST_BYTES || !array_list_add(manifest, s)) {
      free(s);
      array_list_delete(manifest);
      send_status(fd, STATUS_ERROR);
      return -1;
    }
  }
  if (!receive_status(fd, status_out)) {
    array_list_delete(manifest);
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  /* Deletion is a commit operation: never perform it until the sender has
     completed the manifest frame successfully. */
  if (*status_out != STATUS_FINISHED || !config->use_delete) {
    array_list_delete(manifest);
    if (*status_out != STATUS_FINISHED)
      send_status(fd, STATUS_ERROR);
    return *status_out == STATUS_FINISHED ? 0 : -1;
  }
  fprintf(stderr, "Deleting files not in manifest...\n");
  bool deletion_ok =
      delete_extras_limited(config->receive_root_directory, manifest, MAX_SERVER_DELETE_COUNT);
  array_list_delete(manifest);
  if (!deletion_ok)
    send_status(fd, STATUS_ERROR);
  return deletion_ok ? 0 : -1;
}
