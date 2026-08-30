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
#include "file_store.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"

static bool path_is_within_root(const char* root, const char* path) {
  size_t n = strlen(root);
  return strncmp(root, path, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

bool file_save_to_disk(const char* root_directory, const File* file, const Config* config) {
  bool backup_enabled = config && config->backup;
  bool inplace = config && config->inplace;
  bool sparse = config && config->preserve_sparse;
  const char* backup_suffix = (config && config->suffix) ? config->suffix : "~";
  const char* backup_dir = (config && config->backup_dir) ? config->backup_dir : NULL;
  const char* partial_dir = (config && config->partial_dir) ? config->partial_dir : NULL;
  char *confined_backup = NULL, *confined_partial = NULL;

  if (!file || !file->path || !file->data || has_path_traversal(file->path) ||
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

  char* resolved_root = NULL;
  const char* actual_root =
      (partial_dir && config && config->partial) ? confined_partial : root_directory;
  resolved_root = realpath(actual_root, NULL);
  if (resolved_root == NULL) {
    if (mkdir_r(actual_root)) {
      resolved_root = realpath(actual_root, NULL);
    }
  }
  if (resolved_root == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to resolve destination root: %s", actual_root);
    free(confined_backup);
    free(confined_partial);
    return false;
  }
  char* resolved_base = realpath(root_directory, NULL);
  if (resolved_base == NULL || !path_is_within_root(resolved_base, resolved_root)) {
    free(resolved_base);
    free(confined_backup);
    free(confined_partial);
    free(resolved_root);
    return false;
  }
  free(resolved_base);

  char* disk_path = path_cat(resolved_root, file->path);
  if (disk_path == NULL) {
    free(confined_backup);
    free(confined_partial);
    free(resolved_root);
    return false;
  }

  /* --update is receiver-side policy: never replace a newer destination. */
  if (config && config->update) {
    struct stat destination_stat;
    if (stat(disk_path, &destination_stat) == 0 && file->metadata &&
        destination_stat.st_mtime > file->metadata->mtime_sec) {
      free(resolved_root);
      free(confined_backup);
      free(confined_partial);
      free(disk_path);
      return true;
    }
  }

  if (backup_enabled) {
    struct stat backup_stat;
    if (stat(disk_path, &backup_stat) == 0) {
      char* backup_path = NULL;
      if (backup_dir) {
        char* resolved_backup_dir = realpath(confined_backup, NULL);
        if (!resolved_backup_dir) {
          mkdir_r(confined_backup);
          resolved_backup_dir = realpath(confined_backup, NULL);
        }
        if (resolved_backup_dir) {
          char* backup_base = realpath(root_directory, NULL);
          if (backup_base && path_is_within_root(backup_base, resolved_backup_dir))
            backup_path = path_cat(resolved_backup_dir, file->path);
          free(backup_base);
          free(resolved_backup_dir);
        }
      }
      if (!backup_path) {
        size_t path_len = strlen(disk_path);
        size_t suffix_len = strlen(backup_suffix);
        backup_path = malloc(path_len + suffix_len + 1);
        if (backup_path) {
          memcpy(backup_path, disk_path, path_len);
          memcpy(backup_path + path_len, backup_suffix, suffix_len + 1);
        }
      }
      if (backup_path) {
        char* backup_dir_path = str_dup(backup_path);
        if (backup_dir_path) {
          const char* bdir = dirname(backup_dir_path);
          mkdir_r(bdir);
          free(backup_dir_path);
        }
        if (!file_store_rename_secure(disk_path, backup_path)) {
          free(backup_path);
          free(resolved_root);
          free(confined_backup);
          free(confined_partial);
          free(disk_path);
          return false;
        }
        free(backup_path);
      }
    }
  }

  char* dir_dup = str_dup(disk_path);
  if (!dir_dup) {
    free(confined_backup);
    free(confined_partial);
    free(resolved_root);
    free(disk_path);
    return false;
  }
  char* dir_str = dirname(dir_dup);
  if (!mkdir_r(dir_str)) {
    free(dir_dup);
    free(confined_backup);
    free(confined_partial);
    free(resolved_root);
    free(disk_path);
    return false;
  }
  char* resolved_dir = realpath(dir_str, NULL);
  free(dir_dup);
  if (resolved_dir == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to resolve directory for: %s", disk_path);
    free(confined_backup);
    free(confined_partial);
    free(resolved_root);
    free(disk_path);
    return false;
  }

  size_t root_len = strlen(resolved_root);
  if (strncmp(resolved_dir, resolved_root, root_len) != 0 ||
      (resolved_dir[root_len] != '\0' && resolved_dir[root_len] != '/')) {
    log_message(LOG_LEVEL_ERROR, "Path escape detected: %s is outside %s", disk_path, actual_root);
    free(resolved_dir);
    free(confined_backup);
    free(confined_partial);
    free(resolved_root);
    free(disk_path);
    return false;
  }
  free(resolved_dir);
  free(resolved_root);

  bool ok = file_store_write_secure(disk_path, file->data->data, file->data->size, inplace, sparse,
                                    file->metadata);
  free(confined_backup);
  free(confined_partial);
  free(disk_path);
  return ok;
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
    Data* delta_data = receive_data(fd);
    if (!delta_data) {
      delta_signature_destroy(sig);
      free(old_data);
      *failed = true;
      return NULL;
    }

    Data* raw_delta = delta_data;
    if (config->use_compression) {
      raw_delta = data_decompress(delta_data);
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

    void* new_data = delta_apply(old_data, old_size, delta, config->delta_block_size);
    uint64_t new_size = delta->new_file_size;
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

    data_destroy(file->data);
    file->data = data_create(new_data, (size_t)new_size);

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

    Data* file_data = receive_data(fd);
    if (file_data == NULL) {
      file_destroy(file);
      *failed = true;
      return NULL;
    }

    if (config->use_compression) {
      Data* uncompressed = data_decompress(file_data);
      data_destroy(file_data);
      if (uncompressed == NULL) {
        file_destroy(file);
        *failed = true;
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
  *failed = true;
  return NULL;
}

File* receive_incremental_check(int fd, const Config* config, bool* skipped) {
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

  if (has_path_traversal(check_path)) {
    log_message(LOG_LEVEL_ERROR, "Path traversal detected: %s", check_path);
    free(check_path);
    return NULL;
  }

  char* full_path = path_cat(config->receive_root_directory, check_path);
  struct stat st;
  bool has_old_file = false;
  int old_fd = -1;
  if (full_path) {
    char* leaf = NULL;
    int parent_fd = file_store_open_secure_parent(full_path, &leaf);
    if (parent_fd >= 0) {
      old_fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
      free(leaf);
      close(parent_fd);
      has_old_file = old_fd >= 0 && fstat(old_fd, &st) == 0 && S_ISREG(st.st_mode);
    }
  }
  unsigned long long old_size = has_old_file ? (unsigned long long)st.st_size : 0;
  void* old_data = NULL;
  if (has_old_file && old_size > 0) {
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

  bool try_delta = config->use_delta && has_old_file &&
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

  Data* file_data = receive_data(fd);
  if (file_data == NULL) {
    file_destroy(file);
    return NULL;
  }

  if (config->use_compression) {
    Data* uncompressed = data_decompress(file_data);
    data_destroy(file_data);
    if (uncompressed == NULL) {
      file_destroy(file);
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
    log_message(LOG_LEVEL_ERROR, "Invalid received file path: %s", path);
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
  Data* file_data = receive_data(file_descriptor);
  if (file_data == NULL) {
    file_destroy(file);
    return NULL;
  }
  if (config->use_compression) {
    Data* file_data_uncompressed = data_decompress(file_data);
    data_destroy(file_data);
    if (file_data_uncompressed == NULL) {
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
  int received_status = STATUS_ERROR;
  int* status_out = next_status ? next_status : &received_status;
  int count;
  if (!receive_int(fd, &count))
    return -1;
  if (count < 0 || count > MAX_MANIFEST_ENTRIES)
    return -1;
  ArrayList* manifest = array_list_create(free);
  if (!manifest)
    return -1;
  size_t manifest_bytes = 0;
  for (int i = 0; i < count; i++) {
    char* s = receive_str(fd);
    size_t entry_size = s ? strlen(s) : 0;
    if (!s || s[0] == '\0' || s[0] == '/' || has_path_traversal(s) ||
        entry_size > MAX_MANIFEST_BYTES - manifest_bytes ||
        (manifest_bytes += entry_size) > MAX_MANIFEST_BYTES || !array_list_add(manifest, s)) {
      free(s);
      array_list_delete(manifest);
      return -1;
    }
  }
  if (!receive_status(fd, status_out)) {
    array_list_delete(manifest);
    return -1;
  }
  /* Deletion is a commit operation: never perform it until the sender has
     completed the manifest frame successfully. */
  if (*status_out != STATUS_FINISHED || !config->use_delete) {
    array_list_delete(manifest);
    return *status_out == STATUS_FINISHED ? 0 : -1;
  }
  fprintf(stderr, "Deleting files not in manifest...\n");
  bool deletion_ok = delete_extras(config->receive_root_directory, manifest);
  array_list_delete(manifest);
  return deletion_ok ? 0 : -1;
}
