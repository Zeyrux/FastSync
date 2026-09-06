#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "array_list.h"
#include "chmod.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delay_updates.h"
#include "delta.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"

#define MAX_SERVER_DELETE_COUNT 100000U
#define MAX_FILE_DATA_SIZE MAX_RECEIVE_WHOLE_FILE_SIZE

bool file_save_to_disk(const char* root_directory, const File* file, const Config* config) {
  return file_save_to_disk_full(root_directory, file, config) != FILE_SAVE_ERROR;
}

/* --delay-updates receiver path: write the file into a private staging tree
   below the receive root instead of its final destination, and remember it so
   it can be atomically renamed into place only once the whole transfer has
   succeeded.  Existence/update policies (--existing/--ignore-existing/--update)
   are decided against the FINAL destination path at stage time so the run
   decides exactly what an immediate (non-delayed) run would decide; the staged
   file is then never re-checked at publication.  Backups are deferred to
   publication so the final destination is untouched until the transfer ends. */
static FileSaveResult file_stage_delayed_update(const char* root_directory,
                                                const char* destination_path, const File* file,
                                                Config* config) {
  if (!config)
    return FILE_SAVE_ERROR;
  bool sparse = config->preserve_sparse;
  bool preserve_executability = config->use_executability;

  if (config->existing && !file_path_exists_secure(destination_path))
    return FILE_SAVE_SKIPPED;
  if (config->ignore_existing && file_path_exists_secure(destination_path))
    return FILE_SAVE_SKIPPED;
  if (config->update && file_destination_is_newer_secure(destination_path, file->metadata))
    return FILE_SAVE_SKIPPED;

  FileMetadata adjusted_metadata;
  const FileMetadata* metadata = file->metadata;
  if (metadata && config->chmod_spec && *config->chmod_spec) {
    adjusted_metadata = *metadata;
    if (!chmod_apply(adjusted_metadata.mode, config->chmod_spec, &adjusted_metadata.mode))
      return FILE_SAVE_ERROR;
    metadata = &adjusted_metadata;
  }

  if (!config->delay_context) {
    config->delay_context = delay_updates_context_create(root_directory);
    if (!config->delay_context)
      return FILE_SAVE_ERROR;
  }
  DelayUpdatesContext* context = config->delay_context;
  if (!delay_updates_prepare(context))
    return FILE_SAVE_ERROR;

  char* staged_path = path_cat(context->staging_root, file->path);
  if (!staged_path)
    return FILE_SAVE_ERROR;

  /* The staged location is brand new (stale leftovers from a prior crash were
     wiped by prepare), so the plain atomic temp+rename engine installs the
     complete file there.  --temp-dir scratch is deliberately not layered on
     top of the delay-updates staging tree. */
  bool ok =
      file_to_disk_secure_with_fsync(staged_path, file->data->data, file->data->size, false, sparse,
                                     metadata, preserve_executability, config->use_fsync, NULL);
  if (!ok) {
    free(staged_path);
    return FILE_SAVE_ERROR;
  }

  if (!delay_updates_record(context, staged_path, destination_path, file->path)) {
    unlink(staged_path);
    free(staged_path);
    return FILE_SAVE_ERROR;
  }
  free(staged_path);
  return FILE_SAVE_WRITTEN;
}

FileSaveResult file_save_to_disk_full(const char* root_directory, const File* file,
                                      const Config* config) {
  /* Backups are incompatible with ignore-existing: moving the entry first
     would make a concurrent no-replace commit overwrite its old name. */
  bool backup_enabled = config && config->backup && !config->ignore_existing;
  bool inplace = config && config->inplace;
  bool sparse = config && config->preserve_sparse;
  bool preserve_executability = config && config->use_executability;
  const char* backup_suffix = (config && config->suffix) ? config->suffix : "~";
  const char* backup_dir = (config && config->backup_dir) ? config->backup_dir : NULL;
  const char* partial_dir = (config && config->partial_dir) ? config->partial_dir : NULL;
  const char* temp_dir = (config && config->temp_dir) ? config->temp_dir : NULL;
  bool use_partial_root = partial_dir && config && config->partial;
  char *confined_backup = NULL, *confined_partial = NULL, *disk_path = NULL;
  char* destination_path = NULL;
  char *backup_path = NULL, *parent_copy = NULL;

  if (!file || !file->path || !file->data || (file->data->size != 0 && !file->data->data) ||
      has_path_traversal(file->path) ||
      (backup_enabled &&
       (!backup_suffix || backup_suffix[0] == '\0' || strchr(backup_suffix, '/') != NULL ||
        strcmp(backup_suffix, ".") == 0 || strcmp(backup_suffix, "..") == 0))) {
    log_message(LOG_LEVEL_ERROR, "Invalid file or path received");
    return FILE_SAVE_ERROR;
  }

  /* These options arrive from the client.  They are names below the server
     root, never independent filesystem roots.  --temp-dir is confined exactly
     like --backup-dir/--partial-dir: an absolute or `..`-escaping scratch
     directory is rejected outright so nothing is ever created outside the
     authorized destination root. */
  if ((backup_dir && (backup_dir[0] == '/' || has_path_traversal(backup_dir))) ||
      (partial_dir && (partial_dir[0] == '/' || has_path_traversal(partial_dir))) ||
      (temp_dir && (temp_dir[0] == '/' || has_path_traversal(temp_dir))))
    return FILE_SAVE_ERROR;
  if (backup_dir && !(confined_backup = path_cat(root_directory, backup_dir)))
    return FILE_SAVE_ERROR;
  if (partial_dir && !(confined_partial = path_cat(root_directory, partial_dir))) {
    free(confined_backup);
    return FILE_SAVE_ERROR;
  }

  const char* actual_root = use_partial_root ? confined_partial : root_directory;
  destination_path = path_cat(root_directory, file->path);
  disk_path = path_cat(actual_root, file->path);
  if (destination_path == NULL || disk_path == NULL) {
    free(confined_backup);
    free(confined_partial);
    free(destination_path);
    free(disk_path);
    return FILE_SAVE_ERROR;
  }

  /* --delay-updates diverts the whole write into the staging tree; the rest of
     this function is the immediate-install path. */
  if (config && config->delay_updates) {
    FileSaveResult result =
        file_stage_delayed_update(root_directory, destination_path, file, (Config*)config);
    free(confined_backup);
    free(confined_partial);
    free(destination_path);
    free(disk_path);
    return result;
  }

  /* --existing checks the final destination, not a temporary partial path. */
  if (config && config->existing && !file_path_exists_secure(destination_path)) {
    free(confined_backup);
    free(confined_partial);
    free(destination_path);
    free(disk_path);
    return FILE_SAVE_SKIPPED;
  }

  /* --ignore-existing checks the final destination before partial files or
     overwrite policies can modify it. */
  if (config && config->ignore_existing) {
    bool exists = file_path_exists_secure(destination_path);
    if (exists) {
      free(confined_backup);
      free(confined_partial);
      free(destination_path);
      free(disk_path);
      return FILE_SAVE_SKIPPED;
    }
  }

  /* --update is receiver-side policy: never replace a newer destination.
     In partial-dir mode the entry that would be replaced is the real
     destination, not the temporary partial file.  The secure stat does not
     require read permission on the destination. */
  const char* update_target = use_partial_root ? destination_path : disk_path;
  if (config && config->update && file_destination_is_newer_secure(update_target, file->metadata)) {
    free(confined_backup);
    free(confined_partial);
    free(destination_path);
    free(disk_path);
    return FILE_SAVE_SKIPPED;
  }

  if (backup_enabled) {
    /* Back up the entry that the incoming write will replace.  When writing
       through a partial dir the pre-existing destination file is the one to
       preserve; any stale partial file is overwritten without a backup. */
    const char* replace_target = use_partial_root ? destination_path : disk_path;
    struct stat backup_stat;
    if (file_stat_secure(replace_target, &backup_stat)) {
      if (backup_dir) {
        backup_path = path_cat(confined_backup, file->path);
      } else {
        size_t path_len = strlen(replace_target);
        size_t suffix_len = strlen(backup_suffix);
        if (path_len > SIZE_MAX - suffix_len - 1)
          goto fail;
        backup_path = malloc(path_len + suffix_len + 1);
        if (backup_path) {
          memcpy(backup_path, replace_target, path_len);
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
      if (!file_rename_secure(replace_target, backup_path))
        goto fail;
      free(backup_path);
      backup_path = NULL;
    }
  }

  FileMetadata adjusted_metadata;
  const FileMetadata* metadata = file->metadata;
  if (metadata && config && config->chmod_spec && *config->chmod_spec) {
    adjusted_metadata = *metadata;
    if (!chmod_apply(adjusted_metadata.mode, config->chmod_spec, &adjusted_metadata.mode))
      goto fail;
    metadata = &adjusted_metadata;
  }

  /* A configured --temp-dir sends the temporary working copy to a scratch
     directory resolved below the receive root; the engine then atomically
     renames the completed file into the final destination directory.  The
     partial-dir flow already keeps its working copy in a separate directory
     and --inplace writes directly, so neither diverts through the scratch
     dir (matching rsync, where --inplace/--partial-dir supersede --temp-dir). */
  char* confined_temp = NULL;
  bool use_temp_dir = temp_dir != NULL && !inplace && !use_partial_root;
  if (use_temp_dir) {
    confined_temp = path_cat(root_directory, temp_dir);
    if (!confined_temp)
      goto fail;
    /* A user-supplied trailing slash would leave the scratch path ending in
       "/", which has no final component to create/open.  Normalize it away. */
    size_t temp_len = strlen(confined_temp);
    while (temp_len > 1 && confined_temp[temp_len - 1] == '/')
      confined_temp[--temp_len] = '\0';
  }
  bool ok =
      config && config->ignore_existing
          ? file_to_disk_secure_no_replace(disk_path, file->data->data, file->data->size, sparse,
                                           metadata, preserve_executability, confined_temp)
      : config && config->update
          ? file_to_disk_secure_update(disk_path, file->data->data, file->data->size, inplace,
                                       sparse, metadata, preserve_executability, confined_temp)
          : file_to_disk_secure_with_fsync(disk_path, file->data->data, file->data->size, inplace,
                                           sparse, metadata, preserve_executability,
                                           config && config->use_fsync, confined_temp);
  free(confined_temp);
  confined_temp = NULL;
  if (!ok)
    goto fail;

  /* --partial --partial-dir writes the complete file under the partial dir so
     interrupted transfers leave a resumable copy there.  Once the file is
     fully written it must be atomically installed at the real destination;
     otherwise completed transfers would linger under the partial dir. */
  if (use_partial_root) {
    if (!file_rename_secure(disk_path, destination_path))
      goto fail;
  }

  free(parent_copy);
  free(backup_path);
  free(confined_backup);
  free(confined_partial);
  free(destination_path);
  free(disk_path);
  return FILE_SAVE_WRITTEN;

fail:
  free(parent_copy);
  free(backup_path);
  free(confined_backup);
  free(confined_partial);
  free(destination_path);
  free(disk_path);
  return FILE_SAVE_ERROR;
}

static File* receive_delta_file(int fd, const Config* config, const char* check_path,
                                void* old_data, unsigned long long old_size, bool* failed) {
  if (!old_data) {
    *failed = true;
    return NULL;
  }

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
    Data* delta_data = receive_data_limited(fd, MAX_RECEIVE_WHOLE_FILE_SIZE);
    if (!delta_data) {
      delta_signature_destroy(sig);
      free(old_data);
      *failed = true;
      return NULL;
    }

    Data* raw_delta = delta_data;
    if (config->use_compression &&
        !compression_should_skip_with_suffixes(
            check_path, config->skip_compress_suffixes,
            config->skip_compress_set ? config->skip_compress_count : -1)) {
      raw_delta = data_decompress_limited(delta_data, MAX_RECEIVE_WHOLE_FILE_SIZE);
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
    if (new_size > MAX_RECEIVE_WHOLE_FILE_SIZE || new_size > SIZE_MAX) {
      delta_destroy(delta);
      free(old_data);
      delta_signature_destroy(sig);
      send_status(fd, STATUS_ERROR);
      *failed = true;
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
      *failed = true;
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

    Data* file_data = receive_data_limited(fd, MAX_RECEIVE_WHOLE_FILE_SIZE);
    if (file_data == NULL) {
      file_destroy(file);
      *failed = true;
      return NULL;
    }

    if (config->use_compression &&
        !compression_should_skip_with_suffixes(
            file->path, config->skip_compress_suffixes,
            config->skip_compress_set ? config->skip_compress_count : -1)) {
      Data* uncompressed = data_decompress_limited(file_data, MAX_RECEIVE_WHOLE_FILE_SIZE);
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
  long long check_mtime_nsec;
  uint64_t check_checksum = 0;
  if (!receive_n_data(fd, &check_size, sizeof(check_size)) ||
      !receive_n_data(fd, &check_mtime, sizeof(check_mtime))) {
    free(check_path);
    return NULL;
  }
  if (!receive_n_data(fd, &check_mtime_nsec, sizeof(check_mtime_nsec)) || check_mtime_nsec < 0 ||
      check_mtime_nsec >= 1000000000LL) {
    free(check_path);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  if (config->checksum && !receive_n_data(fd, &check_checksum, sizeof(check_checksum))) {
    free(check_path);
    return NULL;
  }

  if (check_size > MAX_RECEIVE_WHOLE_FILE_SIZE) {
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

  /* Open the existing destination entry (if any) once and keep the descriptor
     until the quick-check below decides whether the old contents are needed. */
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
  if (!has_old_file && old_fd >= 0) {
    close(old_fd);
    old_fd = -1;
  }
  unsigned long long old_size = has_old_file ? (unsigned long long)st.st_size : 0;

  /* Decide from metadata alone whether the receiver already holds the file
     the sender is offering.  The old contents are only read into memory when
     a checksum comparison or a delta transfer actually requires them. */
  bool size_equal = has_old_file && old_size == check_size;
  bool match_by_metadata = false;
  if (size_equal && !config->ignore_times && !config->size_only) {
    long long old_mtime_nsec = 0;
#ifdef __linux__
    old_mtime_nsec = st.st_mtim.tv_nsec;
#endif
    match_by_metadata = metadata_mtime_matches(st.st_mtime, old_mtime_nsec, (time_t)check_mtime,
                                               (long)check_mtime_nsec, config->modify_window);
  }

  bool try_delta = config->use_delta && !config->whole_file && has_old_file &&
                   delta_should_attempt(old_size, check_size, config->delta_max_file_size);
  bool checksum_needs_read = size_equal && !config->ignore_times && config->checksum;
  bool need_old_data = checksum_needs_read || try_delta;

  void* old_data = NULL;
  if (need_old_data && has_old_file && old_size > 0 && old_size <= MAX_RECEIVE_WHOLE_FILE_SIZE &&
      old_size <= SIZE_MAX) {
    old_data = protocol_alloc((size_t)old_size);
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

  /* Quick-skip decision.  If no content comparison is required this is final
     and the old file was never read; if the read failed the file is not
     skipped and the transfer proceeds with the full new contents. */
  bool match = false;
  if (checksum_needs_read) {
    if (old_size == 0)
      match = delta_xxhash64("", 0) == check_checksum;
    else
      match = old_data != NULL && delta_xxhash64(old_data, (size_t)old_size) == check_checksum;
  } else if (size_equal && !config->ignore_times) {
    match = config->size_only || match_by_metadata;
  }

  if (match) {
    free(old_data);
    if (!send_status(fd, STATUS_OK)) {
      close(old_fd);
      free(full_path);
      free(check_path);
      return NULL;
    }
    close(old_fd);
    free(full_path);
    free(check_path);
    *skipped = true;
    return NULL;
  }

  if (try_delta && old_data != NULL) {
    bool delta_failed = false;
    File* delta_file =
        receive_delta_file(fd, config, check_path, old_data, old_size, &delta_failed);
    old_data = NULL; /* receive_delta_file consumes the snapshot on every path */
    if (delta_file) {
      close(old_fd);
      free(full_path);
      free(check_path);
      return delta_file;
    }
    if (delta_failed) {
      close(old_fd);
      free(full_path);
      free(check_path);
      return NULL;
    }
  }
  free(old_data);
  old_data = NULL;

  if (!send_status(fd, STATUS_NEXT)) {
    close(old_fd);
    free(full_path);
    free(check_path);
    return NULL;
  }
  close(old_fd);

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

  Data* file_data = receive_data_limited(fd, MAX_RECEIVE_WHOLE_FILE_SIZE);
  if (file_data == NULL) {
    file_destroy(file);
    return NULL;
  }

  if (config->use_compression &&
      !compression_should_skip_with_suffixes(file->path, config->skip_compress_suffixes,
                                             config->skip_compress_set ? config->skip_compress_count
                                                                       : -1)) {
    Data* uncompressed = data_decompress_limited(file_data, MAX_RECEIVE_WHOLE_FILE_SIZE);
    data_destroy(file_data);
    if (uncompressed == NULL) {
      file_destroy(file);
      return NULL;
    }
    if (uncompressed->size > MAX_FILE_DATA_SIZE) {
      data_destroy(uncompressed);
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
  Data* file_data = receive_data_limited(file_descriptor, MAX_RECEIVE_WHOLE_FILE_SIZE);
  if (file_data == NULL) {
    file_destroy(file);
    return NULL;
  }
  if (config->use_compression &&
      !compression_should_skip_with_suffixes(file->path, config->skip_compress_suffixes,
                                             config->skip_compress_set ? config->skip_compress_count
                                                                       : -1)) {
    Data* file_data_uncompressed = data_decompress_limited(file_data, MAX_RECEIVE_WHOLE_FILE_SIZE);
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
  /* With --delay-updates the staged (not yet published) files live directly
     under the receive root in the staging directory; the delete walker must
     not treat them as extras or it would remove every staged file before it
     can be published. */
  const char* skip_staging = config->delay_updates ? DELAY_UPDATES_STAGING_DIR : NULL;
  bool deletion_ok = delete_extras_limited(config->receive_root_directory, manifest,
                                           MAX_SERVER_DELETE_COUNT, skip_staging);
  array_list_delete(manifest);
  if (!deletion_ok)
    send_status(fd, STATUS_ERROR);
  return deletion_ok ? 0 : -1;
}
