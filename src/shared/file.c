#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#include "compression.h"
#include "delta.h"
#include "log.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"

File* file_create(const char* path) {
  File* file = (File*)malloc(sizeof(File));
  if (file == NULL) {
    perror("ERROR: Could not allocate memory for file struct");
    return NULL;
  }

  int path_len = strlen(path);
  file->path = (char*)malloc(path_len + 1);
  if (file->path == NULL) {
    free(file);
    return NULL;
  }

  strcpy(file->path, path);
  file->data = data_create_reserve(0);
  if (file->data == NULL) {
    free(file->path);
    free(file);
    return NULL;
  }
  file->metadata = NULL;
  file->skip = false;
  return file;
}

void file_destroy(void* item) {
  if (item == NULL)
    return;
  File* file = (File*)item;
  data_destroy(file->data);
  file->data = NULL;
  file_metadata_destroy(file->metadata);
  file->metadata = NULL;
  free(file->path);
  file->path = NULL;
  free(file);
}

FileMetadata* file_metadata_create(const struct stat* stats) {
  FileMetadata* m = malloc(sizeof(FileMetadata));
  if (m == NULL) {
    perror("ERROR: Could not allocate memory for file metadata");
    return NULL;
  }
  m->mode = stats->st_mode;
  m->uid = stats->st_uid;
  m->gid = stats->st_gid;
  m->mtime_sec = stats->st_mtime;
#ifdef __linux__
  m->mtime_nsec = stats->st_mtim.tv_nsec;
#else
  m->mtime_nsec = 0;
#endif
  return m;
}

void file_metadata_destroy(void* metadata) {
  free(metadata);
}

bool file_load_data(File* file) {
  if (file == NULL)
    return false;
  if (file->data->data == NULL) {
    file->data->data = malloc(file->data->size);
    if (file->data->data == NULL) {
      perror("Could not allocate memory for file data");
      return false;
    }
  }
  size_t bytes_read = file_content_to_buffer(file);
  if (bytes_read != file->data->size) {
    log_message(LOG_LEVEL_ERROR, "Did not read expected amount of bytes from file");
    return false;
  }
  return true;
}

bool file_send_single_calls(File* file, int file_descriptor, bool use_metadata,
                            int compression_level, bool send_path) {
  const Data* data_to_send = file->data;
  Data* compressed_data = NULL;
  if (compression_level > 0 && !compression_should_skip(file->path)) {
    compressed_data = data_compress(file->data, compression_level);
    if (compressed_data == NULL) {
      log_message(LOG_LEVEL_ERROR, "Failed to compress file data");
      return false;
    }
    data_to_send = compressed_data;
  }
  if (send_path && !send_str(file_descriptor, file->path)) {
    data_destroy(compressed_data);
    return false;
  }
  if (use_metadata && !metadata_send(file_descriptor, file->metadata)) {
    data_destroy(compressed_data);
    return false;
  }
  if (!send_data(file_descriptor, data_to_send)) {
    data_destroy(compressed_data);
    return false;
  }
  data_destroy(compressed_data);
  return true;
}

bool file_save_to_disk(const char* root_directory, File* file, const Config* config) {
  (void)config;
  if (has_path_traversal(file->path)) {
    log_message(LOG_LEVEL_ERROR, "Path traversal detected in file path: %s", file->path);
    return false;
  }
  char* disk_path = path_cat((char*)root_directory, file->path);
  if (disk_path == NULL)
    return false;
  bool ok = to_disk(disk_path, file->data->data, file->data->size);
  if (ok)
    file_restore_metadata(disk_path, file->metadata);
  free(disk_path);
  return ok;
}

static void* old_data_from_path(const char* full_path, unsigned long long old_size) {
  void* data = malloc((size_t)old_size);
  if (!data)
    return NULL;
  FILE* fp = fopen(full_path, "rb");
  if (!fp) {
    free(data);
    return NULL;
  }
  size_t nread = fread(data, 1, (size_t)old_size, fp);
  fclose(fp);
  if (nread != (size_t)old_size) {
    free(data);
    return NULL;
  }
  return data;
}

static File* receive_delta_file(int fd, const Config* config, const char* check_path,
                                void* old_data, unsigned long long old_size) {
  if (!old_data)
    return NULL;

  DeltaSignature* sig = delta_signature_create(old_data, old_size, config->delta_block_size);
  if (!sig) {
    free(old_data);
    return NULL;
  }

  Data* sig_data = delta_signature_serialize(sig);
  if (!sig_data) {
    delta_signature_destroy(sig);
    free(old_data);
    return NULL;
  }

  bool sig_sent = send_status(fd, STATUS_DELTA_SIGNATURE) && send_data(fd, sig_data);
  data_destroy(sig_data);

  if (!sig_sent) {
    delta_signature_destroy(sig);
    free(old_data);
    return NULL;
  }

  Status resp;
  if (!receive_status(fd, &resp)) {
    delta_signature_destroy(sig);
    free(old_data);
    return NULL;
  }

  if (resp == STATUS_DELTA_DATA) {
    Data* delta_data = receive_data(fd);
    if (!delta_data) {
      delta_signature_destroy(sig);
      free(old_data);
      send_status(fd, STATUS_ERROR);
      return NULL;
    }

    Data* raw_delta = delta_data;
    if (config->use_compression) {
      raw_delta = data_decompress(delta_data);
      data_destroy(delta_data);
      if (!raw_delta) {
        free(old_data);
        delta_signature_destroy(sig);
        send_status(fd, STATUS_ERROR);
        return NULL;
      }
    }

    Delta* delta = delta_deserialize(raw_delta);
    data_destroy(raw_delta);
    if (!delta) {
      free(old_data);
      delta_signature_destroy(sig);
      send_status(fd, STATUS_ERROR);
      return NULL;
    }

    void* new_data = delta_apply(old_data, old_size, delta, config->delta_block_size);
    uint64_t new_size = delta->new_file_size;
    delta_destroy(delta);

    if (!new_data) {
      free(old_data);
      delta_signature_destroy(sig);
      send_status(fd, STATUS_ERROR);
      return NULL;
    }

    File* file = file_create(check_path);
    if (!file) {
      free(new_data);
      free(old_data);
      delta_signature_destroy(sig);
      send_status(fd, STATUS_ERROR);
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
        send_status(fd, STATUS_ERROR);
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
      send_status(fd, STATUS_ERROR);
      return NULL;
    }

    if (config->use_metadata) {
      int meta_ok = 1;
      file->metadata = metadata_receive(fd, &meta_ok);
      if (!meta_ok) {
        file_destroy(file);
        send_status(fd, STATUS_ERROR);
        return NULL;
      }
    }

    Data* file_data = receive_data(fd);
    if (file_data == NULL) {
      file_destroy(file);
      send_status(fd, STATUS_ERROR);
      return NULL;
    }

    if (config->use_compression) {
      Data* uncompressed = data_decompress(file_data);
      data_destroy(file_data);
      if (uncompressed == NULL) {
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
  return NULL;
}

File* receive_incremental_check(int fd, const Config* config, bool* skipped) {
  *skipped = false;
  char* check_path = receive_str(fd);
  if (check_path == NULL) {
    send_status(fd, STATUS_ERROR);
    return NULL;
  }

  unsigned long long check_size;
  long long check_mtime;
  if (!receive_n_data(fd, &check_size, sizeof(check_size)) ||
      !receive_n_data(fd, &check_mtime, sizeof(check_mtime))) {
    free(check_path);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }

  if (has_path_traversal(check_path)) {
    log_message(LOG_LEVEL_ERROR, "Path traversal detected: %s", check_path);
    free(check_path);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }

  char* full_path = path_cat(config->receive_root_directory, check_path);
  struct stat st;
  bool has_old_file = (full_path && stat(full_path, &st) == 0);
  unsigned long long old_size = has_old_file ? (unsigned long long)st.st_size : 0;

  bool match = has_old_file && (unsigned long long)st.st_size == check_size &&
               (long long)st.st_mtime == check_mtime;

  if (match) {
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
    void* old_data = old_data_from_path(full_path, old_size);
    File* delta_file = receive_delta_file(fd, config, check_path, old_data, old_size);
    if (delta_file) {
      free(full_path);
      free(check_path);
      return delta_file;
    }
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
    send_status(fd, STATUS_ERROR);
    return NULL;
  }

  if (config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(fd, &meta_ok);
    if (!meta_ok) {
      file_destroy(file);
      send_status(fd, STATUS_ERROR);
      return NULL;
    }
  }

  Data* file_data = receive_data(fd);
  if (file_data == NULL) {
    file_destroy(file);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }

  if (config->use_compression) {
    Data* uncompressed = data_decompress(file_data);
    data_destroy(file_data);
    if (uncompressed == NULL) {
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

bool to_disk(const char* path, const void* data, unsigned long long data_size) {
  char* tmp_path = NULL;
  char* directory = NULL;

  char* path_dup = str_dup(path);
  if (!path_dup)
    return false;
  const char* dir_result = dirname(path_dup);
  directory = str_dup(dir_result);
  free(path_dup);
  if (!directory)
    return false;

  bool ok = true;
  if (!mkdir_r(directory))
    goto done;

  size_t path_len = strlen(path);
  tmp_path = malloc(path_len + 5);
  if (!tmp_path) {
    ok = false;
    goto done;
  }
  memcpy(tmp_path, path, path_len);
  memcpy(tmp_path + path_len, ".tmp", 5);

  FILE* file_pointer = fopen(tmp_path, "wb");
  if (file_pointer == NULL) {
    perror("Could not open temporary file");
    ok = false;
    goto done;
  }
  if (fwrite(data, 1, data_size, file_pointer) != data_size) {
    perror("Failed to write all data to temporary file");
    fclose(file_pointer);
    unlink(tmp_path);
    ok = false;
    goto done;
  }
  fclose(file_pointer);

  if (rename(tmp_path, path) != 0) {
    perror("Failed to atomically rename temporary file");
    unlink(tmp_path);
    ok = false;
    goto done;
  }

done:
  free(tmp_path);
  free(directory);
  return ok;
}

bool file_send_sendfile(File* file, int file_descriptor, bool use_metadata, int compression_level,
                        bool send_path) {
  // sendfile is incompatible with compression (kernel zero-copy).
  // If compression is requested, fall back to the regular send path.
  // NOTE: This is a safety net only — callers must ensure compression_level == 0
  // before calling file_send_sendfile. The fallback to file_send_single_calls
  // preserves the send_path contract, but callers should not rely on it for
  // correctness (the --sendfile flag is validated to be mutually exclusive with
  // -c/--compress at the CLI layer).
  if (compression_level > 0)
    return file_send_single_calls(file, file_descriptor, use_metadata, compression_level,
                                  send_path);

  if (send_path && !send_str(file_descriptor, file->path))
    return false;
  if (use_metadata && !metadata_send(file_descriptor, file->metadata))
    return false;

  int fd = open(file->path, O_RDONLY);
  if (fd == -1) {
    perror("Could not open file for sendfile");
    return false;
  }

  unsigned long long file_size = file->data->size;
  if (!send_n_data(file_descriptor, &file_size, sizeof(unsigned long long))) {
    close(fd);
    return false;
  }

  off_t offset = 0;
  while ((unsigned long long)offset < file_size) {
    ssize_t sent = sendfile(file_descriptor, fd, &offset, file_size - offset);
    if (sent == -1) {
      if (errno == EAGAIN || errno == EINTR)
        continue;
      perror("sendfile failed");
      close(fd);
      return false;
    }
  }

  close(fd);
  return true;
}

File* file_receive(const Config* config, int file_descriptor) {
  char* path = receive_str(file_descriptor);
  if (path == NULL)
    return NULL;
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

size_t file_content_to_buffer(File* file) {
  FILE* file_pointer = fopen(file->path, "rb");
  if (file_pointer == NULL) {
    perror("Could not open the file!");
    return 0;
  }
  size_t bytes_read = fread(file->data->data, 1, file->data->size, file_pointer);
  if (bytes_read != (size_t)file->data->size) {
    fclose(file_pointer);
    perror("Read unexpected number of bytes from File!");
    return 0;
  }
  fclose(file_pointer);
  return bytes_read;
}

int receive_manifest(int fd, const Config* config, int* next_status) {
  int count;
  if (!receive_int(fd, &count))
    return -1;
  ArrayList* manifest = array_list_create(free);
  if (manifest) {
    for (int i = 0; i < count; i++) {
      char* s = receive_str(fd);
      if (s)
        array_list_add(manifest, s);
    }
    fprintf(stderr, "Deleting files not in manifest...\n");
    delete_extras(config->receive_root_directory, manifest);
    array_list_delete(manifest);
  }
  if (!receive_status(fd, next_status))
    return -1;
  return 0;
}
