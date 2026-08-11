#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "compression.h"
#include "delta.h"
#include "log.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"

bool file_checksum(File* file, uint64_t* checksum) {
  if (!file || !checksum || !file->data)
    return false;
  if (file->data->size == 0) {
    *checksum = delta_xxhash64("", 0);
    return true;
  }
  if (!file->data->data && !file_load_data(file))
    return false;
  *checksum = delta_xxhash64(file->data->data, file->data->size);
  return true;
}

File* file_create(const char* path) {
  if (!path)
    return NULL;
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

  memcpy(file->path, path, path_len);
  file->path[path_len] = '\0';
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
    if (file->data->size == 0)
      return true;
    file->data->data = malloc(file->data->size);
    if (file->data->data == NULL) {
      perror("Could not allocate memory for file data");
      return false;
    }
  }
  size_t bytes_read = file_content_to_buffer(file);
  if (bytes_read != file->data->size) {
    log_message(LOG_LEVEL_ERROR, "Did not read expected amount of bytes from file");
    free(file->data->data);
    file->data->data = NULL;
    file->data->size = 0;
    return false;
  }
  return true;
}

bool file_send_single_calls(File* file, int file_descriptor, bool use_metadata,
                            int compression_level, bool send_path) {
  if (!file || !file->path || !file->data)
    return false;
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

static bool to_disk_secure(const char* path, const void* data, unsigned long long data_size,
                           bool inplace, bool sparse, const FileMetadata* metadata);
static int open_secure_parent(const char* path, char** leaf_out);
static bool rename_secure(const char* old_path, const char* new_path);
static int authorized_root_fd = -1;
static char* authorized_root_path;

void file_set_authorized_root(int fd, const char* canonical_path) {
  authorized_root_fd = fd;
  free(authorized_root_path);
  authorized_root_path = canonical_path ? str_dup(canonical_path) : NULL;
}

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
        if (!rename_secure(disk_path, backup_path)) {
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

  bool ok = to_disk_secure(disk_path, file->data->data, file->data->size, inplace, sparse,
                           file->metadata);
  free(confined_backup);
  free(confined_partial);
  free(disk_path);
  return ok;
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
  uint64_t check_checksum = 0;
  if (!receive_n_data(fd, &check_size, sizeof(check_size)) ||
      !receive_n_data(fd, &check_mtime, sizeof(check_mtime))) {
    free(check_path);
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  if (config->checksum && !receive_n_data(fd, &check_checksum, sizeof(check_checksum))) {
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
  bool has_old_file = false;
  int old_fd = -1;
  if (full_path) {
    char* leaf = NULL;
    int parent_fd = open_secure_parent(full_path, &leaf);
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
    File* delta_file = receive_delta_file(fd, config, check_path, old_data, old_size);
    old_data = NULL; /* receive_delta_file consumes the snapshot on every path */
    if (delta_file) {
      free(full_path);
      free(check_path);
      return delta_file;
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

static int open_secure_parent(const char* path, char** leaf_out) {
  char* copy = str_dup(path);
  if (!copy)
    return -1;
  char* parent = dirname(copy);
  const char* slash = strrchr(path, '/');
  char* leaf = str_dup(slash ? slash + 1 : path);
  if (!leaf) {
    free(copy);
    return -1;
  }
  int fd;
  if (authorized_root_fd >= 0 && authorized_root_path && path[0] == '/' &&
      path_is_within_root(authorized_root_path, path)) {
    fd = dup(authorized_root_fd);
    size_t root_len = strlen(authorized_root_path);
    char* relative = str_dup(path + root_len);
    if (!relative) {
      free(copy);
      free(leaf);
      close(fd);
      return -1;
    }
    free(copy);
    copy = relative;
    parent = dirname(copy);
  } else {
    fd = (parent[0] == '/') ? open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
                            : open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  }
  if (fd < 0) {
    free(copy);
    free(leaf);
    return -1;
  }
  char* save = NULL;
  char* component = strtok_r(parent, "/", &save);
  while (component) {
    if (strcmp(component, ".") != 0 && strcmp(component, "..") != 0) {
      int next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (next < 0 && errno == ENOENT && mkdirat(fd, component, 0755) == 0)
        next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (next < 0) {
        close(fd);
        free(copy);
        free(leaf);
        return -1;
      }
      close(fd);
      fd = next;
    }
    component = strtok_r(NULL, "/", &save);
  }
  free(copy);
  *leaf_out = leaf;
  return fd;
}

static bool rename_secure(const char* old_path, const char* new_path) {
  char *old_leaf = NULL, *new_leaf = NULL;
  int old_parent = open_secure_parent(old_path, &old_leaf);
  int new_parent = open_secure_parent(new_path, &new_leaf);
  bool ok = old_parent >= 0 && new_parent >= 0 &&
            renameat(old_parent, old_leaf, new_parent, new_leaf) == 0;
  if (old_parent >= 0)
    close(old_parent);
  if (new_parent >= 0)
    close(new_parent);
  free(old_leaf);
  free(new_leaf);
  return ok;
}

static bool write_all(int fd, const void* data, unsigned long long size) {
  const unsigned char* p = data;
  unsigned long long done = 0;
  while (done < size) {
    ssize_t n = write(fd, p + done, (size_t)(size - done));
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    done += (unsigned long long)n;
  }
  return true;
}

static bool to_disk_secure(const char* path, const void* data, unsigned long long data_size,
                           bool inplace, bool sparse, const FileMetadata* metadata) {
  char* leaf = NULL;
  int dirfd = open_secure_parent(path, &leaf);
  if (dirfd < 0)
    return false;
  int fd = -1;
  bool ok = false;
  if (inplace) {
    fd = openat(dirfd, leaf, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd >= 0) {
      if (!sparse || data_size == 0 || ftruncate(fd, (off_t)data_size) == 0)
        ok = write_all(fd, data, data_size);
      if (ok && metadata)
        ok = file_restore_metadata_fd(fd, metadata);
    }
  } else {
    char tmp[NAME_MAX];
    for (unsigned int i = 0; i < 100 && !ok; ++i) {
      snprintf(tmp, sizeof(tmp), ".%s.tmp.%ld.%u", leaf, (long)getpid(), i);
      fd = openat(dirfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
      if (fd < 0)
        continue;
      if (sparse && data_size > 0)
        ok = ftruncate(fd, (off_t)data_size) == 0;
      if (ok || (!sparse || data_size == 0))
        ok = write_all(fd, data, data_size);
      if (ok && metadata)
        ok = file_restore_metadata_fd(fd, metadata);
      if (close(fd) != 0)
        ok = false;
      fd = -1;
      if (ok && renameat(dirfd, tmp, dirfd, leaf) != 0)
        ok = false;
      if (!ok)
        unlinkat(dirfd, tmp, 0);
    }
  }
  if (fd >= 0)
    close(fd);
  close(dirfd);
  free(leaf);
  return ok;
}

bool to_disk(const char* path, const void* data, unsigned long long data_size, bool inplace,
             bool sparse) {
  if (!path || (!data && data_size != 0) || has_path_traversal(path))
    return false;
  return to_disk_secure(path, data, data_size, inplace, sparse, NULL);
  /* Kept below only as historical context; all writes use descriptor-relative operations. */
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

  if (inplace) {
    FILE* file_pointer = fopen(path, "wb");
    if (file_pointer == NULL) {
      perror("Could not open file for inplace write");
      ok = false;
      goto done;
    }
    if (sparse && data_size > 0) {
      if (fseek(file_pointer, data_size - 1, SEEK_SET) != 0) {
        perror("Failed to seek for sparse file");
        fclose(file_pointer);
        ok = false;
        goto done;
      }
      if (fwrite("", 1, 1, file_pointer) != 1) {
        perror("Failed to write sparse file");
        fclose(file_pointer);
        ok = false;
        goto done;
      }
      rewind(file_pointer);
    }
    if (data_size > 0 && fwrite(data, 1, data_size, file_pointer) != data_size) {
      perror("Failed to write all data to file");
      fclose(file_pointer);
      ok = false;
      goto done;
    }
    fclose(file_pointer);
    free(directory);
    return true;
  }

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
  if (sparse && data_size > 0) {
    if (fseek(file_pointer, data_size - 1, SEEK_SET) != 0) {
      perror("Failed to seek for sparse file");
      fclose(file_pointer);
      ok = false;
      goto done;
    }
    if (fwrite("", 1, 1, file_pointer) != 1) {
      perror("Failed to write sparse file");
      fclose(file_pointer);
      ok = false;
      goto done;
    }
    rewind(file_pointer);
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
  if (!file || !file->path || !file->data)
    return false;
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
  struct stat source_stat;
  if (fstat(fd, &source_stat) != 0 || !S_ISREG(source_stat.st_mode) ||
      (unsigned long long)source_stat.st_size < file_size) {
    close(fd);
    return false;
  }
  if (!send_n_data(file_descriptor, &file_size, sizeof(unsigned long long))) {
    close(fd);
    return false;
  }

  /* sendfile cannot encrypt TLS records.  Keep the framing identical but
     route encrypted transfers through the deadline-aware IO layer. */
  if (io_get_ssl() != NULL) {
    unsigned char buffer[64 * 1024];
    unsigned long long remaining = file_size;
    bool ok = true;
    while (remaining > 0) {
      size_t want = remaining > sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;
      ssize_t got = read(fd, buffer, want);
      if (got <= 0 || !send_n_data(file_descriptor, buffer, (size_t)got)) {
        ok = false;
        break;
      }
      remaining -= (unsigned long long)got;
    }
    close(fd);
    return ok;
  }

  off_t offset = 0;
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += 60;
  while ((unsigned long long)offset < file_size) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long remaining = (long long)(deadline.tv_sec - now.tv_sec) * 1000LL +
                          (deadline.tv_nsec - now.tv_nsec) / 1000000LL;
    if (remaining <= 0) {
      close(fd);
      return false;
    }
    struct pollfd pfd = {.fd = file_descriptor, .events = POLLOUT};
    int timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
    int polled = poll(&pfd, 1, timeout);
    if (polled <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
      close(fd);
      return false;
    }
    ssize_t sent = sendfile(file_descriptor, fd, &offset, file_size - offset);
    if (sent == -1) {
      if (errno == EAGAIN || errno == EINTR)
        continue;
      perror("sendfile failed");
      close(fd);
      return false;
    }
    if (sent == 0) {
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
