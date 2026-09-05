#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "data.h"
#include "delta.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "utils.h"
#include "protocol.h"

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
  File* file = (File*)protocol_alloc(sizeof(File));
  if (file == NULL) {
    log_perror("ERROR: Could not allocate memory for file struct");
    return NULL;
  }

  size_t path_len = strlen(path);
  file->path = (char*)protocol_alloc(path_len + 1);
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
  FileMetadata* m = protocol_alloc(sizeof(FileMetadata));
  if (m == NULL) {
    log_perror("ERROR: Could not allocate memory for file metadata");
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
  if (file == NULL || !file->data)
    return false;
  if (file->data->data == NULL) {
    if (file->data->size == 0)
      return true;
    file->data->data = protocol_alloc(file->data->size);
    if (file->data->data == NULL) {
      log_perror("Could not allocate memory for file data");
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

size_t file_content_to_buffer(File* file) {
  if (!file || !file->path || !file->data || (!file->data->data && file->data->size != 0))
    return 0;
  FILE* file_pointer = fopen(file->path, "rb");
  if (file_pointer == NULL) {
    log_perror("Could not open the file!");
    return 0;
  }
  size_t bytes_read = fread(file->data->data, 1, file->data->size, file_pointer);
  if (bytes_read != (size_t)file->data->size) {
    fclose(file_pointer);
    log_perror("Read unexpected number of bytes from File!");
    return 0;
  }
  fclose(file_pointer);
  return bytes_read;
}

/* ---- Secure filesystem primitives ---- */

static int authorized_root_fd = -1;
static char* authorized_root_path;

static bool path_is_within_root(const char* root, const char* path) {
  size_t root_len = strlen(root);
  return strncmp(root, path, root_len) == 0 && (path[root_len] == '\0' || path[root_len] == '/');
}

bool file_set_authorized_root(int fd, const char* canonical_path) {
  char* path_copy = canonical_path ? str_dup(canonical_path) : NULL;
  if (canonical_path && !path_copy) {
    authorized_root_fd = -1;
    free(authorized_root_path);
    authorized_root_path = NULL;
    return false;
  }
  authorized_root_fd = fd;
  free(authorized_root_path);
  authorized_root_path = path_copy;
  return true;
}

bool file_path_exists_secure(const char* path) {
  if (!path)
    return false;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(path, &leaf, false);
  if (parent_fd < 0)
    return false;
  struct stat st;
  bool exists = fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0;
  close(parent_fd);
  free(leaf);
  return exists;
}

bool file_stat_secure(const char* path, struct stat* st) {
  if (!path || !st)
    return false;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(path, &leaf, false);
  if (parent_fd < 0)
    return false;
  bool exists = fstatat(parent_fd, leaf, st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st->st_mode);
  close(parent_fd);
  free(leaf);
  return exists;
}

static bool stat_is_newer(const struct stat* st, const FileMetadata* metadata) {
  if (!st || !metadata)
    return false;
#ifdef __linux__
  long mtime_nsec = st->st_mtim.tv_nsec;
#else
  long mtime_nsec = 0;
#endif
  return st->st_mtime > metadata->mtime_sec ||
         (st->st_mtime == metadata->mtime_sec && mtime_nsec > metadata->mtime_nsec);
}

bool file_destination_is_newer_secure(const char* path, const FileMetadata* metadata) {
  struct stat st;
  return file_stat_secure(path, &st) && stat_is_newer(&st, metadata);
}

int file_open_secure_parent(const char* path, char** leaf_out, bool create_dirs) {
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
  if (authorized_root_fd >= 0) {
    if (!authorized_root_path || path[0] != '/' ||
        !path_is_within_root(authorized_root_path, path)) {
      free(copy);
      free(leaf);
      return -1;
    }
    fd = dup(authorized_root_fd);
    if (fd < 0) {
      free(copy);
      free(leaf);
      return -1;
    }
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
    if (strcmp(component, "..") == 0) {
      close(fd);
      free(copy);
      free(leaf);
      return -1;
    }
    if (strcmp(component, ".") != 0) {
      int next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (create_dirs && next < 0 && errno == ENOENT) {
        if (mkdirat(fd, component, 0755) == 0 || errno == EEXIST)
          next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      }
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

bool file_ensure_directory_secure(const char* path) {
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(path, &leaf, true);
  if (parent_fd < 0)
    return false;

  int dir_fd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dir_fd < 0 && errno == ENOENT) {
    if (mkdirat(parent_fd, leaf, 0755) == 0 || errno == EEXIST)
      dir_fd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  }
  bool ok = dir_fd >= 0;
  if (dir_fd >= 0)
    close(dir_fd);
  close(parent_fd);
  free(leaf);
  return ok;
}

bool file_rename_secure(const char* old_path, const char* new_path) {
  char *old_leaf = NULL, *new_leaf = NULL;
  int old_parent = file_open_secure_parent(old_path, &old_leaf, false);
  int new_parent = file_open_secure_parent(new_path, &new_leaf, true);
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

static bool file_to_disk_secure_impl(const char* path, const void* data,
                                     unsigned long long data_size, bool inplace, bool sparse,
                                     const FileMetadata* metadata, bool preserve_executability,
                                     bool update, bool no_replace, bool use_fsync) {
  char* leaf = NULL;
  int dirfd = file_open_secure_parent(path, &leaf, true);
  if (dirfd < 0)
    return false;
  int fd = -1;
  bool ok = false;
  if (inplace) {
    fd = openat(dirfd, leaf, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd >= 0) {
      struct stat destination_stat;
      bool newer = false;
      if (update && metadata && fstat(fd, &destination_stat) == 0 &&
          S_ISREG(destination_stat.st_mode)) {
        newer = stat_is_newer(&destination_stat, metadata);
      }
      if (newer) {
        ok = true;
      } else {
        if (!sparse || data_size == 0 || ftruncate(fd, (off_t)data_size) == 0)
          ok = write_all(fd, data, data_size);
        if (ok && metadata)
          ok = file_restore_metadata_fd(fd, metadata, preserve_executability);
        if (ok && use_fsync)
          ok = fsync(fd) == 0;
      }
    }
  } else {
    char tmp[NAME_MAX];
    if (update && metadata) {
      /* This check protects the normal atomic path as far as possible.  A
         concurrent replacement can still occur before the final rename. */
      struct stat destination_stat;
      if (fstatat(dirfd, leaf, &destination_stat, AT_SYMLINK_NOFOLLOW) == 0 &&
          S_ISREG(destination_stat.st_mode) && stat_is_newer(&destination_stat, metadata)) {
        close(dirfd);
        free(leaf);
        return true;
      }
    }
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
        ok = file_restore_metadata_fd(fd, metadata, preserve_executability);
      if (ok && use_fsync)
        ok = fsync(fd) == 0;
      if (close(fd) != 0)
        ok = false;
      fd = -1;
      if (ok) {
        if (no_replace) {
          /* The probe and commit cannot be one operation. A concurrent
             creator may win; EEXIST is then the requested skip. */
          if (linkat(dirfd, tmp, dirfd, leaf, 0) == 0 || errno == EEXIST) {
            if (unlinkat(dirfd, tmp, 0) != 0 && errno != ENOENT)
              ok = false;
          } else {
            ok = false;
          }
        } else if (renameat(dirfd, tmp, dirfd, leaf) != 0) {
          ok = false;
        }
      }
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

bool file_to_disk_secure(const char* path, const void* data, unsigned long long data_size,
                         bool inplace, bool sparse, const FileMetadata* metadata,
                         bool preserve_executability) {
  return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, metadata,
                                   preserve_executability, false, false, false);
}

bool file_to_disk_secure_update(const char* path, const void* data, unsigned long long data_size,
                                bool inplace, bool sparse, const FileMetadata* metadata,
                                bool preserve_executability) {
  return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, metadata,
                                   preserve_executability, true, false, false);
}

bool file_to_disk_secure_with_fsync(const char* path, const void* data,
                                    unsigned long long data_size, bool inplace, bool sparse,
                                    const FileMetadata* metadata, bool preserve_executability,
                                    bool use_fsync) {
  return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, metadata,
                                   preserve_executability, false, false, use_fsync);
}

bool file_to_disk_secure_no_replace(const char* path, const void* data,
                                    unsigned long long data_size, bool sparse,
                                    const FileMetadata* metadata, bool preserve_executability) {
  return file_to_disk_secure_impl(path, data, data_size, false, sparse, metadata,
                                   preserve_executability, false, true, false);
}

bool file_write_to_disk(const char* path, const void* data, unsigned long long data_size,
                        bool inplace, bool sparse) {
  if (!path || (!data && data_size != 0) || has_path_traversal(path))
    return false;
  return file_to_disk_secure(path, data, data_size, inplace, sparse, NULL, false);
}
