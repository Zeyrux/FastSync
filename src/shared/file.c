#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdatomic.h>
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

/* Process-wide counter for scratch temp names.  A --temp-dir scratch directory
   is flat: different destinations that share a basename must never race onto
   the same temp name.  Deriving the trailing number from a global atomic
   sequence keeps every temp name unique across the whole scratch directory
   even when several threads write concurrently, so the O_EXCL creation loop
   below almost never needs a retry. */
static unsigned long long next_temp_sequence(void) {
  static atomic_ullong sequence;
  return atomic_fetch_add_explicit(&sequence, 1, memory_order_relaxed);
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
  file->send_path = NULL;
  file->data = data_create_reserve(0);
  if (file->data == NULL) {
    free(file->path);
    free(file);
    return NULL;
  }
  file->metadata = NULL;
  file->skip = false;
  file->is_dir = false;
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
  free(file->send_path);
  file->send_path = NULL;
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

/* Normalized copy of a directory path: leading '/' kept, trailing '/' removed
 * ("/" and "//" both collapse to "/").  A trailing slash otherwise makes the
 * last path component empty, so probing that empty leaf below its parent
 * always fails. */
static char* normalize_directory_path(const char* path) {
  if (!path)
    return NULL;
  size_t len = strlen(path);
  while (len > 1 && path[len - 1] == '/')
    len--;
  char* norm = malloc(len + 1);
  if (!norm)
    return NULL;
  memcpy(norm, path, len);
  norm[len] = '\0';
  return norm;
}

bool file_ensure_directory_secure(const char* path) {
  if (!path)
    return false;
  char* norm = normalize_directory_path(path);
  if (!norm)
    return false;
  /* The authorized root is already an open directory, and the filesystem root
     is always present: there is no final component left to create for them. */
  bool root_is_open =
      authorized_root_fd >= 0 && authorized_root_path && strcmp(norm, authorized_root_path) == 0;
  if (root_is_open || strcmp(norm, "/") == 0) {
    free(norm);
    return true;
  }
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(norm, &leaf, true);
  free(norm);
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

/* True when `path` resolves to an existing directory below the authorized root
 * (never creating anything). Used by the server to decide whether a client's
 * destination root already exists. A trailing slash on `path` and a destination
 * equal to the authorized root itself are normalized/handled here so both
 * previously-working destination forms keep working. */
bool file_directory_exists_secure(const char* path) {
  if (!path)
    return false;
  char* norm = normalize_directory_path(path);
  if (!norm)
    return false;
  bool root_is_open =
      authorized_root_fd >= 0 && authorized_root_path && strcmp(norm, authorized_root_path) == 0;
  if (root_is_open || strcmp(norm, "/") == 0) {
    free(norm);
    return true;
  }
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(norm, &leaf, false);
  free(norm);
  if (parent_fd < 0)
    return false;
  int dir_fd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dir_fd < 0 && errno == ENOENT)
    dir_fd = -1;
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

/* Open a private staging/scratch directory, creating it (and any missing path
   components) on demand.  dir_path is expected to already be confined below
   the authorized root by the caller; file_open_secure_parent re-checks that
   confinement and rejects `..` components, so a scratch directory can never be
   created or opened outside the destination root.  The directory itself is
   created 0700 so other users cannot race on names inside it.  Returns an
   O_DIRECTORY|O_NOFOLLOW fd, or -1 on error. */
int file_open_private_dir(const char* dir_path) {
  if (!dir_path)
    return -1;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(dir_path, &leaf, true);
  if (parent_fd < 0)
    return -1;
  int fd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0 && errno == ENOENT) {
    if (mkdirat(parent_fd, leaf, 0700) == 0 || errno == EEXIST)
      fd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  }
  close(parent_fd);
  free(leaf);
  return fd;
}

static bool file_to_disk_secure_impl(const char* path, const void* data,
                                     unsigned long long data_size, bool inplace, bool sparse,
                                     const FileMetadata* metadata, bool preserve_executability,
                                     bool update, bool no_replace, bool use_fsync,
                                     const char* temp_dir) {
  char* leaf = NULL;
  int dirfd = file_open_secure_parent(path, &leaf, true);
  if (dirfd < 0)
    return false;
  int fd = -1;
  bool ok = false;
  if (inplace) {
    /* --inplace writes directly into the destination; a scratch --temp-dir
       does not apply and must never redirect these writes. */
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
        /* In-place overwrites: pre-size sparse targets and always trim the
           file to the new payload length afterwards so shorter payloads can
           never leave stale trailing bytes from a previous version. */
        if (sparse && data_size > 0)
          ok = ftruncate(fd, (off_t)data_size) == 0;
        if (ok || !sparse || data_size == 0)
          ok = write_all(fd, data, data_size);
        if (ok)
          ok = ftruncate(fd, (off_t)data_size) == 0;
        /* Normalize the mode: apply the metadata-derived safe mode when the
           sender supplied metadata (setuid/setgid/sticky are never honored);
           otherwise fall back to a safe default so dangerous bits on an
           existing destination cannot survive an overwrite. */
        if (ok) {
          if (metadata)
            ok = file_restore_metadata_fd(fd, metadata, preserve_executability);
          else if (fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)
            ok = false;
        }
        if (ok && use_fsync)
          ok = fsync(fd) == 0;
      }
    }
  } else {
    /* The --update newer-destination check runs first so a skipped file never
       creates an empty scratch directory behind it. */
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
    /* Scratch directory for the temporary working copy.  When NULL the temp
       file is created in the destination directory, exactly as historically. */
    int scratch_dirfd = -1;
    if (temp_dir) {
      scratch_dirfd = file_open_private_dir(temp_dir);
      if (scratch_dirfd < 0) {
        int saved_errno = errno;
        log_message(LOG_LEVEL_ERROR, "could not open --temp-dir scratch directory '%s': %s",
                    temp_dir, strerror(saved_errno));
        close(dirfd);
        free(leaf);
        return false;
      }
    }
    /* Temp names can exceed NAME_MAX for basenames near the limit (leaf plus
       the ".tmp.<pid>.<n>" decoration); heap-size the buffer instead of
       truncating into a fixed array, which would silently collide in a flat
       scratch directory.  The sizing sentinel is the widest value of each
       format. */
    int tmp_size;
    if (scratch_dirfd >= 0)
      tmp_size = snprintf(NULL, 0, ".%s.tmp.%ld.%llu", leaf, (long)getpid(), ~0ULL);
    else
      tmp_size = snprintf(NULL, 0, ".%s.tmp.%ld.%u", leaf, (long)getpid(), 999U);
    if (tmp_size < 0) {
      if (scratch_dirfd >= 0)
        close(scratch_dirfd);
      close(dirfd);
      free(leaf);
      return false;
    }
    char* tmp = malloc((size_t)tmp_size + 1);
    if (!tmp) {
      if (scratch_dirfd >= 0)
        close(scratch_dirfd);
      close(dirfd);
      free(leaf);
      return false;
    }
    for (unsigned int i = 0; i < 100; ++i) {
      /* The temp name is created inside the scratch directory (when one is
         configured) and, on success, atomically renamed into the destination
         directory.  In a shared scratch directory the atomic sequence number
         keeps the name unique even for destinations with a common basename. */
      if (scratch_dirfd >= 0)
        snprintf(tmp, (size_t)tmp_size + 1, ".%s.tmp.%ld.%llu", leaf, (long)getpid(),
                 next_temp_sequence());
      else
        snprintf(tmp, (size_t)tmp_size + 1, ".%s.tmp.%ld.%u", leaf, (long)getpid(), i);
      fd = openat(scratch_dirfd >= 0 ? scratch_dirfd : dirfd, tmp,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
      if (fd < 0)
        continue; /* EEXIST (or a transient open error): try a fresh name. */
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
          if (linkat(scratch_dirfd >= 0 ? scratch_dirfd : dirfd, tmp, dirfd, leaf, 0) == 0 ||
              errno == EEXIST) {
            if (unlinkat(scratch_dirfd >= 0 ? scratch_dirfd : dirfd, tmp, 0) != 0 &&
                errno != ENOENT)
              ok = false;
          } else {
            if (scratch_dirfd >= 0 && errno == EXDEV)
              log_message(LOG_LEVEL_ERROR,
                          "temp dir is on a different filesystem than the destination; cannot "
                          "link file into place (EXDEV); no fallback copy is attempted");
            ok = false;
          }
        } else if (renameat(scratch_dirfd >= 0 ? scratch_dirfd : dirfd, tmp, dirfd, leaf) != 0) {
          if (scratch_dirfd >= 0 && errno == EXDEV)
            log_message(LOG_LEVEL_ERROR,
                        "temp dir is on a different filesystem than the destination; cannot "
                        "atomically install file (EXDEV); no fallback copy is attempted");
          ok = false;
        }
      }
      if (!ok)
        unlinkat(scratch_dirfd >= 0 ? scratch_dirfd : dirfd, tmp, 0);
      /* Once the temp fd was created the outcome is permanent: a write,
         metadata, fsync, close, linkat or renameat failure will not be fixed
         by retrying under a fresh name, so stop here.  Only the open-failure
         path above retries a new name. */
      break;
    }
    free(tmp);
    if (scratch_dirfd >= 0)
      close(scratch_dirfd);
  }
  if (fd >= 0)
    close(fd);
  close(dirfd);
  free(leaf);
  return ok;
}

bool file_to_disk_secure(const char* path, const void* data, unsigned long long data_size,
                         bool inplace, bool sparse, const FileMetadata* metadata,
                         bool preserve_executability, const char* temp_dir) {
  return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, metadata,
                                  preserve_executability, false, false, false, temp_dir);
}

bool file_to_disk_secure_update(const char* path, const void* data, unsigned long long data_size,
                                bool inplace, bool sparse, const FileMetadata* metadata,
                                bool preserve_executability, const char* temp_dir) {
  return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, metadata,
                                  preserve_executability, true, false, false, temp_dir);
}

bool file_to_disk_secure_with_fsync(const char* path, const void* data,
                                    unsigned long long data_size, bool inplace, bool sparse,
                                    const FileMetadata* metadata, bool preserve_executability,
                                    bool use_fsync, const char* temp_dir) {
  return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, metadata,
                                  preserve_executability, false, false, use_fsync, temp_dir);
}

bool file_to_disk_secure_no_replace(const char* path, const void* data,
                                    unsigned long long data_size, bool sparse,
                                    const FileMetadata* metadata, bool preserve_executability,
                                    const char* temp_dir) {
  return file_to_disk_secure_impl(path, data, data_size, false, sparse, metadata,
                                  preserve_executability, false, true, false, temp_dir);
}

bool file_write_to_disk(const char* path, const void* data, unsigned long long data_size,
                        bool inplace, bool sparse) {
  if (!path || (!data && data_size != 0) || has_path_traversal(path))
    return false;
  return file_to_disk_secure(path, data, data_size, inplace, sparse, NULL, false, NULL);
}
