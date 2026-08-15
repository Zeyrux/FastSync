#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file_store.h"
#include "metadata.h"
#include "utils.h"

static int authorized_root_fd = -1;
static char* authorized_root_path;

static bool path_is_within_root(const char* root, const char* path) {
  size_t root_length = strlen(root);
  return strncmp(root, path, root_length) == 0 &&
         (path[root_length] == '\0' || path[root_length] == '/');
}

void file_store_set_authorized_root(int fd, const char* canonical_path) {
  authorized_root_fd = fd;
  free(authorized_root_path);
  authorized_root_path = canonical_path ? str_dup(canonical_path) : NULL;
}

int file_store_open_secure_parent(const char* path, char** leaf_out) {
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
    size_t root_length = strlen(authorized_root_path);
    char* relative = str_dup(path + root_length);
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

bool file_store_rename_secure(const char* old_path, const char* new_path) {
  char *old_leaf = NULL, *new_leaf = NULL;
  int old_parent = file_store_open_secure_parent(old_path, &old_leaf);
  int new_parent = file_store_open_secure_parent(new_path, &new_leaf);
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

bool file_store_write_secure(const char* path, const void* data, unsigned long long data_size,
                             bool inplace, bool sparse, const FileMetadata* metadata) {
  char* leaf = NULL;
  int dirfd = file_store_open_secure_parent(path, &leaf);
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
    int tmp_size = snprintf(NULL, 0, ".%s.tmp.%ld.%u", leaf, (long)getpid(), 99U);
    if (tmp_size < 0) {
      close(dirfd);
      free(leaf);
      return false;
    }
    char* tmp = malloc((size_t)tmp_size + 1);
    if (!tmp) {
      close(dirfd);
      free(leaf);
      return false;
    }
    for (unsigned int i = 0; i < 100 && !ok; ++i) {
      snprintf(tmp, (size_t)tmp_size + 1, ".%s.tmp.%ld.%u", leaf, (long)getpid(), i);
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
    free(tmp);
  }
  if (fd >= 0)
    close(fd);
  close(dirfd);
  free(leaf);
  return ok;
}
