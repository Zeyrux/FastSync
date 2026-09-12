#include "utils.h"
#include "array_list.h"
#include "log.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int authorized_root_fd = -1;
static char* authorized_root_path;

bool utils_set_authorized_root(int fd, const char* canonical_path) {
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

void utils_set_authorized_root_fd(int fd) {
  (void)utils_set_authorized_root(fd, NULL);
}

static bool path_is_within_root(const char* root, const char* path) {
  size_t root_len = strlen(root);
  return strncmp(root, path, root_len) == 0 && (path[root_len] == '\0' || path[root_len] == '/');
}

static int open_authorized_destination(const char* dest_root) {
  if (authorized_root_fd < 0 || !authorized_root_path || !dest_root ||
      !path_is_within_root(authorized_root_path, dest_root))
    return -1;

  int dirfd = dup(authorized_root_fd);
  if (dirfd < 0)
    return -1;

  const char* relative_path = dest_root + strlen(authorized_root_path);
  while (*relative_path == '/')
    relative_path++;
  char* relative = str_dup(*relative_path ? relative_path : ".");
  if (!relative) {
    close(dirfd);
    return -1;
  }

  char* saveptr = NULL;
  char* component = strtok_r(relative, "/", &saveptr);
  while (component) {
    if (strcmp(component, "..") == 0) {
      free(relative);
      close(dirfd);
      return -1;
    }
    if (strcmp(component, ".") == 0) {
      component = strtok_r(NULL, "/", &saveptr);
      continue;
    }
    int next = openat(dirfd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0) {
      free(relative);
      close(dirfd);
      return -1;
    }
    close(dirfd);
    dirfd = next;
    component = strtok_r(NULL, "/", &saveptr);
  }

  free(relative);
  return dirfd;
}

char* str_dup(const char* string) {
  if (string == NULL)
    return NULL;
  size_t str_len = strlen(string);
  char* new_string = (char*)malloc(str_len + 1);
  if (new_string == NULL)
    return NULL;
  memcpy(new_string, string, str_len + 1);
  return new_string;
}

char* output_escape(const char* string, bool eight_bit_output) {
  if (!string)
    return NULL;
  size_t length = strlen(string);
  if (length > (SIZE_MAX - 1) / 5)
    return NULL;
  char* escaped = malloc(length * 5 + 1);
  if (!escaped)
    return NULL;
  size_t out = 0;
  for (size_t i = 0; i < length; i++) {
    unsigned char byte = (unsigned char)string[i];
    if ((byte >= 32 && byte <= 126) || (eight_bit_output && byte >= 128)) {
      escaped[out++] = (char)byte;
    } else {
      escaped[out++] = '\\';
      escaped[out++] = '#';
      escaped[out++] = (char)('0' + ((byte >> 6) & 7));
      escaped[out++] = (char)('0' + ((byte >> 3) & 7));
      escaped[out++] = (char)('0' + (byte & 7));
    }
  }
  escaped[out] = '\0';
  return escaped;
}

/* Match a glob pattern against a string. Supported wildcards:
 *   ?      matches any single character except '/'.
 *   *      matches any sequence of characters within one path component (no '/').
 *   **     matches any sequence of characters, including '/' (cross-directory).
 *   slash-star-star-slash is treated as a cross-directory wildcard when it appears between
 * literals.
 */
bool glob_match(const char* pattern, const char* str) {
  while (*pattern) {
    if (*pattern == '*') {
      if (*(pattern + 1) == '*') {
        /* globstar: match across directories */
        pattern += 2;
        if (*pattern == '\0')
          return true;
        if (*pattern == '/')
          pattern++;
        while (*str) {
          if (glob_match(pattern, str))
            return true;
          str++;
        }
        return glob_match(pattern, str);
      }
      /* single *: match within one path component */
      pattern++;
      while (*str && *str != '/') {
        if (glob_match(pattern, str))
          return true;
        str++;
      }
      return glob_match(pattern, str);
    } else if (*pattern == '?') {
      if (!*str || *str == '/')
        return false;
      pattern++;
      str++;
    } else {
      if (*pattern != *str) {
        /* allow literal / ** / rest to match any number of directories */
        if (*pattern == '/' && *(pattern + 1) == '*' && *(pattern + 2) == '*') {
          const char* rest = pattern + 3;
          if (*rest == '/')
            rest++;
          return glob_match(rest, str);
        }
        return false;
      }
      pattern++;
      str++;
    }
  }
  return *str == '\0';
}

bool format_human_bytes(unsigned long long bytes, char* buffer, size_t buffer_size) {
  static const char* const units[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB"};
  double value = (double)bytes;
  size_t unit = 0;
  int written;

  if (!buffer || buffer_size == 0)
    return false;
  while (value >= 1024.0 && unit < sizeof(units) / sizeof(units[0]) - 1) {
    value /= 1024.0;
    unit++;
  }
  if (unit == 0)
    written = snprintf(buffer, buffer_size, "%llu %s", bytes, units[unit]);
  else
    written = snprintf(buffer, buffer_size, "%.1f %s", value, units[unit]);
  return written >= 0 && (size_t)written < buffer_size;
}

static bool is_dir_in_manifest(const char* rel_path, ArrayList* manifest) {
  size_t len = strlen(rel_path);
  for (int i = 0; i < manifest->size; i++) {
    const char* entry = (const char*)manifest->items[i];
    // Check if entry starts with rel_path + '/' or matches exactly
    if (strncmp(entry, rel_path, len) == 0 && (entry[len] == '/' || entry[len] == '\0'))
      return true;
  }
  return false;
}

/* True when child_rel is, or lies below, a protected entry.  A prefix "a"
   therefore protects "a" and "a/b/c" but not "ab".  Entries with top_level_only
   set only protect DIRECT children of the receive root (at_root); nested
   directories that share such a name stay ordinary destination content. */
bool path_under_skip_prefix(const char* child_rel, bool at_root, const DeleteSkipEntry* skips,
                            int skip_count) {
  for (int i = 0; i < skip_count; i++) {
    if (skips[i].top_level_only && !at_root)
      continue;
    size_t prefix_len = strlen(skips[i].prefix);
    if (strncmp(child_rel, skips[i].prefix, prefix_len) == 0 &&
        (child_rel[prefix_len] == '\0' || child_rel[prefix_len] == '/'))
      return true;
  }
  return false;
}

/* All-or-nothing max-delete needs to know BEFORE any unlink whether the run
   would delete more than max_delete entries.  This rehearsal pass walks the
   destination with the same decisions as the delete pass but never touches the
   filesystem: it counts every regular file the delete pass would unlink and
   every directory it would rmdir (a directory is removed only once every entry
   below it has been removed and nothing the walker leaves in place survives).
   Entries the walker never removes (symlinks, manifest-listed files, protected
   prefixes) mark the enclosing directory as surviving, exactly as they would
   make a real rmdir fail with ENOTEMPTY.  Stops early once *count reaches the
   cap (sets *exceeds).  Returns false on a traversal error. */
static bool count_extras_fd(int dirfd, const char* rel_path, ArrayList* manifest, size_t cap,
                            size_t* count, bool* exceeds, const DeleteSkipEntry* skips,
                            int skip_count, bool* survives) {
  /* openat(dirfd, ".") opens an independent file description: a dup() would
     share dirfd's file offset, and a prior rehearsal pass must not have drained
     this directory's stream before the delete pass reads it again. */
  int scanfd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (scanfd < 0)
    return false;
  DIR* dir = fdopendir(scanfd);
  if (!dir) {
    close(scanfd);
    return false;
  }
  bool operation_ok = true;
  bool local_survives = false;
  bool at_root = rel_path[0] == '\0';
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    if (*exceeds)
      break;
    char* child_rel = path_cat((char*)rel_path, entry->d_name);
    if (!child_rel) {
      operation_ok = false;
      continue;
    }
    if (path_under_skip_prefix(child_rel, at_root, skips, skip_count)) {
      local_survives = true;
      free(child_rel);
      continue;
    }
    struct stat st;
    if (fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno != ENOENT)
        operation_ok = false;
      free(child_rel);
      continue;
    }
    if (S_ISLNK(st.st_mode)) {
      local_survives = true;
      free(child_rel);
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      int childfd = openat(dirfd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      bool child_ok = true;
      bool child_survives = true;
      if (childfd >= 0) {
        child_ok = count_extras_fd(childfd, child_rel, manifest, cap, count, exceeds, skips,
                                   skip_count, &child_survives);
        close(childfd);
      } else if (errno != ENOENT) {
        operation_ok = false;
      }
      if (!child_ok)
        operation_ok = false;
      if (is_dir_in_manifest(child_rel, manifest)) {
        /* A directory with kept content below it is never removed. */
        local_survives = true;
      } else if (child_survives) {
        /* The directory still holds entries the walker leaves in place, so an
           rmdir would fail with ENOTEMPTY; the delete pass leaves it behind
           rather than reporting an error (matching rsync). */
        local_survives = true;
      } else {
        if (*count >= cap) {
          *exceeds = true;
        } else {
          (*count)++;
        }
      }
    } else {
      bool found = false;
      for (int i = 0; i < manifest->size; i++) {
        if (strcmp((char*)manifest->items[i], child_rel) == 0) {
          found = true;
          break;
        }
      }
      if (!found) {
        if (*count >= cap) {
          *exceeds = true;
        } else {
          (*count)++;
        }
      }
    }
    free(child_rel);
  }
  closedir(dir);
  *survives = local_survives;
  return operation_ok;
}

static bool delete_extras_fd(int dirfd, const char* rel_path, ArrayList* manifest,
                             size_t max_delete, size_t* deleted_count, const DeleteSkipEntry* skips,
                             int skip_count) {
  /* Independent file description (see count_extras_fd). */
  int scanfd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (scanfd < 0)
    return false;
  DIR* dir = fdopendir(scanfd);
  if (!dir) {
    close(scanfd);
    return false;
  }
  bool operation_ok = true;
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    char* child_rel = path_cat((char*)rel_path, entry->d_name);
    if (!child_rel) {
      operation_ok = false;
      continue;
    }
    /* A --delay-updates run keeps its staging directory as a direct child of
       the receive root, and basis-dir snapshots live below it too.  Their
       contents are not manifest entries, so descending into them would delete
       every staged / basis file as an "extra".  Only the staging name (a
       top-level-only prefix) and the basis prefixes are protected: a nested
       destination directory that happens to be called .fastsync-stage is
       ordinary content. */
    if (path_under_skip_prefix(child_rel, rel_path[0] == '\0', skips, skip_count)) {
      free(child_rel);
      continue;
    }
    struct stat st;
    if (fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno != ENOENT)
        operation_ok = false;
      free(child_rel);
      continue;
    }
    // Skip symlinks to prevent following them outside the destination tree
    if (S_ISLNK(st.st_mode)) {
      free(child_rel);
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      int childfd = openat(dirfd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      bool child_removed = false;
      if (childfd >= 0) {
        child_removed = delete_extras_fd(childfd, child_rel, manifest, max_delete, deleted_count,
                                         skips, skip_count);
        if (!child_removed)
          operation_ok = false;
        close(childfd);
      } else if (errno != ENOENT) {
        operation_ok = false;
      }
      if (child_removed && !is_dir_in_manifest(child_rel, manifest)) {
        if (*deleted_count >= max_delete) {
          operation_ok = false;
        } else {
          if (unlinkat(dirfd, entry->d_name, AT_REMOVEDIR) != 0) {
            /* ENOENT: already gone (fine).  ENOTEMPTY/EEXIST: the directory
               still holds entries the walker leaves in place (a protected
               excluded prefix, a kept file the manifest protects, a symlink);
               rsync leaves such a directory behind, so this is not an error.
               Only genuine I/O failures abort the deletion. */
            if (errno != ENOENT && errno != ENOTEMPTY && errno != EEXIST)
              operation_ok = false;
          } else {
            (*deleted_count)++;
          }
        }
      }
    } else {
      // Check if relative path is in manifest
      bool found = false;
      for (int i = 0; i < manifest->size; i++) {
        if (strcmp((char*)manifest->items[i], child_rel) == 0) {
          found = true;
          break;
        }
      }
      if (!found) {
        if (*deleted_count >= max_delete) {
          operation_ok = false;
          free(child_rel);
          continue;
        }
        if (unlinkat(dirfd, entry->d_name, 0) != 0) {
          if (errno != ENOENT)
            operation_ok = false;
        } else {
          (*deleted_count)++;
        }
        char* escaped_path = output_escape(child_rel, log_get_8_bit_output());
        fprintf(stderr, "  Deleted: %s\n", escaped_path ? escaped_path : "<allocation failed>");
        free(escaped_path);
      }
    }
    free(child_rel);
  }
  closedir(dir);
  return operation_ok;
}

DeleteWalkResult delete_extras_limited(const char* dest_root, ArrayList* manifest,
                                       size_t max_delete, const DeleteSkipEntry* skips,
                                       int skip_count, size_t* deleted_out) {
  if (deleted_out)
    *deleted_out = 0;
  if (!manifest)
    return DELETE_WALK_ERROR;
  int rootfd;
  if (authorized_root_fd >= 0) {
    if (authorized_root_path)
      rootfd = open_authorized_destination(dest_root);
    else if (dest_root == NULL)
      rootfd = dup(authorized_root_fd);
    else
      rootfd = -1;
  } else {
    rootfd = open(dest_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  }
  if (rootfd < 0)
    return DELETE_WALK_ERROR;
  if (max_delete != SIZE_MAX) {
    /* Rehearse the deletion first so a run that would exceed the cap removes
       nothing (rsync's all-or-nothing --max-delete contract). */
    size_t count = 0;
    bool exceeds = false;
    bool survives = false;
    bool counted_ok = count_extras_fd(rootfd, "", manifest, max_delete, &count, &exceeds, skips,
                                      skip_count, &survives);
    if (!counted_ok) {
      close(rootfd);
      return DELETE_WALK_ERROR;
    }
    if (exceeds) {
      close(rootfd);
      return DELETE_WALK_LIMIT_EXCEEDED;
    }
  }
  size_t deleted_count = 0;
  bool ok = delete_extras_fd(rootfd, "", manifest, max_delete, &deleted_count, skips, skip_count);
  if (close(rootfd) != 0)
    ok = false;
  if (deleted_out)
    *deleted_out = deleted_count;
  return ok ? DELETE_WALK_OK : DELETE_WALK_ERROR;
}

bool delete_extras(const char* dest_root, ArrayList* manifest) {
  return delete_extras_limited(dest_root, manifest, SIZE_MAX, NULL, 0, NULL) == DELETE_WALK_OK;
}

bool has_path_traversal(const char* path) {
  if (!path)
    return true;
  char* dup = str_dup(path);
  if (!dup)
    return true;
  char* saveptr;
  const char* part = strtok_r(dup, "/", &saveptr);
  while (part) {
    if (strcmp(part, "..") == 0) {
      free(dup);
      return true;
    }
    part = strtok_r(NULL, "/", &saveptr);
  }
  free(dup);
  return false;
}

bool utils_valid_batch_path(const char* path) {
  return path && path[0] != '\0' && path[0] != '/' && !has_path_traversal(path);
}

char* path_cat(const char* path1, const char* path2) {
  if (path1 == NULL || *path1 == '\0')
    return str_dup(path2);
  if (path2 == NULL || *path2 == '\0')
    return str_dup(path1);
  size_t path1_len = strlen(path1);
  size_t path2_len = strlen(path2);
  size_t offset = 0;
  if (path1[path1_len - 1] == '/')
    path1_len -= 1;
  if (path2[0] == '/') {
    offset = 1;
    path2_len -= 1;
  }
  if (path1_len > SIZE_MAX - path2_len - 2)
    return NULL;
  char* new_path = malloc(path1_len + path2_len + 2);
  if (new_path == NULL)
    return NULL;
  memcpy(new_path, path1, path1_len);
  new_path[path1_len] = '/';
  memcpy(new_path + path1_len + 1, path2 + offset, path2_len);
  new_path[path1_len + path2_len + 1] = '\0';
  return new_path;
}

bool append_resume_eligible(unsigned long long old_size, unsigned long long check_size) {
  return old_size < check_size;
}

bool append_tail_length(unsigned long long old_size, unsigned long long check_size,
                        unsigned long long* tail_out) {
  if (!tail_out || !append_resume_eligible(old_size, check_size))
    return false;
  *tail_out = check_size - old_size;
  return true;
}

/* True when a bound/peer socket address is on the loopback interface: any
   127.0.0.0/8 IPv4 address, IPv6 ::1, or an IPv4-mapped ::ffff:127.x.x.x.  This
   is the transport-local test the daemon auth gate uses to decide whether a
   plaintext connection is a trustworthy local/SSH channel. */
bool utils_sockaddr_is_loopback(const struct sockaddr* addr) {
  if (!addr)
    return false;
  if (addr->sa_family == AF_INET) {
    const struct sockaddr_in* v4 = (const struct sockaddr_in*)addr;
    uint32_t host = ntohl(v4->sin_addr.s_addr);
    return (host & 0xff000000u) == 0x7f000000u;
  }
  if (addr->sa_family == AF_INET6) {
    const struct sockaddr_in6* v6 = (const struct sockaddr_in6*)addr;
    if (IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr))
      return true;
    /* An IPv4-mapped ::ffff:127.x.x.x is loopback too. */
    if (IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr) && v6->sin6_addr.s6_addr[12] == 127)
      return true;
    return false;
  }
  return false;
}

/* True when the fd's peer is provably a loopback TCP peer: getpeername must
   succeed AND the returned address must classify as loopback.  Everything else
   is NOT local, including a non-socket descriptor (pipe/socketpair): a failed
   getpeername (ENOTSOCK, ENOTCONN, ...) fails closed.  The daemon auth gate
   must not treat "I cannot tell" as "trusted", and daemon auth modules are
   daemon-only anyway (the --stdio path never loads a daemon config). */
bool utils_fd_peer_is_local(int fd) {
  if (fd < 0)
    return false;
  struct sockaddr_storage peer;
  socklen_t length = sizeof(peer);
  if (getpeername(fd, (struct sockaddr*)&peer, &length) != 0)
    return false;
  return utils_sockaddr_is_loopback((const struct sockaddr*)&peer);
}

/* True when a client-supplied host string names a loopback destination:
   "localhost", any 127.0.0.0/8 literal, "::1", or "[::1]". */
bool utils_host_is_loopback(const char* host) {
  if (!host || host[0] == '\0')
    return false;
  if (strcmp(host, "localhost") == 0)
    return true;
  struct in_addr v4;
  if (inet_pton(AF_INET, host, &v4) == 1)
    return (ntohl(v4.s_addr) & 0xff000000u) == 0x7f000000u;
  struct in6_addr addr6;
  if (host[0] == '[') {
    size_t len = strlen(host);
    if (len < 3 || host[len - 1] != ']')
      return false;
    /* inet_pton needs the bare address, not the bracketed form. */
    char bare[INET6_ADDRSTRLEN];
    if (len - 2 >= sizeof(bare))
      return false;
    memcpy(bare, host + 1, len - 2);
    bare[len - 2] = '\0';
    return inet_pton(AF_INET6, bare, &addr6) == 1 && IN6_IS_ADDR_LOOPBACK(&addr6);
  }
  return inet_pton(AF_INET6, host, &addr6) == 1 && IN6_IS_ADDR_LOOPBACK(&addr6);
}
