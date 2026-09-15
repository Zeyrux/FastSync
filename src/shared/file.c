#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* statx + STATX_BTIME for --crtimes birth-time capture */
#endif
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "data.h"
#include "delta.h"
#include "file.h"
#include "file_store.h"
#include "identity.h"
#include "log.h"
#include "metadata.h"
#include "utils.h"
#include "protocol.h"
#include "xattr.h"

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

/* Preallocate `size` bytes on `fd` before any data is written (--preallocate).
 * posix_fallocate reserves real disk blocks, so an out-of-space condition
 * (ENOSPC/EDQUOT) surfaces up front instead of partway through a transfer;
 * unavoidable fragmentation of a streamed file is also reduced.  Some
 * filesystems (e.g. tmpfs, ZFS) do not support it and return EOPNOTSUPP/ENOSYS,
 * where we fall back to ftruncate, which still extends the logical size so the
 * fail-fast/contiguity intent degrades gracefully but never fails.  Genuine
 * allocation failures are propagated as the error code (caller fails the write).
 * posix_fallocate leaves the fd's file offset unchanged, so the subsequent
 * write_all at offset 0 is unaffected.  Returns 0 on success (including the
 * fallback) or a nonzero error code. */
static int preallocate_fd(int fd, unsigned long long size) {
  if (size == 0)
    return 0;
  int rc = posix_fallocate(fd, 0, (off_t)size);
  if (rc == EOPNOTSUPP || rc == ENOSYS) {
    if (ftruncate(fd, (off_t)size) == 0)
      return 0;
    return errno;
  }
  return rc;
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

/* Process-wide umask, captured exactly once.  Reading the umask requires a
 * get+set round trip (umask(0); umask(old)); doing that per write would be racy
 * in the multithreaded receiver, so the value is captured at process startup by
 * file_umask_capture() (called at the top of main(), before any threads exist).
 * The pthread_once fallback keeps a caller that never called the capture (e.g. a
 * unit test) correct. */
static unsigned g_process_umask;
static atomic_bool g_process_umask_captured;
static pthread_once_t g_process_umask_once = PTHREAD_ONCE_INIT;

static void file_capture_umask_now(void) {
  mode_t mask = umask(0);
  umask(mask);
  g_process_umask = (unsigned)mask;
  atomic_store_explicit(&g_process_umask_captured, true, memory_order_release);
}

static void file_capture_umask_once(void) {
  if (atomic_load_explicit(&g_process_umask_captured, memory_order_acquire))
    return;
  file_capture_umask_now();
}

/* Re-captures the umask.  Must only be called while the process is still
 * single-threaded (startup, or the daemon's post-fork setup after umask(0)),
 * so a later re-capture can refresh the cached value before any receiver
 * thread exists. */
void file_umask_capture(void) {
  file_capture_umask_now();
}

unsigned file_process_umask(void) {
  if (!atomic_load_explicit(&g_process_umask_captured, memory_order_acquire))
    pthread_once(&g_process_umask_once, file_capture_umask_once);
  return g_process_umask;
}

/* Base mode applied when the policy does not take the source mode wholesale
 * (i.e. --perms is off).  A pre-existing destination keeps its own mode; a
 * brand-new file is created like rsync: source_mode & 0777 & ~umask (special
 * bits are not part of a mode-preserving transfer without -p).  Only when no
 * metadata is available at all does the historical fixed 0644 default apply.
 * The -E rule (and no-op for a plain -t) is layered on top of this base. */
static mode_t file_mode_base(const FileMetadata* metadata, bool existing_known,
                             mode_t existing_mode) {
  if (existing_known)
    return existing_mode;
  if (metadata)
    return metadata->mode & 0777 & ~(mode_t)file_process_umask();
  return S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
}

bool file_checksum(File* file, ChecksumAlgo algo, uint64_t seed, uint8_t* out, size_t out_capacity,
                   size_t* out_len) {
  if (!file || !out || !out_len || !file->data)
    return false;
  if (file->data->size == 0) {
    return checksum_digest(algo, seed, "", 0, out, out_capacity, out_len);
  }
  if (!file->data->data && !file_load_data(file))
    return false;
  return checksum_digest(algo, seed, file->data->data, file->data->size, out, out_capacity,
                         out_len);
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
  file->dir_time_only = false;
  file->basis_link = NULL;
  file->link_group = 0;
  file->link_first = false;
  file->hardlink_target = NULL;
  file->is_symlink = false;
  file->symlink_target = NULL;
  file->is_special = false;
  file->rdev_major = 0;
  file->rdev_minor = 0;
  file->xattrs = NULL;
  file->dest_state = (OutputDestState){0};
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
  free(file->basis_link);
  file->basis_link = NULL;
  free(file->hardlink_target);
  file->hardlink_target = NULL;
  free(file->symlink_target);
  file->symlink_target = NULL;
  xattr_list_free(file->xattrs);
  file->xattrs = NULL;
  free(file);
}

FileMetadata* file_metadata_create(const char* path, const struct stat* stats, bool capture_atime,
                                   bool capture_crtime) {
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
  /* -U/--atimes: capture the access time from the same pre-read stat the
     scanner already took, so the value is not clobbered by a later read for
     transfer.  The timestamp is populated (and atime_valid set) only on Linux,
     where st_atim is populated; on other platforms the atime is left alone
     rather than clobbered to the default 0/epoch by an unpopulated value. */
#ifdef __linux__
  m->atime_valid = capture_atime;
  m->atime_sec = stats->st_atim.tv_sec;
  m->atime_nsec = stats->st_atim.tv_nsec;
#else
  m->atime_valid = false;
  m->atime_sec = 0;
  m->atime_nsec = 0;
#endif
  /* -N/--crtimes: birth time is not available via struct stat in general; on
     Linux it needs statx STATX_BTIME.  If unavailable it is captured as a
     documented no-op (the flag stays accepted, crtime_valid stays false). */
  m->crtime_valid = false;
  m->crtime_sec = 0;
  m->crtime_nsec = 0;
  if (capture_crtime) {
#ifdef STATX_BTIME
    struct statx stx;
    if (path != NULL && statx(AT_FDCWD, path, AT_STATX_SYNC_AS_STAT, STATX_BTIME, &stx) == 0 &&
        (stx.stx_mask & STATX_BTIME) != 0) {
      m->crtime_valid = true;
      m->crtime_sec = (time_t)stx.stx_btime.tv_sec;
      m->crtime_nsec = (long)stx.stx_btime.tv_nsec;
    }
#endif
  }
  return m;
}

void file_metadata_destroy(void* metadata) {
  free(metadata);
}

/* --open-noatime: process-wide sender policy (client-only, never crosses the
 * wire).  When enabled, opening a source file for transfer uses O_NOATIME so
 * the read does not bump the source's on-disk access time.  It degrades safely
 * to a normal open where O_NOATIME is unavailable (not defined) or refused
 * (EPERM, because it needs CAP_FOWNER): the data path never silently changes,
 * only the atime-bump is skipped. */
static bool file_open_noatime = false;

void file_set_open_noatime(bool enable) {
  file_open_noatime = enable;
}

bool file_get_open_noatime(void) {
  return file_open_noatime;
}

/* Open `path` read-only for transfer, honouring --open-noatime when set. */
int file_open_for_read(const char* path) {
  int flags = O_RDONLY;
#ifdef O_NOATIME
  if (file_get_open_noatime())
    flags |= O_NOATIME;
#endif
  int fd = open(path, flags);
#ifdef O_NOATIME
  if (fd < 0 && (flags & O_NOATIME))
    fd = open(path, O_RDONLY); /* degrade safely on EPERM / unsupported fs */
#endif
  return fd;
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
  int fd = file_open_for_read(file->path);
  if (fd < 0) {
    log_perror("Could not open the file!");
    return 0;
  }
  FILE* file_pointer = fdopen(fd, "rb");
  if (file_pointer == NULL) {
    close(fd);
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

/* --keep-dirlinks (-K) receiver process-wide policy: when set, a destination
 * path component that is itself a symlink to an in-root directory is followed
 * (used as that directory) instead of failing the O_NOFOLLOW walk.  Only ever
 * honoured when the resolved target is a directory that stays beneath the
 * authorized root, so a malicious symlink can never redirect the write outside
 * it.  Client of record is the server's receiver. */
static bool file_keep_dirlinks = false;

void file_set_keep_dirlinks(bool enable) {
  file_keep_dirlinks = enable;
}

/* --trust-sender (Phase 5) receiver process-wide policy: when set, the receiver
 * trusts the sender's file list and skips its own redundant up-front re-
 * validation (empty/".." path rejection, escaping-symlink-target containment).
 * Kept OFF by default; the server's per-connection handler sets it once from the
 * received config before any receiver/writer threads start (each connection is
 * its own forked process, so this per-process value never bleeds across
 * connections). */
static bool file_trust_sender = false;

void file_set_trust_sender(bool enable) {
  file_trust_sender = enable;
}

bool file_get_trust_sender(void) {
  return file_trust_sender;
}

/* rsync 3.4.1 unsafe_symlink(): true when `target` (the link's destination
 * string) points outside the transfer tree rooted at the symlink's own
 * location.  `link_path` is the symlink's path relative to the top of the
 * transfer (including its name).  This is a purely lexical test matching
 * rsync's util1.c: absolute/empty targets are always unsafe; leading "../"
 * components are counted against the symlink's own directory depth; a ".."
 * that would climb above the transfer root is unsafe.  rsync 3.4.1 additionally
 * rejects any INTERNAL "/../" component and a trailing "/..". */
bool file_symlink_unsafe(const char* target, const char* link_path) {
  if (!target || target[0] == '\0' || target[0] == '/')
    return true;
  const char* rest = target;
  while (strncmp(rest, "../", 3) == 0) {
    rest += 3;
    while (*rest == '/')
      rest++;
  }
  if (strstr(rest, "/../") != NULL)
    return true;
  size_t target_len = strlen(target);
  if (target_len > 3 && strcmp(&target[target_len - 3], "/..") == 0)
    return true;

  int depth = 0;
  const char* name;
  const char* slash;
  const char* src = link_path ? link_path : "";
  for (name = src; (slash = strchr(name, '/')) != NULL; name = slash + 1) {
    if (*name == '.' && (name[1] == '/' || (name[1] == '.' && name[2] == '/'))) {
      if (name[1] == '.')
        depth = 0;
    } else {
      depth++;
    }
    while (slash[1] == '/')
      slash++;
  }
  if (*name == '.' && name[1] == '.' && name[2] == '\0')
    depth = 0;

  for (name = target; (slash = strchr(name, '/')) != NULL; name = slash + 1) {
    if (*name == '.' && (name[1] == '/' || (name[1] == '.' && name[2] == '/'))) {
      if (name[1] == '.') {
        if (--depth < 0)
          return true;
      }
    } else {
      depth++;
    }
    while (slash[1] == '/')
      slash++;
  }
  if (*name == '.' && name[1] == '.' && name[2] == '\0')
    depth--;
  return depth < 0;
}

/* Strict lexical helper: true when `target` is relative (not absolute) and
 * contains no ".." component at all, so it can never escape the directory it
 * is created in.  This is stricter than rsync's unsafe_symlink() (which allows
 * an in-tree ".."); the scanner/receiver use file_symlink_unsafe()/--safe-links
 * for rsync parity, and this helper is retained for callers that want the
 * ".."-free guarantee. */
bool file_symlink_target_contained(const char* target) {
  if (!target || target[0] == '\0' || target[0] == '/')
    return false;
  const char* p = target;
  while (*p) {
    const char* slash = strchr(p, '/');
    size_t comp_len = slash ? (size_t)(slash - p) : strlen(p);
    if (comp_len == 2 && p[0] == '.' && p[1] == '.')
      return false;
    if (!slash)
      break;
    p = slash + 1;
  }
  return true;
}

/* Remove a leading symlink munge marker (if present); returns true when the
 * marker was stripped.  `target` is a mutable NUL-terminated buffer. */
bool file_symlink_unmunge(char* target) {
  if (!target)
    return false;
  static const char* const marker = SYMLINK_MUNGE_PREFIX;
  size_t marker_len = strlen(marker);
  if (strncmp(target, marker, marker_len) != 0)
    return false;
  size_t rest = strlen(target + marker_len) + 1;
  memmove(target, target + marker_len, rest);
  return true;
}

/* Owned copy of `target` prefixed with SYMLINK_MUNGE_PREFIX (the receiver-side
 * --munge-links rewriting, matching rsync's receiver).  Returns NULL on
 * allocation failure. */
char* file_symlink_munge(const char* target) {
  if (!target)
    return NULL;
  static const char* const marker = SYMLINK_MUNGE_PREFIX;
  size_t marker_len = strlen(marker);
  size_t target_len = strlen(target);
  char* out = malloc(marker_len + target_len + 1);
  if (!out)
    return NULL;
  memcpy(out, marker, marker_len);
  memcpy(out + marker_len, target, target_len + 1);
  return out;
}

/* Create a symlink at `path` pointing to `target`, confined below the
 * authorized root: the parent directory is opened with an O_NOFOLLOW fd walk
 * and the link is created with symlinkat so neither the destination chain nor
 * the target is ever followed.  The final component is never dereferenced: an
 * existing non-directory entry at `path` is unlinked by name before the link is
 * placed; an existing directory there is left untouched (returns false, so a
 * caller can treat it as a collision).  The link VALUE `target` is copied
 * verbatim, matching rsync -l (which stores absolute and ".."-bearing targets
 * as-is); target policy is the caller's job -- the scanner applies
 * --safe-links/--copy-unsafe-links, and the receiver applies --munge-links.
 * The PLACEMENT path is always confined below the authorized root. */
bool file_symlink_at_secure(const char* path, const char* target) {
  if (!path || !target || has_path_traversal(path))
    return false;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(path, &leaf, true);
  if (parent_fd < 0)
    return false;
  bool ok = false;
  struct stat st;
  bool exists = fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0;
  if (exists && S_ISDIR(st.st_mode)) {
    /* A directory already at this path cannot be replaced atomically with a
       symlink without --force semantics; leave it and report the collision. */
    ok = false;
  } else {
    if (exists && unlinkat(parent_fd, leaf, 0) != 0 && errno != ENOENT)
      goto out;
    ok = symlinkat(target, parent_fd, leaf) == 0;
  }
out:
  close(parent_fd);
  free(leaf);
  return ok;
}

/* Open the directory named by canonical absolute `resolved`, which the caller
 * has already verified lies beneath `root` (the canonical authorized root).
 * Each component is opened relative to the authorized-root fd with O_NOFOLLOW,
 * so a directory swapped for a symlink after the realpath() check cannot
 * redirect the open outside the root -- the walk simply fails.  This replaces
 * re-opening the absolute resolved path (TOCTOU).  Returns an O_DIRECTORY fd,
 * or -1 (the root itself and any error are refused). */
static int open_dir_beneath_root(const char* resolved, const char* root) {
  size_t root_len = strlen(root);
  const char* rel = resolved + root_len;
  while (*rel == '/')
    rel++;
  if (*rel == '\0')
    return -1;
  int root_fd = utils_get_authorized_root_fd();
  if (root_fd < 0)
    return -1;
  int fd = dup(root_fd);
  if (fd < 0)
    return -1;
  char* copy = str_dup(rel);
  if (!copy) {
    close(fd);
    return -1;
  }
  char* save = NULL;
  for (char* component = strtok_r(copy, "/", &save); component;
       component = strtok_r(NULL, "/", &save)) {
    if (strcmp(component, ".") == 0)
      continue;
    /* A canonical realpath() output never contains "." or ".."; refuse ".."
       defensively rather than let it climb toward the root. */
    int next = strcmp(component, "..") == 0
                   ? -1
                   : openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0) {
      close(fd);
      free(copy);
      return -1;
    }
    close(fd);
    fd = next;
  }
  free(copy);
  return fd;
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
  int root_fd = utils_get_authorized_root_fd();
  const char* root_path = utils_get_authorized_root_path();
  if (root_fd >= 0) {
    if (!root_path || path[0] != '/' || !path_is_within_root(root_path, path)) {
      free(copy);
      free(leaf);
      return -1;
    }
    fd = dup(root_fd);
    if (fd < 0) {
      free(copy);
      free(leaf);
      return -1;
    }
    size_t root_len = strlen(root_path);
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
  char rel_buf[PATH_MAX] = "";
  while (component) {
    if (strcmp(component, "..") == 0) {
      close(fd);
      free(copy);
      free(leaf);
      return -1;
    }
    if (strcmp(component, ".") != 0) {
      int next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (next < 0 && create_dirs && errno == ENOENT) {
        bool created = mkdirat(fd, component, 0755) == 0;
        if (created || errno == EEXIST) {
          /* P7 Wave E: --copy-as owns EVERY entry, including the intermediate
             directories this walk creates implicitly.  Its target ids are a
             global policy, so they are available here without per-entry source
             metadata.  Only a directory this walk actually created is chowned
             (a pre-existing destination directory is left alone, matching
             rsync's transferred-entry scope); the helper is a no-op unless an
             identity policy is active. */
          if (created && identity_copy_as_active() &&
              !identity_apply_ownership_link(fd, component, 0, 0)) {
            /* A REQUIRED --copy-as ownership that cannot be applied to a
               directory this walk just created must fail the entry rather than
               leave that implicit parent owned by the receiver.  Preserve the
               failing errno across the cleanup so the caller logs the real
               reason. */
            int saved_errno = errno;
            close(fd);
            free(copy);
            free(leaf);
            errno = saved_errno;
            return -1;
          }
          next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
      }
      /* --keep-dirlinks (-K): a path component that is an existing symlink to
         an in-root directory is used as THAT directory rather than failing the
         O_NOFOLLOW walk.  Only honoured when the symlink resolves to a
         directory that stays beneath the authorized root, so a malicious link
         can never redirect the write outside it. */
      if (next < 0 && file_keep_dirlinks && root_path != NULL &&
          (errno == ELOOP || errno == ENOTDIR || errno == EACCES)) {
        struct stat lst;
        if (fstatat(fd, component, &lst, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(lst.st_mode)) {
          char candidate[PATH_MAX];
          char root[PATH_MAX];
          if (realpath(root_path, root) && snprintf(candidate, sizeof(candidate), "%s%s/%s", root,
                                                    rel_buf, component) < (int)sizeof(candidate)) {
            char resolved[PATH_MAX];
            if (realpath(candidate, resolved) && strcmp(resolved, root) != 0 &&
                strncmp(root, resolved, strlen(root)) == 0 &&
                (resolved[strlen(root)] == '/' || resolved[strlen(root)] == '\0')) {
              struct stat rst;
              if (stat(resolved, &rst) == 0 && S_ISDIR(rst.st_mode)) {
                /* Open the resolved directory through a relative no-follow walk
                   from the authorized-root fd instead of re-opening the
                   absolute `resolved` path: swapping an intermediate directory
                   for a symlink between realpath() and open() (TOCTOU) then
                   merely fails the walk rather than redirecting the fd outside
                   the root. */
                next = open_dir_beneath_root(resolved, root);
              }
            }
          }
        }
      }
      if (next < 0) {
        close(fd);
        free(copy);
        free(leaf);
        return -1;
      }
      close(fd);
      fd = next;
      /* Track the walked relative prefix so the -K candidate path can be
         reconstructed.  An overflow while building it means the whole path is
         at the PATH_MAX edge, so fail hard rather than silently building a
         wrong (truncated) candidate for a later -K follow. */
      size_t need = strlen(rel_buf) + strlen(component) + 2;
      if (need <= sizeof(rel_buf)) {
        strcat(rel_buf, "/");
        strcat(rel_buf, component);
      } else if (file_keep_dirlinks) {
        close(fd);
        free(copy);
        free(leaf);
        return -1;
      }
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
  const char* root_path = utils_get_authorized_root_path();
  bool root_is_open =
      utils_get_authorized_root_fd() >= 0 && root_path && strcmp(norm, root_path) == 0;
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
  bool created = false;
  if (dir_fd < 0 && errno == ENOENT) {
    if (mkdirat(parent_fd, leaf, 0755) == 0) {
      created = true;
      dir_fd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } else if (errno == EEXIST) {
      dir_fd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
  }
  bool ok = dir_fd >= 0;
  /* --copy-as owns a directory this call just created (the final component;
     intermediate components were handled by file_open_secure_parent above).  A
     failed REQUIRED ownership fails the call rather than leaving the directory
     owned by the receiver. */
  if (ok && created && identity_copy_as_active() &&
      !identity_apply_ownership_link(parent_fd, leaf, 0, 0))
    ok = false;
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
  const char* root_path = utils_get_authorized_root_path();
  bool root_is_open =
      utils_get_authorized_root_fd() >= 0 && root_path && strcmp(norm, root_path) == 0;
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

/* Recursively delete every entry inside an open directory, never following a
   symlink (an O_NOFOLLOW fd walk, so a symlink planted inside the tree can
   never redirect removal outside of it).  The directory itself is left in
   place; returns false on any failure. */
static bool wipe_dir_fd(int dirfd) {
  int scanfd = dup(dirfd);
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
    struct stat st;
    if (fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno != ENOENT)
        operation_ok = false;
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      int childfd = openat(dirfd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      bool child_removed = false;
      if (childfd >= 0) {
        child_removed = wipe_dir_fd(childfd);
        close(childfd);
      } else if (errno != ENOENT) {
        operation_ok = false;
      }
      if (child_removed && unlinkat(dirfd, entry->d_name, AT_REMOVEDIR) != 0 && errno != ENOENT)
        operation_ok = false;
    } else {
      /* Files and symlinks alike are removed by name, never followed. */
      if (unlinkat(dirfd, entry->d_name, 0) != 0 && errno != ENOENT)
        operation_ok = false;
    }
  }
  closedir(dir);
  return operation_ok;
}

/* Remove the whole directory tree at `path` (confined below the authorized
   root, symlink-safe).  --force uses this to clear a non-empty destination
   directory that blocks an incoming regular file.  Returns true when the path
   no longer exists as a directory (a missing path or a non-directory at the
   final component is a no-op success; the normal write path replaces files). */
bool file_remove_tree_secure(const char* path) {
  if (!path)
    return false;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(path, &leaf, false);
  if (parent_fd < 0)
    return false;
  int dirfd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dirfd < 0) {
    bool absent = errno == ENOENT || errno == ENOTDIR || errno == ELOOP;
    close(parent_fd);
    free(leaf);
    return absent;
  }
  bool ok = wipe_dir_fd(dirfd);
  close(dirfd);
  if (ok && unlinkat(parent_fd, leaf, AT_REMOVEDIR) != 0 && errno != ENOENT)
    ok = false;
  close(parent_fd);
  free(leaf);
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

/* Open a --temp-dir scratch directory exactly as rsync does: the directory must
 * already exist and is used as given (an absolute path is used verbatim, a
 * relative one was already resolved against the destination root by the
 * caller).  Unlike file_open_private_dir this neither creates it nor confines
 * it below the receive root, because rsync accepts any temp dir -- including
 * one outside the destination tree or on another filesystem.  Returns an
 * O_DIRECTORY|O_CLOEXEC fd, or -1 on error. */
int file_open_temp_dir(const char* dir_path) {
  if (!dir_path)
    return -1;
  return open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

/* After the content and mode/times are restored on the just-written file, apply
 * the per-file xattrs (-X/-A) and, for --fake-super, park the source's
 * uid/gid/mode/mtime in the reserved xattr.  All fd-relative (confined to the
 * destination file) and best-effort: a per-attribute or privilege failure is
 * logged and skipped, never fatal. */
static void restore_extra_fd(int fd, const FileMetadata* metadata, const FileXattrList* xattrs,
                             bool fake_super, FileAttrPolicy policy) {
  xattr_apply_fd(fd, xattrs);
  if (fake_super && metadata) {
    /* Record the ownership that WOULD have been applied: when an explicit
       ownership request (--chown/--usermap/--groupmap/--copy-as or -o/-g) is
       active, the resolved mapping; otherwise the source's own id.  The real
       chown is suppressed (identity_apply_ownership early-returns under
       --fake-super) so recording never defeats the flag.  Mode/mtime are still
       replayed (policy-gated) so unprivileged --fake-super keeps working. */
    uint32_t store_uid;
    uint32_t store_gid;
    identity_resolve_storage_ids((int32_t)metadata->uid, (int32_t)metadata->gid, &store_uid,
                                 &store_gid);
    fake_super_store_fd(fd, store_uid, store_gid, (uint32_t)metadata->mode, metadata->mtime_sec,
                        metadata->mtime_nsec);
    fake_super_restore_fd(fd, policy);
  }
}

static bool file_to_disk_secure_impl(const char* path, const void* data,
                                     unsigned long long data_size, bool inplace, bool sparse,
                                     bool preallocate, const FileMetadata* metadata,
                                     FileAttrPolicy policy, bool update, bool no_replace,
                                     bool use_fsync, const char* temp_dir,
                                     const FileXattrList* xattrs, bool fake_super,
                                     bool keep_partial) {
  char* leaf = NULL;
  int dirfd = file_open_secure_parent(path, &leaf, true);
  if (dirfd < 0)
    return false;
  int fd = -1;
  bool ok = false;
  /* Set when a --temp-dir install fails with EXDEV: rsync then falls back to a
   * non-atomic write directly in the destination directory (see the tail of
   * this function). */
  bool cross_device_fallback = false;
  /* The base mode applied when --perms is off (neither the source mode nor an
   * exec-only change is taken wholesale): a pre-existing destination keeps its
   * own mode (special bits dropped), while a brand-new file uses
   * source&~umask when metadata is available (see file_mode_base) or 0644 when
   * there is none.  Captured from the destination probe before the write. */
  mode_t existing_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  bool existing_mode_known = false;
  if (inplace) {
    /* --inplace writes directly into the destination; a scratch --temp-dir
       does not apply and must never redirect these writes. */
    /* Type gate BEFORE opening: an existing destination entry that is not a
       regular file (FIFO, socket, char/block device, directory) must never be
       opened for writing.  Opening a FIFO would block the receive thread
       forever and writing into a device would bypass the --write-devices /
       super-mode gate (a client-controlled device write).  fstatat with
       AT_SYMLINK_NOFOLLOW does not follow a symlink and does not block. */
    struct stat pre_stat;
    if (fstatat(dirfd, leaf, &pre_stat, AT_SYMLINK_NOFOLLOW) == 0) {
      if (!S_ISREG(pre_stat.st_mode)) {
        close(dirfd);
        free(leaf);
        return false;
      }
      /* Capture the old destination mode before the overwrite so a no--p/-E
       * write can restore it (the write itself may clear setuid/setgid). */
      existing_mode = pre_stat.st_mode & 0777;
      existing_mode_known = true;
    }
    /* O_NONBLOCK: a no-op for a regular file, but a raced-in FIFO cannot block
       the open before the post-open S_ISREG re-check rejects it. */
    fd = openat(dirfd, leaf, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0644);
    if (fd >= 0) {
      struct stat destination_stat;
      /* Re-check the opened descriptor: a concurrent replacement between the
         fstatat probe and the open (or a device/FIFO raced in) must never be
         written through. */
      if (fstat(fd, &destination_stat) != 0 || !S_ISREG(destination_stat.st_mode)) {
        close(fd);
        close(dirfd);
        free(leaf);
        return false;
      }
      bool newer = false;
      if (update && metadata && stat_is_newer(&destination_stat, metadata)) {
        newer = true;
      }
      if (newer) {
        ok = true;
      } else {
        /* Preallocate the expected payload size before writing so an
           out-of-space condition fails cleanly up front (--preallocate).
           --sparse takes precedence: posix_fallocate would allocate every
           block, defeating the holes the sparse writer would create, so the
           two never combine here (the ftruncate presize below stays). */
        int prealloc_rc = 0;
        if (preallocate && !sparse && data_size > 0) {
          prealloc_rc = preallocate_fd(fd, data_size);
          if (prealloc_rc != 0) {
            char* escaped_path = output_escape(path, log_get_8_bit_output());
            log_message(LOG_LEVEL_ERROR, "preallocate failed for '%s' (%s); transfer aborted",
                        escaped_path ? escaped_path : "<allocation failed>", strerror(prealloc_rc));
            free(escaped_path);
          }
        }
        if (prealloc_rc == 0) {
          /* posix_fallocate does not guarantee the fd's file offset is left
             unchanged, so seek back to 0 before the data write. */
          lseek(fd, 0, SEEK_SET);
          if (sparse && data_size > 0)
            ok = ftruncate(fd, (off_t)data_size) == 0;
          if (ok || !sparse || data_size == 0)
            ok = sparse && data_size > 0
                     ? file_store_write_sparse(fd, (const unsigned char*)data, data_size)
                     : write_all(fd, data, data_size);
          if (ok)
            ok = ftruncate(fd, (off_t)data_size) == 0;
          /* Normalize the mode: apply the metadata-derived safe mode when the
             sender supplied metadata (setuid/setgid/sticky are never honored);
             otherwise fall back to a safe default so dangerous bits on an
             existing destination cannot survive an overwrite.  When the policy
             requests neither -p nor -E the source mode is deliberately ignored
             and the pre-existing destination mode (or 0644 for a new file) is
             restored instead.  The exec-bits-only -E change is likewise applied
             on top of that destination-derived base, not the scratch file's
             0600. */
          if (ok) {
            if (metadata) {
              if (!policy.perms &&
                  fchmod(fd, file_mode_base(metadata, existing_mode_known, existing_mode)) != 0)
                ok = false;
              if (ok)
                ok = file_restore_metadata_fd(fd, metadata, policy);
            } else if (fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
              ok = false;
            }
          }
          if (ok)
            restore_extra_fd(fd, metadata, xattrs, fake_super, policy);
          if (ok && use_fsync)
            ok = fsync(fd) == 0;
        }
      }
    }
  } else {
    /* The --update newer-destination check runs first so a skipped file never
       creates an empty scratch directory behind it. */
    /* True once the temp is being written: distinguishes a mid-write/metadata/
       install failure (partial data may exist, --partial may retain it) from a
       pre-write validation failure (nothing to retain). */
    bool write_attempted = false;
    /* Probe the destination ONCE up front: it both drives the --update check
       and records the pre-existing mode the no--p/-E fallback preserves. */
    struct stat destination_stat;
    bool destination_is_regular =
        fstatat(dirfd, leaf, &destination_stat, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(destination_stat.st_mode);
    if (destination_is_regular) {
      existing_mode = destination_stat.st_mode & 0777;
      existing_mode_known = true;
    }
    if (update && metadata && destination_is_regular &&
        stat_is_newer(&destination_stat, metadata)) {
      close(dirfd);
      free(leaf);
      return true;
    }
    /* Scratch directory for the temporary working copy.  When NULL the temp
       file is created in the destination directory, exactly as historically. */
    int scratch_dirfd = -1;
    if (temp_dir) {
      scratch_dirfd = file_open_temp_dir(temp_dir);
      if (scratch_dirfd < 0) {
        int saved_errno = errno;
        log_message(LOG_LEVEL_ERROR,
                    "--temp-dir '%s' could not be opened (rsync requires it to already exist): %s",
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
      int prealloc_rc = 0;
      if (preallocate && !sparse && data_size > 0) {
        prealloc_rc = preallocate_fd(fd, data_size);
        if (prealloc_rc != 0) {
          char* escaped_path = output_escape(path, log_get_8_bit_output());
          log_message(LOG_LEVEL_ERROR, "preallocate failed for '%s' (%s); transfer aborted",
                      escaped_path ? escaped_path : "<allocation failed>", strerror(prealloc_rc));
          free(escaped_path);
        }
      }
      if (prealloc_rc == 0) {
        lseek(fd, 0, SEEK_SET);
        if (sparse && data_size > 0)
          ok = ftruncate(fd, (off_t)data_size) == 0;
        /* A real write attempt begins here (the ftruncate presize succeeded or
           no presize applies): a later mid-write / metadata / fsync / install
           failure may leave partial data that --partial retention can rename. */
        if (ok || (!sparse || data_size == 0)) {
          write_attempted = true;
          ok = sparse && data_size > 0
                   ? file_store_write_sparse(fd, (const unsigned char*)data, data_size)
                   : write_all(fd, data, data_size);
        }
        if (ok) {
          if (metadata) {
            if (!policy.perms &&
                fchmod(fd, file_mode_base(metadata, existing_mode_known, existing_mode)) != 0)
              ok = false;
            if (ok)
              ok = file_restore_metadata_fd(fd, metadata, policy);
          } else if (fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
            ok = false;
          }
        }
        if (ok)
          restore_extra_fd(fd, metadata, xattrs, fake_super, policy);
        if (ok && use_fsync)
          ok = fsync(fd) == 0;
      }
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
            /* Cross-device (or otherwise impossible) link: rsync falls back to
               writing the file directly in the destination directory.  Record
               it and retry below with no scratch dir. */
            if (scratch_dirfd >= 0 && errno == EXDEV)
              cross_device_fallback = true;
            ok = false;
          }
        } else if (renameat(scratch_dirfd >= 0 ? scratch_dirfd : dirfd, tmp, dirfd, leaf) != 0) {
          if (scratch_dirfd >= 0 && errno == EXDEV)
            cross_device_fallback = true;
          ok = false;
        }
      }
      if (!ok) {
        /* --partial retention (best-effort): on a failure that happened after
           the temp held data (mid-write / metadata / fsync / install error),
           keep the already-written temp at the final destination path instead
           of unlinking it, so a later --append / --append-verify run can resume.
           This only ever renames the already-written temp (never a corrupt
           blend); the rename can fail (cross-device, permissions) and we then
           fall through to the normal unlink cleanup.  Never retains when
           keep_partial is off, when nothing was actually written, or under
           --ignore-existing/--existing (no_replace), where the destination is
           not ours to overwrite. */
        if (!keep_partial || !write_attempted || no_replace ||
            renameat(scratch_dirfd >= 0 ? scratch_dirfd : dirfd, tmp, dirfd, leaf) != 0)
          unlinkat(scratch_dirfd >= 0 ? scratch_dirfd : dirfd, tmp, 0);
      }
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
  if (cross_device_fallback) {
    /* rsync semantics: a --temp-dir on another filesystem must not abort the
       write.  Retry once with no scratch dir so the file is written and
       installed non-atomically in the destination directory. */
    log_message(LOG_LEVEL_WARNING,
                "temp dir is on a different filesystem than the destination; falling back to a "
                "non-atomic copy into the destination directory");
    return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, preallocate, metadata,
                                    policy, update, no_replace, use_fsync, NULL, xattrs, fake_super,
                                    keep_partial);
  }
  return ok;
}

bool file_to_disk_secure(const char* path, const void* data, unsigned long long data_size,
                         bool inplace, bool sparse, bool preallocate, const FileMetadata* metadata,
                         FileAttrPolicy policy, const char* temp_dir) {
  return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, preallocate, metadata,
                                  policy, false, false, false, temp_dir, NULL, false, false);
}

bool file_to_disk_secure_update(const char* path, const void* data, unsigned long long data_size,
                                bool inplace, bool sparse, bool preallocate,
                                const FileMetadata* metadata, FileAttrPolicy policy,
                                const char* temp_dir) {
  return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, preallocate, metadata,
                                  policy, true, false, false, temp_dir, NULL, false, false);
}

bool file_to_disk_secure_with_fsync(const char* path, const void* data,
                                    unsigned long long data_size, bool inplace, bool sparse,
                                    bool preallocate, const FileMetadata* metadata,
                                    FileAttrPolicy policy, bool use_fsync, const char* temp_dir) {
  return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, preallocate, metadata,
                                  policy, false, false, use_fsync, temp_dir, NULL, false, false);
}

bool file_to_disk_secure_no_replace(const char* path, const void* data,
                                    unsigned long long data_size, bool sparse, bool preallocate,
                                    const FileMetadata* metadata, FileAttrPolicy policy,
                                    const char* temp_dir) {
  return file_to_disk_secure_impl(path, data, data_size, false, sparse, preallocate, metadata,
                                  policy, false, true, false, temp_dir, NULL, false, false);
}

/* Receiver write-path variant that also applies the per-file xattrs (-X/-A)
 * and, under --fake-super, parks the source stat in the reserved xattr, on the
 * just-written file descriptor before the final rename.  `no_replace` / `update`
 * mirror the plain wrappers; `keep_partial` enables --partial retention of a
 * failed write's temp.  See file_to_disk_secure_impl for the semantics. */
bool file_to_disk_secure_attrs(const char* path, const void* data, unsigned long long data_size,
                               bool inplace, bool sparse, bool preallocate,
                               const FileMetadata* metadata, FileAttrPolicy policy, bool update,
                               bool no_replace, bool use_fsync, const FileXattrList* xattrs,
                               bool fake_super, bool keep_partial, const char* temp_dir) {
  return file_to_disk_secure_impl(path, data, data_size, inplace, sparse, preallocate, metadata,
                                  policy, update, no_replace, use_fsync, temp_dir, xattrs,
                                  fake_super, keep_partial);
}

/* Atomic --link-dest install.  The destination is replaced (via a temporary
 * name and a final rename) with a hard link to `basis_path`.  When a hard
 * link cannot be created (the basis lives on a different filesystem, the
 * filesystem refuses hard links, ...) the install falls back to writing a
 * local copy from `data`/`data_size`, which the caller has already verified is
 * byte-identical to the basis file.  `metadata` is only applied on that copy
 * fallback; a successful hard link keeps the basis inode's own attributes
 * (applying metadata through the shared inode would mutate the basis file).
 * Returns false only when both the link and the copy fallback fail. */
/* --link-dest / -H hardlink install with a byte-copy fallback.  `metadata` is
 * applied only on the copy fallback; a successful hard link keeps the basis
 * inode's own attributes (applying through the shared inode would mutate the
 * basis).  Likewise `xattrs`/`fake_super` are applied only on the copy
 * fallback, so a fallback copy preserves the per-file attributes instead of
 * silently dropping them. */
static bool file_to_disk_secure_link_impl(const char* path, const char* basis_path,
                                          const void* data, unsigned long long data_size,
                                          bool preallocate, const FileMetadata* metadata,
                                          FileAttrPolicy policy, bool use_fsync,
                                          const FileXattrList* xattrs, bool fake_super,
                                          const char* temp_dir) {
  if (!path || !basis_path)
    return false;
  char* leaf = NULL;
  int dirfd = file_open_secure_parent(path, &leaf, true);
  if (dirfd < 0)
    return false;

  int scratch_dirfd = -1;
  if (temp_dir) {
    scratch_dirfd = file_open_temp_dir(temp_dir);
    if (scratch_dirfd < 0) {
      int saved_errno = errno;
      log_message(LOG_LEVEL_ERROR,
                  "--temp-dir '%s' could not be opened (rsync requires it to already exist): %s",
                  temp_dir, strerror(saved_errno));
      close(dirfd);
      free(leaf);
      return false;
    }
  }

  char* basis_leaf = NULL;
  int basis_dirfd = file_open_secure_parent(basis_path, &basis_leaf, false);
  bool linked = false;
  if (basis_dirfd >= 0 && basis_leaf != NULL) {
    int tmp_size = snprintf(NULL, 0, ".%s.tmp.%ld.%llu", leaf, (long)getpid(), ~0ULL);
    char* tmp = NULL;
    if (tmp_size >= 0)
      tmp = malloc((size_t)tmp_size + 1);
    if (!tmp) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed while hard-linking basis file");
    } else {
      for (unsigned int i = 0; i < 100 && !linked; ++i) {
        if (scratch_dirfd >= 0)
          snprintf(tmp, (size_t)tmp_size + 1, ".%s.tmp.%ld.%llu", leaf, (long)getpid(),
                   next_temp_sequence());
        else
          snprintf(tmp, (size_t)tmp_size + 1, ".%s.tmp.%ld.%u", leaf, (long)getpid(), i);
        if (linkat(basis_dirfd, basis_leaf, scratch_dirfd >= 0 ? scratch_dirfd : dirfd, tmp, 0) ==
            0) {
          linked = true;
          break;
        }
        if (errno != EEXIST)
          break; /* EXDEV / EPERM / ...: give up and fall back to a copy */
      }
      if (linked) {
        int target_dirfd = scratch_dirfd >= 0 ? scratch_dirfd : dirfd;
        if (use_fsync) {
          /* O_NONBLOCK: the freshly linked temp is normally the basis's regular
             file, but a raced-in FIFO at the name must not block this reopen
             forever.  With O_NONBLOCK such an open fails with ENXIO instead of
             blocking, which is treated as a benign fsync-skip (the link itself
             is still installed); any other open/fsync failure falls back to the
             byte-copy path as before. */
          int tfd = openat(target_dirfd, tmp, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
          if (tfd < 0) {
            if (errno != ENXIO)
              linked = false;
          } else if (fsync(tfd) != 0) {
            linked = false;
            close(tfd);
          } else {
            close(tfd);
          }
        }
        if (linked && renameat(target_dirfd, tmp, dirfd, leaf) != 0)
          linked = false;
        if (!linked)
          unlinkat(target_dirfd, tmp, 0);
      }
      free(tmp);
    }
  }
  if (basis_dirfd >= 0)
    close(basis_dirfd);
  free(basis_leaf);
  basis_leaf = NULL;

  if (!linked) {
    if (scratch_dirfd >= 0)
      close(scratch_dirfd);
    close(dirfd);
    free(leaf);
    /* The basis file could not be linked in (missing, cross-device, refused
       by the filesystem).  Write a byte-identical local copy instead. */
    return file_to_disk_secure_attrs(path, data, data_size, false, false, preallocate, metadata,
                                     policy, false, false, use_fsync, xattrs, fake_super, false,
                                     temp_dir);
  }

  if (scratch_dirfd >= 0)
    close(scratch_dirfd);
  close(dirfd);
  free(leaf);
  return true;
}

bool file_to_disk_secure_link(const char* path, const char* basis_path, const void* data,
                              unsigned long long data_size, bool preallocate,
                              const FileMetadata* metadata, FileAttrPolicy policy, bool use_fsync,
                              const char* temp_dir) {
  return file_to_disk_secure_link_impl(path, basis_path, data, data_size, preallocate, metadata,
                                       policy, use_fsync, NULL, false, temp_dir);
}

bool file_to_disk_secure_link_attrs(const char* path, const char* basis_path, const void* data,
                                    unsigned long long data_size, bool preallocate,
                                    const FileMetadata* metadata, FileAttrPolicy policy,
                                    bool use_fsync, const FileXattrList* xattrs, bool fake_super,
                                    const char* temp_dir) {
  return file_to_disk_secure_link_impl(path, basis_path, data, data_size, preallocate, metadata,
                                       policy, use_fsync, xattrs, fake_super, temp_dir);
}

bool file_write_to_disk(const char* path, const void* data, unsigned long long data_size,
                        bool inplace, bool sparse) {
  if (!path || (!data && data_size != 0) || has_path_traversal(path))
    return false;
  FileAttrPolicy policy = {false, false, false, false};
  return file_to_disk_secure(path, data, data_size, inplace, sparse, false, NULL, policy, NULL);
}
