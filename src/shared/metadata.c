#include "metadata.h"
#include "file.h"
#include "identity.h"
#include "log.h"
#include "protocol.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/*
 * Wire format serialization (protocol version 2.0.0+):
 * All metadata fields are serialized as fixed-width integers (int32_t / int64_t)
 * to ensure cross-platform binary compatiblity.  See metadata.h for the
 * exact wire layout.
 *
 * Compile-time assertions verify that the native platform types fit within
 * the chosen fixed-width representations.
 */
typedef char static_assert_mode_t_fits[(sizeof(mode_t) <= sizeof(int32_t)) ? 1 : -1];
typedef char static_assert_uid_t_fits[(sizeof(uid_t) <= sizeof(int32_t)) ? 1 : -1];
typedef char static_assert_gid_t_fits[(sizeof(gid_t) <= sizeof(int32_t)) ? 1 : -1];

bool metadata_mtime_matches(time_t left_sec, long left_nsec, time_t right_sec, long right_nsec,
                            int modify_window) {
  int64_t left = (int64_t)left_sec;
  int64_t right = (int64_t)right_sec;
  int64_t seconds;
  int64_t nanoseconds;

  if (left > right || (left == right && left_nsec >= right_nsec)) {
    seconds = left - right;
    nanoseconds = (int64_t)left_nsec - (int64_t)right_nsec;
  } else {
    seconds = right - left;
    nanoseconds = (int64_t)right_nsec - (int64_t)left_nsec;
  }
  if (nanoseconds < 0) {
    seconds--;
    nanoseconds += 1000000000LL;
  }
  if (modify_window == 0)
    return left == right;
  return seconds < modify_window || (seconds == modify_window && nanoseconds == 0);
}

void metadata_to_buf(char** buf, const FileMetadata* m) {
  int32_t present = (m != NULL) ? 1 : 0;
  memcpy(*buf, &present, sizeof(present));
  *buf += sizeof(present);
  if (m == NULL)
    return;
  int32_t mode = (int32_t)m->mode;
  memcpy(*buf, &mode, sizeof(mode));
  *buf += sizeof(mode);
  int32_t uid = (int32_t)m->uid;
  memcpy(*buf, &uid, sizeof(uid));
  *buf += sizeof(uid);
  int32_t gid = (int32_t)m->gid;
  memcpy(*buf, &gid, sizeof(gid));
  *buf += sizeof(gid);
  int64_t mtime_sec = (int64_t)m->mtime_sec;
  memcpy(*buf, &mtime_sec, sizeof(mtime_sec));
  *buf += sizeof(mtime_sec);
  int64_t mtime_nsec = (int64_t)m->mtime_nsec;
  memcpy(*buf, &mtime_nsec, sizeof(mtime_nsec));
  *buf += sizeof(mtime_nsec);
  int32_t atime_valid = m->atime_valid ? 1 : 0;
  memcpy(*buf, &atime_valid, sizeof(atime_valid));
  *buf += sizeof(atime_valid);
  int64_t atime_sec = (int64_t)m->atime_sec;
  memcpy(*buf, &atime_sec, sizeof(atime_sec));
  *buf += sizeof(atime_sec);
  int64_t atime_nsec = (int64_t)m->atime_nsec;
  memcpy(*buf, &atime_nsec, sizeof(atime_nsec));
  *buf += sizeof(atime_nsec);
  int32_t crtime_valid = m->crtime_valid ? 1 : 0;
  memcpy(*buf, &crtime_valid, sizeof(crtime_valid));
  *buf += sizeof(crtime_valid);
  int64_t crtime_sec = (int64_t)m->crtime_sec;
  memcpy(*buf, &crtime_sec, sizeof(crtime_sec));
  *buf += sizeof(crtime_sec);
  int64_t crtime_nsec = (int64_t)m->crtime_nsec;
  memcpy(*buf, &crtime_nsec, sizeof(crtime_nsec));
  *buf += sizeof(crtime_nsec);
}

FileMetadata* metadata_from_buf(const uint8_t* buf, size_t len) {
  if (buf == NULL || len < sizeof(int32_t))
    return NULL;
  int32_t present;
  memcpy(&present, buf, sizeof(present));
  if (present != 1)
    return NULL;
  if (len < sizeof(int32_t) + FILE_METADATA_WIRE_SIZE)
    return NULL;
  const uint8_t* cursor = buf + sizeof(int32_t);
  FileMetadata* m = protocol_alloc(sizeof(FileMetadata));
  if (m == NULL)
    return NULL;
  int32_t mode;
  memcpy(&mode, cursor, sizeof(mode));
  cursor += sizeof(mode);
  m->mode = (mode_t)mode;
  int32_t uid;
  memcpy(&uid, cursor, sizeof(uid));
  cursor += sizeof(uid);
  m->uid = (uid_t)uid;
  int32_t gid;
  memcpy(&gid, cursor, sizeof(gid));
  cursor += sizeof(gid);
  m->gid = (gid_t)gid;
  int64_t mtime_sec;
  memcpy(&mtime_sec, cursor, sizeof(mtime_sec));
  cursor += sizeof(mtime_sec);
  m->mtime_sec = (time_t)mtime_sec;
  int64_t mtime_nsec;
  memcpy(&mtime_nsec, cursor, sizeof(mtime_nsec));
  cursor += sizeof(mtime_nsec);
  m->mtime_nsec = (long)mtime_nsec;
  int32_t atime_valid;
  memcpy(&atime_valid, cursor, sizeof(atime_valid));
  cursor += sizeof(atime_valid);
  int64_t atime_sec;
  memcpy(&atime_sec, cursor, sizeof(atime_sec));
  cursor += sizeof(atime_sec);
  int64_t atime_nsec;
  memcpy(&atime_nsec, cursor, sizeof(atime_nsec));
  cursor += sizeof(atime_nsec);
  int32_t crtime_valid;
  memcpy(&crtime_valid, cursor, sizeof(crtime_valid));
  cursor += sizeof(crtime_valid);
  int64_t crtime_sec;
  memcpy(&crtime_sec, cursor, sizeof(crtime_sec));
  cursor += sizeof(crtime_sec);
  int64_t crtime_nsec;
  memcpy(&crtime_nsec, cursor, sizeof(crtime_nsec));
  cursor += sizeof(crtime_nsec);
  m->atime_valid = atime_valid != 0;
  m->atime_sec = (time_t)atime_sec;
  m->atime_nsec = (long)atime_nsec;
  m->crtime_valid = crtime_valid != 0;
  m->crtime_sec = (time_t)crtime_sec;
  m->crtime_nsec = (long)crtime_nsec;
  if (mtime_nsec < 0 || mtime_nsec >= 1000000000LL || mode < 0 || uid < 0 || gid < 0 ||
      atime_valid < 0 || atime_valid > 1 || crtime_valid < 0 || crtime_valid > 1 ||
      (atime_valid && (atime_nsec < 0 || atime_nsec >= 1000000000LL)) ||
      (crtime_valid && (crtime_nsec < 0 || crtime_nsec >= 1000000000LL))) {
    free(m);
    return NULL;
  }
  return m;
}

bool metadata_send(int file_descriptor, const FileMetadata* m) {
  if (m == NULL) {
    int32_t absent = 0;
    return send_n_data(file_descriptor, &absent, sizeof(absent));
  }
  /* One packed frame (protocol 2.20.0): the int32 present flag followed by the
     fixed FILE_METADATA_WIRE_SIZE-byte field record.  metadata_to_buf() emits
     exactly that layout (present + fields), so build it once and write the
     whole record in a single call instead of one frame per field. */
  char packed[sizeof(int32_t) + FILE_METADATA_WIRE_SIZE];
  char* cursor = packed;
  metadata_to_buf(&cursor, m);
  return send_n_data(file_descriptor, packed, sizeof(packed));
}

FileMetadata* metadata_receive(int file_descriptor, int* ok) {
  int32_t present;
  if (!receive_n_data(file_descriptor, &present, sizeof(present))) {
    if (ok)
      *ok = 0;
    return NULL;
  }
  if (present == 0) {
    if (ok)
      *ok = 1;
    return NULL;
  }
  if (present != 1) {
    if (ok)
      *ok = 0;
    return NULL;
  }
  /* Rebuild the packed record metadata_from_buf() expects: the present flag we
     just read, followed by exactly FILE_METADATA_WIRE_SIZE field bytes. */
  char packed[sizeof(int32_t) + FILE_METADATA_WIRE_SIZE];
  memcpy(packed, &present, sizeof(present));
  if (!receive_n_data(file_descriptor, packed + sizeof(present), FILE_METADATA_WIRE_SIZE)) {
    if (ok)
      *ok = 0;
    return NULL;
  }
  FileMetadata* m = metadata_from_buf((const uint8_t*)packed, sizeof(packed));
  if (m == NULL) {
    if (ok)
      *ok = 0;
    return NULL;
  }
  if (ok)
    *ok = 1;
  return m;
}

static mode_t metadata_mode(const FileMetadata* metadata, mode_t current_mode,
                            bool preserve_executability) {
  const mode_t execute_bits = S_IXUSR | S_IXGRP | S_IXOTH;
  if (preserve_executability)
    return (current_mode & 0777 & ~execute_bits) | (metadata->mode & execute_bits);
  return metadata->mode & 0777 & ~(S_IWGRP | S_IWOTH);
}

void file_restore_metadata(const char* path, const FileMetadata* metadata,
                           bool preserve_executability) {
  if (metadata == NULL)
    return;
  struct stat current;
  mode_t current_mode = stat(path, &current) == 0 ? current.st_mode : 0;
  mode_t safe_mode = metadata_mode(metadata, current_mode, preserve_executability);
  if (chmod(path, safe_mode) != 0) {
    char* escaped_path = output_escape(path, log_get_8_bit_output());
    log_message(LOG_LEVEL_WARNING, "Failed to chmod %s: %s",
                escaped_path ? escaped_path : "<allocation failed>", strerror(errno));
    free(escaped_path);
  }
  /* Never apply client-supplied ownership.  The descriptor API below is the
     receiver write path; retain this legacy API only for compatibility. */
  struct timespec times[2];
  times[0].tv_sec = 0;
  times[0].tv_nsec = UTIME_OMIT;
  times[1].tv_sec = metadata->mtime_sec;
  times[1].tv_nsec = metadata->mtime_nsec;
  if (metadata->atime_valid) {
    times[0].tv_sec = metadata->atime_sec;
    times[0].tv_nsec = metadata->atime_nsec;
  }
  if (metadata->crtime_valid) {
    log_message(LOG_LEVEL_DEBUG,
                "crtime (birth time) %lld.%09ld transmitted for %s but not applied: no portable "
                "setter exists",
                (long long)metadata->crtime_sec, metadata->crtime_nsec, path);
  }
  if (utimensat(AT_FDCWD, path, times, 0) != 0) {
    char* escaped_path = output_escape(path, log_get_8_bit_output());
    log_message(LOG_LEVEL_WARNING, "Failed to set timestamps on %s: %s",
                escaped_path ? escaped_path : "<allocation failed>", strerror(errno));
    free(escaped_path);
  }
}

bool file_restore_symlink_metadata(const char* path, const FileMetadata* metadata,
                                   bool omit_link_times) {
  if (path == NULL || metadata == NULL)
    return !identity_copy_as_active();
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(path, &leaf, false);
  if (parent_fd < 0)
    return !identity_copy_as_active();
  /* Ownership (only when the identity policy is active) via lchown semantics:
     fchownat with AT_SYMLINK_NOFOLLOW never dereferences the link.  A failed
     REQUIRED --copy-as ownership marks the entry failed; every other policy is
     best-effort. */
  bool owned = identity_apply_ownership_link(parent_fd, leaf, (int32_t)metadata->uid,
                                             (int32_t)metadata->gid);
  /* Symlink mode: not settable on Linux (fchmodat AT_SYMLINK_NOFOLLOW returns
     EOPNOTSUPP/ENOTSUP); attempt it for platforms that support it and quietly
     ignore the unsupported case so the transfer never fails over it. */
  mode_t link_mode = metadata->mode & 0777;
  if (fchmodat(parent_fd, leaf, link_mode, AT_SYMLINK_NOFOLLOW) != 0 && errno != EOPNOTSUPP &&
      errno != ENOTSUP && errno != ENOSYS) {
    log_message(LOG_LEVEL_DEBUG, "Could not set symlink mode on %s: %s", path, strerror(errno));
  }
  if (!omit_link_times) {
    struct timespec times[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT},
                                {.tv_sec = metadata->mtime_sec, .tv_nsec = metadata->mtime_nsec}};
    if (metadata->atime_valid) {
      times[0].tv_sec = metadata->atime_sec;
      times[0].tv_nsec = metadata->atime_nsec;
    }
    if (utimensat(parent_fd, leaf, times, AT_SYMLINK_NOFOLLOW) != 0) {
      char* escaped_path = output_escape(path, log_get_8_bit_output());
      log_message(LOG_LEVEL_WARNING, "Failed to set symlink timestamps on %s: %s",
                  escaped_path ? escaped_path : "<allocation failed>", strerror(errno));
      free(escaped_path);
    }
  }
  close(parent_fd);
  free(leaf);
  return owned;
}

bool file_restore_metadata_fd(int fd, const FileMetadata* metadata, bool preserve_executability) {
  if (fd < 0 || metadata == NULL)
    return metadata == NULL;
  bool ok = true;
  struct stat current;
  if (fstat(fd, &current) != 0)
    return false;
  mode_t safe_mode = metadata_mode(metadata, current.st_mode, preserve_executability);
  if (fchmod(fd, safe_mode) != 0)
    ok = false;
  /* Client uid/gid values are deliberately not authoritative UNLESS the client
     explicitly opted in with an identity flag (--numeric-ids / --usermap /
     --groupmap / --chown).  identity_apply_ownership is the controlled,
     privilege-gated path: it consults the negotiated policy, resolves the
     target ids, and applies them via an fd-relative fchown() that is confined
     to the just-written file (EPERM/EACCES are logged, never fatal) -- EXCEPT
     for an active --copy-as, whose forced ownership is REQUIRED: a failure
     marks this entry as failed instead of reporting a wrong-owner write as
     success.  With no identity flag set it is a no-op, so a default or plain -M
     transfer keeps FastSync's existing behavior of never applying client
     ownership. */
  if (!identity_apply_ownership(fd, (int32_t)metadata->uid, (int32_t)metadata->gid))
    ok = false;
  struct timespec times[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT},
                              {.tv_sec = metadata->mtime_sec, .tv_nsec = metadata->mtime_nsec}};
  if (metadata->atime_valid) {
    times[0].tv_sec = metadata->atime_sec;
    times[0].tv_nsec = metadata->atime_nsec;
  }
  /* --crtimes captures and transmits the source birth time, but there is no
   * portable way to set a birth time (utimensat can only set atime/mtime), so
   * the receiver deliberately does NOT apply it.  This is explicit, honest
   * unsupported-attribute handling: log a debug note and continue — never fail
   * the transfer and never pretend the crtime was applied. */
  if (metadata->crtime_valid) {
    log_message(LOG_LEVEL_DEBUG,
                "crtime (birth time) %lld.%09ld transmitted but not applied: no portable setter",
                (long long)metadata->crtime_sec, metadata->crtime_nsec);
  }
  if (futimens(fd, times) != 0)
    ok = false;
  return ok;
}
