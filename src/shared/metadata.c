#include "metadata.h"
#include "file.h"
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
}

FileMetadata* metadata_from_buf(char** buf) {
  int32_t present;
  memcpy(&present, *buf, sizeof(present));
  *buf += sizeof(present);
  if (present != 0 && present != 1)
    return NULL;
  if (!present)
    return NULL;
  FileMetadata* m = malloc(sizeof(FileMetadata));
  if (m == NULL)
    return NULL;
  int32_t mode;
  memcpy(&mode, *buf, sizeof(mode));
  *buf += sizeof(mode);
  m->mode = (mode_t)mode;
  int32_t uid;
  memcpy(&uid, *buf, sizeof(uid));
  *buf += sizeof(uid);
  m->uid = (uid_t)uid;
  int32_t gid;
  memcpy(&gid, *buf, sizeof(gid));
  *buf += sizeof(gid);
  m->gid = (gid_t)gid;
  int64_t mtime_sec;
  memcpy(&mtime_sec, *buf, sizeof(mtime_sec));
  *buf += sizeof(mtime_sec);
  m->mtime_sec = (time_t)mtime_sec;
  int64_t mtime_nsec;
  memcpy(&mtime_nsec, *buf, sizeof(mtime_nsec));
  *buf += sizeof(mtime_nsec);
  m->mtime_nsec = (long)mtime_nsec;
  if (present != 1 || mtime_nsec < 0 || mtime_nsec >= 1000000000LL || mode < 0 || uid < 0 ||
      gid < 0) {
    free(m);
    return NULL;
  }
  return m;
}

bool metadata_send(int file_descriptor, const FileMetadata* m) {
  if (m == NULL) {
    int32_t zero = 0;
    return send_n_data(file_descriptor, &zero, sizeof(zero));
  }
  int32_t present = 1;
  int32_t mode = (int32_t)m->mode;
  int32_t uid = (int32_t)m->uid;
  int32_t gid = (int32_t)m->gid;
  int64_t mtime_sec = (int64_t)m->mtime_sec;
  int64_t mtime_nsec = (int64_t)m->mtime_nsec;
  return send_n_data(file_descriptor, &present, sizeof(present)) &&
         send_n_data(file_descriptor, &mode, sizeof(mode)) &&
         send_n_data(file_descriptor, &uid, sizeof(uid)) &&
         send_n_data(file_descriptor, &gid, sizeof(gid)) &&
         send_n_data(file_descriptor, &mtime_sec, sizeof(mtime_sec)) &&
         send_n_data(file_descriptor, &mtime_nsec, sizeof(mtime_nsec));
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
  FileMetadata* m = malloc(sizeof(FileMetadata));
  if (m == NULL) {
    if (ok)
      *ok = 0;
    return NULL;
  }
  int32_t mode;
  if (!receive_n_data(file_descriptor, &mode, sizeof(mode))) {
    free(m);
    if (ok)
      *ok = 0;
    return NULL;
  }
  m->mode = (mode_t)mode;
  int32_t uid;
  if (!receive_n_data(file_descriptor, &uid, sizeof(uid))) {
    free(m);
    if (ok)
      *ok = 0;
    return NULL;
  }
  m->uid = (uid_t)uid;
  int32_t gid;
  if (!receive_n_data(file_descriptor, &gid, sizeof(gid))) {
    free(m);
    if (ok)
      *ok = 0;
    return NULL;
  }
  m->gid = (gid_t)gid;
  int64_t mtime_sec;
  if (!receive_n_data(file_descriptor, &mtime_sec, sizeof(mtime_sec))) {
    free(m);
    if (ok)
      *ok = 0;
    return NULL;
  }
  m->mtime_sec = (time_t)mtime_sec;
  int64_t mtime_nsec;
  if (!receive_n_data(file_descriptor, &mtime_nsec, sizeof(mtime_nsec))) {
    free(m);
    if (ok)
      *ok = 0;
    return NULL;
  }
  m->mtime_nsec = (long)mtime_nsec;
  if (mtime_nsec < 0 || mtime_nsec >= 1000000000LL || mode < 0 || uid < 0 || gid < 0) {
    free(m);
    if (ok)
      *ok = 0;
    return NULL;
  }
  if (ok)
    *ok = 1;
  return m;
}

void file_restore_metadata(const char* path, const FileMetadata* metadata) {
  if (metadata == NULL)
    return;
  mode_t safe_mode = metadata->mode & 0777 & ~(S_IWGRP | S_IWOTH);
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
  if (utimensat(AT_FDCWD, path, times, 0) != 0) {
    char* escaped_path = output_escape(path, log_get_8_bit_output());
    log_message(LOG_LEVEL_WARNING, "Failed to set timestamps on %s: %s",
                escaped_path ? escaped_path : "<allocation failed>", strerror(errno));
    free(escaped_path);
  }
}

bool file_restore_metadata_fd(int fd, const FileMetadata* metadata) {
  if (fd < 0 || metadata == NULL)
    return metadata == NULL;
  bool ok = true;
  mode_t safe_mode = metadata->mode & 0777 & ~(S_IWGRP | S_IWOTH);
  if (fchmod(fd, safe_mode) != 0)
    ok = false;
  /* Client uid/gid values are deliberately not authoritative. */
  struct timespec times[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT},
                              {.tv_sec = metadata->mtime_sec, .tv_nsec = metadata->mtime_nsec}};
  if (futimens(fd, times) != 0)
    ok = false;
  return ok;
}
