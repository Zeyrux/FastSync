#include "metadata.h"
#include "file.h"
#include "log.h"
#include "protocol.h"
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
  return m;
}

bool metadata_send(int file_descriptor, FileMetadata* m) {
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
  if (!present) {
    if (ok)
      *ok = 1;
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
  if (ok)
    *ok = 1;
  return m;
}

void file_restore_metadata(const char* path, FileMetadata* metadata) {
  if (metadata == NULL)
    return;
  if (chmod(path, metadata->mode & 07777 & ~(S_ISUID | S_ISGID)) != 0)
    log_message(LOG_LEVEL_WARNING, "Failed to chmod %s: %s", path, strerror(errno));
  if (chown(path, metadata->uid, metadata->gid) != 0)
    log_message(LOG_LEVEL_WARNING, "Failed to chown %s: %s", path, strerror(errno));
  struct timespec times[2];
  times[0].tv_sec = 0;
  times[0].tv_nsec = UTIME_OMIT;
  times[1].tv_sec = metadata->mtime_sec;
  times[1].tv_nsec = metadata->mtime_nsec;
  if (utimensat(AT_FDCWD, path, times, 0) != 0)
    log_message(LOG_LEVEL_WARNING, "Failed to set timestamps on %s: %s", path, strerror(errno));
}
