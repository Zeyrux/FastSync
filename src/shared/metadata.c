#include "metadata.h"
#include "file.h"
#include "protocol.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

void metadata_to_buf(char **buf, FileMetadata *m) {
  int present = (m != NULL) ? 1 : 0;
  memcpy(*buf, &present, sizeof(int));
  *buf += sizeof(int);
  if (m == NULL)
    return;
  memcpy(*buf, &m->mode, sizeof(mode_t));        *buf += sizeof(mode_t);
  memcpy(*buf, &m->uid, sizeof(uid_t));          *buf += sizeof(uid_t);
  memcpy(*buf, &m->gid, sizeof(gid_t));          *buf += sizeof(gid_t);
  memcpy(*buf, &m->mtime_sec, sizeof(time_t));   *buf += sizeof(time_t);
  memcpy(*buf, &m->mtime_nsec, sizeof(long));    *buf += sizeof(long);
}

FileMetadata *metadata_from_buf(char **buf) {
  int present;
  memcpy(&present, *buf, sizeof(int));
  *buf += sizeof(int);
  if (!present)
    return NULL;
  FileMetadata *m = malloc(sizeof(FileMetadata));
  memcpy(&m->mode, *buf, sizeof(mode_t));        *buf += sizeof(mode_t);
  memcpy(&m->uid, *buf, sizeof(uid_t));          *buf += sizeof(uid_t);
  memcpy(&m->gid, *buf, sizeof(gid_t));          *buf += sizeof(gid_t);
  memcpy(&m->mtime_sec, *buf, sizeof(time_t));   *buf += sizeof(time_t);
  memcpy(&m->mtime_nsec, *buf, sizeof(long));    *buf += sizeof(long);
  return m;
}

bool metadata_send(int file_descriptor, FileMetadata *m) {
  if (m == NULL) {
    int zero = 0;
    return send_n_data(file_descriptor, &zero, sizeof(int));
  }
  int present = 1;
  return send_n_data(file_descriptor, &present, sizeof(int)) &&
         send_n_data(file_descriptor, &m->mode, sizeof(mode_t)) &&
         send_n_data(file_descriptor, &m->uid, sizeof(uid_t)) &&
         send_n_data(file_descriptor, &m->gid, sizeof(gid_t)) &&
         send_n_data(file_descriptor, &m->mtime_sec, sizeof(time_t)) &&
         send_n_data(file_descriptor, &m->mtime_nsec, sizeof(long));
}

FileMetadata *metadata_receive(int file_descriptor, int *ok) {
  int present;
  if (!receive_n_data(file_descriptor, &present, sizeof(int))) {
    if (ok) *ok = 0;
    return NULL;
  }
  if (!present) {
    if (ok) *ok = 1;
    return NULL;
  }
  FileMetadata *m = malloc(sizeof(FileMetadata));
  if (m == NULL) { if (ok) *ok = 0; return NULL; }
  if (!receive_n_data(file_descriptor, &m->mode, sizeof(mode_t)) ||
      !receive_n_data(file_descriptor, &m->uid, sizeof(uid_t)) ||
      !receive_n_data(file_descriptor, &m->gid, sizeof(gid_t)) ||
      !receive_n_data(file_descriptor, &m->mtime_sec, sizeof(time_t)) ||
      !receive_n_data(file_descriptor, &m->mtime_nsec, sizeof(long))) {
    free(m);
    if (ok) *ok = 0;
    return NULL;
  }
  if (ok) *ok = 1;
  return m;
}

void file_restore_metadata(const char *path, FileMetadata *metadata) {
  if (metadata == NULL)
    return;
  chmod(path, metadata->mode & 07777);
  int chown_ret = chown(path, metadata->uid, metadata->gid);
  (void)chown_ret;
  struct timespec times[2];
  times[0].tv_sec = 0;
  times[0].tv_nsec = UTIME_OMIT;
  times[1].tv_sec = metadata->mtime_sec;
  times[1].tv_nsec = metadata->mtime_nsec;
  utimensat(AT_FDCWD, path, times, 0);
}
