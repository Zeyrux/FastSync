#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "charset.h"
#include "compression.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "xattr.h"

/* Transmit a device/special node (--devices / --specials) as a STATUS_SPECIAL
 * frame: the destination path, the metadata frame (whose mode's S_IFMT bits
 * carry the node kind) and the device rdev major/minor.  The receiver validates
 * the kind and rdev and recreates the node (privilege-gating the mknod). */
bool file_send_special(const File* file, int file_descriptor, bool use_metadata) {
  if (!file || !file_wire_path(file))
    return false;
  if (!send_status(file_descriptor, STATUS_SPECIAL))
    return false;
  if (!send_wire_str(file_descriptor, file_wire_path(file)))
    return false;
  if (use_metadata && !metadata_send(file_descriptor, file->metadata))
    return false;
  int32_t major = file->rdev_major;
  int32_t minor = file->rdev_minor;
  return send_n_data(file_descriptor, &major, sizeof(major)) &&
         send_n_data(file_descriptor, &minor, sizeof(minor));
}

bool file_send_single_calls(File* file, int file_descriptor, bool use_metadata,
                            int compression_level, bool send_path) {
  return file_send_single_calls_with_skip(file, file_descriptor, use_metadata, compression_level,
                                          send_path, NULL, -1, 0, false);
}

bool file_send_single_calls_with_skip(File* file, int file_descriptor, bool use_metadata,
                                      int compression_level, bool send_path,
                                      char* const* skip_suffixes, int skip_count,
                                      int compression_threads, bool send_xattrs) {
  if (!file || !file->path || !file->data || (file->data->size != 0 && !file->data->data))
    return false;
  const Data* data_to_send = file->data;
  Data* compressed_data = NULL;
  if (compression_level > 0 &&
      !compression_should_skip_with_suffixes(file->path, skip_suffixes, skip_count)) {
    compressed_data =
        data_compress_with_threads(file->data, compression_level, compression_threads);
    if (compressed_data == NULL) {
      log_message(LOG_LEVEL_ERROR, "Failed to compress file data");
      return false;
    }
    data_to_send = compressed_data;
  }
  if (send_path && !send_wire_str(file_descriptor, file_wire_path(file))) {
    data_destroy(compressed_data);
    return false;
  }
  if (use_metadata && !metadata_send(file_descriptor, file->metadata)) {
    data_destroy(compressed_data);
    return false;
  }
  if (send_xattrs && !xattr_send(file_descriptor, file ? file->xattrs : NULL)) {
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

bool file_send_sendfile(File* file, int file_descriptor, bool use_metadata, int compression_level,
                        bool send_path) {
  return file_send_sendfile_with_skip(file, file_descriptor, use_metadata, compression_level,
                                      send_path, NULL, -1, 0, false);
}

bool file_send_sendfile_with_skip(File* file, int file_descriptor, bool use_metadata,
                                  int compression_level, bool send_path, char* const* skip_suffixes,
                                  int skip_count, int compression_threads, bool send_xattrs) {
  if (!file || !file->path || !file->data)
    return false;
  if (compression_level > 0)
    return file_send_single_calls_with_skip(file, file_descriptor, use_metadata, compression_level,
                                            send_path, skip_suffixes, skip_count,
                                            compression_threads, send_xattrs);

  if (send_path && !send_wire_str(file_descriptor, file_wire_path(file)))
    return false;
  if (use_metadata && !metadata_send(file_descriptor, file->metadata))
    return false;
  if (send_xattrs && !xattr_send(file_descriptor, file ? file->xattrs : NULL))
    return false;

  int fd = file_open_for_read(file->path);
  if (fd == -1) {
    log_perror("Could not open file for sendfile");
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
  /* A non-positive --timeout disables the deadline: poll blocks until the
   * socket is writable (rsync's --timeout=0 default). */
  int io_timeout_sec = protocol_get_io_timeout_sec();
  struct timespec deadline;
  if (io_timeout_sec > 0) {
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += io_timeout_sec;
  }
  while ((unsigned long long)offset < file_size) {
    int timeout = -1;
    if (io_timeout_sec > 0) {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      long long remaining = (long long)(deadline.tv_sec - now.tv_sec) * 1000LL +
                            (deadline.tv_nsec - now.tv_nsec) / 1000000LL;
      if (remaining <= 0) {
        close(fd);
        return false;
      }
      timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
    }
    struct pollfd pfd = {.fd = file_descriptor, .events = POLLOUT};
    int polled = poll(&pfd, 1, timeout);
    if (polled <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
      close(fd);
      return false;
    }
    ssize_t sent = sendfile(file_descriptor, fd, &offset, file_size - offset);
    if (sent == -1) {
      if (errno == EAGAIN || errno == EINTR)
        continue;
      log_perror("sendfile failed");
      close(fd);
      return false;
    }
    if (sent == 0) {
      close(fd);
      return false;
    }
    protocol_note_bytes_written((unsigned long long)sent);
  }

  close(fd);
  return true;
}
