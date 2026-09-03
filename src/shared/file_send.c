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

#include "compression.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"

bool file_send_single_calls(File* file, int file_descriptor, bool use_metadata,
                            int compression_level, bool send_path) {
  return file_send_single_calls_with_skip(file, file_descriptor, use_metadata, compression_level,
                                          send_path, NULL, -1);
}

bool file_send_single_calls_with_skip(File* file, int file_descriptor, bool use_metadata,
                                      int compression_level, bool send_path,
                                      char* const* skip_suffixes, int skip_count) {
  if (!file || !file->path || !file->data || (file->data->size != 0 && !file->data->data))
    return false;
  const Data* data_to_send = file->data;
  Data* compressed_data = NULL;
  if (compression_level > 0 &&
      !compression_should_skip_with_suffixes(file->path, skip_suffixes, skip_count)) {
    compressed_data = data_compress(file->data, compression_level);
    if (compressed_data == NULL) {
      log_message(LOG_LEVEL_ERROR, "Failed to compress file data");
      return false;
    }
    data_to_send = compressed_data;
  }
  if (send_path && !send_str(file_descriptor, file->path)) {
    data_destroy(compressed_data);
    return false;
  }
  if (use_metadata && !metadata_send(file_descriptor, file->metadata)) {
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
                                      send_path, NULL, -1);
}

bool file_send_sendfile_with_skip(File* file, int file_descriptor, bool use_metadata,
                                  int compression_level, bool send_path, char* const* skip_suffixes,
                                  int skip_count) {
  if (!file || !file->path || !file->data)
    return false;
  if (compression_level > 0)
    return file_send_single_calls_with_skip(file, file_descriptor, use_metadata, compression_level,
                                            send_path, skip_suffixes, skip_count);

  if (send_path && !send_str(file_descriptor, file->path))
    return false;
  if (use_metadata && !metadata_send(file_descriptor, file->metadata))
    return false;

  int fd = open(file->path, O_RDONLY);
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
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += 60;
  while ((unsigned long long)offset < file_size) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long remaining = (long long)(deadline.tv_sec - now.tv_sec) * 1000LL +
                          (deadline.tv_nsec - now.tv_nsec) / 1000000LL;
    if (remaining <= 0) {
      close(fd);
      return false;
    }
    struct pollfd pfd = {.fd = file_descriptor, .events = POLLOUT};
    int timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
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
  }

  close(fd);
  return true;
}
