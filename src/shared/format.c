#include "format.h"
#include "protocol.h"
#include <stdio.h>
#include <string.h>

bool format_human_size_decimal(unsigned long long bytes, char* buffer, size_t buffer_size) {
  if (!buffer || buffer_size == 0)
    return false;
  if (bytes < 1000ULL) {
    int written = snprintf(buffer, buffer_size, "%llu", bytes);
    return written >= 0 && (size_t)written < buffer_size;
  }
  static const char units[] = "KMGTPE";
  double value = (double)bytes;
  size_t divisions = 0;
  while (value >= 1000.0 && divisions < sizeof(units) - 1) {
    value /= 1000.0;
    divisions++;
  }
  int written = snprintf(buffer, buffer_size, "%.2f%c", value, units[divisions - 1]);
  return written >= 0 && (size_t)written < buffer_size;
}

bool format_big_num(unsigned long long value, bool human_readable, char* buffer,
                    size_t buffer_size) {
  if (human_readable)
    return format_human_size_decimal(value, buffer, buffer_size);
  char digits[32];
  int written = snprintf(digits, sizeof(digits), "%llu", value);
  if (written < 0 || (size_t)written >= sizeof(digits))
    return false;
  size_t len = (size_t)written;
  size_t separators = len > 1 ? (len - 1) / 3 : 0;
  size_t total = len + separators;
  if (total + 1 > buffer_size)
    return false;
  size_t out = total;
  buffer[out] = '\0';
  size_t digits_since_sep = 0;
  for (size_t i = len; i > 0; i--) {
    buffer[--out] = digits[i - 1];
    digits_since_sep++;
    if (digits_since_sep == 3 && i > 1) {
      buffer[--out] = ',';
      digits_since_sep = 0;
    }
  }
  return true;
}

bool format_rsync_datetime(time_t when, bool dash, char* buffer, size_t buffer_size) {
  if (!buffer || buffer_size == 0)
    return false;
  struct tm broken_down;
  if (localtime_r(&when, &broken_down) == NULL)
    return false;
  const char* format = dash ? "%Y/%m/%d-%H:%M:%S" : "%Y/%m/%d %H:%M:%S";
  return strftime(buffer, buffer_size, format, &broken_down) != 0;
}

bool format_dest_state_send(int fd, const OutputDestState* state) {
  if (!state)
    return false;
  int32_t has_old = state->existed ? 1 : 0;
  int32_t target_matches = state->target_matches ? 1 : 0;
  uint64_t size = (uint64_t)state->size;
  int64_t mtime = (int64_t)state->mtime_sec;
  int64_t mtime_nsec = state->mtime_nsec;
  uint32_t mode = state->mode;
  int32_t uid = state->uid;
  int32_t gid = state->gid;
  return send_n_data(fd, &has_old, sizeof(has_old)) &&
         send_n_data(fd, &target_matches, sizeof(target_matches)) &&
         send_n_data(fd, &size, sizeof(size)) && send_n_data(fd, &mtime, sizeof(mtime)) &&
         send_n_data(fd, &mtime_nsec, sizeof(mtime_nsec)) && send_n_data(fd, &mode, sizeof(mode)) &&
         send_n_data(fd, &uid, sizeof(uid)) && send_n_data(fd, &gid, sizeof(gid));
}

bool format_dest_state_receive(int fd, OutputDestState* state) {
  if (!state)
    return false;
  int32_t has_old = 0;
  int32_t target_matches = 0;
  uint64_t size = 0;
  int64_t mtime = 0;
  int64_t mtime_nsec = 0;
  uint32_t mode = 0;
  int32_t uid = 0;
  int32_t gid = 0;
  if (!receive_n_data(fd, &has_old, sizeof(has_old)) ||
      !receive_n_data(fd, &target_matches, sizeof(target_matches)) ||
      !receive_n_data(fd, &size, sizeof(size)) || !receive_n_data(fd, &mtime, sizeof(mtime)) ||
      !receive_n_data(fd, &mtime_nsec, sizeof(mtime_nsec)) ||
      !receive_n_data(fd, &mode, sizeof(mode)) || !receive_n_data(fd, &uid, sizeof(uid)) ||
      !receive_n_data(fd, &gid, sizeof(gid)))
    return false;
  memset(state, 0, sizeof(*state));
  state->known = true;
  state->existed = has_old != 0;
  state->target_matches = target_matches != 0;
  state->size = size;
  state->mtime_sec = mtime;
  state->mtime_nsec = mtime_nsec;
  state->mode = mode;
  state->uid = uid;
  state->gid = gid;
  return true;
}

bool format_stats_send(int fd, const ReceiverStats* stats) {
  if (!stats)
    return false;
  unsigned long long fields[12] = {
      stats->matched_data, stats->deleted_files, stats->would_delete_count, stats->literal_bytes,
      stats->created_reg,  stats->created_dir,   stats->created_link,       stats->created_special,
      stats->deleted_reg,  stats->deleted_dir,   stats->deleted_link,       stats->deleted_special,
  };
  return send_n_data(fd, fields, sizeof(fields));
}

bool format_stats_receive(int fd, ReceiverStats* stats) {
  if (!stats)
    return false;
  unsigned long long fields[12] = {0};
  if (!receive_n_data(fd, fields, sizeof(fields)))
    return false;
  memset(stats, 0, sizeof(*stats));
  stats->matched_data = fields[0];
  stats->deleted_files = fields[1];
  stats->would_delete_count = fields[2];
  stats->literal_bytes = fields[3];
  stats->created_reg = fields[4];
  stats->created_dir = fields[5];
  stats->created_link = fields[6];
  stats->created_special = fields[7];
  stats->deleted_reg = fields[8];
  stats->deleted_dir = fields[9];
  stats->deleted_link = fields[10];
  stats->deleted_special = fields[11];
  return true;
}
