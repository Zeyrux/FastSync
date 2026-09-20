#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum { LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR } LogLevel;
typedef enum { LOG_STDERR_ERRORS, LOG_STDERR_ALL } LogStderrMode;

typedef enum {
  LOG_DEBUG_IO = 1u << 0,
  LOG_DEBUG_PROTO = 1u << 1,
  LOG_DEBUG_PACK = 1u << 2,
  LOG_DEBUG_UTIL = 1u << 3,
  /* rsync --debug categories that now map to a natural FastSync event:
   * flist (file-list scan progress), del (deletions), hash/deltasum
   * (whole-file hashing and delta-sum generation), recv (receiver
   * responses/signatures), filter (selection/exclusion decisions) and send
   * (files handed to the sender).  Only emitted when the category is
   * explicitly enabled; a normal run stays silent. */
  LOG_DEBUG_FLIST = 1u << 4,
  LOG_DEBUG_DEL = 1u << 5,
  LOG_DEBUG_HASH = 1u << 6,
  LOG_DEBUG_RECV = 1u << 7,
  LOG_DEBUG_FILTER = 1u << 8,
  LOG_DEBUG_SEND = 1u << 9,
  LOG_DEBUG_ALL = (1u << 10) - 1,
} LogDebugFlag;

typedef enum {
  LOG_INFO_COPY = 1u << 0,
  LOG_INFO_MISC = 1u << 1,
  LOG_INFO_SKIP = 1u << 2,
  LOG_INFO_STATS = 1u << 3,
  /* rsync categories that map to a FastSync event (emitted in rsync's line
   * format): del (deletions), remove (sender-side source removal), name
   * (transferred entry names), flist (file-list header), nonreg (skipped
   * non-regular files), progress (per-file progress).  rsync's `backup`
   * category is accepted for CLI parity but stays silent: the receiver does the
   * backing-up and FastSync has no backup event to report from the sender. */
  LOG_INFO_DEL = 1u << 4,
  LOG_INFO_REMOVE = 1u << 5,
  LOG_INFO_NAME = 1u << 6,
  LOG_INFO_FLIST = 1u << 7,
  LOG_INFO_NONREG = 1u << 8,
  LOG_INFO_PROGRESS = 1u << 9,
  /* Marker for `--info=name2` and higher: also print rsync's
     "NAME is uptodate" line for entries the receiver already has.  It rides in
     the info_level bitset (there is no separate Config field) and is never set
     by --info=all (which selects level 1). */
  LOG_INFO_NAME_UPTODATE = 1u << 10,
  /* --info=mount: print rsync's `[sender] skipping mount-point dir NAME` when
   * -xx/--one-file-system drops a mount-point directory (FastSync's client is
   * the sender). */
  LOG_INFO_MOUNT = 1u << 11,
  LOG_INFO_ALL = LOG_INFO_COPY | LOG_INFO_MISC | LOG_INFO_SKIP | LOG_INFO_STATS | LOG_INFO_DEL |
                 LOG_INFO_REMOVE | LOG_INFO_NAME | LOG_INFO_FLIST | LOG_INFO_NONREG |
                 LOG_INFO_PROGRESS | LOG_INFO_MOUNT,
} LogInfoFlag;

void log_message(LogLevel log_level, const char* message, ...);
void log_perror(const char* context);
void set_log_level(LogLevel level);
void set_log_debug_flags(uint32_t flags);
uint32_t get_log_debug_flags(void);
/* True when a log_debug_message() call with the same flag would actually emit:
 * the debug log level is enabled AND the flag is selected.  Hot paths use this
 * to skip expensive message formatting/escaping when the line is filtered. */
bool log_debug_enabled(LogDebugFlag flag);
void log_debug_message(LogDebugFlag flag, const char* message, ...);
void set_log_info_flags(uint32_t flags);
uint32_t get_log_info_flags(void);
void log_info_message(LogInfoFlag flag, const char* message, ...);
void log_set_file(FILE* fp);
void log_set_8_bit_output(bool enabled);
bool log_get_8_bit_output(void);
void log_set_stderr_mode(LogStderrMode mode);
LogStderrMode log_get_stderr_mode(void);

#endif
