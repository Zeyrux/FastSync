#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdint.h>

typedef enum { LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR } LogLevel;

typedef enum {
  LOG_INFO_COPY = 1u << 0,
  LOG_INFO_DEL = 1u << 1,
  LOG_INFO_FLIST = 1u << 2,
  LOG_INFO_MISC = 1u << 3,
  LOG_INFO_MOUNT = 1u << 4,
  LOG_INFO_NAME = 1u << 5,
  LOG_INFO_NONREG = 1u << 6,
  LOG_INFO_PROGRESS = 1u << 7,
  LOG_INFO_SKIP = 1u << 8,
  LOG_INFO_STATS = 1u << 9,
  LOG_INFO_SYMSAFE = 1u << 10,
  LOG_INFO_BACKUP = 1u << 11,
  LOG_INFO_ALL = (1u << 12) - 1,
} LogInfoFlag;

void log_message(LogLevel log_level, const char* message, ...);
void log_perror(const char* context);
void set_log_level(LogLevel level);
void set_log_info_flags(uint32_t flags);
uint32_t get_log_info_flags(void);
void log_info_message(LogInfoFlag flag, const char* message, ...);
void log_set_file(FILE* fp);

#endif
