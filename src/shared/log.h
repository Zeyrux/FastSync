#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdint.h>

typedef enum { LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR } LogLevel;

typedef enum {
  LOG_DEBUG_IO = 1u << 0,
  LOG_DEBUG_PROTO = 1u << 1,
  LOG_DEBUG_PACK = 1u << 2,
  LOG_DEBUG_UTIL = 1u << 3,
  LOG_DEBUG_ALL = (1u << 4) - 1,
} LogDebugFlag;

void log_message(LogLevel log_level, const char* message, ...);
void log_perror(const char* context);
void set_log_level(LogLevel level);
void set_log_debug_flags(uint32_t flags);
uint32_t get_log_debug_flags(void);
void log_debug_message(LogDebugFlag flag, const char* message, ...);
void log_set_file(FILE* fp);

#endif
