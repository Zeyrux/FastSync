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
  LOG_DEBUG_ACL = 1u << 4,
  LOG_DEBUG_BACKUP = 1u << 5,
  LOG_DEBUG_BIND = 1u << 6,
  LOG_DEBUG_CHKSUM = 1u << 7,
  LOG_DEBUG_CONNECT = 1u << 8,
  LOG_DEBUG_CMD = 1u << 9,
  LOG_DEBUG_DEL = 1u << 10,
  LOG_DEBUG_DIGEST = 1u << 11,
  LOG_DEBUG_DFLT = 1u << 12,
  LOG_DEBUG_FLIST = 1u << 13,
  LOG_DEBUG_FUZZER = 1u << 14,
  LOG_DEBUG_GENR = 1u << 15,
  LOG_DEBUG_HASH = 1u << 16,
  LOG_DEBUG_HLINK = 1u << 17,
  LOG_DEBUG_ICONV = 1u << 18,
  LOG_DEBUG_NSTR = 1u << 19,
  LOG_DEBUG_OWN = 1u << 20,
  LOG_DEBUG_PROC = 1u << 21,
  LOG_DEBUG_RECV = 1u << 22,
  LOG_DEBUG_SEND = 1u << 23,
  LOG_DEBUG_TIME = 1u << 24,
  LOG_DEBUG_TLS = 1u << 25,
  LOG_DEBUG_ALL = (1u << 26) - 1,
} LogDebugFlag;

void log_message(LogLevel log_level, const char* message, ...);
void log_perror(const char* context);
void set_log_level(LogLevel level);
void set_log_debug_flags(uint32_t flags);
uint32_t get_log_debug_flags(void);
void log_debug_message(LogDebugFlag flag, const char* message, ...);
void log_set_file(FILE* fp);

#endif
