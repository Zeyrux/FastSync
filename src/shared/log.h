#ifndef LOG_H
#define LOG_H

#include <stdio.h>

typedef enum { LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR } LogLevel;

void log_message(LogLevel log_level, const char* message, ...);
void set_log_level(LogLevel level);
void log_set_file(FILE* fp);

#endif
