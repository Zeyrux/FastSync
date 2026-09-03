#ifndef LOG_H
#define LOG_H

#include <stdio.h>

typedef enum { LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR } LogLevel;
typedef enum { LOG_STDERR_ERRORS, LOG_STDERR_ALL } LogStderrMode;

void log_message(LogLevel log_level, const char* message, ...);
void log_perror(const char* context);
void set_log_level(LogLevel level);
void log_set_file(FILE* fp);
void log_set_stderr_mode(LogStderrMode mode);
LogStderrMode log_get_stderr_mode(void);

#endif
