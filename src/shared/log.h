#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdbool.h>

typedef enum { LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR } LogLevel;

void log_message(LogLevel log_level, const char* message, ...);
void log_perror(const char* context);
void set_log_level(LogLevel level);
void log_set_file(FILE* fp);
void log_set_8_bit_output(bool enabled);
bool log_get_8_bit_output(void);

#endif
