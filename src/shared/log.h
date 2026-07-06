#ifndef LOG_H
#define LOG_H

typedef enum {
  LOG_LEVEL_DEBUG,
  LOG_LEVEL_INFO,
  LOG_LEVEL_WARNING,
  LOG_LEVEL_ERROR
} LogLevel;

void log_message(LogLevel log_level, char *message, ...);
void set_log_level(LogLevel level);

#endif
