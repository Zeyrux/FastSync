#ifndef CHMOD_H
#define CHMOD_H

#include <stdbool.h>
#include <sys/stat.h>

/* Apply the supported rsync --chmod syntax to a permission mode. */
bool chmod_apply(mode_t mode, const char* spec, mode_t* result);

#endif
