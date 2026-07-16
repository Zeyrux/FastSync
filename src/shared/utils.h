#ifndef UTILS_H
#define UTILS_H

#include "array_list.h"
#include <stdbool.h>

bool mkdir_r(char *path);
char *str_dup(const char *string);
char *path_cat(char *path1, char *path2);
bool glob_match(const char *pattern, const char *str);
void delete_extras(const char *dest_root, ArrayList *manifest);

#endif
