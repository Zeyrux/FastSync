#ifndef UTILS_H
#define UTILS_H

#include "array_list.h"
#include <stdbool.h>

bool mkdir_r(const char* path);
char* str_dup(const char* string);
char* path_cat(const char* path1, const char* path2);
bool glob_match(const char* pattern, const char* str);
bool delete_extras(const char* dest_root, ArrayList* manifest);
void utils_set_authorized_root_fd(int fd);
bool has_path_traversal(const char* path);
bool utils_valid_batch_path(const char* path);

#endif
