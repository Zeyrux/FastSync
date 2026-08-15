#ifndef UTILS_H
#define UTILS_H

#include "array_list.h"
#include <stddef.h>
#include <stdbool.h>

bool mkdir_r(const char* path);
char* str_dup(const char* string);
char* path_cat(const char* path1, const char* path2);
bool glob_match(const char* pattern, const char* str);
bool delete_extras(const char* dest_root, ArrayList* manifest);
bool delete_extras_limited(const char* dest_root, ArrayList* manifest, size_t max_delete);
void utils_set_authorized_root(int fd, const char* canonical_path);
void utils_set_authorized_root_fd(int fd);
bool has_path_traversal(const char* path);

#endif
