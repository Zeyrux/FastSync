#ifndef UTILS_H
#define UTILS_H

#include "array_list.h"
#include <stddef.h>
#include <stdbool.h>

char* str_dup(const char* string);
char* output_escape(const char* string, bool eight_bit_output);
char* path_cat(const char* path1, const char* path2);
bool glob_match(const char* pattern, const char* str);
bool delete_extras(const char* dest_root, ArrayList* manifest);
/* Remove files/dirs under dest_root that are not listed in manifest.  When
   skip_root_child is non-NULL, a direct child of dest_root with that exact
   name is left untouched (used to protect the --delay-updates staging
   directory, which holds files that are still to be published). */
bool delete_extras_limited(const char* dest_root, ArrayList* manifest, size_t max_delete,
                           const char* skip_root_child);
bool utils_set_authorized_root(int fd, const char* canonical_path);
/* The fd-only compatibility form is fail-closed for path-based operations;
 * callers should use utils_set_authorized_root with the canonical identity. */
void utils_set_authorized_root_fd(int fd);
bool has_path_traversal(const char* path);
bool utils_valid_batch_path(const char* path);
bool format_human_bytes(unsigned long long bytes, char* buffer, size_t buffer_size);

#endif
