#ifndef UTILS_H
#define UTILS_H

void mkdir_r(char *path);
char *str_dup(char *string);
void to_disk(char *path, void *data, unsigned long long data_size);
char *path_cat(char *path1, char *path2);

#endif
