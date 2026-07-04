#ifndef SCANNER_H
#define SCANNER_H

#include "chunk.h"
#include "queue.h"
#include <dirent.h>

typedef struct {
  Queue *directories;
  DIR *current_dir;
  char *current_path;
} DirectoryScanner;

DirectoryScanner *directory_scanner_create(char *root_directory);
Chunk *directory_scanner_next(DirectoryScanner *scanner);
void directory_scanner_destroy(DirectoryScanner *scanner);

#endif
