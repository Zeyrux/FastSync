#ifndef SCANNER_H
#define SCANNER_H

#include "chunk.h"
#include "queue.h"
typedef struct {
  Queue *directories;
} DirectoryScanner;

DirectoryScanner *directory_scanner_create(char *root_directory);
Chunk *directory_scanner_next(DirectoryScanner *scanner);
void directory_scanner_destroy(DirectoryScanner *scanner);

#endif
