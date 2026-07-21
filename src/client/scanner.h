#ifndef SCANNER_H
#define SCANNER_H

#include "chunk.h"
#include "queue.h"
#include <dirent.h>
#include <stdbool.h>
#include <threads.h>

typedef struct {
  Queue* directories;
  DIR* current_dir;
  char* current_path;
  bool use_metadata;
  unsigned long long chunk_size;
  char** exclude_patterns;
  int exclude_count;
  char** include_patterns;
  int include_count;
  unsigned long long max_size;
  unsigned long long min_size;
  int max_depth;
  int current_depth;
} DirectoryScanner;

typedef struct {
  Queue* result_queue;
  mtx_t result_mutex;
  cnd_t result_not_empty;
  cnd_t result_not_full;
  int num_threads;
  thrd_t* threads;
  bool done;
  int completed;
  Chunk* initial_chunk;
} ParallelScanner;

DirectoryScanner* directory_scanner_create(const char* root_directory, bool use_metadata,
                                           unsigned long long chunk_size, char** exclude_patterns,
                                           int exclude_count, char** include_patterns,
                                           int include_count, unsigned long long max_size,
                                           unsigned long long min_size, int max_depth);
Chunk* directory_scanner_next(DirectoryScanner* scanner);
void directory_scanner_destroy(DirectoryScanner* scanner);

ParallelScanner* parallel_scanner_create(char* root_directory, bool use_metadata,
                                         unsigned long long chunk_size, char** exclude_patterns,
                                         int exclude_count, char** include_patterns,
                                         int include_count, unsigned long long max_size,
                                         unsigned long long min_size, int max_depth,
                                         int num_threads);
Chunk* parallel_scanner_next(ParallelScanner* scanner);
void parallel_scanner_destroy(ParallelScanner* scanner);

#endif
