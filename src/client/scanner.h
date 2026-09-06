#ifndef SCANNER_H
#define SCANNER_H

#include "chunk.h"
#include "file_list.h"
#include "filter.h"
#include "protocol.h"
#include "queue.h"
#include <dirent.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <threads.h>

typedef struct {
  bool use_metadata;
  unsigned long long chunk_size;
  char** exclude_patterns;
  int exclude_count;
  char** include_patterns;
  int include_count;
  unsigned long long max_size;
  unsigned long long min_size;
  int max_depth;
  int num_threads;
  bool follow_symlinks;
  bool copy_links;
  bool safe_links;
  bool copy_unsafe_links;
  bool checksum;
  bool one_file_system;
  /* Phase 2 (files-from / filter layer). All pointers are shared read-only
   * across scanner instances and worker threads; ownership stays with the
   * caller (client_send). */
  const FileListSet* file_list;       /* --files-from allow-set, or NULL */
  const FilterRuleList* base_filters; /* command-line + -C rules, or NULL */
  bool per_dir_filters;               /* -F: read .rsync-filter per directory */
} ScannerOptions;

/* Internal per-scanner filter state. FilterNode chains represent the ordered
 * per-directory .rsync-filter rules that apply below a directory. */
typedef struct FilterNode FilterNode;

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
  bool follow_symlinks;
  bool copy_links;
  bool safe_links;
  bool copy_unsafe_links;
  bool checksum;
  bool one_file_system;
  dev_t root_dev;
  bool failed;
  /* Phase 2 (files-from / filter layer). */
  char* root_path;          /* transfer root (fs path) for rel computation */
  char* current_rel;        /* rel path of the open directory ("" == root) */
  bool at_seed_dir;         /* next open is the seed directory */
  FilterNode* seed_node;    /* inherited context of the seed dir, or NULL */
  FilterNode* current_node; /* filter context of the open directory */
  ArrayList* filter_nodes;  /* owned FilterNode arena (may be NULL) */
  const FileListSet* file_list;
  const FilterRuleList* base_filters;
  bool per_dir_filters;
} DirectoryScanner;

typedef struct {
  Queue* result_queue;
  mtx_t result_mutex;
  cnd_t result_not_empty;
  cnd_t result_not_full;
  int num_threads;
  int expected_threads;
  int created_threads;
  thrd_t* threads;
  bool done;
  bool failed;
  atomic_bool cancelled;
  int completed;
  Chunk* initial_chunk;
  ProtocolSession* allocation_session;
  FilterNode* root_filter_node; /* root .rsync-filter context (owned by ps) */
} ParallelScanner;

DirectoryScanner* directory_scanner_create(const char* root_directory, bool use_metadata,
                                           unsigned long long chunk_size, char** exclude_patterns,
                                           int exclude_count, char** include_patterns,
                                           int include_count, unsigned long long max_size,
                                           unsigned long long min_size, int max_depth,
                                           bool follow_symlinks, bool copy_links, bool safe_links,
                                           bool copy_unsafe_links, bool checksum);
DirectoryScanner* directory_scanner_create_with_options(const char* root_directory,
                                                        const ScannerOptions* options);
Chunk* directory_scanner_next(DirectoryScanner* scanner);
bool directory_scanner_failed(const DirectoryScanner* scanner);
void directory_scanner_destroy(DirectoryScanner* scanner);

/* --one-file-system (-x) decision: a directory entry may be descended into
 * only when the option is disabled or the entry lives on the same device as
 * the transfer root. Exposed so tests can exercise the rule directly. */
bool scanner_same_filesystem(bool one_file_system, dev_t root_device, dev_t entry_device);

/* Relative path of an on-disk path below `root` ("" == the root itself, NULL
 * when `fs_path` is not under `root`). Handles trailing slashes and a root of
 * "/". Exposed so tests can exercise the mapping directly. */
char* scanner_path_relative(const char* root, const char* fs_path);

ParallelScanner* parallel_scanner_create_with_options(const char* root_directory,
                                                      const ScannerOptions* options,
                                                      ProtocolSession* allocation_session);
Chunk* parallel_scanner_next(ParallelScanner* scanner);
bool parallel_scanner_failed(const ParallelScanner* scanner);
void parallel_scanner_destroy(ParallelScanner* scanner);

#endif
