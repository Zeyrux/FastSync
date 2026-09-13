#include "test_utils.h"
#include "scanner.h"
#include "array_list.h"
#include "file.h"
#include "file_list.h"
#include "filter.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void create_test_file(const char* path, const char* content) {
  (void)file_write_to_disk(path, content, strlen(content), false, false);
}

static void test_scanner_single_file() {
  const char* dir = "test_scan_dir_single";
  const char* file1 = "test_scan_dir_single/file1.txt";
  const char* content1 = "hello scanner";

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(file1, content1);

  DirectoryScanner* scanner = directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 0, 0,
                                                       0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  Chunk* chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 1);
  EXPECT_EQ_STR(chunk->items[0]->path, file1);

  const Chunk* next = directory_scanner_next(scanner);
  EXPECT_NULL(next);

  chunk_destroy(chunk);
  directory_scanner_destroy(scanner);
  unlink(file1);
  rmdir(dir);
}

static void test_scanner_multiple_files() {
  const char* dir = "test_scan_dir_multi";
  const char* file1 = "test_scan_dir_multi/a.txt";
  const char* file2 = "test_scan_dir_multi/b.txt";
  const char* content1 = "alpha";
  const char* content2 = "beta";

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(file1, content1);
  create_test_file(file2, content2);

  DirectoryScanner* scanner = directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 0, 0,
                                                       0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  const Chunk* chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 2);

  int found1 = 0, found2 = 0;
  for (int i = 0; i < chunk->element_count; i++) {
    if (strcmp(chunk->items[i]->path, file1) == 0)
      found1 = 1;
    if (strcmp(chunk->items[i]->path, file2) == 0)
      found2 = 1;
  }
  EXPECT_TRUE(found1);
  EXPECT_TRUE(found2);

  const Chunk* next = directory_scanner_next(scanner);
  EXPECT_NULL(next);

  chunk_destroy((void*)chunk);
  directory_scanner_destroy(scanner);
  unlink(file1);
  unlink(file2);
  rmdir(dir);
}

static void test_scanner_subdirectory() {
  const char* root = "test_scan_sub";
  const char* sub = "test_scan_sub/sub";
  const char* root_file = "test_scan_sub/root.txt";
  const char* sub_file = "test_scan_sub/sub/sub_file.txt";
  const char* content = "nested content";

  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub, 0755), 0);
  create_test_file(root_file, content);
  create_test_file(sub_file, content);

  DirectoryScanner* scanner = directory_scanner_create((char*)root, false, 0, NULL, 0, NULL, 0, 0,
                                                       0, 0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  int total_files = 0;
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    total_files += chunk->element_count;
    chunk_destroy(chunk);
  }
  EXPECT_EQ_INT(total_files, 2);

  directory_scanner_destroy(scanner);
  unlink(root_file);
  unlink(sub_file);
  rmdir(sub);
  rmdir(root);
}

static void test_scanner_empty_directory() {
  const char* dir = "test_scan_empty";

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);

  DirectoryScanner* scanner = directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 0, 0,
                                                       0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  const Chunk* chunk = directory_scanner_next(scanner);
  EXPECT_NULL(chunk);

  directory_scanner_destroy(scanner);
  rmdir(dir);
}

/* --- Exclude/include pattern and size filter edge cases (Issue #56) --- */

static void test_scanner_exclude_pattern() {
  const char* dir = "test_scan_excl";
  const char* f_txt = "test_scan_excl/keep.txt";
  const char* f_tmp = "test_scan_excl/remove.tmp";
  const char* content = "data";

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(f_txt, content);
  create_test_file(f_tmp, content);

  char* exclude[] = {"*.tmp"};
  DirectoryScanner* scanner = directory_scanner_create((char*)dir, false, 0, exclude, 1, NULL, 0, 0,
                                                       0, 0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  Chunk* chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 1);
  EXPECT_EQ_STR(chunk->items[0]->path, f_txt);

  chunk_destroy(chunk);
  EXPECT_NULL(directory_scanner_next(scanner));

  directory_scanner_destroy(scanner);
  unlink(f_txt);
  unlink(f_tmp);
  rmdir(dir);
}

static void test_scanner_exclude_subdirectory() {
  const char* root = "test_scan_excl_sub";
  const char* sub = "test_scan_excl_sub/sub";
  const char* root_txt = "test_scan_excl_sub/root.txt";
  const char* sub_txt = "test_scan_excl_sub/sub/data.txt";
  const char* sub_tmp = "test_scan_excl_sub/sub/temp.tmp";
  const char* content = "data";

  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub, 0755), 0);
  create_test_file(root_txt, content);
  create_test_file(sub_txt, content);
  create_test_file(sub_tmp, content);

  char* exclude[] = {"*.tmp"};
  DirectoryScanner* scanner = directory_scanner_create((char*)root, false, 0, exclude, 1, NULL, 0,
                                                       0, 0, 0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  int total = 0;
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    total += chunk->element_count;
    for (int i = 0; i < chunk->element_count; i++) {
      size_t len = strlen(chunk->items[i]->path);
      EXPECT_TRUE(len < 4 || strcmp(chunk->items[i]->path + len - 4, ".tmp") != 0);
    }
    chunk_destroy(chunk);
  }
  EXPECT_EQ_INT(total, 2);

  directory_scanner_destroy(scanner);
  unlink(root_txt);
  unlink(sub_txt);
  unlink(sub_tmp);
  rmdir(sub);
  rmdir(root);
}

static void test_scanner_include_and_exclude() {
  const char* dir = "test_scan_inc_exc";
  const char* f_txt = "test_scan_inc_exc/a.txt";
  const char* f_log = "test_scan_inc_exc/b.log";
  const char* f_bak = "test_scan_inc_exc/c.bak";
  const char* content = "filter";

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(f_txt, content);
  create_test_file(f_log, content);
  create_test_file(f_bak, content);

  char* exclude[] = {"*.bak"};
  char* include[] = {"*.txt", "*.log"};
  DirectoryScanner* scanner = directory_scanner_create((char*)dir, false, 0, exclude, 1, include, 2,
                                                       0, 0, 0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  Chunk* chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 2);

  int found_txt = 0, found_log = 0;
  for (int i = 0; i < chunk->element_count; i++) {
    if (strstr(chunk->items[i]->path, "a.txt"))
      found_txt = 1;
    if (strstr(chunk->items[i]->path, "b.log"))
      found_log = 1;
  }
  EXPECT_TRUE(found_txt);
  EXPECT_TRUE(found_log);

  chunk_destroy(chunk);
  EXPECT_NULL(directory_scanner_next(scanner));

  directory_scanner_destroy(scanner);
  unlink(f_txt);
  unlink(f_log);
  unlink(f_bak);
  rmdir(dir);
}

static void test_scanner_max_size() {
  const char* dir = "test_scan_max";
  const char* small = "test_scan_max/small.txt";
  const char* large = "test_scan_max/large.txt";
  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(small, "tiny");
  create_test_file(large, "this_content_is_longer_than_ten_chars");

  /* max_size = 10 — only files <= 10 bytes */
  DirectoryScanner* scanner = directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 10,
                                                       0, 0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  Chunk* chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 1);
  EXPECT_EQ_STR(chunk->items[0]->path, small);

  chunk_destroy(chunk);
  EXPECT_NULL(directory_scanner_next(scanner));

  directory_scanner_destroy(scanner);
  unlink(small);
  unlink(large);
  rmdir(dir);
}

static void test_scanner_min_size() {
  const char* dir = "test_scan_min";
  const char* empty_f = "test_scan_min/empty.txt";
  const char* data_f = "test_scan_min/data.txt";

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(empty_f, "");
  create_test_file(data_f, "some content here");

  /* min_size = 1 — only files >= 1 byte */
  DirectoryScanner* scanner = directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 0, 1,
                                                       0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  Chunk* chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 1);
  EXPECT_EQ_STR(chunk->items[0]->path, data_f);

  chunk_destroy(chunk);
  EXPECT_NULL(directory_scanner_next(scanner));

  directory_scanner_destroy(scanner);
  unlink(empty_f);
  unlink(data_f);
  rmdir(dir);
}

static void test_scanner_size_range() {
  const char* dir = "test_scan_range";
  const char* tiny = "test_scan_range/tiny.txt";
  const char* medium = "test_scan_range/med.txt";
  const char* huge = "test_scan_range/huge.txt";

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(tiny, "ab");
  create_test_file(medium, "hello world");
  create_test_file(huge, "this is a much larger file for testing size filters");

  /* Only files between 3 and 20 bytes */
  DirectoryScanner* scanner = directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 20,
                                                       3, 0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  Chunk* chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 1);
  EXPECT_EQ_STR(chunk->items[0]->path, medium);

  chunk_destroy(chunk);
  EXPECT_NULL(directory_scanner_next(scanner));

  directory_scanner_destroy(scanner);
  unlink(tiny);
  unlink(medium);
  unlink(huge);
  rmdir(dir);
}

static void test_scanner_mixed_patterns() {
  /* Combine exclude, include, and size filters together */
  const char* dir = "test_scan_mixed";
  const char* a_txt = "test_scan_mixed/a.txt"; /* size ~= 5  */
  const char* b_bin = "test_scan_mixed/b.bin"; /* size ~= 13 */
  const char* c_txt = "test_scan_mixed/c.txt"; /* size ~= 5  */
  const char* d_bak = "test_scan_mixed/d.bak"; /* size ~= 42 */

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(a_txt, "aaaaa");
  create_test_file(b_bin, "bbbbbbbbbbbbb");
  create_test_file(c_txt, "ccccc");
  create_test_file(d_bak, "dddddddddddddddddddddddddddddddddddddddddd");

  /* Exclude *.bak, include *.txt, min_size=3, max_size=10 */
  char* exclude[] = {"*.bak"};
  char* include[] = {"*.txt"};
  DirectoryScanner* scanner = directory_scanner_create((char*)dir, false, 0, exclude, 1, include, 1,
                                                       10, 3, 0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  Chunk* chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  /* Both a.txt and c.txt meet the criteria: .txt extension, size 5 <= 10 and >= 3 */
  EXPECT_EQ_INT(chunk->element_count, 2);

  chunk_destroy(chunk);
  EXPECT_NULL(directory_scanner_next(scanner));

  directory_scanner_destroy(scanner);
  unlink(a_txt);
  unlink(b_bin);
  unlink(c_txt);
  unlink(d_bak);
  rmdir(dir);
}

static void test_scanner_no_patterns() {
  /* Explicit test with no exclude/include patterns and no size filters.
   * This verifies that NULL/0 for all pattern parameters works correctly. */
  const char* dir = "test_scan_none";
  const char* f1 = "test_scan_none/f1.txt";
  const char* f2 = "test_scan_none/f2.txt";

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(f1, "first");
  create_test_file(f2, "second");

  DirectoryScanner* scanner = directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 0, 0,
                                                       0, false, false, false, false, false);
  EXPECT_NOT_NULL(scanner);

  Chunk* chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 2);

  chunk_destroy(chunk);
  EXPECT_NULL(directory_scanner_next(scanner));

  directory_scanner_destroy(scanner);
  unlink(f1);
  unlink(f2);
  rmdir(dir);
}

static void test_parallel_scanner_root_chunks_without_workers() {
  const char* dir = "test_parallel_scan_root";
  const char* file1 = "test_parallel_scan_root/a.txt";
  const char* file2 = "test_parallel_scan_root/b.txt";

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(file1, "a");
  create_test_file(file2, "b");

  ScannerOptions options = {0};
  options.chunk_size = 1;
  ParallelScanner* scanner = parallel_scanner_create_with_options(dir, &options, NULL);
  EXPECT_NOT_NULL(scanner);

  int total_files = 0;
  Chunk* chunk;
  while ((chunk = parallel_scanner_next(scanner)) != NULL) {
    total_files += chunk->element_count;
    chunk_destroy(chunk);
  }
  EXPECT_EQ_INT(total_files, 2);
  EXPECT_FALSE(parallel_scanner_failed(scanner));

  parallel_scanner_destroy(scanner);
  unlink(file1);
  unlink(file2);
  rmdir(dir);
}

/* --one-file-system (-x) decision is a pure device comparison. */
static void test_scanner_one_file_system_decision() {
  /* Option disabled: every device is allowed (unchanged default behavior). */
  EXPECT_TRUE(scanner_same_filesystem(false, 0, 123));
  EXPECT_TRUE(scanner_same_filesystem(false, 7, 999));
  /* Option enabled: only entries on the root device may be descended into. */
  EXPECT_TRUE(scanner_same_filesystem(true, 7, 7));
  EXPECT_FALSE(scanner_same_filesystem(true, 7, 8));
}

/* With -x over an ordinary tree (all one device) nothing may be skipped. */
static void test_scanner_one_file_system_same_device() {
  const char* root = "test_scan_ofs";
  const char* sub = "test_scan_ofs/sub";
  const char* deeper = "test_scan_ofs/sub/deeper";
  const char* root_file = "test_scan_ofs/root.txt";
  const char* sub_file = "test_scan_ofs/sub/inner.txt";
  const char* deep_file = "test_scan_ofs/sub/deeper/deep.txt";

  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub, 0755), 0);
  EXPECT_EQ_INT(mkdir(deeper, 0755), 0);
  create_test_file(root_file, "root");
  create_test_file(sub_file, "inner");
  create_test_file(deep_file, "deep");

  ScannerOptions options = {0};
  options.one_file_system = true;
  DirectoryScanner* scanner = directory_scanner_create_with_options(root, &options);
  EXPECT_NOT_NULL(scanner);

  int total_files = 0;
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    total_files += chunk->element_count;
    chunk_destroy(chunk);
  }
  EXPECT_EQ_INT(total_files, 3);
  EXPECT_FALSE(directory_scanner_failed(scanner));

  directory_scanner_destroy(scanner);
  unlink(root_file);
  unlink(sub_file);
  unlink(deep_file);
  rmdir(deeper);
  rmdir(sub);
  rmdir(root);
}

/* Multithreaded (-m) scan with -x over a single-device tree must match the
 * single-threaded result. */
static void test_parallel_scanner_one_file_system_same_device() {
  const char* root = "test_parallel_scan_ofs";
  const char* sub = "test_parallel_scan_ofs/sub";
  const char* sub2 = "test_parallel_scan_ofs/sub2";
  const char* root_file = "test_parallel_scan_ofs/root.txt";
  const char* sub_file = "test_parallel_scan_ofs/sub/inner.txt";
  const char* sub2_file = "test_parallel_scan_ofs/sub2/inner2.txt";

  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub2, 0755), 0);
  create_test_file(root_file, "root");
  create_test_file(sub_file, "inner");
  create_test_file(sub2_file, "inner2");

  ScannerOptions options = {0};
  options.one_file_system = true;
  options.num_threads = 2;
  ParallelScanner* scanner = parallel_scanner_create_with_options(root, &options, NULL);
  EXPECT_NOT_NULL(scanner);

  int total_files = 0;
  Chunk* chunk;
  while ((chunk = parallel_scanner_next(scanner)) != NULL) {
    total_files += chunk->element_count;
    chunk_destroy(chunk);
  }
  EXPECT_EQ_INT(total_files, 3);
  EXPECT_FALSE(parallel_scanner_failed(scanner));

  parallel_scanner_destroy(scanner);
  unlink(root_file);
  unlink(sub_file);
  unlink(sub2_file);
  rmdir(sub);
  rmdir(sub2);
  rmdir(root);
}

/* Scan a tree with copy_links semantics, collecting every emitted path.
 * Returns 0 on success, -1 on scanner failure. */
static int collect_directory_scan(const char* root, bool one_file_system, const char* needle,
                                  bool* found, int* total) {
  ScannerOptions options = {0};
  options.copy_links = true;
  options.one_file_system = one_file_system;
  DirectoryScanner* scanner = directory_scanner_create_with_options(root, &options);
  if (!scanner)
    return -1;
  *found = false;
  *total = 0;
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count; i++) {
      (*total)++;
      if (strstr(chunk->items[i]->path, needle) != NULL)
        *found = true;
    }
    chunk_destroy(chunk);
  }
  bool failed = directory_scanner_failed(scanner);
  directory_scanner_destroy(scanner);
  return failed ? -1 : 0;
}

static int collect_parallel_scan(const char* root, bool one_file_system, const char* needle,
                                 bool* found, int* total) {
  ScannerOptions options = {0};
  options.copy_links = true;
  options.one_file_system = one_file_system;
  options.num_threads = 2;
  ParallelScanner* scanner = parallel_scanner_create_with_options(root, &options, NULL);
  if (!scanner)
    return -1;
  *found = false;
  *total = 0;
  Chunk* chunk;
  while ((chunk = parallel_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count; i++) {
      (*total)++;
      if (strstr(chunk->items[i]->path, needle) != NULL)
        *found = true;
    }
    chunk_destroy(chunk);
  }
  bool failed = parallel_scanner_failed(scanner);
  parallel_scanner_destroy(scanner);
  return failed ? -1 : 0;
}

/* Rootless cross-filesystem test: a symlink nested under the scan root points
 * at a directory on another device (typically /dev/shm, a tmpfs distinct from
 * the build filesystem). With --copy-links semantics the scanner resolves the
 * link and must descend into it only when -x is off. The nested placement
 * exercises the skip decision in the sequential walker and in the parallel
 * worker (depth > 1). Skips when no cross-device target is available. */
static void test_scanner_one_file_system_cross_device() {
  struct stat local_stat;
  if (stat(".", &local_stat) != 0)
    return;

  char shm_dir[64] = "/dev/shm/fastsync_ofs_shm_XXXXXX";
  if (mkdtemp(shm_dir) == NULL)
    return;
  struct stat shm_stat;
  if (stat(shm_dir, &shm_stat) != 0 || shm_stat.st_dev == local_stat.st_dev) {
    rmdir(shm_dir);
    return;
  }

  char root_dir[64] = "./fastsync_ofs_root_XXXXXX";
  if (mkdtemp(root_dir) == NULL) {
    rmdir(shm_dir);
    return;
  }

  char nested[96];
  snprintf(nested, sizeof(nested), "%s/nested", root_dir);
  char link_path[128];
  snprintf(link_path, sizeof(link_path), "%s/link", nested);
  char root_file[96];
  snprintf(root_file, sizeof(root_file), "%s/keep.txt", root_dir);
  char shm_file[96];
  snprintf(shm_file, sizeof(shm_file), "%s/inside.txt", shm_dir);

  bool ready = mkdir(nested, 0755) == 0 && symlink(shm_dir, link_path) == 0;
  if (ready) {
    create_test_file(root_file, "keep");
    create_test_file(shm_file, "cross");
  }

  int seq_off_rc, seq_off_total, seq_on_rc, seq_on_total;
  bool seq_off_found, seq_on_found;
  int par_off_rc, par_off_total, par_on_rc, par_on_total;
  bool par_off_found, par_on_found;
  if (!ready) {
    seq_off_rc = seq_on_rc = par_off_rc = par_on_rc = -1;
    seq_off_total = seq_on_total = par_off_total = par_on_total = 0;
    seq_off_found = seq_on_found = par_off_found = par_on_found = false;
  } else {
    int rc, total;
    bool found;
    rc = collect_directory_scan(root_dir, false, "inside.txt", &found, &total);
    seq_off_rc = rc;
    seq_off_total = total;
    seq_off_found = found;
    rc = collect_directory_scan(root_dir, true, "inside.txt", &found, &total);
    seq_on_rc = rc;
    seq_on_total = total;
    seq_on_found = found;
    rc = collect_parallel_scan(root_dir, false, "inside.txt", &found, &total);
    par_off_rc = rc;
    par_off_total = total;
    par_off_found = found;
    rc = collect_parallel_scan(root_dir, true, "inside.txt", &found, &total);
    par_on_rc = rc;
    par_on_total = total;
    par_on_found = found;
  }

  /* Hermetic cleanup regardless of scan outcome, before any assertions. */
  unlink(shm_file);
  rmdir(shm_dir);
  unlink(link_path);
  unlink(root_file);
  rmdir(nested);
  rmdir(root_dir);

  if (!ready)
    return;

  /* Sequential: without -x the symlinked foreign subtree is included. */
  EXPECT_EQ_INT(seq_off_rc, 0);
  EXPECT_TRUE(seq_off_found);
  EXPECT_EQ_INT(seq_off_total, 2);
  /* Sequential: with -x the cross-device subtree is dropped, keep.txt remains. */
  EXPECT_EQ_INT(seq_on_rc, 0);
  EXPECT_FALSE(seq_on_found);
  EXPECT_EQ_INT(seq_on_total, 1);
  /* Parallel: same behavior, worker path (depth > 1). */
  EXPECT_EQ_INT(par_off_rc, 0);
  EXPECT_TRUE(par_off_found);
  EXPECT_EQ_INT(par_off_total, 2);
  EXPECT_EQ_INT(par_on_rc, 0);
  EXPECT_FALSE(par_on_found);
  EXPECT_EQ_INT(par_on_total, 1);
}

/* Collect emitted file paths (relative to `root`) from a sequential scan.
 * Returns 0 on success with *out and *count set (caller frees *out). */
static int collect_files(const char* root, const ScannerOptions* options, char*** out,
                         int* out_count) {
  DirectoryScanner* scanner = directory_scanner_create_with_options(root, options);
  if (!scanner)
    return -1;
  size_t root_len = strlen(root);
  while (root_len > 0 && root[root_len - 1] == '/')
    root_len--;
  int cap = 16;
  int count = 0;
  char** paths = malloc((size_t)cap * sizeof(char*));
  if (!paths) {
    directory_scanner_destroy(scanner);
    return -1;
  }
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count; i++) {
      const char* rel = chunk->items[i]->path + root_len;
      if (*rel == '/')
        rel++;
      if (count == cap) {
        cap *= 2;
        char** grown = realloc(paths, (size_t)cap * sizeof(char*));
        if (!grown) {
          for (int k = 0; k < count; k++)
            free(paths[k]);
          free(paths);
          chunk_destroy(chunk);
          directory_scanner_destroy(scanner);
          return -1;
        }
        paths = grown;
      }
      paths[count++] = str_dup(rel);
    }
    chunk_destroy(chunk);
  }
  bool failed = directory_scanner_failed(scanner);
  directory_scanner_destroy(scanner);
  if (failed) {
    for (int k = 0; k < count; k++)
      free(paths[k]);
    free(paths);
    return -1;
  }
  *out = paths;
  *out_count = count;
  return 0;
}

static int collect_files_parallel(const char* root, const ScannerOptions* options, char*** out,
                                  int* out_count) {
  ParallelScanner* scanner = parallel_scanner_create_with_options(root, options, NULL);
  if (!scanner)
    return -1;
  size_t root_len = strlen(root);
  while (root_len > 0 && root[root_len - 1] == '/')
    root_len--;
  int cap = 16;
  int count = 0;
  char** paths = malloc((size_t)cap * sizeof(char*));
  if (!paths) {
    parallel_scanner_destroy(scanner);
    return -1;
  }
  Chunk* chunk;
  while ((chunk = parallel_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count; i++) {
      const char* rel = chunk->items[i]->path + root_len;
      if (*rel == '/')
        rel++;
      if (count == cap) {
        cap *= 2;
        char** grown = realloc(paths, (size_t)cap * sizeof(char*));
        if (!grown) {
          for (int k = 0; k < count; k++)
            free(paths[k]);
          free(paths);
          chunk_destroy(chunk);
          parallel_scanner_destroy(scanner);
          return -1;
        }
        paths = grown;
      }
      paths[count++] = str_dup(rel);
    }
    chunk_destroy(chunk);
  }
  bool failed = parallel_scanner_failed(scanner);
  parallel_scanner_destroy(scanner);
  if (failed) {
    for (int k = 0; k < count; k++)
      free(paths[k]);
    free(paths);
    return -1;
  }
  *out = paths;
  *out_count = count;
  return 0;
}

static bool has_path(char** paths, int count, const char* rel) {
  for (int i = 0; i < count; i++)
    if (strcmp(paths[i], rel) == 0)
      return true;
  return false;
}

static void free_paths(char** paths, int count) {
  for (int i = 0; i < count; i++)
    free(paths[i]);
  free(paths);
}

static const char* FILE_LIST_PATH = "test_scan_files_from.txt";

/* --files-from: only the listed files (and the subtree of a listed directory)
 * are emitted; unrelated files and directories are pruned. */
static void test_files_from_subset(bool parallel) {
  const char* root = "test_scan_ff";
  const char* sub = "test_scan_ff/sub";
  const char* other = "test_scan_ff/other";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub, 0755), 0);
  EXPECT_EQ_INT(mkdir(other, 0755), 0);
  create_test_file("test_scan_ff/root.txt", "root");
  create_test_file("test_scan_ff/sub/keep.txt", "keep");
  create_test_file("test_scan_ff/sub/skip.bin", "skip");
  create_test_file("test_scan_ff/other/unrelated.txt", "unrelated");

  /* List a root file and a file under sub: sub is descended but its other file
   * is not listed, and the whole `other` directory is pruned. */
  create_test_file(FILE_LIST_PATH, "root.txt\nsub/keep.txt\n");
  char err[160];
  FileListSet* set = file_list_load(FILE_LIST_PATH, false, err, sizeof(err));
  EXPECT_NOT_NULL(set);

  ScannerOptions options = {0};
  options.file_list = set;
  if (parallel)
    options.num_threads = 2;
  char** paths = NULL;
  int count = 0;
  int rc = parallel ? collect_files_parallel(root, &options, &paths, &count)
                    : collect_files(root, &options, &paths, &count);
  EXPECT_EQ_INT(rc, 0);
  EXPECT_EQ_INT(count, 2);
  EXPECT_TRUE(has_path(paths, count, "root.txt"));
  EXPECT_TRUE(has_path(paths, count, "sub/keep.txt"));
  EXPECT_FALSE(has_path(paths, count, "sub/skip.bin"));
  EXPECT_FALSE(has_path(paths, count, "other/unrelated.txt"));
  free_paths(paths, count);
  file_list_destroy(set);
  remove(FILE_LIST_PATH);

  /* Listing a directory transfers its whole subtree. */
  create_test_file(FILE_LIST_PATH, "sub\n");
  set = file_list_load(FILE_LIST_PATH, false, err, sizeof(err));
  EXPECT_NOT_NULL(set);
  options.file_list = set;
  rc = parallel ? collect_files_parallel(root, &options, &paths, &count)
                : collect_files(root, &options, &paths, &count);
  EXPECT_EQ_INT(rc, 0);
  EXPECT_EQ_INT(count, 2);
  EXPECT_TRUE(has_path(paths, count, "sub/keep.txt"));
  EXPECT_TRUE(has_path(paths, count, "sub/skip.bin"));
  EXPECT_FALSE(has_path(paths, count, "root.txt"));
  EXPECT_FALSE(has_path(paths, count, "other/unrelated.txt"));
  free_paths(paths, count);
  file_list_destroy(set);
  remove(FILE_LIST_PATH);

  unlink("test_scan_ff/root.txt");
  unlink("test_scan_ff/sub/keep.txt");
  unlink("test_scan_ff/sub/skip.bin");
  unlink("test_scan_ff/other/unrelated.txt");
  rmdir(other);
  rmdir(sub);
  rmdir(root);
}

/* Filter layer: '-' excludes, first-match-wins ordering with '+', anchored
 * rules, and dir-only rules all prune during the scan. */
static void test_filter_rules(bool parallel) {
  const char* root = "test_scan_filter";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  create_test_file("test_scan_filter/a.txt", "a");
  create_test_file("test_scan_filter/b.tmp", "b");
  create_test_file("test_scan_filter/c.txt", "c");

  /* - *.tmp excludes only the tmp file; other files remain (default include). */
  const char* exclude_only[] = {"- *.tmp"};
  char err[160];
  FilterRuleList* base = filter_base_build(exclude_only, 1, false, err, sizeof(err));
  EXPECT_NOT_NULL(base);
  ScannerOptions options = {0};
  options.base_filters = base;
  if (parallel)
    options.num_threads = 2;
  char** paths = NULL;
  int count = 0;
  int rc = parallel ? collect_files_parallel(root, &options, &paths, &count)
                    : collect_files(root, &options, &paths, &count);
  EXPECT_EQ_INT(rc, 0);
  EXPECT_EQ_INT(count, 2);
  EXPECT_TRUE(has_path(paths, count, "a.txt"));
  EXPECT_TRUE(has_path(paths, count, "c.txt"));
  EXPECT_FALSE(has_path(paths, count, "b.tmp"));
  free_paths(paths, count);
  filter_rule_list_free(base);

  /* Anchored include then exclude-all: only root-level keep* survives. */
  const char* anchored[] = {"+ /a.txt", "- *"};
  base = filter_base_build(anchored, 2, false, err, sizeof(err));
  EXPECT_NOT_NULL(base);
  options.base_filters = base;
  rc = parallel ? collect_files_parallel(root, &options, &paths, &count)
                : collect_files(root, &options, &paths, &count);
  EXPECT_EQ_INT(rc, 0);
  EXPECT_EQ_INT(count, 1);
  EXPECT_TRUE(has_path(paths, count, "a.txt"));
  free_paths(paths, count);
  filter_rule_list_free(base);

  unlink("test_scan_filter/a.txt");
  unlink("test_scan_filter/b.tmp");
  unlink("test_scan_filter/c.txt");
  rmdir(root);
}

/* Anchored dir-only rules prune a whole subtree. */
static void test_filter_dir_only_and_anchored(bool parallel) {
  const char* root = "test_scan_filter_dir";
  const char* sub = "test_scan_filter_dir/sub";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub, 0755), 0);
  create_test_file("test_scan_filter_dir/sub/inner.txt", "x");
  create_test_file("test_scan_filter_dir/keep.txt", "keep");

  const char* rules[] = {"- /sub/"};
  char err[160];
  FilterRuleList* base = filter_base_build(rules, 1, false, err, sizeof(err));
  EXPECT_NOT_NULL(base);
  ScannerOptions options = {0};
  options.base_filters = base;
  if (parallel)
    options.num_threads = 2;
  char** paths = NULL;
  int count = 0;
  int rc = parallel ? collect_files_parallel(root, &options, &paths, &count)
                    : collect_files(root, &options, &paths, &count);
  EXPECT_EQ_INT(rc, 0);
  EXPECT_EQ_INT(count, 1);
  EXPECT_TRUE(has_path(paths, count, "keep.txt"));
  EXPECT_FALSE(has_path(paths, count, "sub/inner.txt"));
  free_paths(paths, count);
  filter_rule_list_free(base);

  unlink("test_scan_filter_dir/sub/inner.txt");
  unlink("test_scan_filter_dir/keep.txt");
  rmdir(sub);
  rmdir(root);
}

/* -C default CVS excludes prune .git/ directories and *.o files. */
static void test_cvs_defaults(bool parallel) {
  const char* root = "test_scan_cvs";
  const char* git = "test_scan_cvs/.git";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(git, 0755), 0);
  create_test_file("test_scan_cvs/.git/config", "cfg");
  create_test_file("test_scan_cvs/object.o", "o");
  create_test_file("test_scan_cvs/keep.txt", "keep");

  char err[160];
  FilterRuleList* base = filter_base_build(NULL, 0, true, err, sizeof(err));
  EXPECT_NOT_NULL(base);
  ScannerOptions options = {0};
  options.base_filters = base;
  if (parallel)
    options.num_threads = 2;
  char** paths = NULL;
  int count = 0;
  int rc = parallel ? collect_files_parallel(root, &options, &paths, &count)
                    : collect_files(root, &options, &paths, &count);
  EXPECT_EQ_INT(rc, 0);
  EXPECT_EQ_INT(count, 1);
  EXPECT_TRUE(has_path(paths, count, "keep.txt"));
  EXPECT_FALSE(has_path(paths, count, ".git/config"));
  EXPECT_FALSE(has_path(paths, count, "object.o"));
  free_paths(paths, count);
  filter_rule_list_free(base);

  unlink("test_scan_cvs/.git/config");
  unlink("test_scan_cvs/object.o");
  unlink("test_scan_cvs/keep.txt");
  rmdir(git);
  rmdir(root);
}

/* -F: a .rsync-filter placed in a directory governs its subtree and the file
 * itself is never transferred. */
static void test_per_dir_filter(bool parallel) {
  const char* root = "test_scan_perdir";
  const char* sub = "test_scan_perdir/sub";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub, 0755), 0);
  create_test_file("test_scan_perdir/drop.tmp", "tmp");
  create_test_file("test_scan_perdir/keep.txt", "keep");
  create_test_file("test_scan_perdir/sub/nested.tmp", "tmp");
  create_test_file("test_scan_perdir/.rsync-filter", "- *.tmp\n");

  ScannerOptions options = {0};
  options.per_dir_filters = true;
  if (parallel)
    options.num_threads = 2;
  char** paths = NULL;
  int count = 0;
  int rc = parallel ? collect_files_parallel(root, &options, &paths, &count)
                    : collect_files(root, &options, &paths, &count);
  EXPECT_EQ_INT(rc, 0);
  EXPECT_EQ_INT(count, 1);
  EXPECT_TRUE(has_path(paths, count, "keep.txt"));
  EXPECT_FALSE(has_path(paths, count, "drop.tmp"));
  EXPECT_FALSE(has_path(paths, count, "sub/nested.tmp"));
  EXPECT_FALSE(has_path(paths, count, ".rsync-filter"));
  free_paths(paths, count);

  unlink("test_scan_perdir/drop.tmp");
  unlink("test_scan_perdir/keep.txt");
  unlink("test_scan_perdir/sub/nested.tmp");
  unlink("test_scan_perdir/.rsync-filter");
  rmdir(sub);
  rmdir(root);
}

/* scanner_path_relative maps an on-disk path to its transfer-relative path,
 * including the "/" transfer-root edge case (regression: children of "/" used
 * to abort the scan because the suffix was mis-read). */
static void test_scanner_path_relative() {
  char* rel = NULL;

  rel = scanner_path_relative("/", "/");
  EXPECT_NOT_NULL(rel);
  EXPECT_EQ_STR(rel, "");
  free(rel);

  rel = scanner_path_relative("/", "/etc");
  EXPECT_NOT_NULL(rel);
  EXPECT_EQ_STR(rel, "etc");
  free(rel);

  rel = scanner_path_relative("/", "/etc/passwd");
  EXPECT_NOT_NULL(rel);
  EXPECT_EQ_STR(rel, "etc/passwd");
  free(rel);

  /* Normal roots: with and without a trailing slash on the root. */
  rel = scanner_path_relative("/tmp/foo", "/tmp/foo");
  EXPECT_NOT_NULL(rel);
  EXPECT_EQ_STR(rel, "");
  free(rel);

  rel = scanner_path_relative("/tmp/foo", "/tmp/foo/bar");
  EXPECT_NOT_NULL(rel);
  EXPECT_EQ_STR(rel, "bar");
  free(rel);

  rel = scanner_path_relative("/tmp/foo/", "/tmp/foo/bar/baz.txt");
  EXPECT_NOT_NULL(rel);
  EXPECT_EQ_STR(rel, "bar/baz.txt");
  free(rel);

  /* A path outside the root maps to NULL. */
  EXPECT_NULL(scanner_path_relative("/tmp/foo", "/tmp"));
  EXPECT_NULL(scanner_path_relative("/tmp/foo", "/tmp/foobar"));
}

/* rsync precedence: a deeper .rsync-filter overrides a shallower one, so an
 * inner "+ *.tmp" re-includes what the outer "- *.tmp" excluded. */
static void test_per_dir_filter_override(bool parallel) {
  const char* root = "test_scan_perdir_ovr";
  const char* sub = "test_scan_perdir_ovr/sub";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub, 0755), 0);
  create_test_file("test_scan_perdir_ovr/.rsync-filter", "- *.tmp\n");
  create_test_file("test_scan_perdir_ovr/sub/.rsync-filter", "+ *.tmp\n");
  create_test_file("test_scan_perdir_ovr/top.tmp", "x");
  create_test_file("test_scan_perdir_ovr/keep.txt", "keep");
  create_test_file("test_scan_perdir_ovr/sub/inside.tmp", "x");

  ScannerOptions options = {0};
  options.per_dir_filters = true;
  if (parallel)
    options.num_threads = 2;
  char** paths = NULL;
  int count = 0;
  int rc = parallel ? collect_files_parallel(root, &options, &paths, &count)
                    : collect_files(root, &options, &paths, &count);
  EXPECT_EQ_INT(rc, 0);
  /* top.tmp is still excluded by the root file; inside.tmp is re-included by
   * the subdir file; .rsync-filter files are never transferred. */
  EXPECT_EQ_INT(count, 2);
  EXPECT_TRUE(has_path(paths, count, "keep.txt"));
  EXPECT_TRUE(has_path(paths, count, "sub/inside.tmp"));
  EXPECT_FALSE(has_path(paths, count, "top.tmp"));
  EXPECT_FALSE(has_path(paths, count, ".rsync-filter"));
  EXPECT_FALSE(has_path(paths, count, "sub/.rsync-filter"));
  free_paths(paths, count);

  unlink("test_scan_perdir_ovr/top.tmp");
  unlink("test_scan_perdir_ovr/keep.txt");
  unlink("test_scan_perdir_ovr/sub/inside.tmp");
  unlink("test_scan_perdir_ovr/.rsync-filter");
  unlink("test_scan_perdir_ovr/sub/.rsync-filter");
  rmdir(sub);
  rmdir(root);
}

typedef struct {
  char rel[512];
  char send[512];
  bool is_dir;
} ScanInfo;

/* Collect every scanner entry below `root` into `out` (at most `max`), mapping
 * paths to their root-relative form and capturing send_path and is_dir. */
static int collect_scan_info(const char* root, const ScannerOptions* options, ScanInfo out[],
                             int max) {
  DirectoryScanner* scanner = directory_scanner_create_with_options(root, options);
  if (!scanner)
    return -1;
  size_t root_len = strlen(root);
  while (root_len > 0 && root[root_len - 1] == '/')
    root_len--;
  int count = 0;
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count && count < max; i++) {
      const File* f = chunk->items[i];
      const char* rel = f->path + root_len;
      if (*rel == '/')
        rel++;
      snprintf(out[count].rel, sizeof(out[count].rel), "%s", rel);
      snprintf(out[count].send, sizeof(out[count].send), "%s", f->send_path ? f->send_path : "");
      out[count].is_dir = f->is_dir;
      count++;
    }
    chunk_destroy(chunk);
  }
  bool failed = directory_scanner_failed(scanner);
  directory_scanner_destroy(scanner);
  return failed ? -1 : count;
}

static bool scan_info_present(const ScanInfo* infos, int count, const char* rel, bool is_dir,
                              const char* send) {
  for (int i = 0; i < count; i++) {
    if (strcmp(infos[i].rel, rel) == 0 && infos[i].is_dir == is_dir &&
        strcmp(infos[i].send, send ? send : "") == 0)
      return true;
  }
  return false;
}

/* Parallel variant of collect_scan_info; drains `scanner` fully and destroys
 * it. */
static int collect_scan_info_parallel(ParallelScanner* scanner, const char* root, ScanInfo out[],
                                      int max) {
  if (!scanner)
    return -1;
  size_t root_len = strlen(root);
  while (root_len > 0 && root[root_len - 1] == '/')
    root_len--;
  int count = 0;
  Chunk* chunk;
  while ((chunk = parallel_scanner_next(scanner)) != NULL) {
    for (int i = 0; i < chunk->element_count && count < max; i++) {
      const File* f = chunk->items[i];
      const char* rel = f->path + root_len;
      if (*rel == '/')
        rel++;
      snprintf(out[count].rel, sizeof(out[count].rel), "%s", rel);
      snprintf(out[count].send, sizeof(out[count].send), "%s", f->send_path ? f->send_path : "");
      out[count].is_dir = f->is_dir;
      count++;
    }
    chunk_destroy(chunk);
  }
  bool failed = parallel_scanner_failed(scanner);
  parallel_scanner_destroy(scanner);
  return failed ? -1 : count;
}

/* -d without --files-from emits exactly the source-root directory (empty) and
 * never descends. */
static void test_dirs_no_descent() {
  const char* root = "test_scan_dirs_root";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir("test_scan_dirs_root/sub", 0755), 0);
  create_test_file("test_scan_dirs_root/a.txt", "a");
  create_test_file("test_scan_dirs_root/sub/b.txt", "b");

  ScannerOptions options = {0};
  options.dirs = true;
  ScanInfo infos[8];
  int count = collect_scan_info(root, &options, infos, 8);
  EXPECT_EQ_INT(count, 1);
  EXPECT_TRUE(scan_info_present(infos, count, "", true, NULL));
  EXPECT_FALSE(scan_info_present(infos, count, "a.txt", false, ""));
  EXPECT_FALSE(scan_info_present(infos, count, "sub/b.txt", false, ""));

  unlink("test_scan_dirs_root/a.txt");
  unlink("test_scan_dirs_root/sub/b.txt");
  rmdir("test_scan_dirs_root/sub");
  rmdir(root);
}

/* -d with --files-from transfers exactly the listed directory (empty) and the
 * listed file; nothing is descended into. */
static void test_dirs_files_from() {
  const char* root = "test_scan_dirs_ff";
  const char* list_path = "test_scan_dirs_ff.list";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir("test_scan_dirs_ff/sub", 0755), 0);
  create_test_file("test_scan_dirs_ff/sub/keep.txt", "keep");
  create_test_file("test_scan_dirs_ff/sub/skip.bin", "skip");
  create_test_file("test_scan_dirs_ff/top.txt", "top");

  char err[160];
  create_test_file(list_path, "sub\nsub/keep.txt\n");
  FileListSet* set = file_list_load(list_path, false, err, sizeof(err));
  EXPECT_NOT_NULL(set);

  for (int relative = 0; relative <= 1; relative++) {
    ScannerOptions options = {0};
    options.dirs = true;
    options.file_list = set;
    options.relative = relative != 0;
    ScanInfo infos[8];
    int count = collect_scan_info(root, &options, infos, 8);
    EXPECT_EQ_INT(count, 2);
    if (relative) {
      EXPECT_TRUE(scan_info_present(infos, count, "sub", true, "sub"));
      EXPECT_TRUE(scan_info_present(infos, count, "sub/keep.txt", false, "sub/keep.txt"));
    } else {
      EXPECT_TRUE(scan_info_present(infos, count, "sub", true, NULL));
      EXPECT_TRUE(scan_info_present(infos, count, "sub/keep.txt", false, NULL));
    }
    EXPECT_FALSE(scan_info_present(infos, count, "sub/skip.bin", false, ""));
    EXPECT_FALSE(scan_info_present(infos, count, "top.txt", false, ""));
  }
  file_list_destroy(set);
  remove(list_path);
  unlink("test_scan_dirs_ff/sub/keep.txt");
  unlink("test_scan_dirs_ff/sub/skip.bin");
  unlink("test_scan_dirs_ff/top.txt");
  rmdir("test_scan_dirs_ff/sub");
  rmdir(root);
}

/* -R with --files-from (no -d): every file keeps its bare relative path as the
 * send_path while the local scan path stays absolute-under-root. */
static void test_files_from_relative_send_path() {
  const char* root = "test_scan_rel_ff";
  const char* list_path = "test_scan_rel_ff.list";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir("test_scan_rel_ff/sub", 0755), 0);
  create_test_file("test_scan_rel_ff/root.txt", "root");
  create_test_file("test_scan_rel_ff/sub/keep.txt", "keep");

  char err[160];
  create_test_file(list_path, "root.txt\nsub/keep.txt\n");
  FileListSet* set = file_list_load(list_path, false, err, sizeof(err));
  EXPECT_NOT_NULL(set);

  for (int parallel = 0; parallel <= 1; parallel++) {
    ScannerOptions options = {0};
    options.file_list = set;
    options.relative = true;
    if (parallel)
      options.num_threads = 2;
    ScanInfo infos[8];
    int count;
    if (parallel) {
      ParallelScanner* scanner = parallel_scanner_create_with_options(root, &options, NULL);
      EXPECT_NOT_NULL(scanner);
      count = collect_scan_info_parallel(scanner, root, infos, 8);
    } else {
      count = collect_scan_info(root, &options, infos, 8);
    }
    EXPECT_EQ_INT(count, 2);
    EXPECT_TRUE(scan_info_present(infos, count, "root.txt", false, "root.txt"));
    EXPECT_TRUE(scan_info_present(infos, count, "sub/keep.txt", false, "sub/keep.txt"));
  }
  file_list_destroy(set);
  remove(list_path);
  unlink("test_scan_rel_ff/root.txt");
  unlink("test_scan_rel_ff/sub/keep.txt");
  rmdir("test_scan_rel_ff/sub");
  rmdir(root);
}

/* P7 Wave D: the recursive scan captures every traversed source directory as an
 * is_dir File (metadata, no payload) in the shared dir_entries list, including
 * the transfer root and an EMPTY directory.  The empty dir is captured even
 * though the receiver deliberately never creates it, so its time can still be
 * applied when the destination already holds that directory. */
static void test_scanner_captures_directory_times() {
  const char* root = "test_scan_dirtime";
  const char* sub = "test_scan_dirtime/sub";
  const char* empty = "test_scan_dirtime/empty";
  const char* file1 = "test_scan_dirtime/sub/a.txt";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub, 0755), 0);
  EXPECT_EQ_INT(mkdir(empty, 0755), 0);
  create_test_file(file1, "x");

  ArrayList* dirs = array_list_create(file_destroy);
  EXPECT_NOT_NULL(dirs);
  ScannerOptions options = {0};
  options.use_metadata = true;
  options.capture_dir_times = true;
  options.dir_entries = dirs;
  DirectoryScanner* scanner = directory_scanner_create_with_options(root, &options);
  EXPECT_NOT_NULL(scanner);
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL)
    chunk_destroy(chunk);
  EXPECT_FALSE(directory_scanner_failed(scanner));

  int found_root = 0;
  int found_sub = 0;
  int found_empty = 0;
  for (int i = 0; i < dirs->size; i++) {
    const File* file = (const File*)dirs->items[i];
    EXPECT_TRUE(file->is_dir);
    EXPECT_NOT_NULL(file->metadata);
    if (strcmp(file->path, root) == 0)
      found_root = 1;
    if (strcmp(file->path, sub) == 0)
      found_sub = 1;
    if (strcmp(file->path, empty) == 0)
      found_empty = 1;
  }
  EXPECT_TRUE(found_root);
  EXPECT_TRUE(found_sub);
  EXPECT_TRUE(found_empty);

  directory_scanner_destroy(scanner);
  array_list_delete(dirs);
  unlink(file1);
  rmdir(empty);
  rmdir(sub);
  rmdir(root);
}

/* Ownership guard for chunk_data_to_chunk(): a returned Chunk owns its File
 * objects, so destroying the chunk must free them exactly once and the scanner
 * must never free them again.  chunk_size = 1 forces the mid-directory
 * conversion branch (chunk_data_size > chunk_size) for every file, and the
 * chunk is destroyed immediately, catching a double free / use-after-free under
 * ASan if ownership transfer regressed.
 *
 * The failure path (array_list_to_array() or chunk_create() returning NULL) is
 * not reachable from a unit test: both allocate through protocol_alloc(), and
 * each allocation they perform is no larger than the array_list allocations
 * that already succeeded while building the list (array_list_to_array() copies
 * exactly `size` pointers, which never exceeds the capacity just grown, and
 * sizeof(Chunk) is far below the initial 100-entry item array).  Binding a
 * small --max-alloc session therefore always fails *before* this function, not
 * inside it, so fault injection cannot isolate these paths. */
static void test_scanner_chunk_ownership() {
  const char* dir = "test_scan_ownership";
  const char* file1 = "test_scan_ownership/a.txt";
  const char* file2 = "test_scan_ownership/b.txt";
  const char* file3 = "test_scan_ownership/c.txt";

  EXPECT_EQ_INT(mkdir(dir, 0755), 0);
  create_test_file(file1, "aaaa");
  create_test_file(file2, "bbbb");
  create_test_file(file3, "cccc");

  ScannerOptions options = {0};
  options.chunk_size = 1;
  DirectoryScanner* scanner = directory_scanner_create_with_options(dir, &options);
  EXPECT_NOT_NULL(scanner);

  int chunks = 0;
  int files = 0;
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    chunks++;
    files += chunk->element_count;
    EXPECT_EQ_INT(chunk->element_count, 1);
    chunk_destroy(chunk);
    EXPECT_FALSE(directory_scanner_failed(scanner));
  }
  EXPECT_EQ_INT(files, 3);
  EXPECT_EQ_INT(chunks, 3);
  EXPECT_FALSE(directory_scanner_failed(scanner));

  directory_scanner_destroy(scanner);
  unlink(file1);
  unlink(file2);
  unlink(file3);
  rmdir(dir);
}

/* The scanner derives entry type from a single lstat() for non-symlinks
 * (regular files and directories) and only calls stat() to dereference real
 * symlinks.  Guard the regular-file/directory/symlink distinction across the
 * default (symlinks skipped), --copy-links (dereferenced) and -l (carried)
 * modes so the lstat/stat reuse cannot misclassify entries. */
static void test_scanner_entry_classification() {
  const char* root = "test_scan_classify";
  const char* sub = "test_scan_classify/sub";
  const char* file = "test_scan_classify/file.txt";
  const char* nested = "test_scan_classify/sub/nested.txt";
  const char* link_file = "test_scan_classify/link_file";
  const char* link_dir = "test_scan_classify/link_dir";

  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sub, 0755), 0);
  create_test_file(file, "hello");    /* 5 bytes */
  create_test_file(nested, "nested"); /* 6 bytes */
  EXPECT_EQ_INT(symlink("file.txt", link_file), 0);
  EXPECT_EQ_INT(symlink("sub", link_dir), 0);

  /* Default: no link option -> symlinks are skipped entirely; regular files and
     directories (descended, not emitted) are classified as before. */
  {
    ScannerOptions options = {0};
    DirectoryScanner* scanner = directory_scanner_create_with_options(root, &options);
    EXPECT_NOT_NULL(scanner);
    size_t root_len = strlen(root);
    bool file_ok = false, nested_ok = false, link_seen = false;
    Chunk* chunk;
    while ((chunk = directory_scanner_next(scanner)) != NULL) {
      for (int i = 0; i < chunk->element_count; i++) {
        const File* f = chunk->items[i];
        const char* rel = f->path + root_len;
        if (*rel == '/')
          rel++;
        if (strcmp(rel, "file.txt") == 0) {
          file_ok = !f->is_dir && !f->is_symlink && f->data->size == 5;
        } else if (strcmp(rel, "sub/nested.txt") == 0) {
          nested_ok = !f->is_dir && !f->is_symlink && f->data->size == 6;
        } else {
          link_seen = true;
        }
      }
      chunk_destroy(chunk);
    }
    EXPECT_FALSE(directory_scanner_failed(scanner));
    EXPECT_TRUE(file_ok);
    EXPECT_TRUE(nested_ok);
    EXPECT_FALSE(link_seen);
    directory_scanner_destroy(scanner);
  }

  /* --copy-links: symlinks are dereferenced.  A link to a file becomes a
     regular file with the referent's size; a link to a directory is traversed. */
  {
    ScannerOptions options = {0};
    options.copy_links = true;
    DirectoryScanner* scanner = directory_scanner_create_with_options(root, &options);
    EXPECT_NOT_NULL(scanner);
    size_t root_len = strlen(root);
    bool file_ok = false, nested_ok = false, link_file_ok = false;
    bool link_dir_nested_ok = false, symlink_leaked = false;
    Chunk* chunk;
    while ((chunk = directory_scanner_next(scanner)) != NULL) {
      for (int i = 0; i < chunk->element_count; i++) {
        const File* f = chunk->items[i];
        const char* rel = f->path + root_len;
        if (*rel == '/')
          rel++;
        if (f->is_symlink)
          symlink_leaked = true;
        if (strcmp(rel, "file.txt") == 0)
          file_ok = !f->is_dir && f->data->size == 5;
        else if (strcmp(rel, "sub/nested.txt") == 0)
          nested_ok = !f->is_dir && f->data->size == 6;
        else if (strcmp(rel, "link_file") == 0)
          link_file_ok = !f->is_dir && f->data->size == 5;
        else if (strcmp(rel, "link_dir/nested.txt") == 0)
          link_dir_nested_ok = !f->is_dir && f->data->size == 6;
      }
      chunk_destroy(chunk);
    }
    EXPECT_FALSE(directory_scanner_failed(scanner));
    EXPECT_TRUE(file_ok);
    EXPECT_TRUE(nested_ok);
    EXPECT_TRUE(link_file_ok);
    EXPECT_TRUE(link_dir_nested_ok);
    EXPECT_FALSE(symlink_leaked);
    directory_scanner_destroy(scanner);
  }

  /* -l (--links): symlinks are carried through as symlinks, not dereferenced. */
  {
    ScannerOptions options = {0};
    options.follow_symlinks = true;
    DirectoryScanner* scanner = directory_scanner_create_with_options(root, &options);
    EXPECT_NOT_NULL(scanner);
    size_t root_len = strlen(root);
    bool file_ok = false, link_file_ok = false, link_dir_ok = false, leaked_dir = false;
    Chunk* chunk;
    while ((chunk = directory_scanner_next(scanner)) != NULL) {
      for (int i = 0; i < chunk->element_count; i++) {
        const File* f = chunk->items[i];
        const char* rel = f->path + root_len;
        if (*rel == '/')
          rel++;
        if (strcmp(rel, "file.txt") == 0)
          file_ok = !f->is_dir && !f->is_symlink && f->data->size == 5;
        else if (strcmp(rel, "link_file") == 0)
          link_file_ok = f->is_symlink && !f->is_dir;
        else if (strcmp(rel, "link_dir") == 0)
          link_dir_ok = f->is_symlink && !f->is_dir;
        else if (strcmp(rel, "link_dir/nested.txt") == 0)
          leaked_dir = true;
      }
      chunk_destroy(chunk);
    }
    EXPECT_FALSE(directory_scanner_failed(scanner));
    EXPECT_TRUE(file_ok);
    EXPECT_TRUE(link_file_ok);
    EXPECT_TRUE(link_dir_ok);
    EXPECT_FALSE(leaked_dir);
    directory_scanner_destroy(scanner);
  }

  unlink(link_file);
  unlink(link_dir);
  unlink(nested);
  unlink(file);
  rmdir(sub);
  rmdir(root);
}

void test_scanner() {
  test_scanner_single_file();
  test_scanner_multiple_files();
  test_scanner_subdirectory();
  test_scanner_empty_directory();
  /* Issue #56: scanner pattern edge cases */
  test_scanner_exclude_pattern();
  test_scanner_exclude_subdirectory();
  test_scanner_include_and_exclude();
  test_scanner_max_size();
  test_scanner_min_size();
  test_scanner_size_range();
  test_scanner_mixed_patterns();
  test_scanner_no_patterns();
  test_parallel_scanner_root_chunks_without_workers();
  test_scanner_one_file_system_decision();
  test_scanner_one_file_system_same_device();
  test_parallel_scanner_one_file_system_same_device();
  test_scanner_one_file_system_cross_device();
  test_files_from_subset(false);
  test_files_from_subset(true);
  test_filter_rules(false);
  test_filter_rules(true);
  test_filter_dir_only_and_anchored(false);
  test_filter_dir_only_and_anchored(true);
  test_cvs_defaults(false);
  test_cvs_defaults(true);
  test_per_dir_filter(false);
  test_per_dir_filter(true);
  test_scanner_path_relative();
  test_per_dir_filter_override(false);
  test_per_dir_filter_override(true);
  test_dirs_no_descent();
  test_dirs_files_from();
  test_files_from_relative_send_path();
  test_scanner_captures_directory_times();
  test_scanner_chunk_ownership();
  test_scanner_entry_classification();
}
