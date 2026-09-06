#include "test_utils.h"
#include "scanner.h"
#include "file.h"
#include "utils.h"
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

  ScannerOptions options = {false, 1, NULL,  0,     NULL,  0,     0,     0,
                            0,     0, false, false, false, false, false, false};
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
}
