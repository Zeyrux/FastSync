#include "test_utils.h"
#include "scanner.h"
#include "file.h"
#include "utils.h"
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void create_test_file(const char* path, const char* content) {
  (void)to_disk(path, content, strlen(content));
}

static void test_scanner_single_file() {
  const char* dir = "test_scan_dir_single";
  const char* file1 = "test_scan_dir_single/file1.txt";
  const char* content1 = "hello scanner";

  mkdir(dir, 0755);
  create_test_file(file1, content1);

  DirectoryScanner* scanner =
      directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 0, 0);
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

  mkdir(dir, 0755);
  create_test_file(file1, content1);
  create_test_file(file2, content2);

  DirectoryScanner* scanner =
      directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 0, 0);
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

  mkdir(root, 0755);
  mkdir(sub, 0755);
  create_test_file(root_file, content);
  create_test_file(sub_file, content);

  DirectoryScanner* scanner =
      directory_scanner_create((char*)root, false, 0, NULL, 0, NULL, 0, 0, 0);
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

  mkdir(dir, 0755);

  DirectoryScanner* scanner =
      directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 0, 0);
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

  mkdir(dir, 0755);
  create_test_file(f_txt, content);
  create_test_file(f_tmp, content);

  char* exclude[] = {"*.tmp"};
  DirectoryScanner* scanner =
      directory_scanner_create((char*)dir, false, 0, exclude, 1, NULL, 0, 0, 0);
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
  /* Exclude patterns match filenames only (via entry->d_name).
   * Files inside subdirectories are also matched by filename. */
  const char* root = "test_scan_excl_sub";
  const char* sub = "test_scan_excl_sub/sub";
  const char* root_txt = "test_scan_excl_sub/root.txt";
  const char* sub_txt = "test_scan_excl_sub/sub/data.txt";
  const char* sub_tmp = "test_scan_excl_sub/sub/temp.tmp";
  const char* content = "data";

  mkdir(root, 0755);
  mkdir(sub, 0755);
  create_test_file(root_txt, content);
  create_test_file(sub_txt, content);
  create_test_file(sub_tmp, content);

  /* Exclude *.tmp — should exclude sub/temp.tmp but keep root.txt and sub/data.txt */
  char* exclude[] = {"*.tmp"};
  DirectoryScanner* scanner =
      directory_scanner_create((char*)root, false, 0, exclude, 1, NULL, 0, 0, 0);
  EXPECT_NOT_NULL(scanner);

  int total = 0;
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    total += chunk->element_count;
    for (int i = 0; i < chunk->element_count; i++) {
      /* No path should end in .tmp */
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
  /* In the scanner, exclude is checked first and takes precedence.
   * Include patterns act as an additional filter: if include_count > 0,
   * the file must match one of the include patterns (after not being excluded).
   * This test uses non-overlapping exclude and include patterns. */
  const char* dir = "test_scan_inc_exc";
  const char* f_txt = "test_scan_inc_exc/a.txt";
  const char* f_log = "test_scan_inc_exc/b.log";
  const char* f_bak = "test_scan_inc_exc/c.bak";
  const char* content = "filter";

  mkdir(dir, 0755);
  create_test_file(f_txt, content);
  create_test_file(f_log, content);
  create_test_file(f_bak, content);

  /* Exclude *.bak. Include *.txt and *.log. */
  char* exclude[] = {"*.bak"};
  char* include[] = {"*.txt", "*.log"};
  DirectoryScanner* scanner =
      directory_scanner_create((char*)dir, false, 0, exclude, 1, include, 2, 0, 0);
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
  /* a.txt included by *.txt, b.log included by *.log, c.bak excluded by *.bak */
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
  mkdir(dir, 0755);
  create_test_file(small, "tiny");
  create_test_file(large, "this_content_is_longer_than_ten_chars");

  /* max_size = 10 — only files <= 10 bytes */
  DirectoryScanner* scanner =
      directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 10, 0);
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

  mkdir(dir, 0755);
  create_test_file(empty_f, "");
  create_test_file(data_f, "some content here");

  /* min_size = 1 — only files >= 1 byte */
  DirectoryScanner* scanner =
      directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 0, 1);
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

  mkdir(dir, 0755);
  create_test_file(tiny, "ab");
  create_test_file(medium, "hello world");
  create_test_file(huge, "this is a much larger file for testing size filters");

  /* Only files between 3 and 20 bytes */
  DirectoryScanner* scanner =
      directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 20, 3);
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

  mkdir(dir, 0755);
  create_test_file(a_txt, "aaaaa");
  create_test_file(b_bin, "bbbbbbbbbbbbb");
  create_test_file(c_txt, "ccccc");
  create_test_file(d_bak, "dddddddddddddddddddddddddddddddddddddddddd");

  /* Exclude *.bak, include *.txt, min_size=3, max_size=10 */
  char* exclude[] = {"*.bak"};
  char* include[] = {"*.txt"};
  DirectoryScanner* scanner =
      directory_scanner_create((char*)dir, false, 0, exclude, 1, include, 1, 10, 3);
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

  mkdir(dir, 0755);
  create_test_file(f1, "first");
  create_test_file(f2, "second");

  DirectoryScanner* scanner =
      directory_scanner_create((char*)dir, false, 0, NULL, 0, NULL, 0, 0, 0);
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
}
