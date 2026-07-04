#include "test_utils.h"
#include "scanner.h"
#include "file.h"
#include "utils.h"
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void create_test_file(const char *path, const char *content) {
  to_disk(path, content, strlen(content));
}

static void test_scanner_single_file() {
  const char *dir = "test_scan_dir_single";
  const char *file1 = "test_scan_dir_single/file1.txt";
  const char *content1 = "hello scanner";

  mkdir(dir, 0755);
  create_test_file(file1, content1);

  DirectoryScanner *scanner = directory_scanner_create((char *)dir);
  EXPECT_NOT_NULL(scanner);

  Chunk *chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 1);
  EXPECT_EQ_STR(chunk->items[0]->path, file1);

  Chunk *next = directory_scanner_next(scanner);
  EXPECT_NULL(next);

  chunk_destroy(chunk);
  directory_scanner_destroy(scanner);
  unlink(file1);
  rmdir(dir);
}

static void test_scanner_multiple_files() {
  const char *dir = "test_scan_dir_multi";
  const char *file1 = "test_scan_dir_multi/a.txt";
  const char *file2 = "test_scan_dir_multi/b.txt";
  const char *content1 = "alpha";
  const char *content2 = "beta";

  mkdir(dir, 0755);
  create_test_file(file1, content1);
  create_test_file(file2, content2);

  DirectoryScanner *scanner = directory_scanner_create((char *)dir);
  EXPECT_NOT_NULL(scanner);

  Chunk *chunk = directory_scanner_next(scanner);
  EXPECT_NOT_NULL(chunk);
  EXPECT_EQ_INT(chunk->element_count, 2);

  int found1 = 0, found2 = 0;
  for (int i = 0; i < chunk->element_count; i++) {
    if (strcmp(chunk->items[i]->path, file1) == 0) found1 = 1;
    if (strcmp(chunk->items[i]->path, file2) == 0) found2 = 1;
  }
  EXPECT_TRUE(found1);
  EXPECT_TRUE(found2);

  Chunk *next = directory_scanner_next(scanner);
  EXPECT_NULL(next);

  chunk_destroy(chunk);
  directory_scanner_destroy(scanner);
  unlink(file1);
  unlink(file2);
  rmdir(dir);
}

static void test_scanner_subdirectory() {
  const char *root = "test_scan_sub";
  const char *sub = "test_scan_sub/sub";
  const char *root_file = "test_scan_sub/root.txt";
  const char *sub_file = "test_scan_sub/sub/sub_file.txt";
  const char *content = "nested content";

  mkdir(root, 0755);
  mkdir(sub, 0755);
  create_test_file(root_file, content);
  create_test_file(sub_file, content);

  DirectoryScanner *scanner = directory_scanner_create((char *)root);
  EXPECT_NOT_NULL(scanner);

  int total_files = 0;
  Chunk *chunk;
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
  const char *dir = "test_scan_empty";

  mkdir(dir, 0755);

  DirectoryScanner *scanner = directory_scanner_create((char *)dir);
  EXPECT_NOT_NULL(scanner);

  Chunk *chunk = directory_scanner_next(scanner);
  EXPECT_NULL(chunk);

  directory_scanner_destroy(scanner);
  rmdir(dir);
}

void test_scanner() {
  test_scanner_single_file();
  test_scanner_multiple_files();
  test_scanner_subdirectory();
  test_scanner_empty_directory();
}
