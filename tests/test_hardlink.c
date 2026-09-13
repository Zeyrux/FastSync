#include "test_hardlink.h"
#include "hardlink.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* A fresh table starts empty and destroy accepts NULL / a fresh table. */
static void test_hardlink_create_destroy() {
  hardlink_table_destroy(NULL);

  HardLinkTable* table = hardlink_table_create();
  EXPECT_NOT_NULL(table);
  EXPECT_EQ_INT((int)table->count, 0);
  EXPECT_EQ_INT((int)table->capacity, 0);
  EXPECT_EQ_INT(table->next_gid, 1);
  hardlink_table_destroy(table);
}

/* The first member of an (dev, ino) group is data-carrying and owns the group;
 * every later member gets the SAME gid, is not first, and points back at the
 * first member's wire path. */
static void test_hardlink_grouping() {
  HardLinkTable* table = hardlink_table_create();
  EXPECT_NOT_NULL(table);

  int gid_a = -1, gid_b = -1;
  bool first_a = false, first_b = false;
  char* first_path_a = NULL;
  char* first_path_b = NULL;

  EXPECT_TRUE(
      hardlink_table_assign(table, "dir/first.txt", 7, 42, &gid_a, &first_a, &first_path_a));
  EXPECT_TRUE(first_a);
  EXPECT_EQ_INT(gid_a, 1);
  EXPECT_NOT_NULL(first_path_a);
  EXPECT_EQ_STR(first_path_a, "dir/first.txt");

  EXPECT_TRUE(
      hardlink_table_assign(table, "dir/second.txt", 7, 42, &gid_b, &first_b, &first_path_b));
  EXPECT_FALSE(first_b);
  EXPECT_EQ_INT(gid_b, gid_a);
  EXPECT_NOT_NULL(first_path_b);
  EXPECT_EQ_STR(first_path_b, "dir/first.txt");

  /* Two members map onto a single stored group. */
  EXPECT_EQ_INT((int)table->count, 1);
  EXPECT_EQ_INT(table->next_gid, 2);

  free(first_path_a);
  free(first_path_b);
  hardlink_table_destroy(table);
}

/* A different inode on the same device is a distinct group with a fresh gid. */
static void test_hardlink_distinct_inode() {
  HardLinkTable* table = hardlink_table_create();
  EXPECT_NOT_NULL(table);

  int gid1 = -1, gid2 = -1;
  bool first1 = false, first2 = false;
  char* path1 = NULL;
  char* path2 = NULL;

  EXPECT_TRUE(hardlink_table_assign(table, "a", 7, 100, &gid1, &first1, &path1));
  EXPECT_TRUE(first1);
  EXPECT_TRUE(hardlink_table_assign(table, "b", 7, 101, &gid2, &first2, &path2));
  EXPECT_TRUE(first2);
  EXPECT_TRUE(gid1 != gid2);
  EXPECT_EQ_INT(gid1, 1);
  EXPECT_EQ_INT(gid2, 2);
  EXPECT_EQ_STR(path1, "a");
  EXPECT_EQ_STR(path2, "b");

  free(path1);
  free(path2);
  hardlink_table_destroy(table);
}

/* Identical (dev, ino) on a DIFFERENT device must never be conflated: inode
 * numbers are only unique per filesystem, so grouping is scoped by st_dev. */
static void test_hardlink_distinct_device() {
  HardLinkTable* table = hardlink_table_create();
  EXPECT_NOT_NULL(table);

  int gid1 = -1, gid2 = -1;
  bool first1 = false, first2 = false;
  char* path1 = NULL;
  char* path2 = NULL;

  EXPECT_TRUE(hardlink_table_assign(table, "dev_a/one", 1, 55, &gid1, &first1, &path1));
  EXPECT_TRUE(hardlink_table_assign(table, "dev_b/one", 2, 55, &gid2, &first2, &path2));
  EXPECT_TRUE(first1);
  EXPECT_TRUE(first2);
  EXPECT_TRUE(gid1 != gid2);
  EXPECT_EQ_INT((int)table->count, 2);

  free(path1);
  free(path2);
  hardlink_table_destroy(table);
}

/* The table owns deep copies of every path: mutating (or freeing) the caller's
 * buffer after assign must not affect the stored / returned paths. */
static void test_hardlink_path_ownership() {
  HardLinkTable* table = hardlink_table_create();
  EXPECT_NOT_NULL(table);

  char caller[] = "owned/path";
  int gid = -1;
  bool is_first = false;
  char* out = NULL;

  EXPECT_TRUE(hardlink_table_assign(table, caller, 3, 9, &gid, &is_first, &out));
  EXPECT_TRUE(is_first);
  /* The returned pointer is a distinct allocation, not the caller's buffer. */
  EXPECT_TRUE(out != caller);
  EXPECT_TRUE(table->items[0].first_path != caller);

  memset(caller, 'X', sizeof(caller) - 1);
  EXPECT_EQ_STR(out, "owned/path");
  EXPECT_EQ_STR(table->items[0].first_path, "owned/path");

  /* Later members get their own independent copy of the first path. */
  char second_caller[] = "owned/second";
  int gid2 = -1;
  bool first2 = true;
  char* out2 = NULL;
  EXPECT_TRUE(hardlink_table_assign(table, second_caller, 3, 9, &gid2, &first2, &out2));
  EXPECT_FALSE(first2);
  EXPECT_EQ_STR(out2, "owned/path");
  EXPECT_TRUE(out2 != table->items[0].first_path);
  EXPECT_TRUE(out2 != out);

  free(out);
  free(out2);
  hardlink_table_destroy(table);
}

/* Bad arguments must be rejected without touching the table. */
static void test_hardlink_reject_bad_args() {
  HardLinkTable* table = hardlink_table_create();
  EXPECT_NOT_NULL(table);

  int gid = 0;
  bool is_first = false;
  char* out = NULL;

  EXPECT_FALSE(hardlink_table_assign(NULL, "x", 1, 1, &gid, &is_first, &out));
  EXPECT_FALSE(hardlink_table_assign(table, NULL, 1, 1, &gid, &is_first, &out));
  EXPECT_FALSE(hardlink_table_assign(table, "x", 1, 1, NULL, &is_first, &out));
  EXPECT_FALSE(hardlink_table_assign(table, "x", 1, 1, &gid, NULL, &out));
  EXPECT_FALSE(hardlink_table_assign(table, "x", 1, 1, &gid, &is_first, NULL));
  EXPECT_EQ_INT((int)table->count, 0);

  hardlink_table_destroy(table);
}

/* Many distinct groups grow the item array through its realloc path and keep
 * gid assignment stable and monotonic. */
static void test_hardlink_many_groups() {
  HardLinkTable* table = hardlink_table_create();
  EXPECT_NOT_NULL(table);

  const int n = 200;
  for (int i = 0; i < n; i++) {
    int gid = -1;
    bool is_first = false;
    char* out = NULL;
    char path[32];
    snprintf(path, sizeof(path), "file_%d", i);
    EXPECT_TRUE(hardlink_table_assign(table, path, 1, (ino_t)(1000 + i), &gid, &is_first, &out));
    EXPECT_TRUE(is_first);
    EXPECT_EQ_INT(gid, i + 1);
    EXPECT_EQ_STR(out, path);
    free(out);
  }
  EXPECT_EQ_INT((int)table->count, n);
  EXPECT_EQ_INT(table->next_gid, n + 1);

  /* Re-querying an existing inode still reports the original gid. */
  int gid = -1;
  bool is_first = true;
  char* out = NULL;
  EXPECT_TRUE(hardlink_table_assign(table, "file_7_again", 1, 1007, &gid, &is_first, &out));
  EXPECT_FALSE(is_first);
  EXPECT_EQ_INT(gid, 8);
  EXPECT_EQ_STR(out, "file_7");
  free(out);

  hardlink_table_destroy(table);
}

void test_hardlink() {
  test_hardlink_create_destroy();
  test_hardlink_grouping();
  test_hardlink_distinct_inode();
  test_hardlink_distinct_device();
  test_hardlink_path_ownership();
  test_hardlink_reject_bad_args();
  test_hardlink_many_groups();
}
