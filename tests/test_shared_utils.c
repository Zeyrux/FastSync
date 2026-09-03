#include "test_shared_utils.h"
#include "utils.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>

void test_shared_utils() {
  char high_bit[] = {'a', (char)0xc3, (char)0xa9, '\n', '\0'};
  char* escaped = output_escape(high_bit, false);
  EXPECT_EQ_STR(escaped, "a\\#303\\#251\\#012");
  free(escaped);
  escaped = output_escape(high_bit, true);
  EXPECT_EQ_STR(escaped, "a\xc3\xa9\\#012");
  free(escaped);

  // Test str_dup
  const char* dup_null = str_dup(NULL);
  EXPECT_NULL(dup_null);

  char* dup_empty = str_dup("");
  EXPECT_NOT_NULL(dup_empty);
  EXPECT_EQ_STR(dup_empty, "");
  free(dup_empty);

  char* dup_normal = str_dup("hello world");
  EXPECT_NOT_NULL(dup_normal);
  EXPECT_EQ_STR(dup_normal, "hello world");
  free(dup_normal);

  // Test path_cat
  char* cat1 = path_cat("/foo", "/bar");
  EXPECT_NOT_NULL(cat1);
  EXPECT_EQ_STR(cat1, "/foo/bar");
  free(cat1);

  char* cat2 = path_cat("/foo/", "/bar");
  EXPECT_NOT_NULL(cat2);
  EXPECT_EQ_STR(cat2, "/foo/bar");
  free(cat2);

  char* cat3 = path_cat("/foo", "bar");
  EXPECT_NOT_NULL(cat3);
  EXPECT_EQ_STR(cat3, "/foo/bar");
  free(cat3);

  char* cat4 = path_cat("/foo/", "bar");
  EXPECT_NOT_NULL(cat4);
  EXPECT_EQ_STR(cat4, "/foo/bar");
  free(cat4);

  char* cat_empty1 = path_cat("", "/bar");
  EXPECT_NOT_NULL(cat_empty1);
  EXPECT_EQ_STR(cat_empty1, "/bar");
  free(cat_empty1);

  char* cat_empty2 = path_cat("/foo", "");
  EXPECT_NOT_NULL(cat_empty2);
  EXPECT_EQ_STR(cat_empty2, "/foo");
  free(cat_empty2);

  char* cat_null1 = path_cat(NULL, "/bar");
  EXPECT_NOT_NULL(cat_null1);
  EXPECT_EQ_STR(cat_null1, "/bar");
  free(cat_null1);

  char* cat_null2 = path_cat("/foo", NULL);
  EXPECT_NOT_NULL(cat_null2);
  EXPECT_EQ_STR(cat_null2, "/foo");
  free(cat_null2);
}
