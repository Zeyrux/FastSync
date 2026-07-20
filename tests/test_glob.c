#include "test_glob.h"
#include "utils.h"
#include "test_utils.h"
#include <string.h>

static void test_glob_exact_match() {
  EXPECT_TRUE(glob_match("foo", "foo"));
}

static void test_glob_question_mark() {
  EXPECT_TRUE(glob_match("f?o", "foo"));
  EXPECT_FALSE(glob_match("f?o", "fo"));
}

static void test_glob_star() {
  EXPECT_TRUE(glob_match("*.txt", "foo.txt"));
  EXPECT_TRUE(glob_match("*.txt", "a.txt"));
}

static void test_glob_star_mid() {
  EXPECT_TRUE(glob_match("f*o", "foo"));
  EXPECT_TRUE(glob_match("f*o", "fxxo"));
  EXPECT_FALSE(glob_match("f*o", "bar"));
}

static void test_glob_no_match() {
  EXPECT_FALSE(glob_match("foo", "bar"));
}

static void test_glob_empty_pattern() {
  EXPECT_TRUE(glob_match("", ""));
  EXPECT_FALSE(glob_match("", "foo"));
}

static void test_glob_star_all() {
  EXPECT_TRUE(glob_match("*", "anything"));
}

static void test_glob_slash_not_matched() {
  EXPECT_FALSE(glob_match("f*o", "f/o"));
}

static void test_glob_complex() {
  EXPECT_TRUE(glob_match("*.c", "main.c"));
  EXPECT_FALSE(glob_match("*.c", "main.h"));
}

static void test_glob_question_star() {
  EXPECT_TRUE(glob_match("?*.txt", "a.txt"));
}

void test_glob() {
  test_glob_exact_match();
  test_glob_question_mark();
  test_glob_star();
  test_glob_star_mid();
  test_glob_no_match();
  test_glob_empty_pattern();
  test_glob_star_all();
  test_glob_slash_not_matched();
  test_glob_complex();
  test_glob_question_star();
}
