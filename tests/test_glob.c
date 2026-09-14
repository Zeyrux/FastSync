#include "test_glob.h"
#include "utils.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static void test_glob_doublestar_match_all() {
  EXPECT_TRUE(glob_match("**", "anything"));
  EXPECT_TRUE(glob_match("**", "path/to/file"));
}

static void test_glob_doublestar_prefix() {
  EXPECT_TRUE(glob_match("**/foo", "foo"));
  EXPECT_TRUE(glob_match("**/foo", "bar/foo"));
  EXPECT_TRUE(glob_match("**/foo", "a/b/c/foo"));
  EXPECT_FALSE(glob_match("**/foo", "foobar"));
  EXPECT_FALSE(glob_match("**/foo", "bar/foobar"));
}

static void test_glob_doublestar_suffix() {
  EXPECT_TRUE(glob_match("foo/**", "foo"));
  EXPECT_TRUE(glob_match("foo/**", "foo/bar"));
  EXPECT_TRUE(glob_match("foo/**", "foo/bar/baz"));
  EXPECT_FALSE(glob_match("foo/**", "foobar"));
}

static void test_glob_doublestar_mid() {
  EXPECT_TRUE(glob_match("a/**/b", "a/b"));
  EXPECT_TRUE(glob_match("a/**/b", "a/x/b"));
  EXPECT_TRUE(glob_match("a/**/b", "a/x/y/z/b"));
  EXPECT_FALSE(glob_match("a/**/b", "a/x/bad"));
}

/* The old backtracking matcher explored an exponential number of paths for a
 * pattern with many `*` wildcards against a long run that never matches the
 * trailing literal.  The iterative matcher must stay bounded: 30 `*a` groups
 * followed by `b` against ten thousand `a`s is a few hundred thousand states,
 * not 2^30 recursion nodes. */
static void test_glob_pathological_is_bounded() {
  char pattern[128];
  size_t pos = 0;
  for (int i = 0; i < 30; i++) {
    pattern[pos++] = '*';
    pattern[pos++] = 'a';
  }
  pattern[pos++] = 'b';
  pattern[pos] = '\0';

  char* text = malloc(10001);
  EXPECT_NOT_NULL(text);
  memset(text, 'a', 10000);
  text[10000] = '\0';

  clock_t start = clock();
  EXPECT_FALSE(glob_match(pattern, text));
  double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
  EXPECT_TRUE(elapsed < 5.0);

  free(text);
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
  test_glob_doublestar_match_all();
  test_glob_doublestar_prefix();
  test_glob_doublestar_suffix();
  test_glob_doublestar_mid();
  test_glob_pathological_is_bounded();
}
