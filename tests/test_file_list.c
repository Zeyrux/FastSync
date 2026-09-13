#include "test_file_list.h"
#include "file_list.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Reference implementation of the ORIGINAL file_list_affects linear scan.  The
   indexed implementation must agree with it on every query; this pins the
   subtle semantics: empty entry == whole tree, exact match, rel under a listed
   directory, and rel an ancestor directory of a listed entry. */
static bool reference_affects(const FileListSet* set, const char* rel) {
  if (!set)
    return true;
  if (!rel)
    return false;
  for (int i = 0; i < set->count; i++) {
    const char* entry = set->entries[i];
    if (entry[0] == '\0')
      return true;
    if (strcmp(rel, entry) == 0)
      return true;
    size_t entry_len = strlen(entry);
    if (strncmp(rel, entry, entry_len) == 0 && (rel[entry_len] == '/' || rel[entry_len] == '\0'))
      return true;
    size_t rel_len = strlen(rel);
    if (strncmp(entry, rel, rel_len) == 0 && (entry[rel_len] == '/' || entry[rel_len] == '\0'))
      return true;
  }
  return false;
}

static void write_list(const char* path, const char* bytes) {
  FILE* fp = fopen(path, "wb");
  EXPECT_NOT_NULL(fp);
  size_t len = strlen(bytes);
  EXPECT_EQ_INT((int)fwrite(bytes, 1, len, fp), (int)len);
  fclose(fp);
}

static void check_queries(const FileListSet* set, const char* const* queries, int query_count) {
  for (int i = 0; i < query_count; i++) {
    bool expected = reference_affects(set, queries[i]);
    bool actual = file_list_affects(set, queries[i]);
    if (expected != actual) {
      printf("    [FAIL] affects(\"%s\"): expected %d, got %d\n", queries[i], expected, actual);
      current_test_failed = true;
      return;
    }
  }
}

static void test_membership_matches_reference() {
  const char* path = "test_file_list_case.txt";
  char err[160];

  /* Nested directories, an ancestor of a listed entry, an exact file, a
     non-matching neighbor with the same prefix, and a literal '*'. */
  write_list(path, "a\na/b\na/b/c\nab\nc.txt\nsub/b.bin\n*\n");
  FileListSet* set = file_list_load(path, false, err, sizeof(err));
  EXPECT_NOT_NULL(set);
  const char* queries[] = {
      "a",    "a/b",   "a/b/c",   "a/b/c/d", "a/bx",   "a/x",       "ab",
      "abc",  "c.txt", "c.txt/x", "c",       "sub",    "sub/b.bin", "sub/b.bin/z",
      "sub2", "*",     "x",       "",        "a/b/cd", "/",         "a/b/",
  };
  check_queries(set, queries, (int)(sizeof(queries) / sizeof(queries[0])));
  EXPECT_TRUE(file_list_affects(set, "a/b/c/d"));
  EXPECT_TRUE(file_list_affects(set, "a/bx")); /* under listed directory "a" */
  EXPECT_TRUE(file_list_affects(set, "a/b/c"));
  EXPECT_TRUE(file_list_affects(set, "a/x"));  /* under listed directory "a" */
  EXPECT_FALSE(file_list_affects(set, "abc")); /* component boundary: not "a" */
  EXPECT_TRUE(file_list_affects(set, "sub"));
  EXPECT_FALSE(file_list_affects(set, "sub2"));
  file_list_destroy(set);
  remove(path);

  /* A single "." entry means the whole tree: every non-NULL query is true. */
  write_list(path, ".\n");
  set = file_list_load(path, false, err, sizeof(err));
  EXPECT_NOT_NULL(set);
  const char* root_queries[] = {"", "a", "a/b/c", "unrelated", "*", "/"};
  for (int i = 0; i < (int)(sizeof(root_queries) / sizeof(root_queries[0])); i++)
    EXPECT_TRUE(file_list_affects(set, root_queries[i]));
  EXPECT_FALSE(file_list_affects(set, NULL));
  check_queries(set, root_queries, (int)(sizeof(root_queries) / sizeof(root_queries[0])));
  file_list_destroy(set);
  remove(path);

  /* Trailing slashes and "./" prefixes normalize away, so the query matches the
     clean path (and not the raw spelling). */
  write_list(path, "./dir/\ndir2/./x\n");
  set = file_list_load(path, false, err, sizeof(err));
  EXPECT_NOT_NULL(set);
  EXPECT_TRUE(file_list_affects(set, "dir"));
  EXPECT_TRUE(file_list_affects(set, "dir/x"));
  EXPECT_TRUE(file_list_affects(set, "dir2/x"));
  EXPECT_TRUE(file_list_affects(set, "dir2"));
  EXPECT_TRUE(file_list_affects(set, "dir/")); /* boundary prefix of listed "dir" */
  check_queries(set, (const char*[]){"dir", "dir/", "dir/x", "dir2", "dir2/x", "dir3"}, 6);
  file_list_destroy(set);
  remove(path);

  /* An empty file yields an empty set: nothing is affected, and NULL set still
     means "everything". */
  write_list(path, "");
  set = file_list_load(path, false, err, sizeof(err));
  EXPECT_NOT_NULL(set);
  EXPECT_EQ_INT(set->count, 0);
  EXPECT_FALSE(file_list_affects(set, "a"));
  EXPECT_FALSE(file_list_affects(set, ""));
  check_queries(set, (const char*[]){"a", "a/b", ""}, 3);
  file_list_destroy(set);
  remove(path);

  /* NULL set is the unrestricted case. */
  EXPECT_TRUE(file_list_affects(NULL, "anything"));
  EXPECT_TRUE(file_list_affects(NULL, NULL));
}

void test_file_list() {
  test_membership_matches_reference();
}
