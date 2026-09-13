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

/* Explicit ancestor/descendant coverage: a query that is a proper ancestor of
   a listed entry is affected, and a query below a listed entry is affected,
   while a component-boundary neighbor is not. */
static void test_ancestor_and_descendant_queries() {
  const char* path = "test_file_list_ancestor.txt";
  char err[160];
  write_list(path, "top/mid/leaf.txt\nsingle.txt\n");
  FileListSet* set = file_list_load(path, false, err, sizeof(err));
  EXPECT_NOT_NULL(set);

  /* q is an ancestor of a listed entry. */
  EXPECT_TRUE(file_list_affects(set, "top"));
  EXPECT_TRUE(file_list_affects(set, "top/mid"));
  EXPECT_FALSE(file_list_affects(set, "top/other")); /* neither direction */
  EXPECT_FALSE(file_list_affects(set, "to"));        /* component boundary */

  /* A listed entry is an ancestor of q. */
  EXPECT_TRUE(file_list_affects(set, "single.txt"));
  EXPECT_TRUE(file_list_affects(set, "single.txt/deeper"));
  EXPECT_FALSE(file_list_affects(set, "single.txtx")); /* boundary */

  check_queries(set,
                (const char*[]){"top", "top/mid", "top/mid/leaf.txt", "top/other", "single.txt",
                                "single.txt/deeper", "single.txtx", "to"},
                8);
  file_list_destroy(set);
  remove(path);
}

/* Regression for the remote OOM: an adversarial --files-from entry made of a
   very deep chain of repeated components must be indexed with memory
   proportional to the entry count.  The old implementation stored one copied
   ancestor prefix per component (O(L^2) bytes for a single entry); the sorted
   index stores the exact entries only. */
static void test_deep_paths_are_bounded() {
  const char* path = "test_file_list_deep.txt";
  enum { COMPONENTS = 20000 };
  size_t entry_len = (size_t)COMPONENTS * 2; /* "a/" per component */
  char* entry = malloc(entry_len + 1);
  EXPECT_NOT_NULL(entry);
  for (size_t i = 0; i < entry_len; i += 2) {
    entry[i] = 'a';
    entry[i + 1] = '/';
  }
  entry[entry_len - 1] = 'z'; /* .../a/z: a deep leaf name */
  entry[entry_len] = '\0';

  FILE* fp = fopen(path, "wb");
  EXPECT_NOT_NULL(fp);
  EXPECT_EQ_INT((int)fwrite(entry, 1, entry_len, fp), (int)entry_len);
  EXPECT_EQ_INT(fputc('\n', fp), '\n');
  fclose(fp);

  char err[160];
  FileListSet* set = file_list_load(path, false, err, sizeof(err));
  EXPECT_NOT_NULL(set);
  EXPECT_EQ_INT(set->count, 1);
  /* One exact entry stored, not one node per path component. */
  EXPECT_EQ_INT((int)set->index.sorted.count, 1);
  EXPECT_EQ_INT((int)set->index.exact.size, 1);
  EXPECT_TRUE(file_list_affects(set, entry)); /* exact */
  EXPECT_TRUE(file_list_affects(set, "a"));   /* ancestor of the entry */
  EXPECT_TRUE(file_list_affects(set, "a/a")); /* deeper ancestor */
  EXPECT_FALSE(file_list_affects(set, "b"));  /* unrelated */
  EXPECT_FALSE(file_list_affects(set, "aa")); /* component boundary */

  file_list_destroy(set);
  remove(path);
  free(entry);
}

void test_file_list() {
  test_membership_matches_reference();
  test_ancestor_and_descendant_queries();
  test_deep_paths_are_bounded();
}
