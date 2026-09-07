#include "test_shared_utils.h"
#include "utils.h"
#include "protocol.h"
#include "test_utils.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <threads.h>
#include <unistd.h>

/* ---- delete-walker tests ---- */

static char* make_walk_root(const char* tag) {
  char* path = malloc(256);
  if (!path)
    return NULL;
  snprintf(path, 256, "/tmp/fastsync_walk_%s_%d", tag, (int)getpid());
  rmdir(path);
  if (mkdir(path, 0755) != 0) {
    free(path);
    return NULL;
  }
  return path;
}

static bool write_file_at(const char* dir, const char* name, const char* content) {
  char* path = path_cat(dir, name);
  if (!path)
    return false;
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  bool ok = fd >= 0;
  if (fd >= 0) {
    if (content) {
      const char* p = content;
      size_t remaining = strlen(content);
      while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n <= 0) {
          ok = false;
          break;
        }
        p += n;
        remaining -= (size_t)n;
      }
    }
    close(fd);
  }
  free(path);
  return ok;
}

static bool file_exists(const char* dir, const char* name) {
  char* path = path_cat(dir, name);
  bool exists = path && access(path, F_OK) == 0;
  free(path);
  return exists;
}

static bool dir_exists(const char* dir, const char* name) {
  char* path = path_cat(dir, name);
  struct stat st;
  bool exists = path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
  free(path);
  return exists;
}

static int make_subdir(const char* root, const char* name) {
  char* path = path_cat(root, name);
  int rc = -1;
  if (path) {
    rc = mkdir(path, 0755);
    free(path);
  }
  return rc;
}

static void remove_walk_tree(const char* path) {
  DIR* dir = opendir(path);
  if (!dir) {
    rmdir(path);
    return;
  }
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    char* child = path_cat(path, entry->d_name);
    if (child) {
      struct stat st;
      if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
        remove_walk_tree(child);
      else
        unlink(child);
      free(child);
    }
  }
  closedir(dir);
  rmdir(path);
}

static ArrayList* make_manifest_strings(const char* const* entries, int count) {
  ArrayList* manifest = array_list_create(free);
  if (!manifest)
    return NULL;
  for (int i = 0; i < count; i++) {
    char* dup = str_dup(entries[i]);
    if (!dup || !array_list_add(manifest, dup)) {
      free(dup);
      array_list_delete(manifest);
      return NULL;
    }
  }
  return manifest;
}

static void test_walker_removes_extras_keeps_manifest_and_protected() {
  char* root = make_walk_root("basic");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "a.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "keep.txt", "kept"));
  EXPECT_EQ_INT(make_subdir(root, "d"), 0);
  EXPECT_TRUE(write_file_at(root, "d/e.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "d/k.txt", "kept"));
  EXPECT_EQ_INT(make_subdir(root, "prot"), 0);
  EXPECT_TRUE(write_file_at(root, "prot/f.txt", "untouched"));

  const char* keeps[] = {"keep.txt", "d/k.txt"};
  ArrayList* manifest = make_manifest_strings(keeps, 2);
  EXPECT_NOT_NULL(manifest);
  DeleteSkipEntry skip = {"prot", false};
  size_t deleted = 0;
  DeleteWalkResult result = delete_extras_limited(root, manifest, 100000, &skip, 1, &deleted);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_OK);
  EXPECT_FALSE(file_exists(root, "a.txt"));
  EXPECT_TRUE(file_exists(root, "keep.txt"));
  EXPECT_FALSE(file_exists(root, "d/e.txt"));
  EXPECT_TRUE(file_exists(root, "d/k.txt"));
  EXPECT_TRUE(dir_exists(root, "d"));
  EXPECT_TRUE(file_exists(root, "prot/f.txt"));
  EXPECT_TRUE(deleted >= 2);
  array_list_delete(manifest);
  remove_walk_tree(root);
  free(root);
}

static void test_walker_max_delete_exceeded_deletes_nothing() {
  char* root = make_walk_root("maxdel");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "a.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "b.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "c.txt", "extra"));
  const char* keeps[1] = {NULL};
  ArrayList* manifest = make_manifest_strings(keeps, 0);
  EXPECT_NOT_NULL(manifest);
  size_t deleted = 999;
  DeleteWalkResult result = delete_extras_limited(root, manifest, 2, NULL, 0, &deleted);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_LIMIT_EXCEEDED);
  EXPECT_EQ_INT((int)deleted, 0);
  EXPECT_TRUE(file_exists(root, "a.txt"));
  EXPECT_TRUE(file_exists(root, "b.txt"));
  EXPECT_TRUE(file_exists(root, "c.txt"));
  array_list_delete(manifest);
  remove_walk_tree(root);
  free(root);
}

static void test_walker_max_delete_exact_bound_deletes() {
  char* root = make_walk_root("maxdel2");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "a.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "b.txt", "extra"));
  const char* keeps[1] = {NULL};
  ArrayList* manifest = make_manifest_strings(keeps, 0);
  EXPECT_NOT_NULL(manifest);
  size_t deleted = 0;
  DeleteWalkResult result = delete_extras_limited(root, manifest, 2, NULL, 0, &deleted);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_OK);
  EXPECT_EQ_INT((int)deleted, 2);
  EXPECT_FALSE(file_exists(root, "a.txt"));
  EXPECT_FALSE(file_exists(root, "b.txt"));
  array_list_delete(manifest);
  remove_walk_tree(root);
  free(root);
}

static void test_walker_unlimited_deletes_all() {
  char* root = make_walk_root("unlim");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "a.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "b.txt", "extra"));
  EXPECT_EQ_INT(make_subdir(root, "emptydir"), 0);
  const char* keeps[1] = {NULL};
  ArrayList* manifest = make_manifest_strings(keeps, 0);
  EXPECT_NOT_NULL(manifest);
  EXPECT_TRUE(delete_extras(root, manifest));
  EXPECT_FALSE(file_exists(root, "a.txt"));
  EXPECT_FALSE(file_exists(root, "b.txt"));
  EXPECT_FALSE(dir_exists(root, "emptydir"));
  array_list_delete(manifest);
  remove_walk_tree(root);
  free(root);
}

/* The 100000-entry server hard bound (MAX_SERVER_DELETE_COUNT, which this test
   exercises through a literal to avoid reaching into file_receive.c) is also
   all-or-nothing: a destination holding more extras than the bound must be left
   completely untouched.  Skipped under valgrind: 100k file creations would be
   far too slow under instrumentation. */
static void test_walker_hard_bound_all_or_nothing() {
  if (is_running_under_valgrind())
    return;
  enum { HARD_BOUND = 100000 };
  char* root = make_walk_root("hardbound");
  EXPECT_NOT_NULL(root);
  int rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  EXPECT_TRUE(rootfd >= 0);
  bool created = true;
  for (int i = 0; created && i < HARD_BOUND + 1; i++) {
    char name[32];
    snprintf(name, sizeof(name), "f%d", i);
    int fd = openat(rootfd, name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
      created = false;
    else
      close(fd);
  }
  EXPECT_TRUE(created);
  const char* keeps[1] = {NULL};
  ArrayList* manifest = make_manifest_strings(keeps, 0);
  EXPECT_NOT_NULL(manifest);
  size_t deleted = 999;
  DeleteWalkResult result = delete_extras_limited(root, manifest, HARD_BOUND, NULL, 0, &deleted);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_LIMIT_EXCEEDED);
  EXPECT_EQ_INT((int)deleted, 0);
  EXPECT_TRUE(file_exists(root, "f0"));
  EXPECT_TRUE(file_exists(root, "f100000"));
  array_list_delete(manifest);
  /* Fast cleanup: unlink every created name through the still-open root fd. */
  if (rootfd >= 0) {
    for (int i = 0; i < HARD_BOUND + 1; i++) {
      char name[32];
      snprintf(name, sizeof(name), "f%d", i);
      (void)unlinkat(rootfd, name, 0);
    }
    close(rootfd);
  }
  rmdir(root);
  free(root);
}

typedef struct {
  bool eight_bit_output;
  const char* expected;
  int failed;
} EscapeThreadArgs;

static int escape_thread(void* arg) {
  EscapeThreadArgs* args = arg;
  for (int i = 0; i < 1000; i++) {
    char* escaped = output_escape("x\xc3\xa9\n", args->eight_bit_output);
    if (!escaped || strcmp(escaped, args->expected) != 0)
      args->failed = 1;
    free(escaped);
  }
  return 0;
}

void test_shared_utils() {
  test_walker_removes_extras_keeps_manifest_and_protected();
  test_walker_max_delete_exceeded_deletes_nothing();
  test_walker_max_delete_exact_bound_deletes();
  test_walker_unlimited_deletes_all();
  test_walker_hard_bound_all_or_nothing();

  /* --append / --append-verify tail-resume math: a resume is eligible only for
     a shorter existing destination, and the tail length is then the difference. */
  EXPECT_TRUE(append_resume_eligible(0, 10));
  EXPECT_TRUE(append_resume_eligible(7, 10));
  EXPECT_FALSE(append_resume_eligible(10, 10));
  EXPECT_FALSE(append_resume_eligible(11, 10));

  unsigned long long tail;
  EXPECT_TRUE(append_tail_length(0, 10, &tail));
  EXPECT_EQ_INT((int)tail, 10);
  EXPECT_TRUE(append_tail_length(7, 10, &tail));
  EXPECT_EQ_INT((int)tail, 3);
  EXPECT_FALSE(append_tail_length(10, 10, &tail));
  EXPECT_FALSE(append_tail_length(11, 10, &tail));
  EXPECT_FALSE(append_tail_length(7, 10, NULL));

  char formatted[32];
  EXPECT_TRUE(format_human_bytes(0, formatted, sizeof(formatted)));
  EXPECT_EQ_STR(formatted, "0 B");
  EXPECT_TRUE(format_human_bytes(1024, formatted, sizeof(formatted)));
  EXPECT_EQ_STR(formatted, "1.0 KB");
  EXPECT_TRUE(format_human_bytes(1536 * 1024, formatted, sizeof(formatted)));
  EXPECT_EQ_STR(formatted, "1.5 MB");
  EXPECT_FALSE(format_human_bytes(1024, formatted, 4));

  char high_bit[] = {'a', (char)0xc3, (char)0xa9, '\n', '\0'};
  char* escaped = output_escape(high_bit, false);
  EXPECT_EQ_STR(escaped, "a\\#303\\#251\\#012");
  free(escaped);
  escaped = output_escape(high_bit, true);
  EXPECT_EQ_STR(escaped, "a\xc3\xa9\\#012");
  free(escaped);

  ProtocolSession safe_session;
  ProtocolSession eight_bit_session;
  protocol_session_init(&safe_session, -1, -1);
  protocol_session_init(&eight_bit_session, -1, -1);
  protocol_session_set_8_bit_output(&safe_session, false);
  protocol_session_set_8_bit_output(&eight_bit_session, true);
  EXPECT_FALSE(safe_session.eight_bit_output);
  EXPECT_TRUE(eight_bit_session.eight_bit_output);

  EscapeThreadArgs safe_args = {false, "x\\#303\\#251\\#012", 0};
  EscapeThreadArgs eight_bit_args = {true, "x\xc3\xa9\\#012", 0};
  thrd_t safe_thread;
  thrd_t eight_bit_thread;
  EXPECT_EQ_INT(thrd_create(&safe_thread, escape_thread, &safe_args), thrd_success);
  EXPECT_EQ_INT(thrd_create(&eight_bit_thread, escape_thread, &eight_bit_args), thrd_success);
  EXPECT_EQ_INT(thrd_join(safe_thread, NULL), thrd_success);
  EXPECT_EQ_INT(thrd_join(eight_bit_thread, NULL), thrd_success);
  EXPECT_FALSE(safe_args.failed);
  EXPECT_FALSE(eight_bit_args.failed);

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
