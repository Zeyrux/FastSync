#include "test_delay_updates.h"
#include "config.h"
#include "delay_updates.h"
#include "file.h"
#include "file_receive.h"
#include "test_utils.h"
#include "utils.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Recursively remove a test tree (never follows symlinks). */
static void remove_tree(const char* path) {
  struct stat st;
  if (lstat(path, &st) != 0)
    return;
  if (S_ISDIR(st.st_mode)) {
    DIR* dir = opendir(path);
    if (!dir)
      return;
    const struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        continue;
      char* child = path_cat(path, entry->d_name);
      if (child) {
        remove_tree(child);
        free(child);
      }
    }
    closedir(dir);
    rmdir(path);
  } else {
    unlink(path);
  }
}

/* Build a File that carries `content`. */
static File* make_file(const char* path, const char* content) {
  File* f = file_create(path);
  if (!f)
    return NULL;
  f->data->data = malloc(strlen(content));
  if (!f->data->data) {
    file_destroy(f);
    return NULL;
  }
  memcpy(f->data->data, content, strlen(content));
  f->data->size = strlen(content);
  return f;
}

static char* read_all(const char* path) {
  FILE* fp = fopen(path, "rb");
  if (!fp)
    return NULL;
  char buf[256] = {0};
  size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
  fclose(fp);
  char* out = malloc(n + 1);
  if (!out)
    return NULL;
  memcpy(out, buf, n);
  out[n] = '\0';
  return out;
}

static void test_delay_updates_no_final_before_publish() {
  const char* root = "test_delay_tmp";
  remove_tree(root);
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->delay_updates = true;

  File* f = make_file("sub/file.txt", "staged payload");
  EXPECT_NOT_NULL(f);
  // cppcheck-suppress knownConditionTrueFalse
  if (!cfg || !f)
    goto out;

  EXPECT_EQ_INT(file_save_to_disk_full(root, f, cfg), FILE_SAVE_WRITTEN);
  EXPECT_NOT_NULL(cfg->delay_context);

  const char* final_path = "test_delay_tmp/sub/file.txt";
  /* Before publication the final destination must not contain the file. */
  EXPECT_FALSE(file_path_exists_secure(final_path));
  /* The complete staged copy must live inside the staging tree. */
  char* staged = path_cat("test_delay_tmp/.fastsync-stage", "/sub/file.txt");
  EXPECT_NOT_NULL(staged);
  // cppcheck-suppress knownConditionTrueFalse
  if (staged) {
    char* content = read_all(staged);
    EXPECT_NOT_NULL(content);
    // cppcheck-suppress knownConditionTrueFalse
    if (content) {
      EXPECT_EQ_STR(content, "staged payload");
      free(content);
    }
    free(staged);
  }

out:
  file_destroy(f);
  config_delete(cfg);
  remove_tree(root);
}

static void test_delay_updates_publish_installs_files() {
  const char* root = "test_delay_pub_tmp";
  remove_tree(root);
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->delay_updates = true;

  File* f = make_file("sub/file.txt", "published payload");
  EXPECT_NOT_NULL(f);
  // cppcheck-suppress knownConditionTrueFalse
  if (!cfg || !f)
    goto out;

  EXPECT_EQ_INT(file_save_to_disk_full(root, f, cfg), FILE_SAVE_WRITTEN);
  const char* final_path = "test_delay_pub_tmp/sub/file.txt";
  EXPECT_FALSE(file_path_exists_secure(final_path));

  EXPECT_TRUE(delay_updates_publish(cfg->delay_context, cfg));
  /* After a successful publish the file is installed and staging is gone. */
  char* content = read_all(final_path);
  EXPECT_NOT_NULL(content);
  // cppcheck-suppress knownConditionTrueFalse
  if (content) {
    EXPECT_EQ_STR(content, "published payload");
    free(content);
  }
  EXPECT_FALSE(file_path_exists_secure("test_delay_pub_tmp/.fastsync-stage"));

out:
  file_destroy(f);
  config_delete(cfg);
  remove_tree(root);
}

/* The staged tree is cleaned on the error/abort path and final files that were
   never published do not appear at the destination. */
static void test_delay_updates_cleanup_removes_staged() {
  const char* root = "test_delay_clean_tmp";
  remove_tree(root);
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->delay_updates = true;

  File* f = make_file("sub/file.txt", "never installed");
  EXPECT_NOT_NULL(f);
  // cppcheck-suppress knownConditionTrueFalse
  if (!cfg || !f)
    goto out;

  EXPECT_EQ_INT(file_save_to_disk_full(root, f, cfg), FILE_SAVE_WRITTEN);
  EXPECT_TRUE(file_path_exists_secure("test_delay_clean_tmp/.fastsync-stage/sub/file.txt"));

  delay_updates_cleanup(cfg->delay_context);
  EXPECT_FALSE(file_path_exists_secure("test_delay_clean_tmp/.fastsync-stage"));
  EXPECT_FALSE(file_path_exists_secure("test_delay_clean_tmp/sub/file.txt"));

out:
  file_destroy(f);
  config_delete(cfg);
  remove_tree(root);
}

/* With --backup the previous version is only moved aside at publication. */
static void test_delay_updates_backup_deferred_to_publish() {
  const char* root = "test_delay_bak_tmp";
  remove_tree(root);
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->delay_updates = true;
  cfg->backup = true;

  EXPECT_TRUE(file_write_to_disk("test_delay_bak_tmp/file.txt", "AAAA", 4, false, false));

  File* f = make_file("file.txt", "BBBB");
  EXPECT_NOT_NULL(f);
  // cppcheck-suppress knownConditionTrueFalse
  if (!cfg || !f)
    goto out;

  EXPECT_EQ_INT(file_save_to_disk_full(root, f, cfg), FILE_SAVE_WRITTEN);
  /* Stage time must not touch the final file or create the backup yet. */
  char* before = read_all("test_delay_bak_tmp/file.txt");
  EXPECT_NOT_NULL(before);
  // cppcheck-suppress knownConditionTrueFalse
  if (before) {
    EXPECT_EQ_STR(before, "AAAA");
    free(before);
  }
  EXPECT_FALSE(file_path_exists_secure("test_delay_bak_tmp/file.txt~"));

  EXPECT_TRUE(delay_updates_publish(cfg->delay_context, cfg));
  char* after = read_all("test_delay_bak_tmp/file.txt");
  char* backup = read_all("test_delay_bak_tmp/file.txt~");
  EXPECT_NOT_NULL(after);
  EXPECT_NOT_NULL(backup);
  // cppcheck-suppress knownConditionTrueFalse
  if (after) {
    EXPECT_EQ_STR(after, "BBBB");
    free(after);
  }
  // cppcheck-suppress knownConditionTrueFalse
  if (backup) {
    EXPECT_EQ_STR(backup, "AAAA");
    free(backup);
  }

out:
  file_destroy(f);
  config_delete(cfg);
  remove_tree(root);
}

/* Skip/update policy checks run against the final path at stage time, matching
   what an immediate run would decide. */
static void test_delay_updates_skip_semantics() {
  const char* root = "test_delay_skip_tmp";
  remove_tree(root);
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->delay_updates = true;

  /* --existing: final destination missing -> skipped, nothing staged. */
  File* missing = make_file("missing.txt", "new");
  EXPECT_NOT_NULL(missing);
  // cppcheck-suppress knownConditionTrueFalse
  if (!cfg || !missing)
    goto out;
  cfg->existing = true;
  EXPECT_EQ_INT(file_save_to_disk_full(root, missing, cfg), FILE_SAVE_SKIPPED);
  cfg->existing = false;

  /* --ignore-existing: final destination present -> skipped. */
  EXPECT_TRUE(file_write_to_disk("test_delay_skip_tmp/existing.txt", "old", 3, false, false));
  File* present = make_file("existing.txt", "new");
  EXPECT_NOT_NULL(present);
  // cppcheck-suppress knownConditionTrueFalse
  if (!present)
    goto out;
  cfg->ignore_existing = true;
  EXPECT_EQ_INT(file_save_to_disk_full(root, present, cfg), FILE_SAVE_SKIPPED);
  cfg->ignore_existing = false;

  /* Without a skip flag the file is staged and later published. */
  File* fresh = make_file("fresh.txt", "content");
  EXPECT_NOT_NULL(fresh);
  // cppcheck-suppress knownConditionTrueFalse
  if (!fresh)
    goto out;
  EXPECT_EQ_INT(file_save_to_disk_full(root, fresh, cfg), FILE_SAVE_WRITTEN);
  EXPECT_TRUE(delay_updates_publish(cfg->delay_context, cfg));
  char* content = read_all("test_delay_skip_tmp/fresh.txt");
  EXPECT_NOT_NULL(content);
  // cppcheck-suppress knownConditionTrueFalse
  if (content) {
    EXPECT_EQ_STR(content, "content");
    free(content);
  }

out:
  file_destroy(missing);
  file_destroy(present);
  file_destroy(fresh);
  config_delete(cfg);
  remove_tree(root);
}

/* The reserved staging name must be recognizable for validation, including
   with a trailing slash. */
static void test_delay_updates_reserved_name_helper() {
  EXPECT_TRUE(delay_updates_staging_name_conflict(".fastsync-stage"));
  EXPECT_TRUE(delay_updates_staging_name_conflict(".fastsync-stage/"));
  EXPECT_TRUE(delay_updates_staging_name_conflict(".fastsync-stage///"));
  EXPECT_FALSE(delay_updates_staging_name_conflict(NULL));
  EXPECT_FALSE(delay_updates_staging_name_conflict(""));
  EXPECT_FALSE(delay_updates_staging_name_conflict("backups"));
  EXPECT_FALSE(delay_updates_staging_name_conflict(".fastsync-stage.bak"));
}

void test_delay_updates() {
  test_delay_updates_reserved_name_helper();
  test_delay_updates_no_final_before_publish();
  test_delay_updates_publish_installs_files();
  test_delay_updates_cleanup_removes_staged();
  test_delay_updates_backup_deferred_to_publish();
  test_delay_updates_skip_semantics();
}
