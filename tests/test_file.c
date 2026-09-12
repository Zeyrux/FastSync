#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* SEEK_HOLE/SEEK_DATA for the sparse-hole sparseness check */
#endif
#include "test_file.h"
#include "file.h"
#include "file_store.h"
#include "data.h"
#include "config.h"
#include "utils.h"
#include "protocol.h"
#include "test_utils.h"
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void test_file_create() {
  File* f = file_create("test_file_create.txt");
  EXPECT_NOT_NULL(f);
  EXPECT_NOT_NULL(f->path);
  EXPECT_EQ_STR(f->path, "test_file_create.txt");
  EXPECT_NOT_NULL(f->data);
  EXPECT_NULL(f->data->data);
  EXPECT_EQ_INT((int)f->data->size, 0);
  EXPECT_NULL(f->metadata);
  file_destroy(f);
}

/* rdev/type validation shared by the wire path and the secure recreation site:
 * a legal char/block major/minor pair is accepted, out-of-range / negative
 * values and non-device entries carrying an rdev are rejected. */
static void test_file_special_rdev_valid() {
  mode_t fake_char = S_IFCHR | 0600;
  mode_t fake_blk = S_IFBLK | 0600;
  mode_t fake_fifo = S_IFIFO | 0600;
  /* char/block devices: accept a legal pair, reject negative / oversized. */
  EXPECT_TRUE(file_special_rdev_valid(1, 3, fake_char));
  EXPECT_TRUE(file_special_rdev_valid(0xffff, 0x00ffffff, fake_blk));
  EXPECT_FALSE(file_special_rdev_valid(-1, 3, fake_char));
  EXPECT_FALSE(file_special_rdev_valid(1, -1, fake_char));
  EXPECT_FALSE(file_special_rdev_valid(0x10000, 3, fake_char));
  EXPECT_FALSE(file_special_rdev_valid(1, 0x1000000, fake_char));
  /* FIFOs/sockets must carry an empty rdev. */
  EXPECT_TRUE(file_special_rdev_valid(0, 0, fake_fifo));
  EXPECT_FALSE(file_special_rdev_valid(1, 0, fake_fifo));
  EXPECT_FALSE(file_special_rdev_valid(0, 0, (mode_t)(S_IFREG | 0600)));
}

static void test_file_destroy_null() {
  file_destroy(NULL);
}

static void test_file_destroy_normal() {
  File* f = file_create("test_destroy.txt");
  EXPECT_NOT_NULL(f);
  file_destroy(f);
}

static void test_file_load_data() {
  const char* content = "Hello Load Test";
  EXPECT_TRUE(
      file_write_to_disk("test_file_load_data.txt", content, strlen(content), false, false));

  struct stat st;
  EXPECT_EQ_INT(stat("test_file_load_data.txt", &st), 0);

  File* f = file_create("test_file_load_data.txt");
  EXPECT_NOT_NULL(f);
  f->data->size = st.st_size;

  EXPECT_TRUE(file_load_data(f));
  EXPECT_NOT_NULL(f->data->data);
  EXPECT_EQ_INT((int)f->data->size, (int)st.st_size);
  EXPECT_EQ_INT(memcmp(f->data->data, content, strlen(content)), 0);

  file_destroy(f);
  unlink("test_file_load_data.txt");
}

static void test_file_load_data_missing_file() {
  File* f = file_create("nonexistent_test_file_xyz.txt");
  EXPECT_NOT_NULL(f);
  f->data->size = 10;
  EXPECT_FALSE(file_load_data(f));
  file_destroy(f);
}

static void test_file_save_to_disk() {
  File* f = file_create("saved_file.txt");
  EXPECT_NOT_NULL(f);
  const char* content = "Save to disk content";
  f->data->data = malloc(strlen(content));
  EXPECT_NOT_NULL(f->data->data);
  memcpy(f->data->data, content, strlen(content));
  f->data->size = strlen(content);

  EXPECT_TRUE(file_save_to_disk("test_save_tmp", f, NULL));

  struct stat st;
  EXPECT_EQ_INT(stat("test_save_tmp/saved_file.txt", &st), 0);

  FILE* fp = fopen("test_save_tmp/saved_file.txt", "rb");
  EXPECT_NOT_NULL(fp);
  char buf[100];
  size_t nread = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  EXPECT_EQ_INT((int)nread, (int)strlen(content));
  EXPECT_EQ_INT(memcmp(buf, content, strlen(content)), 0);

  file_destroy(f);
  unlink("test_save_tmp/saved_file.txt");
  rmdir("test_save_tmp");
}

static void test_file_save_to_disk_with_fsync_config() {
  File* f = file_create("saved_file_fsync.txt");
  EXPECT_NOT_NULL(f);
  const char* content = "Save to disk with fsync";
  f->data->data = malloc(strlen(content));
  EXPECT_NOT_NULL(f->data->data);
  memcpy(f->data->data, content, strlen(content));
  f->data->size = strlen(content);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  config->use_fsync = true;
  EXPECT_TRUE(file_save_to_disk("test_save_fsync_tmp", f, config));

  struct stat st;
  EXPECT_EQ_INT(stat("test_save_fsync_tmp/saved_file_fsync.txt", &st), 0);
  EXPECT_EQ_INT((int)st.st_size, (int)strlen(content));

  file_destroy(f);
  config_delete(config);
  unlink("test_save_fsync_tmp/saved_file_fsync.txt");
  rmdir("test_save_fsync_tmp");
}

static void test_file_save_to_disk_existing() {
  const char* root = "test_existing_tmp";
  const char* existing_path = "test_existing_tmp/existing.txt";
  const char* missing_path = "test_existing_tmp/missing.txt";
  EXPECT_TRUE(file_write_to_disk(existing_path, "old", 3, false, false));

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->existing = true;

  File* existing = file_create("existing.txt");
  EXPECT_NOT_NULL(existing);
  existing->data->data = malloc(3);
  EXPECT_NOT_NULL(existing->data->data);
  memcpy(existing->data->data, "new", 3);
  existing->data->size = 3;
  EXPECT_TRUE(file_save_to_disk(root, existing, cfg));
  file_destroy(existing);

  File* missing = file_create("missing.txt");
  EXPECT_NOT_NULL(missing);
  missing->data->data = malloc(7);
  EXPECT_NOT_NULL(missing->data->data);
  memcpy(missing->data->data, "skipped", 7);
  missing->data->size = 7;
  EXPECT_TRUE(file_save_to_disk(root, missing, cfg));
  file_destroy(missing);

  FILE* fp = fopen(existing_path, "rb");
  char content[4] = {0};
  EXPECT_NOT_NULL(fp);
  // cppcheck-suppress knownConditionTrueFalse
  if (fp) {
    EXPECT_EQ_INT((int)fread(content, 1, 3, fp), 3);
    fclose(fp);
  }
  EXPECT_EQ_STR(content, "new");
  EXPECT_EQ_INT(access(missing_path, F_OK), -1);

  config_delete(cfg);
  unlink(existing_path);
  rmdir("test_existing_tmp");
}

static void test_file_save_to_disk_ignore_existing() {
  const char* path = "test_ignore_existing_tmp/existing.txt";
  EXPECT_TRUE(file_write_to_disk(path, "old", 3, false, false));

  File* file = file_create("existing.txt");
  EXPECT_NOT_NULL(file);
  file->data->data = malloc(3);
  EXPECT_NOT_NULL(file->data->data);
  memcpy(file->data->data, "new", 3);
  file->data->size = 3;

  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  config->ignore_existing = true;
  EXPECT_TRUE(file_save_to_disk("test_ignore_existing_tmp", file, config));

  FILE* stream = fopen(path, "rb");
  char content[4] = {0};
  EXPECT_NOT_NULL(stream);
  // cppcheck-suppress knownConditionTrueFalse
  if (stream) {
    EXPECT_EQ_INT((int)fread(content, 1, 3, stream), 3);
    fclose(stream);
  }
  EXPECT_EQ_STR(content, "old");

  file_destroy(file);
  config_delete(config);
  unlink(path);
  rmdir("test_ignore_existing_tmp");
}

static void test_file_save_to_disk_ignore_existing_entry_types() {
  const char* root = "test_ignore_existing_entries_tmp";
  const char* directory = "test_ignore_existing_entries_tmp/directory";
  const char* link = "test_ignore_existing_entries_tmp/link";
  const char* target = "test_ignore_existing_entries_tmp/target";
  const char* backup = "test_ignore_existing_entries_tmp/backup.txt~";
  const char* backup_file = "test_ignore_existing_entries_tmp/backup.txt";
  Config* config = config_create();
  File* file = file_create("unused");

  unlink(link);
  unlink(target);
  unlink(backup);
  unlink(backup_file);
  rmdir(directory);
  rmdir(root);
  EXPECT_NOT_NULL(config);
  EXPECT_NOT_NULL(file);
  // cppcheck-suppress knownConditionTrueFalse
  if (!config || !file)
    return;
  config->ignore_existing = true;
  config->backup = true;
  file->data->data = malloc(3);
  EXPECT_NOT_NULL(file->data->data);
  // cppcheck-suppress knownConditionTrueFalse
  if (!file->data->data) {
    file_destroy(file);
    config_delete(config);
    return;
  }
  memcpy(file->data->data, "new", 3);
  file->data->size = 3;

  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(directory, 0755), 0);
  EXPECT_TRUE(file_write_to_disk(target, "old", 3, false, false));
  EXPECT_EQ_INT(symlink("target", link), 0);
  free(file->path);
  file->path = str_dup("directory");
  EXPECT_TRUE(file_save_to_disk(root, file, config));
  free(file->path);
  file->path = str_dup("link");
  EXPECT_TRUE(file_save_to_disk(root, file, config));

  free(file->path);
  file->path = str_dup("backup.txt");
  EXPECT_TRUE(file_write_to_disk(backup_file, "old", 3, false, false));
  EXPECT_TRUE(file_save_to_disk(root, file, config));
  EXPECT_TRUE(file_path_exists_secure(backup_file));
  EXPECT_FALSE(file_path_exists_secure(backup));

  file_destroy(file);
  config_delete(config);
  unlink(link);
  unlink(target);
  unlink(backup_file);
  rmdir(directory);
  rmdir(root);
}

/* Issue #253: with --partial --partial-dir a completed write must be installed
   at the real destination rather than left under the partial directory. */
static void test_file_save_to_disk_partial_install() {
  const char* root = "test_partial_install_tmp";
  const char* dest_file = "test_partial_install_tmp/file.txt";
  const char* partial_file = "test_partial_install_tmp/.partial/file.txt";
  unlink(dest_file);
  unlink(partial_file);
  rmdir("test_partial_install_tmp/.partial");
  rmdir(root);

  File* f = file_create("file.txt");
  EXPECT_NOT_NULL(f);
  const char* content = "partial-dir content";
  f->data->data = malloc(strlen(content));
  EXPECT_NOT_NULL(f->data->data);
  memcpy(f->data->data, content, strlen(content));
  f->data->size = strlen(content);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  config->partial = true;
  config->partial_dir = str_dup(".partial");

  EXPECT_EQ_INT(file_save_to_disk_full(root, f, config), FILE_SAVE_WRITTEN);

  FILE* fp = fopen(dest_file, "rb");
  EXPECT_NOT_NULL(fp);
  // cppcheck-suppress knownConditionTrueFalse
  if (fp) {
    char buf[64] = {0};
    size_t nread = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    EXPECT_EQ_INT((int)nread, (int)strlen(content));
    EXPECT_EQ_INT(memcmp(buf, content, strlen(content)), 0);
  }
  /* A completed transfer must not linger under the partial dir. */
  EXPECT_EQ_INT(access(partial_file, F_OK), -1);

  file_destroy(f);
  config_delete(config);
  unlink(dest_file);
  rmdir(root);
}

/* Issue #251: file_save_to_disk_full must distinguish receiver-side skips
   (--existing/--ignore-existing/--update) from real writes so the sender can
   decide whether --remove-source-files may unlink its source. */
static void test_file_save_to_disk_reports_skips() {
  const char* root = "test_save_skip_tmp";
  const char* existing_path = "test_save_skip_tmp/existing.txt";
  unlink(existing_path);
  rmdir(root);
  EXPECT_TRUE(file_write_to_disk(existing_path, "old", 3, false, false));

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);

  File* new_file = file_create("missing.txt");
  EXPECT_NOT_NULL(new_file);
  new_file->data->data = malloc(7);
  EXPECT_NOT_NULL(new_file->data->data);
  memcpy(new_file->data->data, "skipped", 7);
  new_file->data->size = 7;

  /* --existing: destination is missing -> skipped, not an error. */
  cfg->existing = true;
  EXPECT_EQ_INT(file_save_to_disk_full(root, new_file, cfg), FILE_SAVE_SKIPPED);
  cfg->existing = false;

  /* --ignore-existing: destination present -> skipped. */
  File* present = file_create("existing.txt");
  EXPECT_NOT_NULL(present);
  present->data->data = malloc(3);
  EXPECT_NOT_NULL(present->data->data);
  memcpy(present->data->data, "new", 3);
  present->data->size = 3;
  cfg->ignore_existing = true;
  EXPECT_EQ_INT(file_save_to_disk_full(root, present, cfg), FILE_SAVE_SKIPPED);
  cfg->ignore_existing = false;

  /* A normal overwrite of an existing file is a real write. */
  EXPECT_EQ_INT(file_save_to_disk_full(root, present, cfg), FILE_SAVE_WRITTEN);

  /* --update: a newer destination is skipped. */
  struct stat st;
  EXPECT_EQ_INT(stat(existing_path, &st), 0);
  time_t now = time(NULL);
  FileMetadata metadata = {.mode = st.st_mode,
                           .uid = st.st_uid,
                           .gid = st.st_gid,
                           .mtime_sec = now - 100,
                           .mtime_nsec = 0};
  present->metadata = &metadata;
  cfg->update = true;
  EXPECT_EQ_INT(file_save_to_disk_full(root, present, cfg), FILE_SAVE_SKIPPED);
  present->metadata = NULL;

  file_destroy(new_file);
  file_destroy(present);
  config_delete(cfg);
  unlink(existing_path);
  rmdir(root);
}

static void test_file_write_to_disk_basic() {
  const char* content = "Basic file_write_to_disk test";
  EXPECT_TRUE(file_write_to_disk("test_file_write_to_disk_basic.txt", content, strlen(content),
                                 false, false));

  struct stat st;
  EXPECT_EQ_INT(stat("test_file_write_to_disk_basic.txt", &st), 0);
  EXPECT_EQ_INT((int)st.st_size, (int)strlen(content));

  FILE* fp = fopen("test_file_write_to_disk_basic.txt", "rb");
  EXPECT_NOT_NULL(fp);
  char buf[100];
  size_t nread = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  EXPECT_EQ_INT((int)nread, (int)strlen(content));
  EXPECT_EQ_INT(memcmp(buf, content, strlen(content)), 0);

  unlink("test_file_write_to_disk_basic.txt");
}

static void test_file_write_to_disk_with_fsync() {
  const char* path = "test_file_write_to_disk_fsync.txt";
  const char* content = "fsync file content";
  EXPECT_TRUE(file_to_disk_secure_with_fsync(path, content, strlen(content), false, false, false,
                                             NULL, false, true, NULL));
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT((int)st.st_size, (int)strlen(content));
  unlink(path);
}

static void test_file_write_to_disk_preallocate_atomic() {
  const char* path = "test_file_write_prealloc_atomic.txt";
  const char* content = "prealloc atomic content";
  EXPECT_TRUE(
      file_to_disk_secure(path, content, strlen(content), false, false, true, NULL, false, NULL));
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT((int)st.st_size, (int)strlen(content));
  FILE* fp = fopen(path, "rb");
  EXPECT_NOT_NULL(fp);
  char buf[100];
  size_t nread = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  EXPECT_EQ_INT((int)nread, (int)strlen(content));
  EXPECT_EQ_INT(memcmp(buf, content, strlen(content)), 0);
  unlink(path);
}

static void test_file_write_to_disk_preallocate_inplace() {
  const char* path = "test_file_write_prealloc_inplace.txt";
  const char* content = "prealloc inplace content";
  EXPECT_TRUE(
      file_to_disk_secure(path, content, strlen(content), true, false, true, NULL, false, NULL));
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT((int)st.st_size, (int)strlen(content));
  FILE* fp = fopen(path, "rb");
  EXPECT_NOT_NULL(fp);
  char buf[100];
  size_t nread = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  EXPECT_EQ_INT((int)nread, (int)strlen(content));
  EXPECT_EQ_INT(memcmp(buf, content, strlen(content)), 0);
  unlink(path);
}

static void test_file_write_to_disk_creates_dirs() {
  const char* content = "Nested dir test";
  EXPECT_TRUE(file_write_to_disk("test_nested_tmp/nested/file.txt", content, strlen(content), false,
                                 false));

  struct stat st;
  EXPECT_EQ_INT(stat("test_nested_tmp/nested/file.txt", &st), 0);

  FILE* fp = fopen("test_nested_tmp/nested/file.txt", "rb");
  EXPECT_NOT_NULL(fp);
  char buf[100];
  size_t nread = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  EXPECT_EQ_INT((int)nread, (int)strlen(content));
  EXPECT_EQ_INT(memcmp(buf, content, strlen(content)), 0);

  unlink("test_nested_tmp/nested/file.txt");
  rmdir("test_nested_tmp/nested");
  rmdir("test_nested_tmp");
}

static void test_file_write_to_disk_does_not_follow_symlink() {
  const char* outside = "test_file_write_to_disk_outside.txt";
  const char* link = "test_file_write_to_disk_link.txt";
  const char* content = "confined";
  unlink(outside);
  unlink(link);
  EXPECT_TRUE(file_write_to_disk(outside, "outside", 7, false, false));
  EXPECT_EQ_INT(symlink(outside, link), 0);
  EXPECT_TRUE(file_write_to_disk(link, content, strlen(content), false, false));
  FILE* fp = fopen(outside, "rb");
  char buf[16] = {0};
  EXPECT_NOT_NULL(fp);
  // cppcheck-suppress knownConditionTrueFalse
  if (!fp)
    return;
  size_t read_count = fread(buf, 1, sizeof(buf) - 1, fp);
  EXPECT_TRUE(read_count <= sizeof(buf) - 1);
  fclose(fp);
  EXPECT_EQ_STR(buf, "outside");
  unlink(outside);
  unlink(link);
}

static void test_file_symlink_helpers() {
  /* Munge/unmunge round-trip restores the original target. */
  char* munged = file_symlink_munge("target.txt");
  EXPECT_NOT_NULL(munged);
  EXPECT_EQ_INT(memcmp(munged, SYMLINK_MUNGE_PREFIX, strlen(SYMLINK_MUNGE_PREFIX)), 0);
  EXPECT_TRUE(file_symlink_unmunge(munged));
  EXPECT_EQ_STR(munged, "target.txt");
  free(munged);

  char noop[] = "plain-target";
  EXPECT_FALSE(file_symlink_unmunge(noop));
  EXPECT_EQ_STR(noop, "plain-target");

  /* Containment: relative targets without ".." are safe; absolute or
     ".."-escaping targets are not. */
  EXPECT_TRUE(file_symlink_target_contained("a.txt"));
  EXPECT_TRUE(file_symlink_target_contained("sub/dir/file"));
  EXPECT_FALSE(file_symlink_target_contained("/etc/passwd"));
  EXPECT_FALSE(file_symlink_target_contained("../escape"));
  EXPECT_FALSE(file_symlink_target_contained("a/../b"));
  EXPECT_FALSE(file_symlink_target_contained(""));
}

static void test_file_symlink_at_secure() {
  const char* link = "test_symlink_at_secure_link";
  const char* outside = "test_symlink_at_secure_outside.txt";
  unlink(link);
  unlink(outside);
  EXPECT_TRUE(file_write_to_disk(outside, "out", 3, false, false));

  EXPECT_TRUE(file_symlink_at_secure(link, "outside.text"));
  struct stat st;
  EXPECT_EQ_INT(lstat(link, &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));

  /* Replacing an existing non-directory entry is fine. */
  EXPECT_TRUE(file_symlink_at_secure(link, "other.txt"));
  EXPECT_EQ_INT(lstat(link, &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));

  unlink(link);
  unlink(outside);
}

static void test_file_content_to_buffer() {
  const char* content = "Buffer content test";
  EXPECT_TRUE(file_write_to_disk("test_buffer_file.txt", content, strlen(content), false, false));

  File* f = file_create("test_buffer_file.txt");
  EXPECT_NOT_NULL(f);
  f->data->size = strlen(content);
  f->data->data = malloc(f->data->size);
  EXPECT_NOT_NULL(f->data->data);

  size_t bytes_read = file_content_to_buffer(f);
  EXPECT_EQ_INT((int)bytes_read, (int)strlen(content));
  EXPECT_EQ_INT(memcmp(f->data->data, content, strlen(content)), 0);

  file_destroy(f);
  unlink("test_buffer_file.txt");
}

static void test_file_send_receive() {
  File* file = file_create("test_send_recv.txt");
  EXPECT_NOT_NULL(file);
  const char* content = "Hello, File Send!";
  size_t len = strlen(content);
  file->data->data = malloc(len);
  EXPECT_NOT_NULL(file->data->data);
  memcpy(file->data->data, content, len);
  file->data->size = len;

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/tmp");
  cfg->receive_root_directory = str_dup("/tmp");

  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    File* received = file_receive(cfg, p[0]);
    close(p[0]);

    bool ok = true;
    if (!received)
      ok = false;
    else {
      if (!received->path || strcmp(received->path, "test_send_recv.txt") != 0)
        ok = false;
      if (!received->data || received->data->size != len)
        ok = false;
      else if (memcmp(received->data->data, content, len) != 0)
        ok = false;
    }

    file_destroy(received);
    config_delete(cfg);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    bool sent = file_send_single_calls(file, p[1], false, 0, true);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    file_destroy(file);
    config_delete(cfg);

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_file_send_no_path() {
  File* file = file_create("test_no_path.txt");
  EXPECT_NOT_NULL(file);
  const char* content = "No Path Data";
  size_t len = strlen(content);
  file->data->data = malloc(len);
  EXPECT_NOT_NULL(file->data->data);
  memcpy(file->data->data, content, len);
  file->data->size = len;

  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    Data* received = receive_data(p[0]);
    close(p[0]);

    bool ok = true;
    if (!received)
      ok = false;
    else if (received->size != len)
      ok = false;
    else if (memcmp(received->data, content, len) != 0)
      ok = false;

    data_destroy(received);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    bool sent = file_send_single_calls(file, p[1], false, 0, false);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    file_destroy(file);

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_file_metadata_create() {
  EXPECT_TRUE(file_write_to_disk("test_meta_file.txt", "metadata test", 13, false, false));
  struct stat st;
  EXPECT_EQ_INT(stat("test_meta_file.txt", &st), 0);

  FileMetadata* m = file_metadata_create("test_meta_file.txt", &st, false, false);
  EXPECT_NOT_NULL(m);
  EXPECT_EQ_INT(m->mode, st.st_mode);
  EXPECT_EQ_INT(m->uid, st.st_uid);
  EXPECT_EQ_INT(m->gid, st.st_gid);
  EXPECT_EQ_INT((int)m->mtime_sec, (int)st.st_mtime);

  file_metadata_destroy(m);
  unlink("test_meta_file.txt");
}

static void test_file_save_to_disk_path_traversal() {
  /* Test that path traversal is rejected */
  File* f = file_create("../etc/passwd");
  EXPECT_NOT_NULL(f);
  const char* content = "should not save";
  f->data->data = malloc(strlen(content));
  EXPECT_NOT_NULL(f->data->data);
  memcpy(f->data->data, content, strlen(content));
  f->data->size = strlen(content);

  /* file_save_to_disk should detect path traversal and return false */
  EXPECT_FALSE(file_save_to_disk("/tmp", f, NULL));

  file_destroy(f);
}

static void test_file_save_to_disk_deep_traversal() {
  File* f = file_create("subdir/../../etc/passwd");
  EXPECT_NOT_NULL(f);
  const char* content = "should not save";
  f->data->data = malloc(strlen(content));
  EXPECT_NOT_NULL(f->data->data);
  memcpy(f->data->data, content, strlen(content));
  f->data->size = strlen(content);

  EXPECT_FALSE(file_save_to_disk("/tmp", f, NULL));

  file_destroy(f);
}

static void test_file_send_single_calls_compression() {
  File* file = file_create("test_send_comp.txt");
  EXPECT_NOT_NULL(file);
  const char* content = "Hello, Compressed File Transfer!";
  size_t len = strlen(content);
  file->data->data = malloc(len);
  EXPECT_NOT_NULL(file->data->data);
  memcpy(file->data->data, content, len);
  file->data->size = len;

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/tmp");
  cfg->receive_root_directory = str_dup("/tmp");
  cfg->use_compression = true;
  cfg->compression_level = 3;

  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    File* received = file_receive(cfg, p[0]);
    close(p[0]);

    bool ok = true;
    if (!received)
      ok = false;
    else {
      if (strcmp(received->path, "test_send_comp.txt") != 0)
        ok = false;
      if (!received->data || received->data->size != len)
        ok = false;
      else if (memcmp(received->data->data, content, len) != 0)
        ok = false;
    }
    file_destroy(received);
    config_delete(cfg);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    bool sent = file_send_single_calls(file, p[1], false, 3, true);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    file_destroy(file);
    config_delete(cfg);

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_file_send_single_calls_metadata_and_path() {
  /* Create a real file on disk so we can have metadata */
  const char* content = "File with metadata";
  size_t len = strlen(content);
  EXPECT_TRUE(file_write_to_disk("test_meta_send.txt", content, len, false, false));

  struct stat st;
  EXPECT_EQ_INT(stat("test_meta_send.txt", &st), 0);

  File* file = file_create("test_meta_send.txt");
  EXPECT_NOT_NULL(file);
  file->data->size = len;
  file->data->data = malloc(len);
  EXPECT_NOT_NULL(file->data->data);
  memcpy(file->data->data, content, len);
  file->metadata = file_metadata_create("test_meta_send.txt", &st, false, false);
  EXPECT_NOT_NULL(file->metadata);

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/tmp");
  cfg->receive_root_directory = str_dup("/tmp");
  cfg->use_metadata = true;

  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    File* received = file_receive(cfg, p[0]);
    close(p[0]);

    bool ok = true;
    if (!received)
      ok = false;
    else {
      if (strcmp(received->path, "test_meta_send.txt") != 0)
        ok = false;
      if (!received->data || received->data->size != len)
        ok = false;
      else if (memcmp(received->data->data, content, len) != 0)
        ok = false;
      if (!received->metadata)
        ok = false;
    }
    file_destroy(received);
    config_delete(cfg);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    bool sent = file_send_single_calls(file, p[1], true, 0, true);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    file_destroy(file);
    config_delete(cfg);
    unlink("test_meta_send.txt");

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_inplace_overwrite_clears_special_mode_bits() {
  const char* root = "test_inplace_tmp";
  const char* path = "test_inplace_tmp/priv.txt";
  const char* content = "olddata";
  unlink(path);
  rmdir(root);
  EXPECT_EQ_INT(mkdir(root, 0700), 0);

  /* Create a destination carrying setuid + sticky bits. */
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  EXPECT_TRUE(fd >= 0);
  // cppcheck-suppress knownConditionTrueFalse
  if (fd < 0) {
    rmdir(root);
    return;
  }
  EXPECT_EQ_INT((int)write(fd, content, strlen(content)), (int)strlen(content));
  EXPECT_EQ_INT(fchmod(fd, S_ISUID | S_ISVTX | 0755), 0);
  EXPECT_EQ_INT(close(fd), 0);

  /* Overwrite in place without metadata: the mode must be normalized to a
     safe default (0644) and the setuid/sticky bits must be gone. */
  File* f = file_create("priv.txt");
  EXPECT_NOT_NULL(f);
  const char* new_content = "newdata";
  f->data->data = malloc(strlen(new_content));
  EXPECT_NOT_NULL(f->data->data);
  memcpy(f->data->data, new_content, strlen(new_content));
  f->data->size = strlen(new_content);

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->inplace = true;
  EXPECT_TRUE(file_save_to_disk(root, f, cfg));
  file_destroy(f);
  config_delete(cfg);

  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT((int)(st.st_mode & (S_ISUID | S_ISGID | S_ISVTX)), 0);
  EXPECT_EQ_INT((int)(st.st_mode & 0777), 0644);
  FILE* stream = fopen(path, "rb");
  char buf[16] = {0};
  EXPECT_NOT_NULL(stream);
  // cppcheck-suppress knownConditionTrueFalse
  if (stream) {
    size_t nread = fread(buf, 1, sizeof(buf) - 1, stream);
    fclose(stream);
    EXPECT_EQ_INT((int)nread, (int)strlen(new_content));
  }
  EXPECT_EQ_STR(buf, new_content);

  unlink(path);
  rmdir(root);
}

static void test_inplace_overwrite_metadata_strips_special_bits() {
  const char* root = "test_inplace_meta_tmp";
  const char* path = "test_inplace_meta_tmp/meta.txt";
  const char* source = "test_inplace_meta_source.txt";
  unlink(path);
  unlink(source);
  rmdir(root);
  EXPECT_EQ_INT(mkdir(root, 0700), 0);

  /* Existing destination with setuid+sticky set. */
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  EXPECT_TRUE(fd >= 0);
  // cppcheck-suppress knownConditionTrueFalse
  if (fd < 0) {
    rmdir(root);
    return;
  }
  EXPECT_EQ_INT((int)write(fd, "olddata", 7), 7);
  EXPECT_EQ_INT(fchmod(fd, S_ISUID | S_ISVTX | 0755), 0);
  EXPECT_EQ_INT(close(fd), 0);

  /* Build source metadata carrying a plain executable mode (no specials). */
  EXPECT_TRUE(file_write_to_disk(source, "source", 6, false, false));
  EXPECT_EQ_INT(chmod(source, 0755), 0);
  struct stat source_st;
  EXPECT_EQ_INT(stat(source, &source_st), 0);

  File* f = file_create("meta.txt");
  EXPECT_NOT_NULL(f);
  const char* new_content = "meta";
  f->data->data = malloc(strlen(new_content));
  EXPECT_NOT_NULL(f->data->data);
  memcpy(f->data->data, new_content, strlen(new_content));
  f->data->size = strlen(new_content);
  f->metadata = file_metadata_create(source, &source_st, false, false);
  EXPECT_NOT_NULL(f->metadata);

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->inplace = true;
  EXPECT_TRUE(file_save_to_disk(root, f, cfg));
  file_destroy(f);
  config_delete(cfg);
  unlink(source);

  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  /* Metadata-derived mode is applied and never includes setuid/setgid/sticky. */
  EXPECT_EQ_INT((int)(st.st_mode & (S_ISUID | S_ISGID | S_ISVTX)), 0);
  EXPECT_EQ_INT((int)(st.st_mode & 0777), 0755);

  unlink(path);
  rmdir(root);
}

static void test_inplace_overwrite_truncates_shorter_payload() {
  const char* root = "test_inplace_trunc_tmp";
  const char* path = "test_inplace_trunc_tmp/big.txt";
  unlink(path);
  rmdir(root);
  EXPECT_EQ_INT(mkdir(root, 0700), 0);

  const char* old_content = "0123456789abcdef"; /* 16 bytes */
  EXPECT_TRUE(file_write_to_disk(path, old_content, strlen(old_content), false, false));

  File* f = file_create("big.txt");
  EXPECT_NOT_NULL(f);
  const char* new_content = "hi";
  f->data->data = malloc(strlen(new_content));
  EXPECT_NOT_NULL(f->data->data);
  memcpy(f->data->data, new_content, strlen(new_content));
  f->data->size = strlen(new_content);

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->inplace = true;
  EXPECT_TRUE(file_save_to_disk(root, f, cfg));
  file_destroy(f);
  config_delete(cfg);

  /* A shorter payload must truncate the file: no stale trailing bytes. */
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT((int)st.st_size, (int)strlen(new_content));
  FILE* stream = fopen(path, "rb");
  char buf[32] = {0};
  EXPECT_NOT_NULL(stream);
  // cppcheck-suppress knownConditionTrueFalse
  if (stream) {
    size_t nread = fread(buf, 1, sizeof(buf) - 1, stream);
    fclose(stream);
    EXPECT_EQ_INT((int)nread, (int)strlen(new_content));
  }
  EXPECT_EQ_STR(buf, new_content);

  unlink(path);
  rmdir(root);
}

/* Explicit directory entries (--dirs) create the directory under the receive
   root through the same save funnel, creating parents as needed, and reject
   traversal the same way a file path does. */
static void test_dir_entry_save_to_disk() {
  const char* root = "test_dir_entry_root";
  EXPECT_EQ_INT(mkdir(root, 0755), 0);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);

  File* dir = file_create("alpha/beta/gamma");
  EXPECT_NOT_NULL(dir);
  dir->is_dir = true;
  EXPECT_EQ_INT(file_save_to_disk_full(root, dir, config), FILE_SAVE_WRITTEN);
  EXPECT_EQ_INT(file_save_to_disk_full(root, dir, config), FILE_SAVE_WRITTEN);
  file_destroy(dir);

  struct stat st;
  EXPECT_EQ_INT(stat("test_dir_entry_root/alpha/beta/gamma", &st), 0);
  EXPECT_TRUE(S_ISDIR(st.st_mode));

  /* The directory-entry save path never follows or escapes. */
  File* evil = file_create("../dir_entry_escape");
  EXPECT_NOT_NULL(evil);
  evil->is_dir = true;
  EXPECT_EQ_INT(file_save_to_disk_full(root, evil, config), FILE_SAVE_ERROR);
  file_destroy(evil);
  EXPECT_EQ_INT(lstat("../dir_entry_escape", &st), -1);

  config_delete(config);
  rmdir("test_dir_entry_root/alpha/beta/gamma");
  rmdir("test_dir_entry_root/alpha/beta");
  rmdir("test_dir_entry_root/alpha");
  rmdir(root);
}

/* ---- Phase 5 (--trust-sender) safety-floor tests ----
 *
 * --trust-sender is a receiver-local policy that never crosses the wire: a real
 * receiver enables it from its own process (the standalone server's --trust-
 * sender CLI switch, which a client forwards as --remote-option=--trust-sender),
 * so these tests force file_set_trust_sender(true) directly.  Trust must RELAX
 * only the redundant list-level re-validation (an escaping symlink TARGET is
 * copied verbatim, rsync -l parity) and must NEVER disable the low-level
 * fd-relative confinement floor: file_open_secure_parent's ".." rejection, the
 * O_NOFOLLOW parent walk, leaf/destination confinement, and the ungated
 * has_path_traversal on the link's own placement path in file_symlink_at_secure
 * stay hard.  A hostile sender therefore still cannot place a file, directory
 * or symlink outside the receive root even with trust on. */

static void test_trust_sender_relaxes_symlink_target() {
  const char* root = "test_trust_sender_root";
  const char* link = "test_trust_sender_root/escape_link";
  unlink(link);
  rmdir(root);
  EXPECT_EQ_INT(mkdir(root, 0755), 0);

  /* Control: without trust an absolute (escaping) target is refused and the
     link is never placed. */
  file_set_trust_sender(false);
  EXPECT_FALSE(file_symlink_at_secure(link, "/etc/passwd"));
  struct stat st;
  EXPECT_EQ_INT(lstat(link, &st), -1);

  /* Trust ON: the escaping target is copied verbatim (rsync -l parity) ... */
  file_set_trust_sender(true);
  EXPECT_TRUE(file_symlink_at_secure(link, "/etc/passwd"));
  EXPECT_EQ_INT(lstat(link, &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));
  /* ...but the link itself still lands beneath the receive root. */
  char target[128];
  ssize_t target_len = readlink(link, target, sizeof(target) - 1);
  EXPECT_TRUE(target_len > 0);
  // cppcheck-suppress knownConditionTrueFalse
  if (target_len > 0) {
    target[target_len] = '\0';
    EXPECT_EQ_STR(target, "/etc/passwd");
  }
  unlink(link);

  /* Same relaxation through the real save funnel (file_save_to_disk_full). */
  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  const char* save_link = "test_trust_sender_root/save_link";
  unlink(save_link);

  File* sym = file_create("save_link");
  EXPECT_NOT_NULL(sym);
  sym->is_symlink = true;
  sym->symlink_target = str_dup("/etc/passwd");
  EXPECT_NOT_NULL(sym->symlink_target);

  file_set_trust_sender(false);
  EXPECT_EQ_INT(file_save_to_disk_full(root, sym, config), FILE_SAVE_SKIPPED);
  EXPECT_EQ_INT(lstat(save_link, &st), -1);

  file_set_trust_sender(true);
  EXPECT_EQ_INT(file_save_to_disk_full(root, sym, config), FILE_SAVE_WRITTEN);
  EXPECT_EQ_INT(lstat(save_link, &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));

  file_destroy(sym);
  config_delete(config);
  unlink(save_link);
  rmdir(root);
}

static void test_trust_sender_confines_hostile_paths() {
  const char* root = "test_trust_sender_root";
  const char* escaped_file = "../test_trust_sender_escaped_file.txt";
  const char* escaped_dir = "../test_trust_sender_escaped_dir";
  const char* escaped_link = "../test_trust_sender_escaped_link";
  unlink(escaped_file);
  rmdir(escaped_dir);
  unlink(escaped_link);
  unlink(root);
  rmdir(root);
  EXPECT_EQ_INT(mkdir(root, 0755), 0);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  file_set_trust_sender(true);
  struct stat st;

  /* A hostile regular-file path that would escape the root is contained: the
     save-layer ".." re-check is relaxed under trust, so the attempt reaches the
     secure floor, which refuses the walk -- nothing appears outside. */
  File* file = file_create(escaped_file);
  EXPECT_NOT_NULL(file);
  file->data->data = malloc(5);
  EXPECT_NOT_NULL(file->data->data);
  memcpy(file->data->data, "evil", 4);
  file->data->size = 4;
  EXPECT_EQ_INT(file_save_to_disk_full(root, file, config), FILE_SAVE_ERROR);
  file_destroy(file);
  EXPECT_EQ_INT(lstat(escaped_file, &st), -1);

  /* A hostile directory entry is contained the same way. */
  File* dir = file_create(escaped_dir);
  EXPECT_NOT_NULL(dir);
  dir->is_dir = true;
  EXPECT_EQ_INT(file_save_to_disk_full(root, dir, config), FILE_SAVE_ERROR);
  file_destroy(dir);
  EXPECT_EQ_INT(lstat(escaped_dir, &st), -1);

  /* A hostile symlink whose OWN placement path escapes the root is refused even
     under trust: the ungated has_path_traversal in file_symlink_at_secure never
     turns off. */
  EXPECT_FALSE(file_symlink_at_secure("test_trust_sender_root/../escaped_link", "/etc/passwd"));
  EXPECT_EQ_INT(lstat(escaped_link, &st), -1);

  /* file_open_secure_parent still refuses a ".." component outright. */
  char* leaf = NULL;
  EXPECT_EQ_INT(file_open_secure_parent("test_trust_sender_root/../../etc/passwd", &leaf, true),
                -1);
  free(leaf);

  config_delete(config);
  rmdir(root);
}

/* The same guarantees under a configured authorized root: a within-root link
   with an escaping target is created (relaxed), while a placement path that is
   a clean absolute path OUTSIDE the authorized root (no ".." anywhere) is
   refused by the leaf/destination confinement. */
static void test_trust_sender_authorized_root_confinement() {
  const char* root = "test_trust_sender_root";
  const char* sibling = "test_trust_sender_sibling";
  unlink(root);
  rmdir(root);
  rmdir(sibling);
  EXPECT_EQ_INT(mkdir(root, 0755), 0);
  EXPECT_EQ_INT(mkdir(sibling, 0755), 0);

  char root_abs[PATH_MAX];
  char sibling_abs[PATH_MAX];
  EXPECT_NOT_NULL(realpath(root, root_abs));
  EXPECT_NOT_NULL(realpath(sibling, sibling_abs));
  int root_fd = open(root_abs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  EXPECT_TRUE(root_fd >= 0);
  // cppcheck-suppress knownConditionTrueFalse
  if (root_fd < 0) {
    rmdir(root);
    rmdir(sibling);
    return;
  }
  EXPECT_TRUE(file_set_authorized_root(root_fd, root_abs));

  file_set_trust_sender(true);
  struct stat st;

  /* Within the authorized root, an escaping symlink TARGET is copied verbatim. */
  char* inside_link = path_cat(root_abs, "authorized_escape_link");
  EXPECT_NOT_NULL(inside_link);
  unlink(inside_link);
  EXPECT_TRUE(file_symlink_at_secure(inside_link, "/etc/passwd"));
  EXPECT_EQ_INT(lstat(inside_link, &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));
  unlink(inside_link);

  /* A clean absolute path in a sibling directory (outside the authorized root)
     is still refused even under trust. */
  char* outside_link = path_cat(sibling_abs, "test_trust_sender_outside_link");
  EXPECT_NOT_NULL(outside_link);
  unlink(outside_link);
  EXPECT_FALSE(file_symlink_at_secure(outside_link, "/etc/passwd"));
  EXPECT_EQ_INT(lstat(outside_link, &st), -1);

  free(outside_link);
  free(inside_link);
  file_set_authorized_root(-1, NULL);
  close(root_fd);
  unlink("test_trust_sender_outside_link");
  rmdir(sibling);
  rmdir(root);
}

void test_trust_sender() {
  /* The final reset lines always run (a failing EXPECT only returns from the
     helper), so a later group never inherits a stray trust/authorized-root
     policy. */
  file_set_trust_sender(false);
  test_trust_sender_relaxes_symlink_target();
  test_trust_sender_confines_hostile_paths();
  test_trust_sender_authorized_root_confinement();
  file_set_trust_sender(false);
  file_set_authorized_root(-1, NULL);
}

/* --sparse/-S hole preservation: a buffer with a long zero run written via
 * file_store_write_secure(sparse=true) must round-trip its content exactly and
 * have the right logical size, and should additionally be genuinely sparse on
 * filesystems that support holes.  The sparseness assertion is tolerant: if the
 * filesystem reports no holes (SEEK_HOLE/SEEK_DATA -> ENXIO) we skip the strict
 * block-count check, but content and size always hold. */
static void test_file_write_to_disk_sparse_preserves_holes() {
  const char* path = "test_sparse_file.bin";
  unlink(path);
  /* 256 KiB with a 128 KiB zero run in the middle, bracketed by headers/tails. */
  const unsigned long long size = 256u * 1024u;
  unsigned char* buf = malloc(size);
  EXPECT_NOT_NULL(buf);
  /* cppcheck-suppress knownConditionTrueFalse -- EXPECT_NOT_NULL above asserts,
     but cppcheck cannot see through the macro; the guard is defensive. */
  if (!buf)
    return;
  memset(buf, 0, size);
  for (unsigned long long i = 0; i < 4096; i++) {
    buf[i] = (unsigned char)(i % 251);
    buf[size - 1 - i] = (unsigned char)((i * 7) % 253);
  }

  EXPECT_TRUE(file_store_write_secure(path, buf, size, false, true, NULL, false));

  /* Logical size must equal data_size exactly. */
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT((int)st.st_size, (int)size);

  /* Content must round-trip exactly: the full readback must equal the original
     buffer byte-for-byte (header, the hole region staying zero, and tail) —
     a writer bug in the lseek-offset bookkeeping would show up here. */
  int fd = open(path, O_RDONLY);
  EXPECT_TRUE(fd >= 0);
  /* cppcheck-suppress knownConditionTrueFalse -- EXPECT_TRUE above asserts,
     but cppcheck cannot see through the macro; the guard is defensive. */
  if (fd >= 0) {
    unsigned char* readback = malloc(size);
    if (readback) {
      unsigned long long got = 0;
      while (got < size) {
        ssize_t n = read(fd, readback + got, (size_t)(size - got));
        if (n <= 0)
          break;
        got += (unsigned long long)n;
      }
      EXPECT_EQ_INT((int)got, (int)size);
      if (got == size)
        EXPECT_EQ_INT(memcmp(readback, buf, size), 0);
      free(readback);
    }
    /* Tolerant sparseness check: seek for holes; skip if unsupported. */
    off_t hole_off = lseek(fd, (off_t)4096, SEEK_HOLE);
    if (hole_off >= 0 && hole_off < (off_t)size) {
      off_t next_data = lseek(fd, hole_off, SEEK_DATA);
      fstat(fd, &st);
      int blocks = (int)(st.st_blocks * 512);
      if (next_data > hole_off)
        EXPECT_TRUE(blocks < (int)size);
    }
    close(fd);
  }
  free(buf);
  unlink(path);
}

/* --partial retention is hard to provoke end-to-end mid-transfer (the whole
 * image is in one in-memory write), so this drives the failure path directly:
 * a metadata whose mtime_nsec is out of the legal [0,999999999] range makes
 * futimens (in file_restore_metadata_fd) fail with EINVAL AFTER the temp has
 * been fully written.  With keep_partial=true the written temp must be renamed
 * to the destination path (a resumable partial); with keep_partial=false the
 * same failure must leave NOTHING behind.  The retention is always best-effort
 * (never a corrupt blend), and this asserts the both-on/off behavior. */
static void test_file_write_to_disk_partial_retention() {
  const char* path = "test_partial_retention.bin";
  unlink(path);
  const char content[] = "partial-retention payload";
  FileMetadata m;
  memset(&m, 0, sizeof(m));
  m.mode = 0644;
  m.uid = (uid_t)geteuid();
  m.gid = (gid_t)getegid();
  m.mtime_sec = 1700000000;
  m.mtime_nsec = 2000000000; /* invalid: forces futimens EINVAL after the write */
  m.atime_valid = false;
  m.crtime_valid = false;
  bool ok = file_to_disk_secure_attrs(path, content, strlen(content), false, false, true, &m, false,
                                      false, false, false, NULL, false, true, NULL);
  EXPECT_FALSE(ok); /* the write itself succeeded, but metadata restore failed */
  /* Retained: the already-written temp now sits at the destination path. */
  int fd = open(path, O_RDONLY);
  EXPECT_TRUE(fd >= 0);
  /* cppcheck-suppress knownConditionTrueFalse -- EXPECT_TRUE above asserts,
     but cppcheck cannot see through the macro; the guard is defensive. */
  if (fd >= 0) {
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    EXPECT_EQ_INT((int)strlen(content), (int)n);
    if (n == (ssize_t)strlen(content))
      EXPECT_TRUE(memcmp(buf, content, strlen(content)) == 0);
  }
  unlink(path);

  /* Same failure with keep_partial=false: temp is unlinked, nothing retained. */
  ok = file_to_disk_secure_attrs(path, content, strlen(content), false, false, true, &m, false,
                                 false, false, false, NULL, false, false, NULL);
  EXPECT_FALSE(ok);
  EXPECT_TRUE(access(path, F_OK) == -1);
}

void test_file() {
  test_file_create();
  test_file_special_rdev_valid();
  test_file_destroy_null();
  test_file_destroy_normal();
  test_file_load_data();
  test_file_load_data_missing_file();
  test_file_save_to_disk();
  test_file_save_to_disk_with_fsync_config();
  test_file_save_to_disk_existing();
  test_file_save_to_disk_ignore_existing();
  test_file_save_to_disk_ignore_existing_entry_types();
  test_file_save_to_disk_partial_install();
  test_file_save_to_disk_reports_skips();
  test_file_write_to_disk_sparse_preserves_holes();
  test_file_write_to_disk_partial_retention();
  test_file_write_to_disk_basic();
  test_file_write_to_disk_with_fsync();
  test_file_write_to_disk_preallocate_atomic();
  test_file_write_to_disk_preallocate_inplace();
  test_file_write_to_disk_creates_dirs();
  test_file_write_to_disk_does_not_follow_symlink();
  test_file_content_to_buffer();
  test_file_symlink_helpers();
  test_file_symlink_at_secure();
  test_file_save_to_disk_path_traversal();
  test_file_save_to_disk_deep_traversal();
  test_dir_entry_save_to_disk();
  if (!is_running_under_valgrind()) {
    // Fork tests are skipped under valgrind because the parent process runs
    // orders of magnitude slower than the child (parent is instrumented, child
    // is not), which causes pipe-based protocol handshake timeouts. The parent
    // process itself has zero valgrind errors -- the failures are all in the
    // forked children where inherited allocations are reported as leaks.
    test_file_send_receive();
    test_file_send_no_path();
    test_file_send_single_calls_compression();
    test_file_send_single_calls_metadata_and_path();
  }
  test_file_metadata_create();
  test_inplace_overwrite_clears_special_mode_bits();
  test_inplace_overwrite_metadata_strips_special_bits();
  test_inplace_overwrite_truncates_shorter_payload();
}
