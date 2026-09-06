#include "test_file.h"
#include "file.h"
#include "data.h"
#include "config.h"
#include "utils.h"
#include "protocol.h"
#include "test_utils.h"
#include <fcntl.h>
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
  EXPECT_TRUE(file_to_disk_secure_with_fsync(path, content, strlen(content), false, false, NULL,
                                             false, true, NULL));
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT((int)st.st_size, (int)strlen(content));
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

  FileMetadata* m = file_metadata_create(&st);
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
  file->metadata = file_metadata_create(&st);
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
  f->metadata = file_metadata_create(&source_st);
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

void test_file() {
  test_file_create();
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
  test_file_write_to_disk_basic();
  test_file_write_to_disk_with_fsync();
  test_file_write_to_disk_creates_dirs();
  test_file_write_to_disk_does_not_follow_symlink();
  test_file_content_to_buffer();
  test_file_save_to_disk_path_traversal();
  test_file_save_to_disk_deep_traversal();
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
