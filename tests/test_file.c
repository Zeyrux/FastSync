#include "test_file.h"
#include "file.h"
#include "data.h"
#include "utils.h"
#include "protocol.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
  EXPECT_TRUE(file_write_to_disk("test_file_load_data.txt", content, strlen(content), false, false));

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

static void test_file_write_to_disk_basic() {
  const char* content = "Basic file_write_to_disk test";
  EXPECT_TRUE(file_write_to_disk("test_file_write_to_disk_basic.txt", content, strlen(content), false, false));

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

static void test_file_write_to_disk_creates_dirs() {
  const char* content = "Nested dir test";
  EXPECT_TRUE(file_write_to_disk("test_nested_tmp/nested/file.txt", content, strlen(content), false, false));

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

void test_file() {
  test_file_create();
  test_file_destroy_null();
  test_file_destroy_normal();
  test_file_load_data();
  test_file_load_data_missing_file();
  test_file_save_to_disk();
  test_file_write_to_disk_basic();
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
}
