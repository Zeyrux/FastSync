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
  EXPECT_TRUE(to_disk("test_file_load_data.txt", content, strlen(content)));

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

static void test_to_disk_basic() {
  const char* content = "Basic to_disk test";
  EXPECT_TRUE(to_disk("test_to_disk_basic.txt", content, strlen(content)));

  struct stat st;
  EXPECT_EQ_INT(stat("test_to_disk_basic.txt", &st), 0);
  EXPECT_EQ_INT((int)st.st_size, (int)strlen(content));

  FILE* fp = fopen("test_to_disk_basic.txt", "rb");
  EXPECT_NOT_NULL(fp);
  char buf[100];
  size_t nread = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);
  EXPECT_EQ_INT((int)nread, (int)strlen(content));
  EXPECT_EQ_INT(memcmp(buf, content, strlen(content)), 0);

  unlink("test_to_disk_basic.txt");
}

static void test_to_disk_creates_dirs() {
  const char* content = "Nested dir test";
  EXPECT_TRUE(to_disk("test_nested_tmp/nested/file.txt", content, strlen(content)));

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

static void test_file_content_to_buffer() {
  const char* content = "Buffer content test";
  EXPECT_TRUE(to_disk("test_buffer_file.txt", content, strlen(content)));

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

  Config* cfg = config_create(str_dup(PROTOCOL_VERSION), str_dup("/tmp"), str_dup("/tmp"), false,
                              false, false, false, false, 0, false, 0);

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
  EXPECT_TRUE(to_disk("test_meta_file.txt", "metadata test", 13));
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

void test_file() {
  test_file_create();
  test_file_destroy_null();
  test_file_destroy_normal();
  test_file_load_data();
  test_file_load_data_missing_file();
  test_file_save_to_disk();
  test_to_disk_basic();
  test_to_disk_creates_dirs();
  test_file_content_to_buffer();
  if (!is_running_under_valgrind()) {
    // Fork tests are skipped under valgrind because the parent process runs
    // orders of magnitude slower than the child (parent is instrumented, child
    // is not), which causes pipe-based protocol handshake timeouts. The parent
    // process itself has zero valgrind errors -- the failures are all in the
    // forked children where inherited allocations are reported as leaks.
    test_file_send_receive();
    test_file_send_no_path();
  }
  test_file_metadata_create();
}
