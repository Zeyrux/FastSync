#include "test_file_sendfile.h"
#include "file.h"
#include "config.h"
#include "protocol.h"
#include "utils.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Test basic sendfile transfer: create a file, send it via file_send_sendfile,
 * receive via file_receive, and verify contents. */
static void test_sendfile_basic() {
  const char* content = "Hello from sendfile test!";
  size_t len = strlen(content);
  EXPECT_TRUE(file_write_to_disk("test_sendfile_basic.txt", content, len, false, false));

  File* file = file_create("test_sendfile_basic.txt");
  EXPECT_NOT_NULL(file);
  /* Set the size so file_send_sendfile can report it */
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
    /* Child: receive */
    close(p[1]);
    File* received = file_receive(cfg, p[0]);
    close(p[0]);

    bool ok = true;
    if (!received)
      ok = false;
    else {
      if (!received->path || strcmp(received->path, "test_sendfile_basic.txt") != 0)
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
    /* Parent: send via sendfile */
    close(p[0]);
    bool sent = file_send_sendfile(file, p[1], false, 0, true);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    file_destroy(file);
    config_delete(cfg);
    unlink("test_sendfile_basic.txt");

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Test sendfile with an empty file */
static void test_sendfile_empty_file() {
  const char* content = "";
  size_t len = 0;
  EXPECT_TRUE(file_write_to_disk("test_sendfile_empty.txt", content, len, false, false));

  File* file = file_create("test_sendfile_empty.txt");
  EXPECT_NOT_NULL(file);
  file->data->size = 0;

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
      if (strcmp(received->path, "test_sendfile_empty.txt") != 0)
        ok = false;
      if (received->data->size != 0)
        ok = false;
    }
    file_destroy(received);
    config_delete(cfg);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    bool sent = file_send_sendfile(file, p[1], false, 0, true);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    file_destroy(file);
    config_delete(cfg);
    unlink("test_sendfile_empty.txt");

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Test error path: file does not exist on disk */
static void test_sendfile_missing_file() {
  File* file = file_create("nonexistent_sendfile_test_file.txt");
  EXPECT_NOT_NULL(file);
  file->data->size = 100; /* fake size */

  /* Use a pipe that we can write to but sendfile should fail */
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  /* file_send_sendfile will try to open the nonexistent file -> should return false */
  bool sent = file_send_sendfile(file, p[1], false, 0, true);

  close(p[0]);
  close(p[1]);
  file_destroy(file);

  EXPECT_FALSE(sent);
}

/* Test compression level > 0 falls back to file_send_single_calls */
static void test_sendfile_compression_fallback() {
  const char* content = "Compression fallback content";
  size_t len = strlen(content);
  EXPECT_TRUE(file_write_to_disk("test_sendfile_comp.txt", content, len, false, false));

  struct stat st;
  EXPECT_EQ_INT(stat("test_sendfile_comp.txt", &st), 0);

  File* file = file_create("test_sendfile_comp.txt");
  EXPECT_NOT_NULL(file);
  /* Load the file data into memory (required by file_send_single_calls fallback) */
  file->data->size = (size_t)st.st_size;
  EXPECT_TRUE(file_load_data(file));

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/tmp");
  cfg->receive_root_directory = str_dup("/tmp");
  cfg->use_compression = true;
  cfg->compression_level = 3;
  EXPECT_NOT_NULL(cfg);

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
      if (received->data->size != len)
        ok = false;
      else if (memcmp(received->data->data, content, len) != 0)
        ok = false;
    }
    file_destroy(received);
    config_delete(cfg);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    /* compression_level = 3 triggers fallback to file_send_single_calls */
    bool sent = file_send_sendfile(file, p[1], false, 3, true);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    file_destroy(file);
    config_delete(cfg);
    unlink("test_sendfile_comp.txt");

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Test sendfile without path (send_path = false) */
static void test_sendfile_no_path() {
  const char* content = "No path sendfile test";
  size_t len = strlen(content);
  EXPECT_TRUE(file_write_to_disk("test_sendfile_nopath.txt", content, len, false, false));

  File* file = file_create("test_sendfile_nopath.txt");
  EXPECT_NOT_NULL(file);
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
    bool sent = file_send_sendfile(file, p[1], false, 0, false);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    file_destroy(file);
    unlink("test_sendfile_nopath.txt");

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

void test_file_sendfile() {
  if (!is_running_under_valgrind()) {
    // Fork tests are skipped under valgrind because the parent process runs
    // orders of magnitude slower than the child (parent is instrumented, child
    // is not), which causes pipe-based protocol handshake timeouts. The parent
    // process itself has zero valgrind errors -- the failures are all in the
    // forked children where inherited allocations are reported as leaks.
    test_sendfile_basic();
    test_sendfile_empty_file();
    test_sendfile_compression_fallback();
    test_sendfile_no_path();
  }
  test_sendfile_missing_file(); // no fork, safe under valgrind
}
