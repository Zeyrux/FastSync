#include "test_server.h"
#include "config.h"
#include "file.h"
#include "protocol.h"
#include "test_utils.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* Include server.c but rename main to avoid conflict with test runner's main */
#define main server_main_
#include "server.c"
#undef main

/* Test receive_files with immediate FINISHED status */
static void test_receive_files_finished() {
  Config* cfg = config_create(str_dup(PROTOCOL_VERSION), str_dup("/src"), str_dup("/tmp/dst"),
                              false, false, false, false, false, 0, false, 0);
  EXPECT_NOT_NULL(cfg);

  /* Use socketpair for full-duplex communication */
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    /* Child: run receive_files - needs both directions */
    close(p[1]);
    io_set_fds(p[0], p[0]);
    int ret = receive_files(cfg, p[0]);
    close(p[0]);
    config_delete(cfg);
    _exit(ret == 0 ? 0 : 1);
  } else {
    /* Parent: send FINISHED */
    close(p[0]);
    io_set_fds(p[1], p[1]);
    send_status(p[1], STATUS_FINISHED);
    Status resp;
    receive_status(p[1], &resp);

    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(cfg);

    EXPECT_EQ_INT(resp, STATUS_OK);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Test receive_files with STATUS_NEXT + file data */
static void test_receive_files_single_file() {
  const char* content = "Hello from server test!";
  size_t len = strlen(content);

  Config* cfg = config_create(str_dup(PROTOCOL_VERSION), str_dup("/src"), str_dup("/tmp/dst"),
                              false, false, false, false, false, 0, false, 0);
  EXPECT_NOT_NULL(cfg);

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    int ret = receive_files(cfg, p[0]);
    close(p[0]);
    config_delete(cfg);
    _exit(ret == 0 ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);

    send_status(p[1], STATUS_NEXT);

    File* file = file_create("test_server_file.txt");
    EXPECT_NOT_NULL(file);
    file->data->data = malloc(len);
    EXPECT_NOT_NULL(file->data->data);
    memcpy(file->data->data, content, len);
    file->data->size = len;

    send_str(p[1], file->path);
    send_data(p[1], file->data);
    file_destroy(file);

    send_status(p[1], STATUS_FINISHED);
    Status resp;
    receive_status(p[1], &resp);

    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(cfg);

    EXPECT_EQ_INT(resp, STATUS_OK);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Test receive_files with STATUS_ABORT */
static void test_receive_files_abort() {
  Config* cfg = config_create(str_dup(PROTOCOL_VERSION), str_dup("/src"), str_dup("/tmp/dst"),
                              false, false, false, false, false, 0, false, 0);
  EXPECT_NOT_NULL(cfg);

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    int ret = receive_files(cfg, p[0]);
    close(p[0]);
    config_delete(cfg);
    _exit(ret == -1 ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    send_status(p[1], STATUS_ABORT);

    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(cfg);

    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

void test_server() {
  if (!is_running_under_valgrind()) {
    test_receive_files_finished();
    test_receive_files_single_file();
    test_receive_files_abort();
  }
}
