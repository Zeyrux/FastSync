#include "test_server.h"
#include "config.h"
#include "file.h"
#include "protocol.h"
#include "test_utils.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Include server.c but rename main to avoid conflict with test runner's main */
#define main server_main_
#define FASTSYNC_SERVER_AS_LIB
#include "server.c"
#undef main

/* Test receive_files with immediate FINISHED status */
static void test_receive_files_finished() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/tmp/dst");

  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    /* Child: run receive_files */
    close(p[1]);

    int ret = receive_files(cfg, p[0]);
    close(p[0]);
    config_delete(cfg);
    _exit(ret == 0 ? 0 : 1);
  } else {
    /* Parent: send FINISHED then ok */
    close(p[0]);

    /* receive_files expects an initial status, then loops.
     * If we send STATUS_FINISHED first, it won't enter the loop body
     * (status == STATUS_FINISHED doesn't match any case).
     * After the loop, it checks if status == STATUS_FINISHED -> yes.
     * Then sends STATUS_OK and returns 0. */
    send_status(p[1], STATUS_FINISHED);
    /* receive_files will send STATUS_OK back, read it */
    Status resp;
    receive_status(p[1], &resp);

    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    config_delete(cfg);

    EXPECT_EQ_INT(resp, STATUS_OK);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Test receive_files with STATUS_NEXT + file data */
static void test_receive_files_single_file() {
  const char* content = "Hello from server test!";
  size_t len = strlen(content);

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/tmp/dst");

  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    /* Child: receive_files will try to call file_receive */
    close(p[1]);

    int ret = receive_files(cfg, p[0]);
    close(p[0]);
    config_delete(cfg);
    _exit(ret == 0 ? 0 : 1);
  } else {
    /* Parent: send a file */
    close(p[0]);

    /* Send initial status = STATUS_NEXT */
    send_status(p[1], STATUS_NEXT);

    /* Now send the file data */
    File* file = file_create("test_server_file.txt");
    EXPECT_NOT_NULL(file);
    file->data->data = malloc(len);
    EXPECT_NOT_NULL(file->data->data);
    memcpy(file->data->data, content, len);
    file->data->size = len;

    /* Send path, then data (no metadata since config has use_metadata=false) */
    send_str(p[1], file->path);
    send_data(p[1], file->data);

    file_destroy(file);

    /* Now send FINISHED to complete */
    send_status(p[1], STATUS_FINISHED);
    Status resp;
    receive_status(p[1], &resp);

    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    config_delete(cfg);

    EXPECT_EQ_INT(resp, STATUS_OK);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Test receive_files with STATUS_ABORT */
static void test_receive_files_abort() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/tmp/dst");

  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    int ret = receive_files(cfg, p[0]);
    close(p[0]);
    config_delete(cfg);
    /* Should return -1 on abort */
    _exit(ret == -1 ? 0 : 1);
  } else {
    close(p[0]);

    /* Send STATUS_ABORT */
    send_status(p[1], STATUS_ABORT);

    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

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
