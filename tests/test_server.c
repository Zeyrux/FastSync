#include "test_server.h"
#include "config.h"
#include "delta.h"
#include "file.h"
#include "protocol.h"
#include "test_utils.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "receiver.h"

/* Test receive_files with immediate FINISHED status */
static void test_receive_files_finished() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/tmp/dst");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    /* Child: use p[0] for both read and write */
    close(p[1]);
    io_set_fds(p[0], p[0]);
    int ret = receiver_receive_files(cfg, p[0]);
    close(p[0]);
    config_delete(cfg);
    _exit(ret == 0 ? 0 : 1);
  } else {
    /* Parent: use p[1] for both read and write */
    close(p[0]);
    io_set_fds(p[1], p[1]);
    send_status(p[1], STATUS_FINISHED);
    /* receive_files expects an initial status, then loops.
     * If we send STATUS_FINISHED first, it won't enter the loop body
     * (status == STATUS_FINISHED doesn't match any case).
     * After the loop, it checks if status == STATUS_FINISHED -> yes.
     * Then sends STATUS_OK and returns 0. */
    /* receive_files will send STATUS_OK back, read it */
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

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/tmp/dst");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    /* Child: use p[0] for both read and write */
    close(p[1]);
    io_set_fds(p[0], p[0]);
    int ret = receiver_receive_files(cfg, p[0]);
    close(p[0]);
    config_delete(cfg);
    _exit(ret == 0 ? 0 : 1);
  } else {
    /* Parent: use p[1] for both read and write */
    close(p[0]);
    io_set_fds(p[1], p[1]);

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
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/tmp/dst");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    int ret = receiver_receive_files(cfg, p[0]);
    close(p[0]);
    config_delete(cfg);
    /* Should return -1 on abort */
    _exit(ret == -1 ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    /* Send STATUS_ABORT */
    send_status(p[1], STATUS_ABORT);

    int status;
    waitpid(pid, &status, 0);

    close(p[1]);

    config_delete(cfg);

    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_receive_manifest_rejects_traversal() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->receive_root_directory = str_dup("/tmp/dst");
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_str(p[1], "../outside"));
  EXPECT_EQ_INT(receive_manifest(p[0], cfg, NULL), -1);
  close(p[0]);
  close(p[1]);
  config_delete(cfg);
}

static void test_receive_incremental_check_rejects_invalid_nanoseconds() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->receive_root_directory = str_dup("/tmp/dst");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  EXPECT_TRUE(send_str(p[1], "file.txt"));
  unsigned long long size = 0;
  long long mtime = 100;
  long long mtime_nsec = 1000000000LL;
  EXPECT_TRUE(send_n_data(p[1], &size, sizeof(size)));
  EXPECT_TRUE(send_n_data(p[1], &mtime, sizeof(mtime)));
  EXPECT_TRUE(send_n_data(p[1], &mtime_nsec, sizeof(mtime_nsec)));

  bool skipped = false;
  EXPECT_NULL(receive_incremental_check(p[0], cfg, &skipped));
  Status status;
  EXPECT_TRUE(receive_status(p[1], &status));
  EXPECT_EQ_INT(status, STATUS_ERROR);
  EXPECT_FALSE(skipped);

  close(p[0]);
  close(p[1]);
  config_delete(cfg);
}

static char* make_check_root(const char* tag) {
  char tmpl[128];
  snprintf(tmpl, sizeof(tmpl), "/tmp/fastsync_%s_XXXXXX", tag);
  char* path = str_dup(tmpl);
  if (!path)
    return NULL;
  if (!mkdtemp(path)) {
    free(path);
    return NULL;
  }
  return path;
}

static void write_check_file(const char* dir, const char* name, const char* content) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s", dir, name);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    size_t len = strlen(content);
    if (write(fd, content, len) != (ssize_t)len) {
      /* intentionally ignored in tests */
    }
    close(fd);
  }
}

/* Issue #255: a same-size/mtime match is decided from metadata alone, so the
   receiver answers STATUS_OK (skip) and never asks for a data body. */
static void test_incremental_check_quick_skip_by_mtime() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  char* root = make_check_root("qskip");
  EXPECT_NOT_NULL(root);
  cfg->receive_root_directory = str_dup(root);
  write_check_file(root, "file.txt", "0123456789abcdef");

  char path[1024];
  snprintf(path, sizeof(path), "%s/file.txt", root);
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    alarm(30);
    close(p[1]);
    io_set_fds(p[0], p[0]);
    bool skipped = false;
    File* file = receive_incremental_check(p[0], cfg, &skipped);
    bool ok = file == NULL && skipped;
    file_destroy(file);
    config_delete(cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    EXPECT_TRUE(send_str(p[1], "file.txt"));
    unsigned long long size = (unsigned long long)st.st_size;
    long long mtime = (long long)st.st_mtime;
    long long mtime_nsec = 0;
#ifdef __linux__
    mtime_nsec = (long long)st.st_mtim.tv_nsec;
#endif
    EXPECT_TRUE(send_n_data(p[1], &size, sizeof(size)));
    EXPECT_TRUE(send_n_data(p[1], &mtime, sizeof(mtime)));
    EXPECT_TRUE(send_n_data(p[1], &mtime_nsec, sizeof(mtime_nsec)));
    Status s;
    EXPECT_TRUE(receive_status(p[1], &s));
    EXPECT_EQ_INT(s, STATUS_OK);

    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(cfg);
    unlink(path);
    rmdir(root);
    free(root);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Issue #255: a size mismatch cannot be a skip, so the receiver answers
   STATUS_NEXT and consumes the full data body that follows. */
static void test_incremental_check_size_mismatch_full_transfer() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  char* root = make_check_root("qnext");
  EXPECT_NOT_NULL(root);
  cfg->receive_root_directory = str_dup(root);
  write_check_file(root, "file.txt", "0123456789abcdef");

  char path[1024];
  snprintf(path, sizeof(path), "%s/file.txt", root);
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    alarm(30);
    close(p[1]);
    io_set_fds(p[0], p[0]);
    bool skipped = false;
    File* file = receive_incremental_check(p[0], cfg, &skipped);
    bool ok = file != NULL && !skipped && file->path != NULL && strcmp(file->path, "file.txt") == 0;
    file_destroy(file);
    config_delete(cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    EXPECT_TRUE(send_str(p[1], "file.txt"));
    unsigned long long size = (unsigned long long)st.st_size + 1;
    long long mtime = (long long)st.st_mtime;
    long long mtime_nsec = 0;
#ifdef __linux__
    mtime_nsec = (long long)st.st_mtim.tv_nsec;
#endif
    EXPECT_TRUE(send_n_data(p[1], &size, sizeof(size)));
    EXPECT_TRUE(send_n_data(p[1], &mtime, sizeof(mtime)));
    EXPECT_TRUE(send_n_data(p[1], &mtime_nsec, sizeof(mtime_nsec)));
    Status s;
    EXPECT_TRUE(receive_status(p[1], &s));
    EXPECT_EQ_INT(s, STATUS_NEXT);

    Data* body = data_create_reserve(8);
    EXPECT_NOT_NULL(body);
    body->data = malloc(8);
    EXPECT_NOT_NULL(body->data);
    memcpy(body->data, "replaced", 8);
    body->size = 8;
    EXPECT_TRUE(send_data(p[1], body));
    data_destroy(body);

    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(cfg);
    unlink(path);
    rmdir(root);
    free(root);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Issue #256: when a received delta claims a result above the whole-file cap,
   receive_delta_file must mark the operation failed so the caller aborts with
   STATUS_ERROR instead of emitting STATUS_NEXT and waiting for a body that
   never arrives. */
static void test_incremental_check_delta_oversize_reports_failure() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  char* root = make_check_root("qdelta");
  EXPECT_NOT_NULL(root);
  cfg->receive_root_directory = str_dup(root);
  cfg->use_delta = true;

  char content[20000];
  memset(content, 'a', sizeof(content));
  content[sizeof(content) - 1] = '\0';
  write_check_file(root, "file.txt", content);

  char path[1024];
  snprintf(path, sizeof(path), "%s/file.txt", root);
  struct stat st;
  EXPECT_EQ_INT(stat(path, &st), 0);
  EXPECT_EQ_INT((int)st.st_size, 19999);

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    alarm(30);
    close(p[1]);
    io_set_fds(p[0], p[0]);
    bool skipped = false;
    File* file = receive_incremental_check(p[0], cfg, &skipped);
    bool ok = file == NULL && !skipped;
    if (ok)
      send_status(p[0], STATUS_ERROR); /* mirror the server error path */
    file_destroy(file);
    config_delete(cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    EXPECT_TRUE(send_str(p[1], "file.txt"));
    unsigned long long size = (unsigned long long)st.st_size;
    long long mtime = 1; /* different from the file mtime: force a transfer */
    long long mtime_nsec = 0;
    EXPECT_TRUE(send_n_data(p[1], &size, sizeof(size)));
    EXPECT_TRUE(send_n_data(p[1], &mtime, sizeof(mtime)));
    EXPECT_TRUE(send_n_data(p[1], &mtime_nsec, sizeof(mtime_nsec)));

    Status s;
    EXPECT_TRUE(receive_status(p[1], &s));
    EXPECT_EQ_INT(s, STATUS_DELTA_SIGNATURE);
    Data* sig_data = receive_data(p[1]);
    EXPECT_NOT_NULL(sig_data);
    DeltaSignature* sig = delta_signature_deserialize(sig_data);
    EXPECT_NOT_NULL(sig);
    delta_signature_destroy(sig);
    data_destroy(sig_data);

    /* Send a delta whose claimed output size exceeds the whole-file cap. */
    Delta delta;
    memset(&delta, 0, sizeof(delta));
    delta.new_file_size = MAX_RECEIVE_WHOLE_FILE_SIZE + 1;
    Data* bogus = delta_serialize(&delta);
    EXPECT_NOT_NULL(bogus);
    EXPECT_TRUE(send_status(p[1], STATUS_DELTA_DATA));
    EXPECT_TRUE(bogus != NULL && send_data(p[1], bogus));
    data_destroy(bogus);

    /* The receiver must answer with an error, never with STATUS_NEXT. */
    EXPECT_TRUE(receive_status(p[1], &s));
    EXPECT_EQ_INT(s, STATUS_ERROR);

    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(cfg);
    unlink(path);
    rmdir(root);
    free(root);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

void test_server() {
  if (!is_running_under_valgrind()) {
    test_receive_files_finished();
    test_receive_files_single_file();
    test_receive_files_abort();
    test_receive_manifest_rejects_traversal();
    test_receive_incremental_check_rejects_invalid_nanoseconds();
    test_incremental_check_quick_skip_by_mtime();
    test_incremental_check_size_mismatch_full_transfer();
    test_incremental_check_delta_oversize_reports_failure();
  }
}
