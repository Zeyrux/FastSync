#include "test_server.h"
#include "checksum.h"
#include "config.h"
#include "delta.h"
#include "file.h"
#include "log.h"
#include "protocol.h"
#include "test_utils.h"
#include "utils.h"
#include <dirent.h>
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
  EXPECT_NULL(receive_manifest_entries(p[0]));
  Status status;
  EXPECT_TRUE(receive_status(p[1], &status));
  EXPECT_EQ_INT(status, STATUS_ERROR);
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
  /* Sized so a caller that passes a PATH_MAX-bounded `dir` (e.g. one of the
     test's own char[1024] stack buffers) still provably fits with the joined
     name, keeping -Werror=format-truncation quiet. */
  char path[4096];
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

/* Server-contacting --dry-run: with the wire config's dry_run set, a file that
   is NOT up to date makes the receiver answer STATUS_DRY_RUN_TRANSFER and
   return immediately; no data body is read and the destination file is left
   byte-for-byte unchanged (no temp file, no write, no rename). */
static void test_incremental_check_dry_run_reports_transfer_without_writing() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->dry_run = true;
  char* root = make_check_root("dryw");
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
    bool would_transfer = false;
    File* file = receive_incremental_check_ex(p[0], cfg, &skipped, &would_transfer);
    bool ok = file == NULL && !skipped && would_transfer;
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
    EXPECT_EQ_INT(s, STATUS_DRY_RUN_TRANSFER);

    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(cfg);
    /* The destination file must be untouched and no temp sibling may appear. */
    char buf[32] = {0};
    int fd = open(path, O_RDONLY);
    EXPECT_TRUE(fd >= 0);
    ssize_t got = read(fd, buf, sizeof(buf) - 1);
    EXPECT_EQ_INT((int)got, 16);
    EXPECT_EQ_STR(buf, "0123456789abcdef");
    close(fd);
    DIR* d = opendir(root);
    EXPECT_NOT_NULL(d);
    int entries = 0;
    const struct dirent* e;
    while ((e = readdir(d)) != NULL) {
      if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
        entries++;
    }
    closedir(d);
    EXPECT_EQ_INT(entries, 1);
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

/* Late-timing keep-set leak guard: a manifest parked by the commit path must
   be freed on every error exit, never leaked.  These tests drive
   receiver_process_pending() through an error AFTER the manifest was parked and
   are exercised under ASan/valgrind to prove the list is released. */

static Config* make_late_delete_config(const char* root) {
  Config* cfg = config_create();
  if (!cfg)
    return NULL;
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup(root);
  cfg->use_delete = true;
  cfg->delete_after = true;
  return cfg;
}

static int run_pending_receiver(Config* cfg, int fd, DeleteManifest** pending) {
  ReceiverSink sink = {0};
  return receiver_process_pending(cfg, fd, &sink, pending, NULL);
}

static void test_late_manifest_abort_frees_keepset() {
  Config* cfg = make_late_delete_config("/tmp/fastsync_late_abort");
  EXPECT_NOT_NULL(cfg);
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  EXPECT_TRUE(send_status(p[1], STATUS_MANIFEST));
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_str(p[1], "keep.txt"));
  EXPECT_TRUE(send_int(p[1], 0)); /* protected-prefix section is empty */
  EXPECT_TRUE(send_int(p[1], 0)); /* missing-args section is empty */
  EXPECT_TRUE(send_int(p[1], 0)); /* synchronized-directories section is empty */
  EXPECT_TRUE(send_status(p[1], STATUS_ABORT));

  DeleteManifest* pending = NULL;
  EXPECT_EQ_INT(run_pending_receiver(cfg, p[0], &pending), -1);
  EXPECT_NULL(pending);

  close(p[0]);
  close(p[1]);
  config_delete(cfg);
}

static void test_late_manifest_eof_frees_keepset() {
  Config* cfg = make_late_delete_config("/tmp/fastsync_late_eof");
  EXPECT_NOT_NULL(cfg);
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  EXPECT_TRUE(send_status(p[1], STATUS_MANIFEST));
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_str(p[1], "keep.txt"));
  EXPECT_TRUE(send_int(p[1], 0)); /* protected-prefix section is empty */
  EXPECT_TRUE(send_int(p[1], 0)); /* missing-args section is empty */
  EXPECT_TRUE(send_int(p[1], 0)); /* synchronized-directories section is empty */
  shutdown(p[1], SHUT_WR);

  DeleteManifest* pending = NULL;
  EXPECT_EQ_INT(run_pending_receiver(cfg, p[0], &pending), -1);
  EXPECT_NULL(pending);

  close(p[0]);
  close(p[1]);
  config_delete(cfg);
}

static void test_late_second_manifest_frees_both() {
  Config* cfg = make_late_delete_config("/tmp/fastsync_late_second");
  EXPECT_NOT_NULL(cfg);
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  EXPECT_TRUE(send_status(p[1], STATUS_MANIFEST));
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_str(p[1], "first.txt"));
  EXPECT_TRUE(send_int(p[1], 0)); /* protected-prefix section is empty */
  EXPECT_TRUE(send_int(p[1], 0)); /* missing-args section is empty */
  EXPECT_TRUE(send_int(p[1], 0)); /* synchronized-directories section is empty */
  EXPECT_TRUE(send_status(p[1], STATUS_MANIFEST));
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_str(p[1], "second.txt"));
  EXPECT_TRUE(send_int(p[1], 0)); /* protected-prefix section is empty */
  EXPECT_TRUE(send_int(p[1], 0)); /* missing-args section is empty */
  EXPECT_TRUE(send_int(p[1], 0)); /* synchronized-directories section is empty */

  DeleteManifest* pending = NULL;
  EXPECT_EQ_INT(run_pending_receiver(cfg, p[0], &pending), -1);
  EXPECT_NULL(pending);

  close(p[0]);
  close(p[1]);
  config_delete(cfg);
}

/* A delete-manifest frame with all four sections round-trips: the receiver
   keeps the keep-set, protected prefixes, missing-args paths and synchronized
   directories, and every section is confined exactly like the keep-set (a
   traversal entry in the missing section is rejected).
   receive_manifest_entries() reads the counts directly (the leading
   STATUS_MANIFEST code is consumed by the caller, so these frames do not send
   it). */
static void test_receive_manifest_three_sections() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->receive_root_directory = str_dup("/tmp/dst");
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);

  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_str(p[1], "keep.txt"));
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_str(p[1], "protected.txt"));
  EXPECT_TRUE(send_int(p[1], 2));
  EXPECT_TRUE(send_str(p[1], "gone.txt"));
  EXPECT_TRUE(send_str(p[1], "dir/gone.bin"));
  EXPECT_TRUE(send_int(p[1], 2));
  EXPECT_TRUE(send_str(p[1], "."));
  EXPECT_TRUE(send_str(p[1], "dir"));

  DeleteManifest* manifest = receive_manifest_entries(p[0]);
  EXPECT_NOT_NULL(manifest);
  EXPECT_EQ_INT(manifest->keeps->size, 1);
  EXPECT_EQ_STR((char*)manifest->keeps->items[0], "keep.txt");
  EXPECT_EQ_INT(manifest->protected->size, 1);
  EXPECT_EQ_STR((char*)manifest->protected->items[0], "protected.txt");
  EXPECT_EQ_INT(manifest->missing->size, 2);
  EXPECT_EQ_STR((char*)manifest->missing->items[0], "gone.txt");
  EXPECT_EQ_STR((char*)manifest->missing->items[1], "dir/gone.bin");
  EXPECT_EQ_INT(manifest->dirs->size, 2);
  EXPECT_EQ_STR((char*)manifest->dirs->items[0], ".");
  EXPECT_EQ_STR((char*)manifest->dirs->items[1], "dir");
  delete_manifest_free(manifest);

  /* A traversal entry in the missing section is rejected like every other. */
  EXPECT_TRUE(send_int(p[1], 0));
  EXPECT_TRUE(send_int(p[1], 0));
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_str(p[1], "../escape"));
  EXPECT_NULL(receive_manifest_entries(p[0]));
  Status status;
  EXPECT_TRUE(receive_status(p[1], &status));
  EXPECT_EQ_INT(status, STATUS_ERROR);

  close(p[0]);
  close(p[1]);
  config_delete(cfg);
}

/* --delete-missing-args exact-path deletions: regular files and empty
   directories are removed, a non-empty directory survives without
   --force/--delete and is recursively removed with --force or --delete, and a
   missing mirror is a no-op. */
static void test_manifest_delete_missing_args() {
  char* root = make_check_root("qmissing");
  EXPECT_NOT_NULL(root);
  write_check_file(root, "gone.txt", "stale");
  char empty_dir[1024], full_dir[1024], inner[1024];
  snprintf(empty_dir, sizeof(empty_dir), "%s/empty_dir", root);
  snprintf(full_dir, sizeof(full_dir), "%s/full_dir", root);
  snprintf(inner, sizeof(inner), "%s/full_dir/inner.txt", root);
  EXPECT_EQ_INT(mkdir(empty_dir, 0755), 0);
  EXPECT_EQ_INT(mkdir(full_dir, 0755), 0);
  write_check_file(full_dir, "inner.txt", "content");

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->receive_root_directory = str_dup(root);
  cfg->delete_missing_args = true;

  DeleteManifest* manifest = calloc(1, sizeof(DeleteManifest));
  EXPECT_NOT_NULL(manifest);
  manifest->keeps = array_list_create(free);
  manifest->protected = array_list_create(free);
  manifest->missing = array_list_create(free);
  EXPECT_TRUE(array_list_add(manifest->missing, str_dup("gone.txt")));
  EXPECT_TRUE(array_list_add(manifest->missing, str_dup("empty_dir")));
  EXPECT_TRUE(array_list_add(manifest->missing, str_dup("full_dir")));
  EXPECT_TRUE(array_list_add(manifest->missing, str_dup("never_here.txt")));
  /* A deeper entry whose destination parent directory does not exist is a
     no-op (nothing to delete), never a failure. */
  EXPECT_TRUE(array_list_add(manifest->missing, str_dup("no_parent_here/gone.txt")));

  /* Without --delete/--force the non-empty directory survives (rsync parity). */
  EXPECT_TRUE(manifest_delete_missing_args(cfg, manifest));
  char path[1024];
  snprintf(path, sizeof(path), "%s/gone.txt", root);
  EXPECT_EQ_INT(access(path, F_OK), -1);
  snprintf(path, sizeof(path), "%s/empty_dir", root);
  EXPECT_EQ_INT(access(path, F_OK), -1);
  snprintf(path, sizeof(path), "%s/full_dir", root);
  EXPECT_EQ_INT(access(path, F_OK), 0);
  EXPECT_EQ_INT(access(inner, F_OK), 0);

  /* With --force the non-empty directory mirror is removed recursively. */
  cfg->force_delete = true;
  EXPECT_TRUE(array_list_add(manifest->missing, str_dup("full_dir")));
  EXPECT_TRUE(manifest_delete_missing_args(cfg, manifest));
  EXPECT_EQ_INT(access(full_dir, F_OK), -1);
  snprintf(path, sizeof(path), "%s/no_parent_here", root);
  EXPECT_EQ_INT(access(path, F_OK), -1);

  delete_manifest_free(manifest);
  config_delete(cfg);
  remove(full_dir);
  rmdir(empty_dir);
  rmdir(root);
  free(root);
}

/* A delete-missing-args manifest parked by the commit path is committed after
   STATUS_FINISHED: the mirror that exists is removed, a missing mirror is a
   no-op, and unrelated destination content is untouched (no --delete). */
static void test_receiver_pending_commits_missing_args() {
  char* root = make_check_root("qmisscomm");
  EXPECT_NOT_NULL(root);
  write_check_file(root, "gone.txt", "stale");
  write_check_file(root, "extra.txt", "unrelated");

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup(root);
  cfg->delete_missing_args = true;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  EXPECT_TRUE(send_status(p[1], STATUS_MANIFEST));
  EXPECT_TRUE(send_int(p[1], 0)); /* keep-set empty */
  EXPECT_TRUE(send_int(p[1], 0)); /* protected empty */
  EXPECT_TRUE(send_int(p[1], 2));
  EXPECT_TRUE(send_str(p[1], "gone.txt"));
  EXPECT_TRUE(send_str(p[1], "never_here.txt"));
  EXPECT_TRUE(send_int(p[1], 0)); /* no synchronized directories */
  EXPECT_TRUE(send_status(p[1], STATUS_FINISHED));

  /* NULL pending: the single-threaded commit path deletes at FINISHED.  The
     sink sends the terminal STATUS_OK success frame. */
  ReceiverSink sink = {.send_success = true};
  EXPECT_EQ_INT(receiver_process_pending(cfg, p[0], &sink, NULL, NULL), 0);
  Status ack;
  EXPECT_TRUE(receive_status(p[1], &ack));
  EXPECT_EQ_INT(ack, STATUS_OK);

  char path[1024];
  snprintf(path, sizeof(path), "%s/gone.txt", root);
  EXPECT_EQ_INT(access(path, F_OK), -1);
  snprintf(path, sizeof(path), "%s/extra.txt", root);
  EXPECT_EQ_INT(access(path, F_OK), 0);

  close(p[0]);
  close(p[1]);
  config_delete(cfg);
  {
    /* remove fixtures */
    char pth[1024];
    snprintf(pth, sizeof(pth), "%s/extra.txt", root);
    remove(pth);
    rmdir(root);
  }
  free(root);
}

/* A6: an attacker-controlled file path appearing in a log line must be escaped
   so a control byte cannot forge a second log record.  The socket special-node
   branch logs file->path before touching the filesystem, making it a cheap way
   to exercise an escaped site.  The captured line must contain the escaped path
   (`\#012` for the newline), never the raw control byte. */
static void test_special_socket_path_log_escaped() {
  set_log_level(LOG_LEVEL_WARNING);
  log_set_8_bit_output(false);

  const char* root = "test_special_sock_escape_root";
  const char* existing = "test_special_sock_escape_root/evil\npath";
  unlink(existing);
  rmdir(root);
  EXPECT_EQ_INT(mkdir(root, 0700), 0);
  FILE* planted = fopen(existing, "wb");
  EXPECT_NOT_NULL(planted);
  fclose(planted);

  FILE* capture = tmpfile();
  EXPECT_NOT_NULL(capture);
  log_set_file(capture);

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->preserve_specials = true;
  cfg->use_metadata = true;

  File* file = file_create("evil\npath");
  EXPECT_NOT_NULL(file);
  file->is_special = true;
  file->metadata = calloc(1, sizeof(FileMetadata));
  EXPECT_NOT_NULL(file->metadata);
  file->metadata->mode = S_IFSOCK | 0644;

  /* A non-matching entry already occupies the path: the socket creation is
     refused and the warning must escape the path's control byte. */
  FileSaveResult result = file_save_to_disk_full(root, file, cfg);
  EXPECT_EQ_INT(result, FILE_SAVE_SKIPPED);

  fflush(capture);
  rewind(capture);
  char output[512] = {0};
  size_t length = fread(output, 1, sizeof(output) - 1, capture);
  output[length] = '\0';

  log_set_file(NULL);
  fclose(capture);
  file_destroy(file);
  config_delete(cfg);
  unlink(existing);
  rmdir(root);

  EXPECT_NOT_NULL(strstr(output, "refusing to replace existing entry with socket: evil\\#012path"));
}

/* B1: a client-planted FIFO at the destination must not block the receiver's
 * incremental-check open.  With the O_NONBLOCK open plus the post-open S_ISREG
 * gate the FIFO is simply "no existing regular file", so the receiver proceeds
 * to a full transfer; without O_NONBLOCK the child blocks in openat() and the
 * alarm(30) kills it. */
static void test_incremental_check_fifo_destination_does_not_hang() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  char* root = make_check_root("qffo");
  EXPECT_NOT_NULL(root);
  cfg->receive_root_directory = str_dup(root);
  char path[1024];
  snprintf(path, sizeof(path), "%s/file.txt", root);
  EXPECT_EQ_INT(mkfifo(path, 0600), 0);

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
    bool ok = file != NULL && !skipped;
    file_destroy(file);
    config_delete(cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    EXPECT_TRUE(send_str(p[1], "file.txt"));
    unsigned long long size = 4;
    long long mtime = 42;
    long long mtime_nsec = 0;
    EXPECT_TRUE(send_n_data(p[1], &size, sizeof(size)));
    EXPECT_TRUE(send_n_data(p[1], &mtime, sizeof(mtime)));
    EXPECT_TRUE(send_n_data(p[1], &mtime_nsec, sizeof(mtime_nsec)));
    Status s;
    EXPECT_TRUE(receive_status(p[1], &s));
    EXPECT_EQ_INT(s, STATUS_NEXT);

    Data* body = data_create_reserve(4);
    EXPECT_NOT_NULL(body);
    body->data = malloc(4);
    EXPECT_NOT_NULL(body->data);
    memcpy(body->data, "data", 4);
    body->size = 4;
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

/* A server-contacting --dry-run with an alternate basis dir must never read or
   hash the basis file.  An exact (size+mtime+content) basis match would
   otherwise let a client probe the basis bytes against its own supplied digest
   (a 1-bit content oracle).  The dry-run decision is metadata-only, so even a
   byte-identical basis is reported as would-transfer, not a compare-dest skip. */
static void test_incremental_check_dry_run_basis_does_not_read_content() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->dry_run = true;
  char* root = make_check_root("dryb");
  EXPECT_NOT_NULL(root);
  cfg->receive_root_directory = str_dup(root);

  char basis_dir[1024];
  char basis_path[2048];
  snprintf(basis_dir, sizeof(basis_dir), "%s/basis", root);
  EXPECT_EQ_INT(mkdir(basis_dir, 0700), 0);
  const char* content = "basis content that matches\n";
  write_check_file(basis_dir, "file.txt", content);
  snprintf(basis_path, sizeof(basis_path), "%s/file.txt", basis_dir);
  struct stat bst;
  EXPECT_EQ_INT(stat(basis_path, &bst), 0);
  EXPECT_EQ_INT(config_basis_append(cfg, BASIS_DEST_COMPARE, "basis"), 0);

  /* The (correct) source digest for the basis bytes: an unfixed dry-run would
     read+hash the basis and treat this as an exact compare-dest hit. */
  uint8_t digest[CHECKSUM_MAX_DIGEST_LEN];
  size_t digest_len = 0;
  EXPECT_TRUE(checksum_digest((ChecksumAlgo)cfg->checksum_algo, cfg->checksum_seed, content,
                              strlen(content), digest, sizeof(digest), &digest_len));

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
    bool would_transfer = false;
    File* file = receive_incremental_check_ex(p[0], cfg, &skipped, &would_transfer);
    bool ok = file == NULL && !skipped && would_transfer;
    file_destroy(file);
    config_delete(cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    EXPECT_TRUE(send_str(p[1], "file.txt"));
    unsigned long long size = (unsigned long long)bst.st_size;
    long long mtime = (long long)bst.st_mtime;
    long long mtime_nsec = 0;
#ifdef __linux__
    mtime_nsec = (long long)bst.st_mtim.tv_nsec;
#endif
    EXPECT_TRUE(send_n_data(p[1], &size, sizeof(size)));
    EXPECT_TRUE(send_n_data(p[1], &mtime, sizeof(mtime)));
    EXPECT_TRUE(send_n_data(p[1], &mtime_nsec, sizeof(mtime_nsec)));
    uint8_t wire_len = (uint8_t)digest_len;
    EXPECT_TRUE(send_n_data(p[1], &wire_len, sizeof(wire_len)));
    EXPECT_TRUE(send_n_data(p[1], digest, digest_len));
    Status s;
    EXPECT_TRUE(receive_status(p[1], &s));
    /* A skip here would mean the receiver read+hashed the basis file. */
    EXPECT_EQ_INT(s, STATUS_DRY_RUN_TRANSFER);

    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(cfg);
    /* The dry-run must not have materialized anything in the receive root. */
    char dest_path[2048];
    snprintf(dest_path, sizeof(dest_path), "%s/file.txt", root);
    EXPECT_FALSE(file_path_exists_secure(dest_path));
    unlink(basis_path);
    rmdir(basis_dir);
    rmdir(root);
    free(root);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* B1: a FIFO planted in a --link-dest basis directory must not block
 * basis_open_regular() either; the basis match is simply declined. */
static void test_incremental_check_basis_fifo_does_not_hang() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  char* root = make_check_root("qbfi");
  EXPECT_NOT_NULL(root);
  cfg->receive_root_directory = str_dup(root);
  char basis_dir[1024];
  char basis_path[2048];
  snprintf(basis_dir, sizeof(basis_dir), "%s/basis", root);
  EXPECT_EQ_INT(mkdir(basis_dir, 0700), 0);
  snprintf(basis_path, sizeof(basis_path), "%s/file.txt", basis_dir);
  EXPECT_EQ_INT(mkfifo(basis_path, 0600), 0);
  EXPECT_EQ_INT(config_basis_append(cfg, BASIS_DEST_LINK, "basis"), 0);

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
    bool ok = file != NULL && !skipped;
    file_destroy(file);
    config_delete(cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    EXPECT_TRUE(send_str(p[1], "file.txt"));
    unsigned long long size = 4;
    long long mtime = 42;
    long long mtime_nsec = 0;
    EXPECT_TRUE(send_n_data(p[1], &size, sizeof(size)));
    EXPECT_TRUE(send_n_data(p[1], &mtime, sizeof(mtime)));
    EXPECT_TRUE(send_n_data(p[1], &mtime_nsec, sizeof(mtime_nsec)));
    /* config_has_basis() makes the request carry the source digest. */
    uint8_t wire_len = checksum_digest_len((ChecksumAlgo)cfg->checksum_algo);
    uint8_t digest[CHECKSUM_MAX_DIGEST_LEN] = {0};
    EXPECT_TRUE(send_n_data(p[1], &wire_len, sizeof(wire_len)));
    EXPECT_TRUE(send_n_data(p[1], digest, wire_len));
    Status s;
    EXPECT_TRUE(receive_status(p[1], &s));
    EXPECT_EQ_INT(s, STATUS_NEXT);

    Data* body = data_create_reserve(4);
    EXPECT_NOT_NULL(body);
    body->data = malloc(4);
    EXPECT_NOT_NULL(body->data);
    memcpy(body->data, "data", 4);
    body->size = 4;
    EXPECT_TRUE(send_data(p[1], body));
    data_destroy(body);

    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(cfg);
    unlink(basis_path);
    rmdir(basis_dir);
    rmdir(root);
    free(root);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* B5: the aggregate entry count across the three manifest sections is capped at
 * MAX_MANIFEST_ENTRIES, and a section that would push the total over the cap is
 * rejected before its entries are read (so a tiny first section followed by a
 * huge claimed second section fails fast). */
static void test_receive_manifest_total_entry_cap() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->receive_root_directory = str_dup("/tmp/dst");
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);

  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_str(p[1], "keep.txt"));
  /* The second section alone is within its per-section cap, but 1 + it exceeds
     the cross-section cap; the receiver must reject at the count. */
  EXPECT_TRUE(send_int(p[1], MAX_MANIFEST_ENTRIES));
  EXPECT_NULL(receive_manifest_entries(p[0]));
  Status status;
  EXPECT_TRUE(receive_status(p[1], &status));
  EXPECT_EQ_INT(status, STATUS_ERROR);

  close(p[0]);
  close(p[1]);
  config_delete(cfg);
}

/* A server-contacting --dry-run must never delete, even on the per-directory
   (--delete-during/--delete-delay) commit path.  The receive path already skips
   plan application under -n, but a plan frame carrying --delete-missing-args
   exact deletions used to be honored by delete_plan_session_commit().  Seed a
   destination mirror, stream a plan naming it, and prove it survives. */
static void test_dry_run_delete_plan_commit_does_not_delete() {
  char* root = make_check_root("drydelplan");
  EXPECT_NOT_NULL(root);
  write_check_file(root, "victim.txt", "must survive");

  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup(root);
  cfg->use_delete = true;
  cfg->delete_during = true;
  cfg->delete_missing_args = true;
  cfg->dry_run = true;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  EXPECT_TRUE(send_status(p[1], STATUS_DELETE_PLAN));
  EXPECT_TRUE(send_int(p[1], 1));  /* first frame carries the config sections */
  EXPECT_TRUE(send_int(p[1], 0));  /* protected prefixes */
  EXPECT_TRUE(send_int(p[1], 0));  /* size-skipped prefixes */
  EXPECT_TRUE(send_int(p[1], 1));  /* missing-args exact deletions */
  EXPECT_TRUE(send_str(p[1], "victim.txt"));
  EXPECT_TRUE(send_str(p[1], ".")); /* receive root plan */
  EXPECT_TRUE(send_int(p[1], 0));   /* kept child directories */
  EXPECT_TRUE(send_int(p[1], 0));   /* kept child files */
  EXPECT_TRUE(send_status(p[1], STATUS_FINISHED));

  ReceiverSink sink = {.send_success = true};
  EXPECT_EQ_INT(receiver_process_pending(cfg, p[0], &sink, NULL, NULL), 0);

  char path[1024];
  snprintf(path, sizeof(path), "%s/victim.txt", root);
  EXPECT_EQ_INT(access(path, F_OK), 0);

  close(p[0]);
  close(p[1]);
  config_delete(cfg);
  remove(path);
  rmdir(root);
  free(root);
}

void test_server() {
  test_special_socket_path_log_escaped();
  if (!is_running_under_valgrind()) {
    test_receive_files_finished();
    test_receive_files_single_file();
    test_receive_files_abort();
    test_receive_manifest_rejects_traversal();
    test_receive_incremental_check_rejects_invalid_nanoseconds();
    test_incremental_check_quick_skip_by_mtime();
    test_incremental_check_size_mismatch_full_transfer();
    test_incremental_check_dry_run_reports_transfer_without_writing();
    test_incremental_check_delta_oversize_reports_failure();
    test_incremental_check_fifo_destination_does_not_hang();
    test_incremental_check_basis_fifo_does_not_hang();
    test_incremental_check_dry_run_basis_does_not_read_content();
    test_receive_manifest_total_entry_cap();
    test_late_manifest_abort_frees_keepset();
    test_late_manifest_eof_frees_keepset();
    test_late_second_manifest_frees_both();
    test_receive_manifest_three_sections();
    test_manifest_delete_missing_args();
    test_receiver_pending_commits_missing_args();
    test_dry_run_delete_plan_commit_does_not_delete();
  }
}
