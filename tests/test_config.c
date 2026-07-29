#include "test_config.h"
#include "config.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "test_utils.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void test_config_lifecycle() {
  Config* cfg = config_create(str_dup("1.0"), str_dup("/src"), str_dup("/dst"), true, true, false,
                              false, false, 1, false, 0);
  EXPECT_NOT_NULL(cfg);
  EXPECT_EQ_STR(cfg->version, "1.0");
  EXPECT_EQ_STR(cfg->send_directory, "/src");
  EXPECT_EQ_STR(cfg->receive_root_directory, "/dst");
  EXPECT_TRUE(cfg->save_to_disk);
  EXPECT_TRUE(cfg->use_multithreading);
  EXPECT_FALSE(cfg->use_chunk_serialization);
  EXPECT_FALSE(cfg->use_compression);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_TCP);
  EXPECT_NULL(cfg->ssh_destination);
  config_delete(cfg);
}

static void test_config_ssh_dest() {
  Config* cfg = config_create(str_dup("1.0"), str_dup("/src"), str_dup("user@host:/dst"), true,
                              false, false, false, false, 1, false, 0);
  EXPECT_NOT_NULL(cfg);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_TCP);
  EXPECT_NULL(cfg->ssh_destination);
  EXPECT_EQ_STR(cfg->receive_root_directory, "user@host:/dst");

  config_parse_ssh_dest(cfg);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_SSH);
  EXPECT_EQ_STR(cfg->ssh_destination, "user@host:/dst");
  EXPECT_EQ_STR(cfg->receive_root_directory, "/dst");
  config_delete(cfg);
}

static void test_config_ssh_dest_local_path() {
  Config* cfg = config_create(str_dup("1.0"), str_dup("/src"), str_dup("/local/path"), true, false,
                              false, false, false, 1, false, 0);
  config_parse_ssh_dest(cfg);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_TCP);
  EXPECT_NULL(cfg->ssh_destination);
  EXPECT_EQ_STR(cfg->receive_root_directory, "/local/path");
  config_delete(cfg);
}

static void test_config_ssh_dest_no_user() {
  Config* cfg = config_create(str_dup("1.0"), str_dup("/src"), str_dup("host:/remote"), true, false,
                              false, false, false, 1, false, 0);
  config_parse_ssh_dest(cfg);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_SSH);
  EXPECT_EQ_STR(cfg->ssh_destination, "host:/remote");
  EXPECT_EQ_STR(cfg->receive_root_directory, "/remote");
  config_delete(cfg);
}

static void test_pipeline_sender_lifecycle() {
  Config* cfg = config_create(str_dup("2.0"), str_dup("/src2"), str_dup("/dst2"), false, false,
                              true, true, false, 1, false, 0);
  Queue* q1 = queue_create(5, NULL);
  Queue* q2 = queue_create(15, NULL);

  PipelineContextSender* pcs = pipeline_context_sender_create(cfg, q1, q2);
  EXPECT_NOT_NULL(pcs);
  EXPECT_EQ_STR(pcs->config->version, "2.0");
  EXPECT_EQ_INT(pcs->queue_scanner->capacity, 5);
  EXPECT_EQ_INT(pcs->queue_loader->capacity, 15);
  EXPECT_FALSE(pcs->scanner_done);
  EXPECT_FALSE(pcs->loader_done);

  pipeline_context_sender_destroy(pcs);
}

static void test_pipeline_receiver_lifecycle() {
  Config* cfg = config_create(str_dup("3.0"), str_dup("/src3"), str_dup("/dst3"), true, true, true,
                              true, false, 1, false, 0);
  Queue* q = queue_create(20, NULL);

  PipelineContextReceiver* pcr = pipeline_context_receiver_create(cfg, q, 42);
  EXPECT_NOT_NULL(pcr);
  EXPECT_EQ_STR(pcr->config->version, "3.0");
  EXPECT_EQ_INT(pcr->queue->capacity, 20);
  EXPECT_EQ_INT(pcr->file_descriptor, 42);
  EXPECT_FALSE(pcr->receiver_done);

  pipeline_context_receiver_destroy(pcr);
}

/* Test config_send/config_receive round-trip over a socketpair */
static void test_config_send_receive() {
  Config* send_cfg = config_create(str_dup(PROTOCOL_VERSION), str_dup("/send/src"),
                                   str_dup("/send/dst"), true, true, true, true, true, 5, false,
                                   1024);
  EXPECT_NOT_NULL(send_cfg);

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv_cfg = config_receive(p[0]);
    close(p[0]);

    bool ok = true;
    if (!recv_cfg) ok = false;
    else {
      if (strcmp(recv_cfg->version, PROTOCOL_VERSION) != 0) ok = false;
      if (strcmp(recv_cfg->send_directory, "/send/src") != 0) ok = false;
      if (strcmp(recv_cfg->receive_root_directory, "/send/dst") != 0) ok = false;
      if (!recv_cfg->save_to_disk) ok = false;
      if (!recv_cfg->use_multithreading) ok = false;
      if (!recv_cfg->use_chunk_serialization) ok = false;
      if (recv_cfg->compression_level != 5) ok = false;
      if (recv_cfg->chunk_size != 1024) ok = false;
    }
    config_delete(recv_cfg);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);
    config_delete(send_cfg);

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Test config_send/receive version mismatch rejection */
static void test_config_send_receive_version_mismatch() {
  Config* cfg = config_create(str_dup("0.0"), str_dup("/src"), str_dup("/dst"), false, false, false,
                              false, false, 0, false, 0);

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv = config_receive(p[0]);
    close(p[0]);
    _exit(recv == NULL ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], cfg);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);
    config_delete(cfg);

    /* config_send should return false because config_receive sends STATUS_ERROR */
    EXPECT_FALSE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Test is_remote_dest edge cases */
static void test_is_remote_dest() {
  EXPECT_TRUE(is_remote_dest("user@host:/path"));
  EXPECT_TRUE(is_remote_dest("host:/path"));
  EXPECT_TRUE(is_remote_dest("user@192.168.1.1:/remote/path"));
  EXPECT_FALSE(is_remote_dest(NULL));
  EXPECT_FALSE(is_remote_dest(""));
  EXPECT_FALSE(is_remote_dest(":"));
  EXPECT_FALSE(is_remote_dest("/local/path"));
  EXPECT_FALSE(is_remote_dest("relative/path"));
  EXPECT_TRUE(is_remote_dest("C:/windows/path"));
  EXPECT_FALSE(is_remote_dest("noslash"));
  EXPECT_FALSE(is_remote_dest("/"));
  EXPECT_TRUE(is_remote_dest("host:"));
  EXPECT_TRUE(is_remote_dest("user@host:"));
}

void test_config() {
  test_config_lifecycle();
  test_config_ssh_dest();
  test_config_ssh_dest_local_path();
  test_config_ssh_dest_no_user();
  test_pipeline_sender_lifecycle();
  test_pipeline_receiver_lifecycle();
  if (!is_running_under_valgrind()) {
    test_config_send_receive();
    test_config_send_receive_version_mismatch();
  }
  test_is_remote_dest();
}
