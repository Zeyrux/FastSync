#include "test_config.h"
#include "config.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "test_utils.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static Config* make_config(const char* version, const char* src, const char* dst, bool save,
                           bool mt, bool cs, bool comp, bool meta, int clevel, bool sf,
                           unsigned long long csize) {
  Config* cfg = config_create();
  if (!cfg)
    return NULL;
  cfg->version = str_dup(version);
  cfg->send_directory = str_dup(src);
  cfg->receive_root_directory = str_dup(dst);
  cfg->save_to_disk = save;
  cfg->use_multithreading = mt;
  cfg->use_chunk_serialization = cs;
  cfg->use_compression = comp;
  cfg->use_metadata = meta;
  cfg->compression_level = clevel;
  cfg->use_sendfile = sf;
  if (csize > 0)
    cfg->chunk_size = csize;
  return cfg;
}

static void test_config_lifecycle() {
  Config* cfg = make_config("1.0", "/src", "/dst", true, true, false, false, false, 1, false, 0);
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
  Config* cfg = make_config("1.0", "/src", "user@host:/dst", true, false, false, false, false, 1,
                            false, 0);
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
  Config* cfg = make_config("1.0", "/src", "/local/path", true, false, false, false, false, 1,
                            false, 0);
  config_parse_ssh_dest(cfg);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_TCP);
  EXPECT_NULL(cfg->ssh_destination);
  EXPECT_EQ_STR(cfg->receive_root_directory, "/local/path");
  config_delete(cfg);
}

static void test_config_ssh_dest_no_user() {
  Config* cfg = make_config("1.0", "/src", "host:/remote", true, false, false, false, false, 1,
                            false, 0);
  config_parse_ssh_dest(cfg);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_SSH);
  EXPECT_EQ_STR(cfg->ssh_destination, "host:/remote");
  EXPECT_EQ_STR(cfg->receive_root_directory, "/remote");
  config_delete(cfg);
}

static void test_pipeline_sender_lifecycle() {
  Config* cfg = make_config("2.0", "/src2", "/dst2", false, false, true, true, false, 1, false, 0);
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
  Config* cfg = make_config("3.0", "/src3", "/dst3", true, true, true, true, false, 1, false, 0);
  Queue* q = queue_create(20, NULL);

  PipelineContextReceiver* pcr = pipeline_context_receiver_create(cfg, q, 42);
  EXPECT_NOT_NULL(pcr);
  EXPECT_EQ_STR(pcr->config->version, "3.0");
  EXPECT_EQ_INT(pcr->queue->capacity, 20);
  EXPECT_EQ_INT(pcr->file_descriptor, 42);
  EXPECT_FALSE(pcr->receiver_done);

  pipeline_context_receiver_destroy(pcr);
}

static void test_config_send_receive() {
  /* Create a config to send */
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/send/src");
  send_cfg->receive_root_directory = str_dup("/send/dst");
  send_cfg->save_to_disk = true;
  send_cfg->use_multithreading = true;
  send_cfg->use_chunk_serialization = true;
  send_cfg->use_compression = true;
  send_cfg->use_metadata = true;
  send_cfg->compression_level = 5;
  send_cfg->chunk_size = 1024;

  /* Use pipe for communication */
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    /* Child: receive the config */
    close(p[1]);
    Config* recv_cfg = config_receive(p[0]);
    close(p[0]);

    bool ok = true;
    if (!recv_cfg)
      ok = false;
    else {
      if (strcmp(recv_cfg->version, PROTOCOL_VERSION) != 0)
        ok = false;
      if (strcmp(recv_cfg->send_directory, "/send/src") != 0)
        ok = false;
      if (strcmp(recv_cfg->receive_root_directory, "/send/dst") != 0)
        ok = false;
      if (!recv_cfg->save_to_disk)
        ok = false;
      if (!recv_cfg->use_multithreading)
        ok = false;
      if (!recv_cfg->use_chunk_serialization)
        ok = false;
      if (recv_cfg->compression_level != 5)
        ok = false;
      if (recv_cfg->chunk_size != 1024)
        ok = false;
    }
    config_delete(recv_cfg);
    _exit(ok ? 0 : 1);
  } else {
    /* Parent: send the config */
    close(p[0]);
    bool sent = config_send(p[1], send_cfg);
    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    config_delete(send_cfg);

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_config_send_receive_version_mismatch() {
  /* Create a config with a different protocol version */
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup("0.0");
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");

  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    /* Should fail because version "0.0" != PROTOCOL_VERSION */
    Config* recv = config_receive(p[0]);
    close(p[0]);
    /* recv should be NULL on version mismatch */
    _exit(recv == NULL ? 0 : 1);
  } else {
    close(p[0]);
    bool sent = config_send(p[1], cfg);
    close(p[1]);

    /* send should succeed (sends the config, receives ERROR on version mismatch) */
    int status;
    waitpid(pid, &status, 0);

    config_delete(cfg);

    /* config_send returns false because it receives STATUS_ERROR back */
    EXPECT_FALSE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_is_remote_dest() {
  /* Valid SSH-style destinations */
  EXPECT_TRUE(is_remote_dest("user@host:/path"));
  EXPECT_TRUE(is_remote_dest("host:/path"));
  EXPECT_TRUE(is_remote_dest("user@192.168.1.1:/remote/path"));

  /* Invalid destinations */
  EXPECT_FALSE(is_remote_dest(NULL));
  EXPECT_FALSE(is_remote_dest(""));
  EXPECT_FALSE(is_remote_dest(":"));
  EXPECT_FALSE(is_remote_dest("/local/path"));
  EXPECT_FALSE(is_remote_dest("relative/path"));
  EXPECT_FALSE(is_remote_dest("C:/windows/path"));

  /* Edge cases */
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
