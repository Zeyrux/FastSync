#include "test_multiprocessing.h"
#include "multiprocessing.h"
#include "config.h"
#include "protocol.h"
#include "queue.h"
#include "utils.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* Test pipeline_context_sender_create/destroy with valid arguments */
static void test_sender_create_destroy() {
  Config* cfg = config_create(str_dup("1.0"), str_dup("/src"), str_dup("/dst"), false, false, false,
                              false, false, 0, false, 0);
  EXPECT_NOT_NULL(cfg);

  Queue* q_scanner = queue_create(5, NULL);
  EXPECT_NOT_NULL(q_scanner);

  Queue* q_loader = queue_create(10, NULL);
  EXPECT_NOT_NULL(q_loader);

  PipelineContextSender* ctx = pipeline_context_sender_create(cfg, q_scanner, q_loader);
  EXPECT_NOT_NULL(ctx);
  EXPECT_EQ_STR(ctx->config->version, "1.0");
  EXPECT_EQ_INT(ctx->queue_scanner->capacity, 5);
  EXPECT_EQ_INT(ctx->queue_loader->capacity, 10);
  EXPECT_FALSE(ctx->scanner_done);
  EXPECT_FALSE(ctx->loader_done);
  EXPECT_NULL(ctx->manifest);

  pipeline_context_sender_destroy(ctx);
}

/* Test pipeline_context_receiver_create/destroy with valid arguments */
static void test_receiver_create_destroy() {
  Config* cfg = config_create(str_dup("2.0"), str_dup("/src"), str_dup("/dst"), true, true, false,
                              false, false, 0, false, 0);
  EXPECT_NOT_NULL(cfg);

  Queue* q = queue_create(20, NULL);
  EXPECT_NOT_NULL(q);

  PipelineContextReceiver* ctx = pipeline_context_receiver_create(cfg, q, 42);
  EXPECT_NOT_NULL(ctx);
  EXPECT_EQ_STR(ctx->config->version, "2.0");
  EXPECT_EQ_INT(ctx->queue->capacity, 20);
  EXPECT_EQ_INT(ctx->file_descriptor, 42);
  EXPECT_FALSE(ctx->receiver_done);

  pipeline_context_receiver_destroy(ctx);
}

/* Test that create handles various queue capacities */
static void test_sender_queue_capacities() {
  Config* cfg = config_create(str_dup("3.0"), str_dup("/src"), str_dup("/dst"), false, false, false,
                              false, false, 0, false, 0);
  EXPECT_NOT_NULL(cfg);

  /* Single-element queues */
  Queue* q1 = queue_create(1, NULL);
  Queue* q2 = queue_create(1, NULL);
  PipelineContextSender* ctx = pipeline_context_sender_create(cfg, q1, q2);
  EXPECT_NOT_NULL(ctx);
  EXPECT_EQ_INT(ctx->queue_scanner->capacity, 1);
  EXPECT_EQ_INT(ctx->queue_loader->capacity, 1);
  pipeline_context_sender_destroy(ctx);
}

/* Test that create handles zero-capacity queues */
static void test_sender_zero_capacity() {
  Config* cfg = config_create(str_dup("4.0"), str_dup("/src"), str_dup("/dst"), false, false, false,
                              false, false, 0, false, 0);
  EXPECT_NOT_NULL(cfg);

  Queue* q1 = queue_create(0, NULL);
  Queue* q2 = queue_create(0, NULL);
  PipelineContextSender* ctx = pipeline_context_sender_create(cfg, q1, q2);
  EXPECT_NOT_NULL(ctx);
  EXPECT_EQ_INT(ctx->queue_scanner->capacity, 0);
  EXPECT_EQ_INT(ctx->queue_loader->capacity, 0);
  pipeline_context_sender_destroy(ctx);
}

/* Test receiver with zero file_descriptor */
static void test_receiver_fd_zero() {
  Config* cfg = config_create(str_dup("5.0"), str_dup("/src"), str_dup("/dst"), false, false, false,
                              false, false, 0, false, 0);
  Queue* q = queue_create(5, NULL);
  PipelineContextReceiver* ctx = pipeline_context_receiver_create(cfg, q, 0);
  EXPECT_NOT_NULL(ctx);
  EXPECT_EQ_INT(ctx->file_descriptor, 0);
  EXPECT_FALSE(ctx->receiver_done);
  pipeline_context_receiver_destroy(ctx);
}

/* Test that receive_thread completes cleanly when sent FINISHED immediately */
static void test_receive_thread_finished() {
  Config* cfg = config_create(str_dup(PROTOCOL_VERSION), str_dup("/src"), str_dup("/tmp/dst"),
                              true, false, false, false, false, 0, false, 0);

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);

    Queue* q = queue_create(5, file_destroy);
    EXPECT_NOT_NULL(q);
    PipelineContextReceiver* ctx = pipeline_context_receiver_create(cfg, q, p[0]);
    EXPECT_NOT_NULL(ctx);

    int ret = receive_thread(ctx);

    pipeline_context_receiver_destroy(ctx);
    close(p[0]);
    _exit(ret == thrd_success ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);

    send_status(p[1], STATUS_FINISHED);

    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(cfg);

    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Test that write_thread completes when queue signals done */
static void test_write_thread_done() {
  Config* cfg = config_create(str_dup(PROTOCOL_VERSION), str_dup("/src"), str_dup("/tmp/dst"),
                              false, false, false, false, false, 0, false, 0);

  Queue* q = queue_create(5, file_destroy);
  EXPECT_NOT_NULL(q);

  PipelineContextReceiver* ctx = pipeline_context_receiver_create(cfg, q, 0);
  EXPECT_NOT_NULL(ctx);

  /* Mark as done so write_thread exits immediately */
  ctx->receiver_done = true;

  thrd_t writer;
  int ret = thrd_create(&writer, write_thread, ctx);
  EXPECT_EQ_INT(ret, thrd_success);

  int result;
  thrd_join(writer, &result);
  EXPECT_EQ_INT(result, thrd_success);

  /* Clean up manually (pipeline_context_receiver_destroy would double-free) */
  mtx_destroy(&ctx->mutex);
  cnd_destroy(&ctx->condition_not_full);
  cnd_destroy(&ctx->condition_not_empty);
  free(ctx);
  queue_destroy(q);
  config_delete(cfg);
}

void test_multiprocessing() {
  test_sender_create_destroy();
  test_receiver_create_destroy();
  test_sender_queue_capacities();
  test_sender_zero_capacity();
  test_receiver_fd_zero();
  if (!is_running_under_valgrind()) {
    test_receive_thread_finished();
  }
  test_write_thread_done();
}
