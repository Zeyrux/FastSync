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
#include <sys/wait.h>
#include <unistd.h>

/* Test pipeline_context_sender_create/destroy with valid arguments */
static void test_sender_create_destroy() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup("1.0");
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");

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
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup("2.0");
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  cfg->save_to_disk = true;
  cfg->use_multithreading = true;

  Queue* q = queue_create(20, NULL);
  EXPECT_NOT_NULL(q);

  PipelineContextReceiver* ctx = pipeline_context_receiver_create(cfg, q, 42, NULL);
  EXPECT_NOT_NULL(ctx);
  EXPECT_EQ_STR(ctx->config->version, "2.0");
  EXPECT_EQ_INT(ctx->queue->capacity, 20);
  EXPECT_EQ_INT(ctx->file_descriptor, 42);
  EXPECT_FALSE(ctx->receiver_done);

  pipeline_context_receiver_destroy(ctx);
}

/* Test that create handles various queue capacities */
static void test_sender_queue_capacities() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup("3.0");
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");

  /* Single-element queues */
  Queue* q1 = queue_create(1, NULL);
  Queue* q2 = queue_create(1, NULL);
  PipelineContextSender* ctx = pipeline_context_sender_create(cfg, q1, q2);
  EXPECT_NOT_NULL(ctx);
  EXPECT_EQ_INT(ctx->queue_scanner->capacity, 1);
  EXPECT_EQ_INT(ctx->queue_loader->capacity, 1);
  pipeline_context_sender_destroy(ctx);
}

/* Invalid queue capacities must not create unusable pipeline queues. */
static void test_sender_zero_capacity() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup("4.0");
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");

  // cppcheck-suppress constVariablePointer
  Queue* const q1 = queue_create(0, NULL);
  // cppcheck-suppress constVariablePointer
  Queue* const q2 = queue_create(0, NULL);
  EXPECT_NULL(q1);
  EXPECT_NULL(q2);
  config_delete(cfg);
}

/* Test receiver with zero file_descriptor */
static void test_receiver_fd_zero() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup("5.0");
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  Queue* q = queue_create(5, NULL);
  PipelineContextReceiver* ctx = pipeline_context_receiver_create(cfg, q, 0, NULL);
  EXPECT_NOT_NULL(ctx);
  EXPECT_EQ_INT(ctx->file_descriptor, 0);
  EXPECT_FALSE(ctx->receiver_done);
  pipeline_context_receiver_destroy(ctx);
}

/* Test that receive_thread completes cleanly when sent FINISHED immediately */
static void test_receive_thread_finished() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/tmp/dst");
  cfg->save_to_disk = true;

  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    /* Child: run receive_thread */
    close(p[1]);

    Queue* q = queue_create(5, file_destroy);
    EXPECT_NOT_NULL(q);
    PipelineContextReceiver* ctx = pipeline_context_receiver_create(cfg, q, p[0], NULL);
    EXPECT_NOT_NULL(ctx);

    int ret = receive_thread(ctx);

    pipeline_context_receiver_destroy(ctx);
    close(p[0]);
    _exit(ret == thrd_success ? 0 : 1);
  } else {
    /* Parent: send STATUS_FINISHED then STATUS_MANIFEST */
    close(p[0]);

    /* Send a STATUS_FINISHED to make receive_thread exit cleanly.
     * receive_thread reads status, sees FINISHED, then exits loop.
     * After the loop it expects STATUS_MANIFEST check, but we sent
     * FINISHED so it will just return thrd_success. */
    send_status(p[1], STATUS_FINISHED);

    close(p[1]);

    int status;
    waitpid(pid, &status, 0);

    /* Parent must free its own copies of config (child has separate copies) */
    config_delete(cfg);

    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* A malformed terminal status must wake a writer waiting on an empty queue. */
static void test_receive_thread_failure_wakes_writer() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/tmp/dst");

  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  Queue* q = queue_create(1, file_destroy);
  EXPECT_NOT_NULL(q);
  PipelineContextReceiver* ctx = pipeline_context_receiver_create(cfg, q, p[0], NULL);
  EXPECT_NOT_NULL(ctx);

  thrd_t receiver;
  thrd_t writer;
  EXPECT_EQ_INT(thrd_create(&writer, write_thread, ctx), thrd_success);
  EXPECT_EQ_INT(thrd_create(&receiver, receive_thread, ctx), thrd_success);
  EXPECT_TRUE(send_status(p[1], STATUS_OK));
  close(p[1]);

  int receiver_result;
  int writer_result;
  EXPECT_EQ_INT(thrd_join(receiver, &receiver_result), thrd_success);
  EXPECT_EQ_INT(thrd_join(writer, &writer_result), thrd_success);
  EXPECT_EQ_INT(receiver_result, thrd_error);
  EXPECT_EQ_INT(writer_result, thrd_success);
  EXPECT_TRUE(ctx->receiver_done);

  close(p[0]);
  pipeline_context_receiver_destroy(ctx);
}

/* Test that write_thread completes cleanly when queue signals done */
static void test_write_thread_done() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/tmp/dst");
  cfg->save_to_disk = false;

  Queue* q = queue_create(5, file_destroy);
  EXPECT_NOT_NULL(q);

  PipelineContextReceiver* ctx = pipeline_context_receiver_create(cfg, q, 0, NULL);
  EXPECT_NOT_NULL(ctx);

  /* Mark receiver as done BEFORE starting the thread so it exits immediately */
  ctx->receiver_done = true;

  thrd_t writer;
  int ret = thrd_create(&writer, write_thread, ctx);
  EXPECT_EQ_INT(ret, thrd_success);

  int result;
  thrd_join(writer, &result);
  EXPECT_EQ_INT(result, thrd_success);

  /* Don't call pipeline_context_receiver_destroy because it frees ctx
   * and write_thread doesn't destroy ctx. Actually looking at the code:
   * write_thread reads context fields but doesn't free anything.
   * The caller is responsible for cleanup. So we need to clean up.
   * But wait - write_thread takes ownership? Let me check...
   * No, write_thread just processes and returns. The caller frees.
   *
   * However, pipeline_context_receiver_destroy will call config_delete
   * and queue_destroy which would double-free since we created them
   * in this test. Let me just free the context directly. */
  mtx_destroy(&ctx->mutex);
  cnd_destroy(&ctx->condition_not_full);
  cnd_destroy(&ctx->condition_not_empty);
  free(ctx);

  /* q and cfg still need cleanup */
  queue_destroy(q);
  config_delete(cfg);
}

typedef struct {
  PipelineContextReceiver* context;
  File* file;
  atomic_bool* done;
  atomic_bool* result;
} ByteBudgetEnqueueArg;

static int byte_budget_enqueue_worker(void* arg) {
  ByteBudgetEnqueueArg* worker = arg;
  bool ok = pipeline_context_receiver_enqueue_file(worker->context, worker->file);
  atomic_store(worker->result, ok);
  atomic_store(worker->done, true);
  return thrd_success;
}

/* A receiver must not buffer more decompressed/copied payload bytes ahead of
   the (slow) disk writer than the configured byte budget: an enqueue that
   would exceed the budget blocks until the writer releases bytes. */
static void test_receiver_enqueue_byte_budget() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  cfg->save_to_disk = false;

  Queue* q = queue_create(16, file_destroy);
  EXPECT_NOT_NULL(q);
  PipelineContextReceiver* ctx = pipeline_context_receiver_create(cfg, q, -1, NULL);
  EXPECT_NOT_NULL(ctx);
  pipeline_context_receiver_set_queue_byte_limit(ctx, 3000);
  ctx->receiver_done = false;

  File* first = file_create("budget_file_1");
  EXPECT_NOT_NULL(first);
  first->data->size = 2000;
  EXPECT_TRUE(pipeline_context_receiver_enqueue_file(ctx, first));
  EXPECT_EQ_INT((int)ctx->queued_bytes, 2000);

  /* Second 2000-byte payload would push the pipeline to 4000 > 3000 budget,
     so the enqueue must block until the first payload is released. */
  File* second = file_create("budget_file_2");
  EXPECT_NOT_NULL(second);
  second->data->size = 2000;
  atomic_bool done;
  atomic_bool result;
  atomic_init(&done, false);
  atomic_init(&result, false);
  ByteBudgetEnqueueArg arg = {ctx, second, &done, &result};
  thrd_t enqueuer;
  EXPECT_EQ_INT(thrd_create(&enqueuer, byte_budget_enqueue_worker, &arg), thrd_success);

  /* Give a broken (unbounded) implementation every chance to enqueue. */
  struct timespec wait = {0, 200 * 1000000L};
  thrd_sleep(&wait, NULL);
  EXPECT_FALSE(atomic_load(&done));
  EXPECT_EQ_INT((int)ctx->queued_bytes, 2000); /* budget still honored */

  /* Simulate the disk writer: dequeue + destroy + release the first file.
     Releasing bytes unblocks the waiting enqueuer, which then admits the
     second payload, so only the post-join state (below) is deterministic. */
  File* drained = queue_dequeue_multithreaded(q, &ctx->mutex, &ctx->condition_not_empty,
                                              &ctx->condition_not_full, &ctx->receiver_done);
  EXPECT_NOT_NULL(drained);
  file_destroy(drained);
  pipeline_context_receiver_note_bytes_released(ctx, 2000);

  EXPECT_EQ_INT(thrd_join(enqueuer, NULL), thrd_success);
  EXPECT_TRUE(atomic_load(&done));
  EXPECT_TRUE(atomic_load(&result));
  EXPECT_EQ_INT((int)ctx->queued_bytes, 2000); /* second payload now in flight */

  /* Tear down: the second file is still queued and is freed by queue_destroy. */
  mtx_destroy(&ctx->mutex);
  cnd_destroy(&ctx->condition_not_full);
  cnd_destroy(&ctx->condition_not_empty);
  free(ctx);
  queue_destroy(q);
  config_delete(cfg);
}

/* Build a one-file chunk that appears to hold `bytes` of loaded payload by
   handing it a real buffer of that size (the byte accounting counts only
   in-memory `data->data`, mirroring sendfile's streamed chunks). */
static Chunk* make_loaded_chunk(const char* name, size_t bytes) {
  File* file = file_create(name);
  if (!file)
    return NULL;
  void* buffer = malloc(bytes > 0 ? bytes : 1);
  if (!buffer) {
    file_destroy(file);
    return NULL;
  }
  file->data->data = buffer;
  file->data->size = bytes;
  File* items[1] = {file};
  Chunk* chunk = chunk_create(items, 1);
  if (!chunk)
    file_destroy(file);
  return chunk;
}

/* Only loaded (in-memory) payload is charged: a chunk whose files have no
   buffer (e.g. sendfile streams the bytes from disk) accounts for zero. */
static void test_sender_chunk_bytes_accounting() {
  EXPECT_EQ_INT((int)pipeline_context_sender_chunk_bytes(NULL), 0);

  File* streamed = file_create("sender_account_streamed");
  EXPECT_NOT_NULL(streamed);
  streamed->data->size = 4096; /* declared size, but no in-memory buffer */
  File* streamed_items[1] = {streamed};
  Chunk* streamed_chunk = chunk_create(streamed_items, 1);
  EXPECT_NOT_NULL(streamed_chunk);
  EXPECT_EQ_INT((int)pipeline_context_sender_chunk_bytes(streamed_chunk), 0);
  chunk_destroy(streamed_chunk);

  Chunk* loaded = make_loaded_chunk("sender_account_loaded", 2000);
  EXPECT_NOT_NULL(loaded);
  EXPECT_EQ_INT((int)pipeline_context_sender_chunk_bytes(loaded), 2000);
  chunk_destroy(loaded);
}

typedef struct {
  PipelineContextSender* context;
  Chunk* chunk;
  atomic_bool* done;
  atomic_bool* result;
} SenderByteBudgetArg;

static int sender_byte_budget_worker(void* arg) {
  SenderByteBudgetArg* worker = arg;
  bool ok = pipeline_context_sender_enqueue_chunk(worker->context, worker->chunk);
  atomic_store(worker->result, ok);
  atomic_store(worker->done, true);
  return thrd_success;
}

/* The sender's loader stage must not buffer more loaded payload bytes ahead of
   the network writer than the configured byte budget: an enqueue that would
   exceed the budget blocks until the sender releases bytes. */
static void test_sender_enqueue_byte_budget() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup(PROTOCOL_VERSION);
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");

  Queue* q_scanner = queue_create(16, chunk_destroy);
  Queue* q_loader = queue_create(16, chunk_destroy);
  EXPECT_NOT_NULL(q_scanner);
  EXPECT_NOT_NULL(q_loader);
  PipelineContextSender* ctx = pipeline_context_sender_create(cfg, q_scanner, q_loader);
  EXPECT_NOT_NULL(ctx);
  pipeline_context_sender_set_queue_byte_limit(ctx, 3000);

  Chunk* first = make_loaded_chunk("sender_budget_1", 2000);
  EXPECT_NOT_NULL(first);
  EXPECT_TRUE(pipeline_context_sender_enqueue_chunk(ctx, first));
  EXPECT_EQ_INT((int)ctx->queued_bytes, 2000);

  /* A second 2000-byte chunk would push the pipeline to 4000 > 3000 budget, so
     its enqueue must block until the first chunk's bytes are released. */
  Chunk* second = make_loaded_chunk("sender_budget_2", 2000);
  EXPECT_NOT_NULL(second);
  atomic_bool done;
  atomic_bool result;
  atomic_init(&done, false);
  atomic_init(&result, false);
  SenderByteBudgetArg arg = {ctx, second, &done, &result};
  thrd_t enqueuer;
  EXPECT_EQ_INT(thrd_create(&enqueuer, sender_byte_budget_worker, &arg), thrd_success);

  /* Give a broken (unbounded) implementation every chance to enqueue. */
  struct timespec wait = {0, 200 * 1000000L};
  thrd_sleep(&wait, NULL);
  EXPECT_FALSE(atomic_load(&done));
  EXPECT_EQ_INT((int)ctx->queued_bytes, 2000); /* budget still honored */

  /* Simulate the sender: dequeue + destroy the first chunk, then release its
     bytes.  Only the post-join state (below) is deterministic. */
  Chunk* drained =
      queue_dequeue_multithreaded(q_loader, &ctx->mutex_loader, &ctx->condition_not_empty_loader,
                                  &ctx->condition_not_full_loader, &ctx->loader_done);
  EXPECT_NOT_NULL(drained);
  chunk_destroy(drained);
  pipeline_context_sender_note_bytes_released(ctx, 2000);

  EXPECT_EQ_INT(thrd_join(enqueuer, NULL), thrd_success);
  EXPECT_TRUE(atomic_load(&done));
  EXPECT_TRUE(atomic_load(&result));
  EXPECT_EQ_INT((int)ctx->queued_bytes, 2000); /* second payload now in flight */

  /* pipeline_context_sender_destroy frees the still-queued second chunk and
     owns cfg/q_scanner/q_loader from here on. */
  pipeline_context_sender_destroy(ctx);
}

void test_multiprocessing() {
  test_sender_create_destroy();
  test_receiver_create_destroy();
  test_sender_queue_capacities();
  test_sender_zero_capacity();
  test_receiver_fd_zero();
  if (!is_running_under_valgrind()) {
    test_receive_thread_finished();
    test_receive_thread_failure_wakes_writer();
  }
  test_write_thread_done();
  test_receiver_enqueue_byte_budget();
  test_sender_chunk_bytes_accounting();
  test_sender_enqueue_byte_budget();
}
