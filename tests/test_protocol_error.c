/* Unit tests for the protocol 2.21.0 STATUS_ERROR_DETAIL frame API:
 * send_error_detail() / receive_status() mapping / protocol_last_error(). */
#include "protocol.h"
#include "test_utils.h"
#include <string.h>
#include <threads.h>
#include <unistd.h>

/* A detail frame maps back to STATUS_ERROR for the caller and its body is
 * captured verbatim. */
static void test_error_detail_maps_and_captures(void) {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  protocol_clear_last_error();

  EXPECT_TRUE(send_error_detail(0, "module is read-only"));
  Status received = STATUS_OK;
  EXPECT_TRUE(receive_status(0, &received));
  EXPECT_EQ_INT((int)received, (int)STATUS_ERROR);
  EXPECT_EQ_STR(protocol_last_error(), "module is read-only");

  close(p[0]);
  close(p[1]);
}

/* An over-long message is sliced to the hard cap before it goes on the wire, so
 * the receiver never retains more than MAX_ERROR_DETAIL_BYTES. */
static void test_error_detail_over_long_is_bounded(void) {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  char big[MAX_ERROR_DETAIL_BYTES + 512];
  memset(big, 'x', sizeof(big) - 1);
  big[sizeof(big) - 1] = '\0';
  EXPECT_TRUE(send_error_detail(0, big));
  Status received = STATUS_OK;
  EXPECT_TRUE(receive_status(0, &received));
  EXPECT_EQ_INT((int)received, (int)STATUS_ERROR);
  EXPECT_EQ_INT((int)strlen(protocol_last_error()), (int)MAX_ERROR_DETAIL_BYTES);

  close(p[0]);
  close(p[1]);
}

/* A bare STATUS_ERROR (no detail body) must not leave a stale reason visible. */
static void test_bare_error_clears_last_error(void) {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  EXPECT_TRUE(send_error_detail(0, "stale reason"));
  Status received = STATUS_OK;
  EXPECT_TRUE(receive_status(0, &received));
  EXPECT_EQ_STR(protocol_last_error(), "stale reason");

  EXPECT_TRUE(send_status(0, STATUS_ERROR));
  EXPECT_TRUE(receive_status(0, &received));
  EXPECT_EQ_INT((int)received, (int)STATUS_ERROR);
  EXPECT_EQ_STR(protocol_last_error(), "");

  close(p[0]);
  close(p[1]);
}

/* A tiny --max-alloc must not prevent the bounded detail body from being
 * drained: the status still maps to STATUS_ERROR with the full reason, and the
 * following frame is read intact (no desync). */
static void test_error_detail_drains_despite_tiny_max_alloc(void) {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession receiver;
  protocol_session_init(&receiver, p[0], p[1]);
  protocol_session_set_max_alloc(&receiver, 4);
  ProtocolSession sender;
  protocol_session_init(&sender, -1, p[1]);

  EXPECT_TRUE(protocol_send_status(&sender, STATUS_ERROR_DETAIL));
  EXPECT_TRUE(protocol_send_str(&sender, "reason"));
  Status status = STATUS_OK;
  EXPECT_TRUE(protocol_receive_status(&receiver, &status));
  EXPECT_EQ_INT((int)status, (int)STATUS_ERROR);
  EXPECT_EQ_STR(protocol_last_error(), "reason");

  EXPECT_TRUE(protocol_send_status(&sender, STATUS_NEXT));
  EXPECT_TRUE(protocol_receive_status(&receiver, &status));
  EXPECT_EQ_INT((int)status, (int)STATUS_NEXT);

  close(p[0]);
  close(p[1]);
}

typedef struct {
  ProtocolSession* receiver;
} DetailWorkerArg;

static int detail_worker(void* arg) {
  DetailWorkerArg* worker = arg;
  Status status = STATUS_OK;
  if (!protocol_receive_status(worker->receiver, &status) || status != STATUS_ERROR)
    return thrd_error;
  return strcmp(protocol_last_error(), "worker reason") == 0 ? thrd_success : thrd_error;
}

/* Each thread keeps its own last-error buffer: a detail captured on a worker
 * must not overwrite the one captured on the main thread. */
static void test_last_error_is_thread_local(void) {
  int main_pipe[2];
  int worker_pipe[2];
  EXPECT_EQ_INT(pipe(main_pipe), 0);
  EXPECT_EQ_INT(pipe(worker_pipe), 0);

  io_set_fds(main_pipe[0], main_pipe[1]);
  io_set_bwlimit(0);
  EXPECT_TRUE(send_error_detail(0, "main reason"));
  Status received = STATUS_OK;
  EXPECT_TRUE(receive_status(0, &received));
  EXPECT_EQ_STR(protocol_last_error(), "main reason");

  ProtocolSession receiver;
  protocol_session_init(&receiver, worker_pipe[0], -1);
  ProtocolSession sender;
  protocol_session_init(&sender, -1, worker_pipe[1]);
  EXPECT_TRUE(protocol_send_status(&sender, STATUS_ERROR_DETAIL));
  EXPECT_TRUE(protocol_send_str(&sender, "worker reason"));

  DetailWorkerArg arg = {.receiver = &receiver};
  thrd_t thread;
  EXPECT_EQ_INT(thrd_create(&thread, detail_worker, &arg), thrd_success);
  int result = 0;
  EXPECT_EQ_INT(thrd_join(thread, &result), thrd_success);
  EXPECT_EQ_INT(result, thrd_success);

  /* The worker's capture must not have disturbed this thread's buffer. */
  EXPECT_EQ_STR(protocol_last_error(), "main reason");

  close(main_pipe[0]);
  close(main_pipe[1]);
  close(worker_pipe[0]);
  close(worker_pipe[1]);
}

void test_protocol_error(void) {
  test_error_detail_maps_and_captures();
  test_error_detail_over_long_is_bounded();
  test_bare_error_clears_last_error();
  test_error_detail_drains_despite_tiny_max_alloc();
  test_last_error_is_thread_local();
}
