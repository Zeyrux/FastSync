/* Unit tests for the protocol 2.21.0 STATUS_ERROR_DETAIL frame API:
 * send_error_detail() / receive_status() mapping / protocol_last_error(). */
#include "protocol.h"
#include "test_utils.h"
#include <string.h>
#include <threads.h>
#include <time.h>
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
  /* The bounded detail reader must never touch the session allocation ceiling. */
  EXPECT_EQ_INT((int)receiver.max_alloc, 4);

  EXPECT_TRUE(protocol_send_status(&sender, STATUS_NEXT));
  EXPECT_TRUE(protocol_receive_status(&receiver, &status));
  EXPECT_EQ_INT((int)status, (int)STATUS_NEXT);

  close(p[0]);
  close(p[1]);
}

/* An over-cap (but not absurd) declared length is drained through a fixed
 * scratch buffer so the stream stays in sync, and yields an empty detail.  The
 * session's tiny --max-alloc must remain untouched. */
static void test_error_detail_over_cap_is_drained(void) {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession receiver;
  protocol_session_init(&receiver, p[0], p[1]);
  protocol_session_set_max_alloc(&receiver, 8);
  ProtocolSession sender;
  protocol_session_init(&sender, -1, p[1]);

  size_t size = MAX_ERROR_DETAIL_BYTES + 128;
  EXPECT_TRUE(protocol_send_status(&sender, STATUS_ERROR_DETAIL));
  EXPECT_TRUE(protocol_send_n_data(&sender, &size, sizeof(size)));
  char chunk[512];
  memset(chunk, 'z', sizeof(chunk));
  size_t written = 0;
  while (written < size) {
    size_t n = size - written < sizeof(chunk) ? size - written : sizeof(chunk);
    EXPECT_TRUE(protocol_send_n_data(&sender, chunk, n));
    written += n;
  }
  EXPECT_TRUE(protocol_send_status(&sender, STATUS_NEXT));

  Status status = STATUS_OK;
  EXPECT_TRUE(protocol_receive_status(&receiver, &status));
  EXPECT_EQ_INT((int)status, (int)STATUS_ERROR);
  EXPECT_EQ_STR(protocol_last_error(), "");
  EXPECT_EQ_INT((int)receiver.max_alloc, 8);

  /* Stream is still framed: the following status is read intact. */
  EXPECT_TRUE(protocol_receive_status(&receiver, &status));
  EXPECT_EQ_INT((int)status, (int)STATUS_NEXT);

  close(p[0]);
  close(p[1]);
}

/* A declared length beyond even the absolute string bound can never be drained
 * sensibly, so it is a fatal framing error and the status read fails. */
static void test_error_detail_absurd_length_is_fatal(void) {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession receiver;
  protocol_session_init(&receiver, p[0], p[1]);
  ProtocolSession sender;
  protocol_session_init(&sender, -1, p[1]);

  size_t size = (size_t)MAX_STRING_SIZE + 1;
  EXPECT_TRUE(protocol_send_status(&sender, STATUS_ERROR_DETAIL));
  EXPECT_TRUE(protocol_send_n_data(&sender, &size, sizeof(size)));

  Status status = STATUS_OK;
  EXPECT_FALSE(protocol_receive_status(&receiver, &status));

  close(p[0]);
  close(p[1]);
}

/* The detail body must share the caller's deadline: with the session window at
 * the 60 s default, a withheld body under a 1 s receive_status_timed deadline
 * must fail in about a second, not fall back to the session timeout. */
static void test_error_detail_body_honors_deadline(void) {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  /* Only the status header, body withheld. */
  EXPECT_TRUE(send_status(0, STATUS_ERROR_DETAIL));

  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  Status status = STATUS_OK;
  EXPECT_FALSE(receive_status_timed(0, &status, 1));
  clock_gettime(CLOCK_MONOTONIC, &end);
  long long elapsed_ms =
      (end.tv_sec - start.tv_sec) * 1000LL + (end.tv_nsec - start.tv_nsec) / 1000000LL;
  EXPECT_TRUE(elapsed_ms < 10000);

  close(p[0]);
  close(p[1]);
}

typedef struct {
  int peer_read_fd;
  int peer_write_fd;
  bool replied;
} DetailKeepalivePeerArg;

static int detail_keepalive_peer(void* arg) {
  DetailKeepalivePeerArg* peer = arg;
  ProtocolSession session;
  protocol_session_init(&session, peer->peer_read_fd, peer->peer_write_fd);
  Status status = STATUS_ERROR;
  if (protocol_receive_status(&session, &status) && status == STATUS_KEEPALIVE) {
    /* The busy receiver answers the real status (with its detail) first, then the
       keepalive reply it owes -- which the client then drains. */
    peer->replied = protocol_send_status(&session, STATUS_ERROR_DETAIL) &&
                    protocol_send_str(&session, "boom") &&
                    protocol_send_status(&session, STATUS_KEEPALIVE);
  }
  return thrd_success;
}

/* Draining the keepalive replies the peer still owes must not erase the terminal
 * detail that arrived just before them. */
static void test_error_detail_survives_keepalive_drain(void) {
  int to_client[2];
  int to_peer[2];
  EXPECT_EQ_INT(pipe(to_client), 0);
  EXPECT_EQ_INT(pipe(to_peer), 0);

  ProtocolSession session;
  protocol_session_init(&session, to_client[0], to_peer[1]);

  DetailKeepalivePeerArg peer = {.peer_read_fd = to_peer[0], .peer_write_fd = to_client[1]};
  thrd_t thread;
  EXPECT_EQ_INT(thrd_create(&thread, detail_keepalive_peer, &peer), thrd_success);

  Status received = STATUS_OK;
  EXPECT_TRUE(protocol_receive_status_keepalive(&session, &received, 10, 1, NULL));
  EXPECT_EQ_INT((int)received, (int)STATUS_ERROR);
  EXPECT_EQ_STR(protocol_last_error(), "boom");

  int result = 0;
  EXPECT_EQ_INT(thrd_join(thread, &result), thrd_success);
  EXPECT_EQ_INT(result, thrd_success);
  EXPECT_TRUE(peer.replied);

  close(to_client[0]);
  close(to_client[1]);
  close(to_peer[0]);
  close(to_peer[1]);
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
  test_error_detail_over_cap_is_drained();
  test_error_detail_absurd_length_is_fatal();
  test_error_detail_body_honors_deadline();
  test_error_detail_survives_keepalive_drain();
  test_last_error_is_thread_local();
}
