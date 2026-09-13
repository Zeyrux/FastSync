#include "protocol.h"
#include "test_utils.h"
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <threads.h>

typedef struct {
  ProtocolSession* session;
  bool allocation_allowed;
} AllocationWorkerArg;

static int allocation_worker(void* arg) {
  AllocationWorkerArg* worker = arg;
  protocol_session_bind(worker->session);
  void* allocation = protocol_alloc(8);
  worker->allocation_allowed = allocation != NULL;
  free(allocation);
  protocol_session_unbind();
  return thrd_success;
}

typedef struct {
  ProtocolSession* session;
  int read_fd;
  bool released;
} AccountingWorkerArg;

typedef struct {
  ProtocolSession* session;
  atomic_int* ready;
  atomic_bool* release;
  bool received;
} ConcurrentAccountingWorkerArg;

static int accounting_worker(void* arg) {
  AccountingWorkerArg* worker = arg;
  protocol_session_bind(worker->session);
  Data* data = protocol_receive_data_limited(worker->session, 8);
  if (data) {
    data_destroy(data);
    worker->released = atomic_load(&worker->session->total_allocated_bytes) == 0;
  }
  protocol_session_unbind();
  return data ? thrd_success : thrd_error;
}

static int concurrent_accounting_worker(void* arg) {
  ConcurrentAccountingWorkerArg* worker = arg;
  protocol_session_bind(worker->session);
  Data* data = protocol_receive_data_limited(worker->session, 8);
  worker->received = data != NULL;
  atomic_fetch_add(worker->ready, 1);
  while (!atomic_load(worker->release))
    thrd_yield();
  data_destroy(data);
  protocol_session_unbind();
  return thrd_success;
}

static void test_send_receive_n_data() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  const char payload[] = "binary\x00test";
  size_t len = sizeof(payload);
  EXPECT_TRUE(send_n_data(0, payload, len));

  char buf[64];
  memset(buf, 0, sizeof(buf));
  EXPECT_TRUE(receive_n_data(0, buf, len));
  EXPECT_EQ_INT(memcmp(buf, payload, len), 0);

  close(p[0]);
  close(p[1]);
}

static void test_send_receive_n_data_zero() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  EXPECT_TRUE(send_n_data(0, "", 0));

  char buf[4];
  EXPECT_TRUE(receive_n_data(0, buf, 0));

  close(p[0]);
  close(p[1]);
}

static void test_explicit_session_context() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession session;
  protocol_session_init(&session, p[0], p[1]);
  protocol_session_set_bwlimit(&session, 0);

  const char payload[] = "explicit context";
  char received[sizeof(payload)] = {0};
  EXPECT_TRUE(protocol_send_n_data(&session, payload, sizeof(payload)));
  EXPECT_TRUE(protocol_receive_n_data(&session, received, sizeof(received)));
  EXPECT_EQ_INT(memcmp(payload, received, sizeof(payload)), 0);

  close(p[0]);
  close(p[1]);
}

static void test_send_receive_str() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  EXPECT_TRUE(send_str(0, ""));

  char* received = receive_str(0);
  EXPECT_NOT_NULL(received);
  EXPECT_EQ_STR(received, "");
  free(received);

  close(p[0]);
  close(p[1]);
}

static void test_send_receive_str_normal() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  EXPECT_TRUE(send_str(0, "Hello, Protocol!"));

  char* received = receive_str(0);
  EXPECT_NOT_NULL(received);
  EXPECT_EQ_STR(received, "Hello, Protocol!");
  free(received);

  close(p[0]);
  close(p[1]);
}

static void test_send_receive_data() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  unsigned char bin[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF};
  void* buf = malloc(sizeof(bin));
  EXPECT_NOT_NULL(buf);
  memcpy(buf, bin, sizeof(bin));
  Data* original = data_create(buf, sizeof(bin));
  EXPECT_TRUE(send_data(0, original));

  Data* received = receive_data(0);
  EXPECT_NOT_NULL(received);
  EXPECT_EQ_INT((int)received->size, (int)sizeof(bin));
  EXPECT_EQ_INT(memcmp(received->data, bin, sizeof(bin)), 0);

  data_destroy(original);
  data_destroy(received);
  close(p[0]);
  close(p[1]);
}

static void test_send_receive_int() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  int val = 42;
  EXPECT_TRUE(send_int(0, val));
  int received = 0;
  EXPECT_TRUE(receive_int(0, &received));
  EXPECT_EQ_INT(received, 42);

  val = 0;
  EXPECT_TRUE(send_int(0, val));
  EXPECT_TRUE(receive_int(0, &received));
  EXPECT_EQ_INT(received, 0);

  val = INT_MAX;
  EXPECT_TRUE(send_int(0, val));
  EXPECT_TRUE(receive_int(0, &received));
  EXPECT_EQ_INT(received, INT_MAX);

  close(p[0]);
  close(p[1]);
}

static void test_send_receive_status() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  Status statuses[] = {STATUS_OK,        STATUS_ERROR, STATUS_FINISHED,        STATUS_NEXT,
                       STATUS_CHUNK,     STATUS_CHECK, STATUS_DELTA_SIGNATURE, STATUS_DELTA_DATA,
                       STATUS_KEEPALIVE, STATUS_ABORT, STATUS_CHECK_BATCH};
  int count = sizeof(statuses) / sizeof(statuses[0]);

  for (int i = 0; i < count; i++) {
    EXPECT_TRUE(send_status(0, statuses[i]));
    Status received = -1;
    EXPECT_TRUE(receive_status(0, &received));
    EXPECT_EQ_INT((int)received, (int)statuses[i]);
  }

  close(p[0]);
  close(p[1]);
}

static void test_receive_n_data_truncated() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  close(p[1]);

  char buf[32];
  EXPECT_FALSE(receive_n_data(0, buf, 32));

  close(p[0]);
}

static void test_receive_str_truncated() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  close(p[1]);

  const char* received = receive_str(0);
  EXPECT_NULL(received);

  close(p[0]);
}

static void test_max_alloc_rejects_single_buffer() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession session;
  protocol_session_init(&session, p[0], p[1]);
  protocol_session_set_max_alloc(&session, 4);
  protocol_session_bind(&session);
  char payload[8] = {0};
  EXPECT_TRUE(write(p[1], &(size_t){sizeof(payload)}, sizeof(size_t)) == sizeof(size_t));
  EXPECT_NULL(protocol_receive_str(&session));
  protocol_session_unbind();
  close(p[0]);
  close(p[1]);
}

static void test_explicit_session_max_alloc_cannot_be_bypassed() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession explicit_session;
  ProtocolSession unrelated_session;
  protocol_session_init(&explicit_session, p[0], p[1]);
  protocol_session_init(&unrelated_session, p[0], p[1]);
  protocol_session_set_max_alloc(&explicit_session, 4);
  protocol_session_set_max_alloc(&unrelated_session, 64);
  protocol_session_bind(&unrelated_session);

  unsigned long long size = 8;
  EXPECT_EQ_INT((int)write(p[1], &size, sizeof(size)), (int)sizeof(size));
  EXPECT_EQ_INT((int)write(p[1], "12345678", 8), 8);
  EXPECT_NULL(protocol_receive_data_limited(&explicit_session, 8));
  EXPECT_EQ_INT((int)atomic_load(&explicit_session.total_allocated_bytes), 0);

  protocol_session_unbind();
  close(p[0]);
  close(p[1]);
}

static void test_max_alloc_allows_configured_buffer() {
  ProtocolSession session;
  protocol_session_init(&session, -1, -1);
  protocol_session_set_max_alloc(&session, 4);
  protocol_session_bind(&session);
  void* allowed = protocol_alloc(4);
  const void* rejected = protocol_alloc(5);
  EXPECT_NOT_NULL(allowed);
  EXPECT_NULL(rejected);
  free(allowed);
  protocol_session_unbind();
}

static void test_max_alloc_is_bound_in_worker_threads() {
  enum { WORKER_COUNT = 4 };
  ProtocolSession sessions[WORKER_COUNT];
  AllocationWorkerArg args[WORKER_COUNT] = {0};
  thrd_t threads[WORKER_COUNT];
  for (int i = 0; i < WORKER_COUNT; i++) {
    protocol_session_init(&sessions[i], -1, -1);
    protocol_session_set_max_alloc(&sessions[i], 4);
    args[i].session = &sessions[i];
    EXPECT_EQ_INT(thrd_create(&threads[i], allocation_worker, &args[i]), thrd_success);
  }
  for (int i = 0; i < WORKER_COUNT; i++) {
    int result;
    EXPECT_EQ_INT(thrd_join(threads[i], &result), thrd_success);
    EXPECT_EQ_INT(result, thrd_success);
    EXPECT_FALSE(args[i].allocation_allowed);
  }
}

static void test_protocol_accounting_is_released_in_worker_threads() {
  enum { WORKER_COUNT = 4 };
  ProtocolSession sessions[WORKER_COUNT];
  AccountingWorkerArg args[WORKER_COUNT] = {0};
  thrd_t threads[WORKER_COUNT];
  for (int i = 0; i < WORKER_COUNT; i++) {
    int p[2];
    EXPECT_EQ_INT(pipe(p), 0);
    protocol_session_init(&sessions[i], p[0], p[1]);
    protocol_session_set_max_alloc(&sessions[i], 64);
    unsigned long long size = 8;
    EXPECT_EQ_INT((int)write(p[1], &size, sizeof(size)), (int)sizeof(size));
    EXPECT_EQ_INT((int)write(p[1], "12345678", 8), 8);
    close(p[1]);
    args[i].session = &sessions[i];
    args[i].read_fd = p[0];
    EXPECT_EQ_INT(thrd_create(&threads[i], accounting_worker, &args[i]), thrd_success);
  }
  for (int i = 0; i < WORKER_COUNT; i++) {
    int result;
    EXPECT_EQ_INT(thrd_join(threads[i], &result), thrd_success);
    EXPECT_EQ_INT(result, thrd_success);
    EXPECT_TRUE(args[i].released);
    EXPECT_EQ_INT((int)atomic_load(&sessions[i].total_allocated_bytes), 0);
    close(args[i].read_fd);
  }
}

static void test_protocol_accounting_reservation_is_atomic() {
  enum { WORKER_COUNT = 8 };
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession session;
  protocol_session_init(&session, p[0], p[1]);
  protocol_session_set_max_alloc(&session, 64);
  const unsigned long long budget_before = MAX_SERVER_ALLOC - 8;
  atomic_store(&session.total_allocated_bytes, budget_before);

  for (int i = 0; i < WORKER_COUNT; i++) {
    unsigned long long size = 8;
    EXPECT_EQ_INT((int)write(p[1], &size, sizeof(size)), (int)sizeof(size));
    EXPECT_EQ_INT((int)write(p[1], "12345678", 8), 8);
  }
  close(p[1]);

  atomic_int ready;
  atomic_bool release;
  atomic_init(&ready, 0);
  atomic_init(&release, false);
  ConcurrentAccountingWorkerArg args[WORKER_COUNT] = {0};
  thrd_t threads[WORKER_COUNT];
  for (int i = 0; i < WORKER_COUNT; i++) {
    args[i].session = &session;
    args[i].ready = &ready;
    args[i].release = &release;
    EXPECT_EQ_INT(thrd_create(&threads[i], concurrent_accounting_worker, &args[i]), thrd_success);
  }
  while (atomic_load(&ready) != WORKER_COUNT)
    thrd_yield();
  bool budget_ok = atomic_load(&session.total_allocated_bytes) == budget_before + 8;
  atomic_store(&release, true);
  int received = 0;
  for (int i = 0; i < WORKER_COUNT; i++) {
    int result;
    EXPECT_EQ_INT(thrd_join(threads[i], &result), thrd_success);
    EXPECT_EQ_INT(result, thrd_success);
    received += args[i].received ? 1 : 0;
  }
  EXPECT_EQ_INT(received, 1);
  EXPECT_TRUE(budget_ok);
  EXPECT_EQ_INT((int)atomic_load(&session.total_allocated_bytes), (int)budget_before);
  close(p[0]);
}

static void test_protocol_string_accounting_is_transient() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession session;
  protocol_session_init(&session, p[0], p[1]);
  protocol_session_set_max_alloc(&session, 64);
  EXPECT_TRUE(protocol_send_str(&session, "temporary"));
  char* received = protocol_receive_str(&session);
  EXPECT_NOT_NULL(received);
  EXPECT_EQ_STR(received, "temporary");
  EXPECT_EQ_INT((int)atomic_load(&session.total_allocated_bytes), 0);
  free(received);
  close(p[0]);
  close(p[1]);
}

static void test_protocol_accounting_release_does_not_underflow() {
  ProtocolSession session;
  protocol_session_init(&session, -1, -1);
  atomic_store(&session.total_allocated_bytes, 4);
  protocol_session_bind(&session);
  protocol_release_memory(8);
  EXPECT_EQ_INT((int)atomic_load(&session.total_allocated_bytes), 0);
  protocol_release_memory(1);
  EXPECT_EQ_INT((int)atomic_load(&session.total_allocated_bytes), 0);
  protocol_session_unbind();
}

/* A Data acquired on session A must return its connection-memory charge to A
   even when a different session B is bound at destroy time: releasing against
   the thread-local bound session would leak A's budget and drain B's. */
static void test_receive_data_charge_follows_owning_session() {
  int pipe_a[2];
  int pipe_b[2];
  EXPECT_EQ_INT(pipe(pipe_a), 0);
  EXPECT_EQ_INT(pipe(pipe_b), 0);

  ProtocolSession session_a;
  ProtocolSession session_b;
  protocol_session_init(&session_a, pipe_a[0], pipe_a[1]);
  protocol_session_init(&session_b, pipe_b[0], pipe_b[1]);
  protocol_session_set_max_alloc(&session_a, 64);
  protocol_session_set_max_alloc(&session_b, 64);

  unsigned long long size = 8;
  EXPECT_EQ_INT((int)write(pipe_a[1], &size, sizeof(size)), (int)sizeof(size));
  EXPECT_EQ_INT((int)write(pipe_a[1], "12345678", 8), 8);
  EXPECT_EQ_INT((int)write(pipe_b[1], &size, sizeof(size)), (int)sizeof(size));
  EXPECT_EQ_INT((int)write(pipe_b[1], "abcdefgh", 8), 8);

  Data* data_a = protocol_receive_data_limited(&session_a, 8);
  Data* data_b = protocol_receive_data_limited(&session_b, 8);
  EXPECT_NOT_NULL(data_a);
  EXPECT_NOT_NULL(data_b);
  EXPECT_TRUE(data_a->owner == &session_a);
  EXPECT_TRUE(data_b->owner == &session_b);
  EXPECT_EQ_INT((int)atomic_load(&session_a.total_allocated_bytes), 8);
  EXPECT_EQ_INT((int)atomic_load(&session_b.total_allocated_bytes), 8);

  /* Destroy A's Data while the unrelated session B is the bound session. */
  protocol_session_bind(&session_b);
  data_destroy(data_a);
  protocol_session_unbind();

  EXPECT_EQ_INT((int)atomic_load(&session_a.total_allocated_bytes), 0);
  EXPECT_EQ_INT((int)atomic_load(&session_b.total_allocated_bytes), 8);

  data_destroy(data_b);
  EXPECT_EQ_INT((int)atomic_load(&session_b.total_allocated_bytes), 0);

  close(pipe_a[0]);
  close(pipe_a[1]);
  close(pipe_b[0]);
  close(pipe_b[1]);
}

static void test_protocol_session_io_timeout() {
  /* Default is the built-in 60 s window; the setter stores exactly what it is
   * given (<= 0 means "fall back to the default") so callers can propagate
   * --timeout without special-casing 0. */
  ProtocolSession session;
  protocol_session_init(&session, -1, -1);
  EXPECT_EQ_INT(session.io_timeout_sec, 60);

  protocol_session_set_io_timeout(&session, 120);
  EXPECT_EQ_INT(session.io_timeout_sec, 120);
  protocol_session_set_io_timeout(&session, 0);
  EXPECT_EQ_INT(session.io_timeout_sec, 0);
  /* A NULL session is a no-op, not a crash. */
  protocol_session_set_io_timeout(NULL, 5);

  /* A short per-session deadline must actually bound a non-responsive read:
   * with no writer the poll waits for the configured 1 s and then fails,
   * rather than the built-in 60 s. */
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession timed;
  protocol_session_init(&timed, p[0], p[1]);
  protocol_session_set_io_timeout(&timed, 1);
  char buf[4];
  EXPECT_FALSE(protocol_receive_n_data(&timed, buf, sizeof(buf)));
  close(p[0]);
  close(p[1]);
}

static void test_send_receive_status_timed() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  /* The extended-deadline variant must read an ordinary status just like the
     default window, and must fail cleanly on EOF rather than block. */
  EXPECT_TRUE(send_status(0, STATUS_OK));
  Status received = -1;
  EXPECT_TRUE(receive_status_timed(0, &received, 5));
  EXPECT_EQ_INT((int)received, (int)STATUS_OK);

  close(p[1]);
  EXPECT_FALSE(receive_status_timed(0, &received, 5));

  close(p[0]);
}

static bool keepalive_always_abort(void) {
  return true;
}

/* A pre-buffered KEEPALIVE reply from the peer must be consumed transparently,
   leaving the first real status visible to the caller. */
static void test_receive_status_keepalive_skips_reply() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession session;
  protocol_session_init(&session, p[0], p[1]);

  EXPECT_TRUE(protocol_send_status(&session, STATUS_KEEPALIVE));
  EXPECT_TRUE(protocol_send_status(&session, STATUS_OK));

  Status received = STATUS_ERROR;
  EXPECT_TRUE(protocol_receive_status_keepalive(&session, &received, 5, 1, NULL));
  EXPECT_EQ_INT((int)received, (int)STATUS_OK);

  close(p[0]);
  close(p[1]);
}

/* The abort callback ends the wait immediately, before any keepalive traffic. */
static void test_receive_status_keepalive_aborts() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  ProtocolSession session;
  protocol_session_init(&session, p[0], p[1]);

  Status received = STATUS_ERROR;
  EXPECT_FALSE(
      protocol_receive_status_keepalive(&session, &received, 5, 1, keepalive_always_abort));

  close(p[0]);
  close(p[1]);
}

typedef struct {
  int peer_read_fd;
  int peer_write_fd;
  bool replied;
} KeepalivePeerArg;

static int keepalive_peer(void* arg) {
  KeepalivePeerArg* peer = arg;
  ProtocolSession session;
  protocol_session_init(&session, peer->peer_read_fd, peer->peer_write_fd);
  Status status = STATUS_ERROR;
  if (protocol_receive_status(&session, &status) && status == STATUS_KEEPALIVE) {
    /* Model the busy receiver: it sends the real ack first, then the keepalive
       reply it owes for the queued keepalive (which the client must drain so it
       does not desynchronize the stream). */
    peer->replied = protocol_send_status(&session, STATUS_OK) &&
                    protocol_send_status(&session, STATUS_KEEPALIVE);
  }
  return thrd_success;
}

/* While the peer is silent the helper must emit STATUS_KEEPALIVE, then consume
   the peer's ack and drain the keepalive reply that follows it -- proving the
   inline keepalive loop works without a second writer racing the send path. */
static void test_receive_status_keepalive_emits() {
  int to_client[2];
  int to_peer[2];
  EXPECT_EQ_INT(pipe(to_client), 0);
  EXPECT_EQ_INT(pipe(to_peer), 0);

  ProtocolSession session;
  protocol_session_init(&session, to_client[0], to_peer[1]);

  KeepalivePeerArg peer = {.peer_read_fd = to_peer[0], .peer_write_fd = to_client[1]};
  thrd_t thread;
  EXPECT_EQ_INT(thrd_create(&thread, keepalive_peer, &peer), thrd_success);

  Status received = STATUS_ERROR;
  EXPECT_TRUE(protocol_receive_status_keepalive(&session, &received, 10, 1, NULL));
  EXPECT_EQ_INT((int)received, (int)STATUS_OK);

  int result = 0;
  EXPECT_EQ_INT(thrd_join(thread, &result), thrd_success);
  EXPECT_EQ_INT(result, thrd_success);
  EXPECT_TRUE(peer.replied);

  close(to_client[0]);
  close(to_client[1]);
  close(to_peer[0]);
  close(to_peer[1]);
}

void test_protocol() {
  test_send_receive_n_data();
  test_send_receive_n_data_zero();
  test_explicit_session_context();
  test_send_receive_str();
  test_send_receive_str_normal();
  test_send_receive_data();
  test_send_receive_int();
  test_send_receive_status();
  test_protocol_session_io_timeout();
  test_send_receive_status_timed();
  test_receive_status_keepalive_skips_reply();
  test_receive_status_keepalive_aborts();
  test_receive_status_keepalive_emits();
  test_receive_n_data_truncated();
  test_receive_str_truncated();
  test_max_alloc_rejects_single_buffer();
  test_explicit_session_max_alloc_cannot_be_bypassed();
  test_max_alloc_allows_configured_buffer();
  test_max_alloc_is_bound_in_worker_threads();
  test_protocol_accounting_is_released_in_worker_threads();
  test_protocol_accounting_reservation_is_atomic();
  test_protocol_string_accounting_is_transient();
  test_protocol_accounting_release_does_not_underflow();
  test_receive_data_charge_follows_owning_session();
}
