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

void test_protocol() {
  test_send_receive_n_data();
  test_send_receive_n_data_zero();
  test_explicit_session_context();
  test_send_receive_str();
  test_send_receive_str_normal();
  test_send_receive_data();
  test_send_receive_int();
  test_send_receive_status();
  test_receive_n_data_truncated();
  test_receive_str_truncated();
  test_max_alloc_rejects_single_buffer();
  test_max_alloc_allows_configured_buffer();
  test_max_alloc_is_bound_in_worker_threads();
  test_protocol_accounting_is_released_in_worker_threads();
}
