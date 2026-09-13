#include "test_receiver_timeout.h"

#include "protocol.h"
#include "receiver.h"
#include "test_utils.h"
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static bool sink_discard(File* file, void* context) {
  (void)context;
  file_destroy(file);
  return true;
}

/* The idle/session bound is a pure function of three monotonic timestamps, so
 * it can be exercised deterministically without sleeping an hour.  A tiny
 * overridden limit covers the same arithmetic the loop uses. */
static void test_receiver_time_limit_predicate() {
  receiver_set_time_limits(10, 100);
  struct timespec start = {.tv_sec = 1000, .tv_nsec = 0};
  struct timespec fresh = {.tv_sec = 1000, .tv_nsec = 0};
  struct timespec just_idle = {.tv_sec = 1009, .tv_nsec = 0}; /* 9 s no progress */
  struct timespec idle = {.tv_sec = 1010, .tv_nsec = 0};      /* 10 s no progress */
  struct timespec just_wall = {.tv_sec = 1099, .tv_nsec = 0};
  struct timespec wall = {.tv_sec = 1100, .tv_nsec = 0};    /* 100 s session */
  struct timespec wp_just = {.tv_sec = 1098, .tv_nsec = 0}; /* idle 1 s */
  struct timespec wp_wall = {.tv_sec = 1099, .tv_nsec = 0}; /* idle 1 s */

  EXPECT_FALSE(receiver_time_limit_exceeded(&start, &fresh, &fresh));
  EXPECT_FALSE(receiver_time_limit_exceeded(&start, &fresh, &just_idle));
  EXPECT_TRUE(receiver_time_limit_exceeded(&start, &fresh, &idle));
  EXPECT_FALSE(receiver_time_limit_exceeded(&start, &wp_just, &just_wall));
  EXPECT_TRUE(receiver_time_limit_exceeded(&start, &wp_wall, &wall));

  /* Reset restores the generous production defaults (1 h idle / 24 h total). */
  receiver_reset_time_limits();
  struct timespec under_hour = {.tv_sec = 1000 + 3599, .tv_nsec = 0};
  EXPECT_FALSE(receiver_time_limit_exceeded(&start, &start, &under_hour));
  receiver_reset_time_limits();
}

/* Drive the actual receive loop with a test-only idle limit of 0 so the very
 * first keepalive is rejected: this exercises the loop's abort path (log +
 * STATUS_ERROR + return -1) with no timing dependence. */
static void test_receiver_aborts_idle_keepalive() {
  receiver_set_time_limits(0, 3600);
  int sv[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  ReceiverSink sink = {.store_file = sink_discard,
                       .context = NULL,
                       .send_error = true,
                       .send_success = false,
                       .send_success_frame = NULL};

  /* Bind an explicit session so the fd-based receive helpers use the
   * socketpair rather than any transport left over from an earlier test. */
  ProtocolSession session;
  protocol_session_init(&session, sv[1], sv[1]);
  protocol_session_bind(&session);

  Status keepalive = STATUS_KEEPALIVE;
  ssize_t wrote = write(sv[0], &keepalive, sizeof(keepalive));
  int result = -2;
  if (wrote == (ssize_t)sizeof(keepalive))
    result = receiver_process_pending(config, sv[1], &sink, NULL);
  Status reply = STATUS_OK;
  ssize_t got = -1;
  if (result == -1)
    got = read(sv[0], &reply, sizeof(reply));

  /* Tear down the binding/descriptors BEFORE asserting: an EXPECT_* failure
   * returns immediately, and a dangling bound_session would poison later
   * fd-level protocol I/O tests. */
  protocol_session_unbind();
  config_delete(config);
  close(sv[0]);
  close(sv[1]);
  receiver_reset_time_limits();

  EXPECT_EQ_INT((int)wrote, (int)sizeof(keepalive));
  EXPECT_EQ_INT(result, -1);
  EXPECT_EQ_INT((int)got, (int)sizeof(reply));
  EXPECT_EQ_INT((int)reply, (int)STATUS_ERROR);
}

void test_receiver_timeout(void) {
  /* EXPECT_* returns from the current function on failure, so reset the
   * process-global limits around the subtests (and again after) to guarantee a
   * failed assertion cannot leave the receiver aborted for later tests. */
  receiver_reset_time_limits();
  test_receiver_time_limit_predicate();
  test_receiver_aborts_idle_keepalive();
  receiver_reset_time_limits();
}
