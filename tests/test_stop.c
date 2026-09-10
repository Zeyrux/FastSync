#include "test_stop.h"
#include "stop_condition.h"
#include "test_utils.h"
#include <limits.h>
#include <time.h>

static void test_stop_after_parse_valid() {
  int minutes = 0;
  EXPECT_TRUE(stop_parse_after_minutes("5", &minutes));
  EXPECT_EQ_INT(minutes, 5);
  EXPECT_TRUE(stop_parse_after_minutes("1", &minutes));
  EXPECT_EQ_INT(minutes, 1);
  EXPECT_TRUE(stop_parse_after_minutes("1440", &minutes));
  EXPECT_EQ_INT(minutes, 1440);
  EXPECT_TRUE(stop_parse_after_minutes("2147483647", &minutes));
  EXPECT_EQ_INT(minutes, INT_MAX);
}

static void test_stop_after_parse_invalid() {
  int minutes = 0;
  EXPECT_FALSE(stop_parse_after_minutes("0", &minutes));
  EXPECT_FALSE(stop_parse_after_minutes("-1", &minutes));
  EXPECT_FALSE(stop_parse_after_minutes("abc", &minutes));
  EXPECT_FALSE(stop_parse_after_minutes("", &minutes));
  EXPECT_FALSE(stop_parse_after_minutes("5x", &minutes));
  EXPECT_FALSE(stop_parse_after_minutes("1.5", &minutes));
  EXPECT_FALSE(stop_parse_after_minutes(" 5 ", &minutes));
  EXPECT_FALSE(stop_parse_after_minutes("2147483648", &minutes));
  EXPECT_FALSE(stop_parse_after_minutes(NULL, &minutes));
}

static void test_stop_at_parse_hhmm() {
  time_t now = 1700000000;
  time_t deadline = 0;

  EXPECT_TRUE(stop_parse_at_time("12:30", now, &deadline));
  struct tm t;
  EXPECT_NOT_NULL(localtime_r(&deadline, &t));
  EXPECT_EQ_INT(t.tm_hour, 12);
  EXPECT_EQ_INT(t.tm_min, 30);
  EXPECT_EQ_INT(t.tm_sec, 0);

  EXPECT_TRUE(stop_parse_at_time("12:30:59", now, &deadline));
  EXPECT_NOT_NULL(localtime_r(&deadline, &t));
  EXPECT_EQ_INT(t.tm_hour, 12);
  EXPECT_EQ_INT(t.tm_min, 30);
  EXPECT_EQ_INT(t.tm_sec, 59);

  EXPECT_TRUE(stop_parse_at_time("00:00", now, &deadline));
  EXPECT_NOT_NULL(localtime_r(&deadline, &t));
  EXPECT_EQ_INT(t.tm_hour, 0);
  EXPECT_EQ_INT(t.tm_min, 0);
  EXPECT_EQ_INT(t.tm_sec, 0);
}

static void test_stop_at_parse_now_plus() {
  time_t now = 1700000000;
  time_t deadline = 0;

  EXPECT_TRUE(stop_parse_at_time("now+90s", now, &deadline));
  EXPECT_EQ_INT(deadline, now + 90);
  EXPECT_TRUE(stop_parse_at_time("now+5m", now, &deadline));
  EXPECT_EQ_INT(deadline, now + 300);
  EXPECT_TRUE(stop_parse_at_time("now+2h", now, &deadline));
  EXPECT_EQ_INT(deadline, now + 7200);
  EXPECT_TRUE(stop_parse_at_time("now+1d", now, &deadline));
  EXPECT_EQ_INT(deadline, now + 86400);
  EXPECT_TRUE(stop_parse_at_time("now+0s", now, &deadline));
  EXPECT_EQ_INT(deadline, now);
}

static void test_stop_at_parse_invalid() {
  time_t now = 1700000000;
  time_t deadline = 0;
  EXPECT_FALSE(stop_parse_at_time("12", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("12:3", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("1234", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("12:30:5", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("12:30:5x", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("24:00", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("12:60", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("12:30:61", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("12;00", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("now", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("now+", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("now+5", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("now+5x", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("now-5m", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("now+1w", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("abc", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time("", now, &deadline));
  EXPECT_FALSE(stop_parse_at_time(NULL, now, &deadline));
}

static void test_stop_deadline_latency() {
  struct timespec now;
  EXPECT_EQ_INT(clock_gettime(CLOCK_MONOTONIC, &now), 0);

  StopCondition future = stop_condition_make(true, 60, false, 0, now);
  EXPECT_TRUE(future.has_monotonic);
  EXPECT_EQ_INT(future.monotonic_deadline.tv_sec, now.tv_sec + 3600);
  EXPECT_EQ_INT(future.monotonic_deadline.tv_nsec, now.tv_nsec);
  EXPECT_FALSE(future.has_wall);
  EXPECT_FALSE(stop_condition_reached(&future));

  /* Move the 60-minute deadline into the past: the check now reports reached. */
  StopCondition past = stop_condition_make(true, 60, false, 0, now);
  past.monotonic_deadline.tv_sec -= 7200;
  EXPECT_TRUE(stop_condition_reached(&past));

  StopCondition no_after = stop_condition_make(false, 0, false, 0, now);
  EXPECT_FALSE(no_after.has_monotonic);
  EXPECT_FALSE(no_after.has_wall);
  EXPECT_FALSE(stop_condition_reached(&no_after));

  /* --stop-at: a wall-clock deadline in the past/now is reached; one in the
     future is not, and it stays independent of the monotonic half. */
  StopCondition wall_future = stop_condition_make(false, 0, true, time(NULL) + 3600, now);
  EXPECT_TRUE(wall_future.has_wall);
  EXPECT_FALSE(wall_future.has_monotonic);
  EXPECT_FALSE(stop_condition_reached(&wall_future));

  StopCondition wall_past = stop_condition_make(false, 0, true, time(NULL) - 1, now);
  EXPECT_TRUE(stop_condition_reached(&wall_past));

  EXPECT_FALSE(stop_condition_reached(NULL));
}

void test_stop(void) {
  test_stop_after_parse_valid();
  test_stop_after_parse_invalid();
  test_stop_at_parse_hhmm();
  test_stop_at_parse_now_plus();
  test_stop_at_parse_invalid();
  test_stop_deadline_latency();
}