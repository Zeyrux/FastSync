#include "test_format.h"
#include "format.h"
#include "test_utils.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void expect_big_num(unsigned long long value, bool human, const char* expected) {
  char buffer[64];
  EXPECT_TRUE(format_big_num(value, human, buffer, sizeof(buffer)));
  EXPECT_EQ_STR(buffer, expected);
}

static void test_human_size_decimal() {
  /* Values below 1000 print verbatim; larger values use the largest unit that
   * keeps the value below 1000 and exactly two decimals (rsync human_num). */
  expect_big_num(0, true, "0");
  expect_big_num(999, true, "999");
  expect_big_num(1000, true, "1.00K");
  expect_big_num(1500, true, "1.50K");
  expect_big_num(9999, true, "10.00K");
  expect_big_num(999999, true, "1000.00K");
  expect_big_num(1000000, true, "1.00M");
  expect_big_num(1500000, true, "1.50M");
}

static void test_big_num_grouping() {
  /* Non-human numbers are comma-grouped every three digits (rsync big_num). */
  expect_big_num(0, false, "0");
  expect_big_num(1, false, "1");
  expect_big_num(999, false, "999");
  expect_big_num(1000, false, "1,000");
  expect_big_num(4096, false, "4,096");
  expect_big_num(1234567, false, "1,234,567");
  expect_big_num(1000000000ULL, false, "1,000,000,000");
}

static void test_datetime_format() {
  char buffer[32];
  time_t when = 1700000000;
  EXPECT_TRUE(format_rsync_datetime(when, true, buffer, sizeof(buffer)));
  /* %M shape: YYYY/MM/DD-HH:MM:SS */
  EXPECT_EQ_INT(strlen(buffer), 19);
  EXPECT_EQ_INT(buffer[4], '/');
  EXPECT_EQ_INT(buffer[7], '/');
  EXPECT_EQ_INT(buffer[10], '-');
  EXPECT_EQ_INT(buffer[13], ':');
  EXPECT_EQ_INT(buffer[16], ':');

  char space_form[32];
  EXPECT_TRUE(format_rsync_datetime(when, false, space_form, sizeof(space_form)));
  EXPECT_EQ_INT(space_form[10], ' ');
}

static void test_dest_state_roundtrip() {
  /* The wire codec is exercised over a socketpair so the real send/receive
   * primitives run. */
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
    return;
  OutputDestState out;
  memset(&out, 0, sizeof(out));
  out.known = true;
  out.existed = true;
  out.target_matches = true;
  out.size = 123456789ULL;
  out.mtime_sec = 1700000000;
  out.mtime_nsec = 123456789;
  out.mode = 0100644;
  out.uid = 1000;
  out.gid = 1000;
  OutputDestState in;
  memset(&in, 0, sizeof(in));
  EXPECT_TRUE(format_dest_state_send(fds[0], &out));
  EXPECT_TRUE(format_dest_state_receive(fds[1], &in));
  EXPECT_TRUE(in.known);
  EXPECT_TRUE(in.existed);
  EXPECT_TRUE(in.target_matches);
  EXPECT_TRUE(in.size == out.size);
  EXPECT_TRUE(in.mtime_sec == out.mtime_sec);
  EXPECT_TRUE(in.mtime_nsec == out.mtime_nsec);
  EXPECT_TRUE(in.mode == out.mode);
  EXPECT_TRUE(in.uid == out.uid);
  EXPECT_TRUE(in.gid == out.gid);
  close(fds[0]);
  close(fds[1]);
}

static void test_stats_roundtrip() {
  /* STATUS_STATS grew from three counters (2.25.0) to eight (2.28.0); the codec
   * must carry every field, including the receiver-observed literal/created
   * counters, across the wire in order. */
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
    return;
  ReceiverStats out;
  memset(&out, 0, sizeof(out));
  out.matched_data = 111111111ULL;
  out.deleted_files = 7;
  out.would_delete_count = 3;
  out.literal_bytes = 222222222ULL;
  out.created_reg = 5;
  out.created_dir = 4;
  out.created_link = 2;
  out.created_special = 1;
  out.deleted_reg = 9;
  out.deleted_dir = 6;
  out.deleted_link = 3;
  out.deleted_special = 2;
  ReceiverStats in;
  memset(&in, 0, sizeof(in));
  EXPECT_TRUE(format_stats_send(fds[0], &out));
  EXPECT_TRUE(format_stats_receive(fds[1], &in));
  EXPECT_TRUE(in.matched_data == out.matched_data);
  EXPECT_TRUE(in.deleted_files == out.deleted_files);
  EXPECT_TRUE(in.would_delete_count == out.would_delete_count);
  EXPECT_TRUE(in.literal_bytes == out.literal_bytes);
  EXPECT_TRUE(in.created_reg == out.created_reg);
  EXPECT_TRUE(in.created_dir == out.created_dir);
  EXPECT_TRUE(in.created_link == out.created_link);
  EXPECT_TRUE(in.created_special == out.created_special);
  EXPECT_TRUE(in.deleted_reg == out.deleted_reg);
  EXPECT_TRUE(in.deleted_dir == out.deleted_dir);
  EXPECT_TRUE(in.deleted_link == out.deleted_link);
  EXPECT_TRUE(in.deleted_special == out.deleted_special);
  close(fds[0]);
  close(fds[1]);
}

void test_format(void) {
  test_human_size_decimal();
  test_big_num_grouping();
  test_datetime_format();
  test_dest_state_roundtrip();
  test_stats_roundtrip();
}
