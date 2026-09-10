#include "test_motd.h"
#include "motd.h"
#include "protocol.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Write `body` (len bytes) to a fresh temp file; returns its heap path. */
static int write_file(const char* body, size_t len, char** out_path) {
  char tmpl[] = "/tmp/fastsync_motd_XXXXXX";
  int fd = mkstemp(tmpl);
  if (fd < 0)
    return -1;
  if (write(fd, body, len) != (ssize_t)len) {
    close(fd);
    unlink(tmpl);
    return -1;
  }
  close(fd);
  *out_path = strdup(tmpl);
  return *out_path ? 0 : -1;
}

static void test_motd_read_present() {
  char* path;
  char body[] = "Welcome to FastSync\nBe excellent to each other.\n";
  EXPECT_EQ_INT(write_file(body, strlen(body), &path), 0);
  char* motd = motd_read_file(path);
  unlink(path);
  free(path);
  EXPECT_NOT_NULL(motd);
  EXPECT_EQ_STR(motd, body);
  free(motd);
}

static void test_motd_read_absent() {
  EXPECT_NULL(motd_read_file("/nonexistent/fastsync_motd_zzz"));
  EXPECT_NULL(motd_read_file(""));
  EXPECT_NULL(motd_read_file(NULL));
}

static void test_motd_read_unreadable() {
  /* Reading a directory through fopen succeeds for the open but fread fails
   * with EISDIR, which is a reliable "unreadable" probe even for root. */
  const char* dir = "/tmp";
  EXPECT_NULL(motd_read_file(dir));
}

static void test_motd_read_large_truncated() {
  size_t total = MOTD_MAX_BYTES + 100;
  char* body = malloc(total);
  EXPECT_NOT_NULL(body);
  memset(body, 'x', total);
  body[0] = 'h';
  char* path;
  EXPECT_EQ_INT(write_file(body, total, &path), 0);
  char* motd = motd_read_file(path);
  unlink(path);
  free(path);
  EXPECT_NOT_NULL(motd);
  EXPECT_EQ_INT((int)strlen(motd), MOTD_MAX_BYTES);
  EXPECT_EQ_INT(motd[0], 'h');
  EXPECT_EQ_INT(motd[MOTD_MAX_BYTES - 1], 'x');
  EXPECT_EQ_STR(motd + MOTD_MAX_BYTES, "");
  free(motd);
  free(body);
}

static void test_motd_render_escaping() {
  /* Newlines/tabs survive; control bytes (ESC included) become \NNN octal. */
  char* rendered = motd_render("line1\n\tansi\033[31m", false);
  EXPECT_NOT_NULL(rendered);
  EXPECT_EQ_STR(rendered, "line1\n\tansi\\#033[31m");
  free(rendered);

  /* High-bit bytes are escaped without --8-bit-output. */
  rendered = motd_render("\xC3\xA9", false);
  EXPECT_NOT_NULL(rendered);
  EXPECT_EQ_STR(rendered, "\\#303\\#251");
  free(rendered);

  /* --8-bit-output keeps bytes >= 0x80 verbatim. */
  rendered = motd_render("\xC3\xA9", true);
  EXPECT_NOT_NULL(rendered);
  EXPECT_EQ_STR(rendered, "\xC3\xA9");
  free(rendered);

  EXPECT_NULL(motd_render(NULL, false));
}

static void test_motd_frame_roundtrip() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  const char* motd = "Greetings from the module server.\nEnjoy your stay.\n";
  EXPECT_TRUE(motd_send(0, motd));
  char* received = motd_receive(0);
  EXPECT_NOT_NULL(received);
  EXPECT_EQ_STR(received, motd);
  free(received);

  /* An unset MOTD is an empty (but present) frame, not an error. */
  EXPECT_TRUE(motd_send(0, NULL));
  received = motd_receive(0);
  EXPECT_NOT_NULL(received);
  EXPECT_EQ_STR(received, "");
  free(received);

  close(p[0]);
  close(p[1]);
}

static void test_motd_receive_over_bound_rejected() {
  int p[2];
  EXPECT_EQ_INT(pipe(p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  size_t size = MOTD_MAX_BYTES + 100;
  char* big = malloc(size);
  EXPECT_NOT_NULL(big);
  memset(big, 'a', size);
  big[size - 1] = '\0';
  /* A (hostile/oversized) peer frame within MAX_STRING_SIZE but above the MOTD
   * bound is consumed and discarded: motd_receive returns NULL and the stream
   * stays framed for the next message. */
  EXPECT_TRUE(send_str(0, big));
  EXPECT_NULL(motd_receive(0));
  EXPECT_TRUE(send_str(0, "after"));
  char* next = receive_str(0);
  EXPECT_NOT_NULL(next);
  EXPECT_EQ_STR(next, "after");
  free(next);
  free(big);
  close(p[0]);
  close(p[1]);
}

void test_motd() {
  test_motd_read_present();
  test_motd_read_absent();
  test_motd_read_unreadable();
  test_motd_read_large_truncated();
  test_motd_render_escaping();
  test_motd_frame_roundtrip();
  test_motd_receive_over_bound_rejected();
}