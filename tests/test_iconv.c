#include "test_iconv.h"
#include "charset.h"
#include "protocol.h"
#include "test_utils.h"
#include "utils.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* --- CONVERT_SPEC parsing ------------------------------------------------ */

static void test_iconv_spec_parse_split() {
  char* local = NULL;
  char* remote = NULL;
  EXPECT_EQ_INT(charset_spec_parse("utf-8,iso-8859-1", &local, &remote), 0);
  EXPECT_EQ_STR(local, "utf-8");
  EXPECT_EQ_STR(remote, "iso-8859-1");
  free(local);
  free(remote);
}

static void test_iconv_spec_parse_single_defaults_to_local() {
  char* local = NULL;
  char* remote = NULL;
  EXPECT_EQ_INT(charset_spec_parse("utf-8", &local, &remote), 0);
  EXPECT_EQ_STR(local, "utf-8");
  EXPECT_EQ_STR(remote, "utf-8");
  free(local);
  free(remote);
}

static void test_iconv_spec_parse_garbage() {
  char* local = NULL;
  char* remote = NULL;
  EXPECT_EQ_INT(charset_spec_parse(NULL, &local, &remote), -1);
  EXPECT_EQ_INT(charset_spec_parse("", &local, &remote), -1);
  EXPECT_EQ_INT(charset_spec_parse(",", &local, &remote), -1);
  EXPECT_EQ_INT(charset_spec_parse("utf-8,", &local, &remote), -1);
  EXPECT_EQ_INT(charset_spec_parse(",utf-8", &local, &remote), -1);
}

static void test_iconv_spec_valid() {
  EXPECT_TRUE(charset_spec_valid(NULL));
  EXPECT_TRUE(charset_spec_valid("utf-8"));
  EXPECT_TRUE(charset_spec_valid("utf-8,iso-8859-1"));
  EXPECT_TRUE(charset_spec_valid("iso-8859-1,ascii"));
  EXPECT_FALSE(charset_spec_valid("no-such-charset,utf-8"));
  EXPECT_FALSE(charset_spec_valid("utf-8,no-such-charset"));
  EXPECT_FALSE(charset_spec_valid(",,,"));
  EXPECT_FALSE(charset_spec_valid("utf-8,"));
}

/* --- one-shot conversion ------------------------------------------------ */

static void test_iconv_utf8_to_latin1() {
  void* conv = charset_conversion_open("utf-8", "iso-8859-1");
  EXPECT_NOT_NULL(conv);
  char* out = charset_convert(conv, "caf\xc3\xa9", NULL);
  EXPECT_NOT_NULL(out);
  EXPECT_EQ_INT(strcmp(out, "caf\xe9"), 0);
  free(out);
  charset_conversion_close(conv);
}

static void test_iconv_latin1_to_utf8() {
  void* conv = charset_conversion_open("iso-8859-1", "utf-8");
  EXPECT_NOT_NULL(conv);
  char* out = charset_convert(conv, "caf\xe9", NULL);
  EXPECT_NOT_NULL(out);
  EXPECT_EQ_INT(strcmp(out, "caf\xc3\xa9"), 0);
  free(out);
  charset_conversion_close(conv);
}

static void test_iconv_invalid_sequence_fails() {
  int err = 0;
  /* 0xff is not a valid UTF-8 sequence. */
  void* conv = charset_conversion_open("utf-8", "ascii");
  EXPECT_NOT_NULL(conv);
  EXPECT_TRUE(charset_convert(conv, "bad\xff", &err) == NULL);
  EXPECT_TRUE(err == EILSEQ || err == EINVAL);
  charset_conversion_close(conv);
}

static void test_iconv_unrepresentable_fails() {
  /* "caf\xc3\xa9" (UTF-8 for cafe) has no ASCII representation. */
  void* conv = charset_conversion_open("utf-8", "ascii");
  EXPECT_NOT_NULL(conv);
  EXPECT_TRUE(charset_convert(conv, "caf\xc3\xa9", NULL) == NULL);
  charset_conversion_close(conv);
}

/* --- process-wide wire conversion ---------------------------------------- */

static void test_iconv_wire_sender_converts_local_to_remote() {
  EXPECT_TRUE(charset_wire_init_sender("utf-8,iso-8859-1"));
  char* wire = charset_wire_apply("caf\xc3\xa9");
  EXPECT_NOT_NULL(wire);
  EXPECT_EQ_INT(strcmp(wire, "caf\xe9"), 0);
  free(wire);
  charset_wire_free();
}

static void test_iconv_wire_receiver_converts_remote_to_local() {
  EXPECT_TRUE(charset_wire_init_receiver("utf-8,iso-8859-1", NULL));
  char* local = charset_wire_apply("caf\xe9");
  EXPECT_NOT_NULL(local);
  EXPECT_EQ_INT(strcmp(local, "caf\xc3\xa9"), 0);
  free(local);
  charset_wire_free();
}

static void test_iconv_wire_disabled_passthrough() {
  charset_wire_init_sender(NULL);
  EXPECT_FALSE(charset_wire_active());
  char* out = charset_wire_apply("plain/name\xff");
  EXPECT_NOT_NULL(out);
  EXPECT_EQ_INT(strcmp(out, "plain/name\xff"), 0);
  free(out);
  charset_wire_free();
}

static void test_iconv_wire_str_roundtrip() {
  EXPECT_TRUE(charset_wire_init_sender("utf-8,iso-8859-1"));
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    charset_wire_free();
    charset_wire_init_receiver("utf-8,iso-8859-1", NULL);
    char* got = receive_wire_str(p[0]);
    bool ok = got != NULL && strcmp(got, "caf\xc3\xa9") == 0;
    free(got);
    charset_wire_free();
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = send_wire_str(p[1], "caf\xc3\xa9");
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    charset_wire_free();
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

void test_iconv() {
  test_iconv_spec_parse_split();
  test_iconv_spec_parse_single_defaults_to_local();
  test_iconv_spec_parse_garbage();
  test_iconv_spec_valid();
  test_iconv_utf8_to_latin1();
  test_iconv_latin1_to_utf8();
  test_iconv_invalid_sequence_fails();
  test_iconv_unrepresentable_fails();
  test_iconv_wire_sender_converts_local_to_remote();
  test_iconv_wire_receiver_converts_remote_to_local();
  test_iconv_wire_disabled_passthrough();
  test_iconv_wire_str_roundtrip();
}