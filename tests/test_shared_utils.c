#include "test_shared_utils.h"
#include "utils.h"
#include "protocol.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <threads.h>

typedef struct {
  bool eight_bit_output;
  const char* expected;
  int failed;
} EscapeThreadArgs;

static int escape_thread(void* arg) {
  EscapeThreadArgs* args = arg;
  for (int i = 0; i < 1000; i++) {
    char* escaped = output_escape("x\xc3\xa9\n", args->eight_bit_output);
    if (!escaped || strcmp(escaped, args->expected) != 0)
      args->failed = 1;
    free(escaped);
  }
  return 0;
}

void test_shared_utils() {
  char formatted[32];
  EXPECT_TRUE(format_human_bytes(0, formatted, sizeof(formatted)));
  EXPECT_EQ_STR(formatted, "0 B");
  EXPECT_TRUE(format_human_bytes(1024, formatted, sizeof(formatted)));
  EXPECT_EQ_STR(formatted, "1.0 KB");
  EXPECT_TRUE(format_human_bytes(1536 * 1024, formatted, sizeof(formatted)));
  EXPECT_EQ_STR(formatted, "1.5 MB");
  EXPECT_FALSE(format_human_bytes(1024, formatted, 4));

  char high_bit[] = {'a', (char)0xc3, (char)0xa9, '\n', '\0'};
  char* escaped = output_escape(high_bit, false);
  EXPECT_EQ_STR(escaped, "a\\#303\\#251\\#012");
  free(escaped);
  escaped = output_escape(high_bit, true);
  EXPECT_EQ_STR(escaped, "a\xc3\xa9\\#012");
  free(escaped);

  ProtocolSession safe_session;
  ProtocolSession eight_bit_session;
  protocol_session_init(&safe_session, -1, -1);
  protocol_session_init(&eight_bit_session, -1, -1);
  protocol_session_set_8_bit_output(&safe_session, false);
  protocol_session_set_8_bit_output(&eight_bit_session, true);
  EXPECT_FALSE(safe_session.eight_bit_output);
  EXPECT_TRUE(eight_bit_session.eight_bit_output);

  EscapeThreadArgs safe_args = {false, "x\\#303\\#251\\#012", 0};
  EscapeThreadArgs eight_bit_args = {true, "x\xc3\xa9\\#012", 0};
  thrd_t safe_thread;
  thrd_t eight_bit_thread;
  EXPECT_EQ_INT(thrd_create(&safe_thread, escape_thread, &safe_args), thrd_success);
  EXPECT_EQ_INT(thrd_create(&eight_bit_thread, escape_thread, &eight_bit_args), thrd_success);
  EXPECT_EQ_INT(thrd_join(safe_thread, NULL), thrd_success);
  EXPECT_EQ_INT(thrd_join(eight_bit_thread, NULL), thrd_success);
  EXPECT_FALSE(safe_args.failed);
  EXPECT_FALSE(eight_bit_args.failed);

  // Test str_dup
  const char* dup_null = str_dup(NULL);
  EXPECT_NULL(dup_null);

  char* dup_empty = str_dup("");
  EXPECT_NOT_NULL(dup_empty);
  EXPECT_EQ_STR(dup_empty, "");
  free(dup_empty);

  char* dup_normal = str_dup("hello world");
  EXPECT_NOT_NULL(dup_normal);
  EXPECT_EQ_STR(dup_normal, "hello world");
  free(dup_normal);

  // Test path_cat
  char* cat1 = path_cat("/foo", "/bar");
  EXPECT_NOT_NULL(cat1);
  EXPECT_EQ_STR(cat1, "/foo/bar");
  free(cat1);

  char* cat2 = path_cat("/foo/", "/bar");
  EXPECT_NOT_NULL(cat2);
  EXPECT_EQ_STR(cat2, "/foo/bar");
  free(cat2);

  char* cat3 = path_cat("/foo", "bar");
  EXPECT_NOT_NULL(cat3);
  EXPECT_EQ_STR(cat3, "/foo/bar");
  free(cat3);

  char* cat4 = path_cat("/foo/", "bar");
  EXPECT_NOT_NULL(cat4);
  EXPECT_EQ_STR(cat4, "/foo/bar");
  free(cat4);

  char* cat_empty1 = path_cat("", "/bar");
  EXPECT_NOT_NULL(cat_empty1);
  EXPECT_EQ_STR(cat_empty1, "/bar");
  free(cat_empty1);

  char* cat_empty2 = path_cat("/foo", "");
  EXPECT_NOT_NULL(cat_empty2);
  EXPECT_EQ_STR(cat_empty2, "/foo");
  free(cat_empty2);

  char* cat_null1 = path_cat(NULL, "/bar");
  EXPECT_NOT_NULL(cat_null1);
  EXPECT_EQ_STR(cat_null1, "/bar");
  free(cat_null1);

  char* cat_null2 = path_cat("/foo", NULL);
  EXPECT_NOT_NULL(cat_null2);
  EXPECT_EQ_STR(cat_null2, "/foo");
  free(cat_null2);
}
