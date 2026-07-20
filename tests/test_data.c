#include "data.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>

static void test_data_create() {
  char* buf = malloc(6);
  EXPECT_NOT_NULL(buf);
  memcpy(buf, "hello", 6);
  Data* d = data_create(buf, 6);
  EXPECT_NOT_NULL(d);
  EXPECT_NOT_NULL(d->data);
  EXPECT_TRUE(d->data == buf);
  EXPECT_EQ_INT((int)d->size, 6);
  data_destroy(d);
}

static void test_data_create_empty() {
  Data* d = data_create_empty(256);
  EXPECT_NOT_NULL(d);
  EXPECT_NOT_NULL(d->data);
  EXPECT_EQ_INT((int)d->size, 256);
  data_destroy(d);
}

static void test_data_create_reserve() {
  Data* d = data_create_reserve(1024);
  EXPECT_NOT_NULL(d);
  EXPECT_NULL(d->data);
  EXPECT_EQ_INT((int)d->size, 1024);
  data_destroy(d);
}

static void test_data_destroy_null() {
  data_destroy(NULL);
}

static void test_data_destroy_normal() {
  Data* d = data_create_empty(128);
  EXPECT_NOT_NULL(d);
  data_destroy(d);
}

void test_data() {
  test_data_create();
  test_data_create_empty();
  test_data_create_reserve();
  test_data_destroy_null();
  test_data_destroy_normal();
}
