#include "test_queue.h"
#include "queue.h"
#include "test_utils.h"
#include <stdlib.h>
#include <threads.h>
#include <stdbool.h>
#include <stdio.h>

static void test_queue_basic() {
  Queue *q = queue_create(10, NULL);
  EXPECT_NOT_NULL(q);
  EXPECT_TRUE(queue_is_empty(q));
  EXPECT_FALSE(queue_is_full(q));

  int *vals[5];
  for (int i = 0; i < 5; i++) {
    vals[i] = malloc(sizeof(int));
    *vals[i] = (i + 1) * 10;
    queue_enqueue(q, vals[i]);
  }

  EXPECT_FALSE(queue_is_empty(q));
  EXPECT_FALSE(queue_is_full(q));
  EXPECT_EQ_INT(q->size, 5);

  int *v1 = (int *)queue_dequeue(q);
  EXPECT_NOT_NULL(v1);
  EXPECT_EQ_INT(*v1, 10);
  free(v1);

  int *v2 = (int *)queue_dequeue(q);
  EXPECT_NOT_NULL(v2);
  EXPECT_EQ_INT(*v2, 20);
  free(v2);

  EXPECT_EQ_INT(q->size, 3);

  int *vals2[3];
  for (int i = 0; i < 3; i++) {
    vals2[i] = malloc(sizeof(int));
    *vals2[i] = (i + 6) * 10;
    queue_enqueue(q, vals2[i]);
  }

  EXPECT_EQ_INT(q->size, 6);

  int expected_vals[] = {30, 40, 50, 60, 70, 80};
  for (int i = 0; i < 6; i++) {
    int *v = (int *)queue_dequeue(q);
    EXPECT_NOT_NULL(v);
    EXPECT_EQ_INT(*v, expected_vals[i]);
    free(v);
  }

  EXPECT_TRUE(queue_is_empty(q));
  queue_destroy(q);
}

static void test_queue_resize() {
  Queue *q = queue_create(3, NULL);
  EXPECT_NOT_NULL(q);
  EXPECT_EQ_INT(q->capacity, 3);

  int a = 1, b = 2, c = 3, d = 4, e = 5;

  queue_enqueue(q, &a);
  queue_enqueue(q, &b);
  queue_enqueue(q, &c);

  EXPECT_TRUE(queue_is_full(q));

  int *v1 = (int *)queue_dequeue(q);
  EXPECT_NOT_NULL(v1);
  EXPECT_EQ_INT(*v1, 1);

  // Now front = 1, rear = 0, size = 2 (wrapped state)
  queue_enqueue(q, &d); 
  EXPECT_TRUE(queue_is_full(q));

  // This enqueue triggers capacity doubling
  queue_enqueue(q, &e); 
  EXPECT_FALSE(queue_is_full(q));
  EXPECT_EQ_INT(q->capacity, 6);
  EXPECT_EQ_INT(q->size, 4);

  // Dequeue all and check order: B, C, D, E
  int *v2 = (int *)queue_dequeue(q);
  EXPECT_NOT_NULL(v2);
  EXPECT_EQ_INT(*v2, 2);

  int *v3 = (int *)queue_dequeue(q);
  EXPECT_NOT_NULL(v3);
  EXPECT_EQ_INT(*v3, 3);

  int *v4 = (int *)queue_dequeue(q);
  EXPECT_NOT_NULL(v4);
  EXPECT_EQ_INT(*v4, 4);

  int *v5 = (int *)queue_dequeue(q);
  EXPECT_NOT_NULL(v5);
  EXPECT_EQ_INT(*v5, 5);

  EXPECT_TRUE(queue_is_empty(q));
  queue_destroy(q);
}

static int destroyer_calls = 0;
static void my_destroyer(void *item) {
  destroyer_calls++;
  free(item);
}

static void test_queue_destroyer() {
  destroyer_calls = 0;
  Queue *q = queue_create(5, my_destroyer);
  EXPECT_NOT_NULL(q);

  for (int i = 0; i < 3; i++) {
    int *val = malloc(sizeof(int));
    *val = i;
    queue_enqueue(q, val);
  }

  int *v = (int *)queue_dequeue(q);
  EXPECT_NOT_NULL(v);
  EXPECT_EQ_INT(*v, 0);
  free(v);

  queue_destroy(q);
  EXPECT_EQ_INT(destroyer_calls, 2);
}

typedef struct {
  Queue *q;
  mtx_t *mutex;
  cnd_t *cnd_empty;
  cnd_t *cnd_full;
  bool done;
  int sum;
} ThreadContext;

static int consumer_func(void *arg) {
  ThreadContext *ctx = (ThreadContext *)arg;
  while (true) {
    int *val = (int *)queue_dequeue_multithreaded(ctx->q, ctx->mutex, ctx->cnd_empty, ctx->cnd_full, &ctx->done);
    if (val == NULL) {
      break;
    }
    ctx->sum += *val;
    free(val);
  }
  return 0;
}

static void test_queue_multithreaded() {
  Queue *q = queue_create(2, NULL);
  mtx_t mutex;
  cnd_t cnd_empty;
  cnd_t cnd_full;

  mtx_init(&mutex, mtx_plain);
  cnd_init(&cnd_empty);
  cnd_init(&cnd_full);

  ThreadContext ctx = {
    .q = q,
    .mutex = &mutex,
    .cnd_empty = &cnd_empty,
    .cnd_full = &cnd_full,
    .done = false,
    .sum = 0
  };

  thrd_t consumer;
  int res = thrd_create(&consumer, consumer_func, &ctx);
  EXPECT_EQ_INT(res, thrd_success);

  for (int i = 1; i <= 100; i++) {
    int *val = malloc(sizeof(int));
    *val = i;
    queue_enqueue_multithreaded(q, val, &mutex, &cnd_empty, &cnd_full);
  }

  mtx_lock(&mutex);
  ctx.done = true;
  cnd_signal(&cnd_empty);
  mtx_unlock(&mutex);

  int join_res;
  thrd_join(consumer, &join_res);

  EXPECT_EQ_INT(ctx.sum, 5050);
  EXPECT_TRUE(queue_is_empty(q));

  queue_destroy(q);
  mtx_destroy(&mutex);
  cnd_destroy(&cnd_empty);
  cnd_destroy(&cnd_full);
}

void test_queue() {
  test_queue_basic();
  test_queue_resize();
  test_queue_destroyer();
  test_queue_multithreaded();
}
