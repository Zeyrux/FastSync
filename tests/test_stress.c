#include "test_stress.h"
#include "test_utils.h"
#include "queue.h"
#include <threads.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#define ITEMS_PER_PRODUCER 2500
#define NUM_PRODUCERS 4
#define NUM_CONSUMERS 4
#define TOTAL_ITEMS (ITEMS_PER_PRODUCER * NUM_PRODUCERS)

typedef struct {
  Queue* q;
  mtx_t* mutex;
  cnd_t* cnd_empty;
  cnd_t* cnd_full;
  int producer_id;
} ProducerCtx;

typedef struct {
  Queue* q;
  mtx_t* mutex;
  cnd_t* cnd_empty;
  cnd_t* cnd_full;
  volatile int* producers_remaining;
  volatile bool* producers_done;
} ConsumerMPMC;

static int mpmc_producer_func(void* arg) {
  ProducerCtx* ctx = (ProducerCtx*)arg;
  for (int i = 1; i <= ITEMS_PER_PRODUCER; i++) {
    int* val = malloc(sizeof(int));
    *val = ctx->producer_id * ITEMS_PER_PRODUCER + i;
    queue_enqueue_multithreaded(ctx->q, val, ctx->mutex, ctx->cnd_empty, ctx->cnd_full);
  }
  return 0;
}

static int mpmc_consumer_func(void* arg) {
  ConsumerMPMC* ctx = (ConsumerMPMC*)arg;
  while (true) {
    int* val = (int*)queue_dequeue_multithreaded(ctx->q, ctx->mutex, ctx->cnd_empty, ctx->cnd_full,
                                                 (const bool*)ctx->producers_done);
    if (val == NULL)
      break;
    free(val);
  }
  return 0;
}

static void test_queue_mpmc_stress() {
  Queue* q = queue_create(16, NULL);
  mtx_t mutex;
  cnd_t cnd_empty;
  cnd_t cnd_full;

  mtx_init(&mutex, mtx_plain);
  cnd_init(&cnd_empty);
  cnd_init(&cnd_full);

  volatile int producers_remaining = NUM_PRODUCERS;
  volatile bool producers_done = false;

  ConsumerMPMC cctx = {.q = q,
                       .mutex = &mutex,
                       .cnd_empty = &cnd_empty,
                       .cnd_full = &cnd_full,
                       .producers_remaining = &producers_remaining,
                       .producers_done = &producers_done};

  thrd_t consumers[NUM_CONSUMERS];
  for (int i = 0; i < NUM_CONSUMERS; i++) {
    int res = thrd_create(&consumers[i], mpmc_consumer_func, &cctx);
    EXPECT_EQ_INT(res, thrd_success);
  }

  ProducerCtx pctxs[NUM_PRODUCERS];
  thrd_t producers[NUM_PRODUCERS];
  for (int i = 0; i < NUM_PRODUCERS; i++) {
    pctxs[i] = (ProducerCtx){
        .q = q, .mutex = &mutex, .cnd_empty = &cnd_empty, .cnd_full = &cnd_full, .producer_id = i};
    int res = thrd_create(&producers[i], mpmc_producer_func, &pctxs[i]);
    EXPECT_EQ_INT(res, thrd_success);
  }

  for (int i = 0; i < NUM_PRODUCERS; i++) {
    thrd_join(producers[i], NULL);
    mtx_lock(&mutex);
    producers_remaining--;
    if (producers_remaining == 0)
      producers_done = true;
    cnd_broadcast(&cnd_empty);
    mtx_unlock(&mutex);
  }

  for (int i = 0; i < NUM_CONSUMERS; i++) {
    thrd_join(consumers[i], NULL);
  }

  EXPECT_TRUE(queue_is_empty(q));

  queue_destroy(q);
  mtx_destroy(&mutex);
  cnd_destroy(&cnd_empty);
  cnd_destroy(&cnd_full);
}

typedef struct {
  Queue* q;
  mtx_t* mutex;
  cnd_t* cnd_empty;
  cnd_t* cnd_full;
  bool done;
  int items_sent;
  int items_received;
} BackpressureCtx;

static int bp_producer_func(void* arg) {
  BackpressureCtx* ctx = (BackpressureCtx*)arg;
  for (int i = 0; i < 5; i++) {
    int* val = malloc(sizeof(int));
    *val = i + 1;
    queue_enqueue_multithreaded(ctx->q, val, ctx->mutex, ctx->cnd_empty, ctx->cnd_full);
    ctx->items_sent++;
  }
  return 0;
}

static int bp_consumer_func(void* arg) {
  BackpressureCtx* ctx = (BackpressureCtx*)arg;
  while (ctx->items_received < 5) {
    int* val = (int*)queue_dequeue_multithreaded(ctx->q, ctx->mutex, ctx->cnd_empty, ctx->cnd_full,
                                                 &ctx->done);
    if (val == NULL)
      break;
    ctx->items_received++;
    free(val);
  }
  return 0;
}

static void test_queue_backpressure() {
  Queue* q = queue_create(1, NULL);
  mtx_t mutex;
  cnd_t cnd_empty;
  cnd_t cnd_full;

  mtx_init(&mutex, mtx_plain);
  cnd_init(&cnd_empty);
  cnd_init(&cnd_full);

  BackpressureCtx ctx = {.q = q,
                         .mutex = &mutex,
                         .cnd_empty = &cnd_empty,
                         .cnd_full = &cnd_full,
                         .items_sent = 0,
                         .items_received = 0,
                         .done = false};

  thrd_t producer, consumer;
  int res;

  res = thrd_create(&consumer, bp_consumer_func, &ctx);
  EXPECT_EQ_INT(res, thrd_success);

  res = thrd_create(&producer, bp_producer_func, &ctx);
  EXPECT_EQ_INT(res, thrd_success);

  thrd_join(producer, NULL);

  mtx_lock(&mutex);
  ctx.done = true;
  cnd_signal(&cnd_empty);
  mtx_unlock(&mutex);

  thrd_join(consumer, NULL);

  EXPECT_EQ_INT(ctx.items_sent, 5);
  EXPECT_EQ_INT(ctx.items_received, 5);
  EXPECT_TRUE(queue_is_empty(q));

  queue_destroy(q);
  mtx_destroy(&mutex);
  cnd_destroy(&cnd_empty);
  cnd_destroy(&cnd_full);
}

static void test_queue_rapid_create_destroy() {
  for (int i = 0; i < 100; i++) {
    Queue* q = queue_create(4, free);
    EXPECT_NOT_NULL(q);

    for (int j = 0; j < 3; j++) {
      int* val = malloc(sizeof(int));
      *val = j;
      queue_enqueue(q, val);
    }

    while (!queue_is_empty(q)) {
      void* v = queue_dequeue(q);
      free(v);
    }

    queue_destroy(q);
  }
}

void test_stress() {
  test_queue_mpmc_stress();
  test_queue_backpressure();
  test_queue_rapid_create_destroy();
}
