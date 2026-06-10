#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>
#include <threads.h>

typedef struct Queue {
  void **items;
  int front;
  int rear;
  int size;
  int capacity;
  void (*item_destroyer)(void *item);
} Queue;

Queue *queue_create(int capacity, void (*destroyer)(void *item));
void queue_destroy(Queue *queue);
bool queue_is_empty(Queue *queue);
bool queue_is_full(Queue *queue);
void queue_double_capacity(Queue *queue);
void queue_enqueue(Queue *queue, void *item);
void queue_enqueue_multithreaded(Queue *queue, void *item, mtx_t *mutex,
                                 cnd_t *condition_not_empty,
                                 cnd_t *condition_not_full);
void *queue_dequeue(Queue *queue);
void *queue_dequeue_multithreaded(Queue *queue, mtx_t *mutex,
                                  cnd_t *condition_not_empty,
                                  cnd_t *condition_not_full,
                                  bool *other_thread_done);

#endif
