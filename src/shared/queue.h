#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>
#include <stdatomic.h>
#include <threads.h>

typedef struct Queue {
  void** items;
  int front;
  int rear;
  int size;
  int capacity;
  void (*item_destroyer)(void* item);
} Queue;

Queue* queue_create(int capacity, void (*destroyer)(void* item));
void queue_destroy(Queue* queue);
bool queue_is_empty(const Queue* queue);
bool queue_is_full(const Queue* queue);
bool queue_enqueue(Queue* queue, void* item);
bool queue_enqueue_multithreaded(Queue* queue, void* item, mtx_t* mutex, cnd_t* condition_not_empty,
                                 cnd_t* condition_not_full);
bool queue_enqueue_multithreaded_cancel(Queue* queue, void* item, mtx_t* mutex,
                                        cnd_t* condition_not_empty, cnd_t* condition_not_full,
                                        const atomic_bool* cancelled);
void* queue_dequeue(Queue* queue);
void* queue_dequeue_multithreaded(Queue* queue, mtx_t* mutex, cnd_t* condition_not_empty,
                                  cnd_t* condition_not_full, const bool* other_thread_done);

/* LIFO stack operations over the same ring buffer.  queue_push() is the enqueue
   primitive; queue_pop() removes from the rear, so a sequence of pushes is
   returned in reverse order.  Used by the sequential scanner's depth-first
   traversal. */
bool queue_push(Queue* queue, void* item);
void* queue_pop(Queue* queue);

#endif
