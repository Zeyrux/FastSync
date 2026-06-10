#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

#include "queue.h"

Queue *queue_create(int capacity, void (*destroyer)(void *item)) {
  Queue *queue = (Queue *)malloc(sizeof(Queue));
  if (queue == NULL) {
    perror("FATAL ERROR: Could not allocate memory for queue structure");
    exit(EXIT_FAILURE);
  }

  queue->items = malloc(capacity * sizeof(void *));
  if (queue->items == NULL) {
    perror("FATAL ERROR: Could not allocate memory for queue items");
    free(queue);
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < capacity; ++i) {
    queue->items[i] = NULL;
  }

  queue->capacity = capacity;
  queue->front = 0;
  queue->rear = 0;
  queue->size = 0;
  queue->item_destroyer = destroyer;

  return queue;
}

void queue_destroy(Queue *queue) {
  if (queue == NULL)
    return;

  if (queue->item_destroyer != NULL) {
    for (int i = 0; i < queue->size; ++i) {
      int index = (queue->front + i) % queue->capacity;
      queue->item_destroyer(queue->items[index]);
    }
  }
  free(queue->items);
  free(queue);
}

bool queue_is_empty(Queue *queue) {
  if (queue == NULL)
    return true;
  return queue->size == 0;
}

bool queue_is_full(Queue *queue) {
  if (queue == NULL)
    return false;
  return queue->size == queue->capacity;
}

void queue_double_capacity(Queue *queue) {
  if (queue == NULL)
    return;
  unsigned int new_capacity = queue->capacity * 2;
  if (new_capacity <= 1)
    new_capacity = 100;
  void **new_items = malloc(new_capacity * sizeof(void *));
  if (new_items == NULL) {
    perror("FATAL ERROR: Could not allocate memory for doubling capacity of "
           "queue.");
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < queue->size; i++)
    new_items[i] = queue->items[(i + queue->front) % queue->capacity];
  free(queue->items);
  queue->items = new_items;
  queue->front = 0;
  queue->rear = queue->size;
  queue->capacity = new_capacity;
}

void queue_enqueue(Queue *queue, void *item) {
  if (queue == NULL || item == NULL) {
    perror("ERROR: Cannot enqueue with a null queue or item.\n");
    exit(EXIT_FAILURE);
  }
  if (queue_is_full(queue))
    queue_double_capacity(queue);
  queue->items[queue->rear] = item;
  queue->rear = (queue->rear + 1) % queue->capacity;
  queue->size++;
}

void queue_enqueue_multithreaded(Queue *queue, void *item, mtx_t *mutex,
                                 cnd_t *condition_not_empty,
                                 cnd_t *condition_not_full) {
  mtx_lock(mutex);
  while (queue_is_full(queue))
    cnd_wait(condition_not_full, mutex);
  queue_enqueue(queue, item);
  cnd_signal(condition_not_empty);
  mtx_unlock(mutex);
}

void *queue_dequeue(Queue *queue) {
  if (queue == NULL || queue_is_empty(queue)) {
    perror("ERROR: Could not dequeue from null or empty queue.");
    return NULL;
  }

  void *item = queue->items[queue->front];
  queue->items[queue->front] = NULL;
  queue->front = (queue->front + 1) % queue->capacity;
  queue->size--;
  return item;
}

void *queue_dequeue_multithreaded(Queue *queue, mtx_t *mutex,
                                  cnd_t *condition_not_empty,
                                  cnd_t *condition_not_full,
                                  bool *other_thread_done) {
  mtx_lock(mutex);
  while (queue_is_empty(queue) && !*other_thread_done)
    cnd_wait(condition_not_empty, mutex);
  if (queue_is_empty(queue) && *other_thread_done) {
    mtx_unlock(mutex);
    return NULL;
  }
  void *item = queue_dequeue(queue);
  cnd_signal(condition_not_full);
  mtx_unlock(mutex);
  return item;
}
