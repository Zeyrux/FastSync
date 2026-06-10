#include "array_list.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ArrayList *array_list_create(void (*item_destroyer)(void *item)) {
  ArrayList *list = (ArrayList *)malloc(sizeof(ArrayList));
  if (list == NULL) {
    perror("FATAL ERROR: Could not allocate memory for array list struct");
    exit(EXIT_FAILURE);
  }

  list->items = malloc(INITIAL_ARRAY_SIZE * sizeof(void *));
  if (list->items == NULL) {
    perror("FATAL ERROR: Could not allocate memory for list items");
    free(list);
    exit(EXIT_FAILURE);
  }
  list->size = 0;
  list->capacity = INITIAL_ARRAY_SIZE;
  list->item_destroyer = item_destroyer;
  return list;
}

void array_list_delete(ArrayList *array_list) {
  if (array_list == NULL)
    return;
  if (array_list->item_destroyer != NULL) {
    for (int i = 0; i < array_list->size; i++) {
      array_list->item_destroyer(array_list->items[i]);
      array_list->items[i] = NULL;
    }
  }
  free(array_list->items);
  free(array_list);
}

void array_list_clear(ArrayList *array_list) {
  if (array_list == NULL)
    return;
  for (int i = 0; i < array_list->size; i++)
    array_list->items[i] = NULL;
  array_list->size = 0;
}

void array_list_extend(ArrayList *array_list) {
  if (array_list == NULL)
    return;
  int new_capacity = array_list->capacity * 2;
  if (new_capacity == 0)
    new_capacity = INITIAL_ARRAY_SIZE;
  array_list->items = realloc(array_list->items, new_capacity * sizeof(void *));
  if (array_list->items == NULL) {
    perror("FATAL ERROR: Could not reallocate memory for array list struct");
    exit(EXIT_FAILURE);
  }
  array_list->capacity = new_capacity;
}

void array_list_add(ArrayList *array_list, void *item) {
  if (array_list == NULL) {
    return;
  }
  if (array_list->capacity == array_list->size) {
    array_list_extend(array_list);
  }
  array_list->items[array_list->size] = item;
  array_list->size += 1;
}

void **array_list_to_array(ArrayList *array_list) {
  if (array_list == NULL) {
    return NULL;
  }
  void **array = malloc(array_list->size * sizeof(void *));
  if (array == NULL) {
    perror("Could not malloc space for array from array list!");
    return NULL;
  }
  memcpy(array, array_list->items, array_list->size * sizeof(void *));
  return array;
}
