#ifndef ARRAY_LIST_H
#define ARRAY_LIST_H

#define INITIAL_ARRAY_SIZE 100

typedef struct ArrayList {
  void **items;
  int size;
  int capacity;
  void (*item_destroyer)(void *item);
} ArrayList;

ArrayList *array_list_create(void (*item_destroyer)(void *item));
void array_list_delete(ArrayList *array_list);
void array_list_clear(ArrayList *array_list);
void array_list_extend(ArrayList *array_list);
void array_list_add(ArrayList *array_list, void *item);
void **array_list_to_array(ArrayList *array_list);

#endif
