#include "test_array_list.h"
#include "array_list.h"
#include "test_utils.h"
#include <stdlib.h>

static int destroyer_calls = 0;
static void test_destroyer(void* item) {
  destroyer_calls++;
  free(item);
}

void test_array_list() {
  ArrayList* list = array_list_create(free);
  EXPECT_NOT_NULL(list);
  EXPECT_EQ_INT(list->size, 0);
  EXPECT_EQ_INT(list->capacity, 100);

  // Test adding
  int* val1 = malloc(sizeof(int));
  if (!val1)
    return;
  *val1 = 42;
  array_list_add(list, val1);
  EXPECT_EQ_INT(list->size, 1);
  EXPECT_EQ_INT(*(int*)list->items[0], 42);

  // Test extending capacity
  // Initial capacity is 100. Let's add 105 elements.
  for (int i = 0; i < 105; i++) {
    int* val = malloc(sizeof(int));
    if (!val)
      return;
    *val = i;
    array_list_add(list, val);
  }
  EXPECT_EQ_INT(list->size, 106);
  EXPECT_EQ_INT(list->capacity, 200); // 100 * 2

  // Verify contents
  EXPECT_EQ_INT(*(int*)list->items[0], 42);
  EXPECT_EQ_INT(*(int*)list->items[1], 0);
  EXPECT_EQ_INT(*(int*)list->items[105], 104);

  // Test array conversion
  void** arr = array_list_to_array(list);
  EXPECT_NOT_NULL(arr);
  EXPECT_EQ_INT(*(int*)arr[0], 42);
  EXPECT_EQ_INT(*(int*)arr[105], 104);
  free(arr);

  // Delete list, verifying the destroyer is called 106 times
  destroyer_calls = 0;
  list->item_destroyer = test_destroyer;
  array_list_delete(list);
  EXPECT_EQ_INT(destroyer_calls, 106);
}
