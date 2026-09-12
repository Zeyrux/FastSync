#include "test_array_list.h"
#include "array_list.h"
#include "test_utils.h"
#include <limits.h>
#include <stdlib.h>

static int destroyer_calls = 0;
static void test_destroyer(void* item) {
  destroyer_calls++;
  free(item);
}

static void test_array_list_basic() {
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

/* A capacity that would overflow `capacity * 2` must be refused instead of
 * wrapping into signed-overflow UB; array_list_add surfaces the failure. */
static void test_array_list_extend_overflow_guard() {
  ArrayList* list = array_list_create(NULL);
  EXPECT_NOT_NULL(list);
  list->capacity = INT_MAX / 2 + 1;
  list->size = list->capacity;
  EXPECT_FALSE(array_list_add(list, NULL));
  list->size = 0;
  array_list_delete(list);
}

void test_array_list() {
  test_array_list_basic();
  test_array_list_extend_overflow_guard();
}
