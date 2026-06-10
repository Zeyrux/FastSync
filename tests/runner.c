#include "test_array_list.h"
#include "test_chunk.h"
#include "test_config.h"
#include "test_queue.h"
#include "test_shared_utils.h"
#include "test_utils.h"
#include <stdio.h>

// Define global test state variables
int tests_run = 0;
int tests_failed = 0;
bool current_test_failed = false;

int main() {
  printf("\033[1;36m=== RUNNING UNIT TESTS ===\033[0m\n\n");

  RUN_TEST(test_queue);
  RUN_TEST(test_array_list);
  RUN_TEST(test_shared_utils);
  RUN_TEST(test_chunk);
  RUN_TEST(test_config);

  printf("\n\033[1;36m=== TEST SUMMARY ===\033[0m\n");
  printf("Total Tests Run: %d\n", tests_run);
  if (tests_failed > 0) {
    printf("Status: \033[1;31m%d FAILED\033[0m\n", tests_failed);
    return 1;
  } else {
    printf("Status: \033[1;32mALL PASSED\033[0m\n");
    return 0;
  }
}
