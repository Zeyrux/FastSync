#include "test_array_list.h"
#include "test_chunk.h"
#include "test_compression.h"
#include "test_config.h"
#include "test_data.h"
#include "test_delta.h"
#include "test_file.h"
#include "test_file_sendfile.h"
#include "test_glob.h"
#include "test_log.h"
#include "test_metadata.h"
#include "test_multiprocessing.h"
#include "test_property.h"
#include "test_protocol.h"
#include "test_queue.h"
#include "test_robustness.h"
#include "test_scanner.h"
#include "test_shared_utils.h"
#include "test_stress.h"
#include "test_transport_tcp.h"
#include "test_transport_ssh.h"
#include "test_transport_tls.h"
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
  RUN_TEST(test_compression);
  RUN_TEST(test_scanner);
  RUN_TEST(test_delta);
  RUN_TEST(test_data);
  RUN_TEST(test_protocol);
  RUN_TEST(test_metadata);
  RUN_TEST(test_glob);
  RUN_TEST(test_file);
  RUN_TEST(test_file_sendfile);
  RUN_TEST(test_multiprocessing);
  RUN_TEST(test_log);
  RUN_TEST(test_transport_tcp);
  RUN_TEST(test_transport_ssh);
  RUN_TEST(test_transport_tls);
  RUN_TEST(test_robustness);
  RUN_TEST(test_stress);
  RUN_TEST(test_property);
  RUN_TEST(test_transport_tcp);
  RUN_TEST(test_transport_ssh);
  RUN_TEST(test_transport_tls);

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
