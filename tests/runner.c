#include "test_array_list.h"
#include "test_chunk.h"
#include "test_change_list.h"
#include "test_checksum.h"
#include "test_client_cli.h"
#include "test_compression.h"
#include "test_config.h"
#include "test_credentials.h"
#include "test_data.h"
#include "test_daemon_conf.h"
#include "test_delay_updates.h"
#include "test_delta.h"
#include "test_file.h"
#include "test_file_sendfile.h"
#include "test_fuzz_smoke.h"
#include "test_glob.h"
#include "test_log.h"
#include "test_metadata.h"
#include "test_motd.h"
#include "test_multiprocessing.h"
#include "test_property.h"
#include "test_protocol.h"
#include "test_queue.h"
#include "test_robustness.h"
#include "test_scanner.h"
#include "test_server.h"
#include "test_server_cli.h"
#include "test_shared_utils.h"
#include "test_stress.h"
#include "test_stop.h"
#include "test_transport_tcp.h"
#include "test_transport_ssh.h"
#include "test_transport_tls.h"
#include "test_utils.h"
#include "test_xattr.h"
#include <stdio.h>
#include <signal.h>

// Define global test state variables
int tests_run = 0;
int tests_failed = 0;
bool current_test_failed = false;

int main() {
  signal(SIGPIPE, SIG_IGN);
  printf("\033[1;36m=== RUNNING UNIT TESTS ===\033[0m\n\n");

  RUN_TEST(test_queue);
  RUN_TEST(test_array_list);
  RUN_TEST(test_shared_utils);
  RUN_TEST(test_chunk);
  RUN_TEST(test_change_list);
  RUN_TEST(test_config);
  RUN_TEST(test_credentials);
  RUN_TEST(test_compression);
  RUN_TEST(test_scanner);
  RUN_TEST(test_checksum);
  RUN_TEST(test_delta);
  RUN_TEST(test_data);
  RUN_TEST(test_protocol);
  RUN_TEST(test_metadata);
  RUN_TEST(test_glob);
  RUN_TEST(test_file);
  RUN_TEST(test_trust_sender);
  RUN_TEST(test_delay_updates);
  RUN_TEST(test_file_sendfile);
  RUN_TEST(test_multiprocessing);
  RUN_TEST(test_log);
  RUN_TEST(test_robustness);
  RUN_TEST(test_stress);
  RUN_TEST(test_stop);
  RUN_TEST(test_property);
  RUN_TEST(test_transport_tcp);
  RUN_TEST(test_transport_ssh);
  RUN_TEST(test_transport_tls);
  RUN_TEST(test_client_cli);
  RUN_TEST(test_server);
  RUN_TEST(test_daemon_conf);
  RUN_TEST(test_motd);
  RUN_TEST(test_server_cli);
  RUN_TEST(test_fuzz_smoke);
  RUN_TEST(test_xattr);

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
