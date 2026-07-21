#include "test_transport_ssh.h"
#include "test_utils.h"
#include "transport_ssh.h"

static void test_ssh_connect_invalid_dest_no_colon() {
  /* cppcheck-suppress constVariablePointer */
  Client* c = client_connect_ssh("/path/to/dest", 22);
  EXPECT_NULL(c);
}

static void test_ssh_connect_invalid_dest_empty() {
  /* cppcheck-suppress constVariablePointer */
  Client* c = client_connect_ssh("", 22);
  EXPECT_NULL(c);
}

void test_transport_ssh() {
  test_ssh_connect_invalid_dest_no_colon();
  test_ssh_connect_invalid_dest_empty();
}
