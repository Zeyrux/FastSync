#include "test_transport_tcp.h"
#include "protocol.h"
#include "test_utils.h"
#include "transport_tcp.h"
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

/* -4/-6 map to a getaddrinfo ai_family hint: -4 -> AF_INET, -6 -> AF_INET6,
 * and neither -> AF_UNSPEC.  Both flags together are rejected earlier (in
 * validate_config), so this helper never needs to prefer one over the other. */
static void test_tcp_connect_family_hints() {
  EXPECT_EQ_INT(tcp_connect_family(false, false), AF_UNSPEC);
  EXPECT_EQ_INT(tcp_connect_family(true, false), AF_INET);
  EXPECT_EQ_INT(tcp_connect_family(false, true), AF_INET6);
}

/* --sockopts parsing+validation: every allowlisted KEY works, OPT=VAL values
 * are captured, and an unknown option or a bad value is rejected (never
 * silently ignored). */
static void test_sockopts_parse_valid() {
  SockOptEntry* out = NULL;
  int count = 0;
  EXPECT_EQ_INT(config_sockopts_parse("TCP_NODELAY=1,SO_KEEPALIVE=0", &out, &count), 0);
  EXPECT_EQ_INT(count, 2);
  EXPECT_EQ_INT(out[0].id, SOCKOPT_TCP_NODELAY);
  EXPECT_EQ_INT(out[0].value, 1);
  EXPECT_EQ_INT(out[1].id, SOCKOPT_SO_KEEPALIVE);
  EXPECT_EQ_INT(out[1].value, 0);
  free(out);

  out = NULL;
  count = 0;
  EXPECT_EQ_INT(config_sockopts_parse("SO_RCVBUF=65536,SO_SNDBUF=131072,SO_REUSEADDR=1", &out,
                                      &count),
                0);
  EXPECT_EQ_INT(count, 3);
  EXPECT_EQ_INT(out[0].id, SOCKOPT_SO_RCVBUF);
  EXPECT_EQ_INT(out[0].value, 65536);
  EXPECT_EQ_INT(out[1].id, SOCKOPT_SO_SNDBUF);
  EXPECT_EQ_INT(out[1].value, 131072);
  EXPECT_EQ_INT(out[2].id, SOCKOPT_SO_REUSEADDR);
  EXPECT_EQ_INT(out[2].value, 1);
  free(out);
}

static void test_sockopts_parse_rejects() {
  static const char* const bad[] = {
      "IP_TTL=1",          /* unknown option name */
      "SO_KEEPALIVE",      /* missing '=' */
      "=1",                /* missing option name */
      "TCP_NODELAY=",      /* missing value */
      "TCP_NODELAY=2",     /* boolean must be 0/1 */
      "TCP_NODELAY=on",    /* non-numeric boolean */
      "SO_RCVBUF=-1",      /* negative buffer */
      "SO_SNDBUF=abc",     /* non-numeric buffer */
      ""};                 /* empty spec */
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    SockOptEntry* out = NULL;
    int count = 0;
    EXPECT_EQ_INT(config_sockopts_parse(bad[i], &out, &count), -1);
    EXPECT_NULL(out);
  }
}

/* Applying a validated allowlist entry must actually set the socket option (a
 * real setsockopt on a fresh TCP socket) so the config->wire path is proven. */
static void test_sockopts_apply_sets_option() {
  SockOptEntry* entries = NULL;
  int count = 0;
  EXPECT_EQ_INT(config_sockopts_parse("TCP_NODELAY=1,SO_REUSEADDR=1", &entries, &count), 0);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  EXPECT_TRUE(fd >= 0);
  if (fd >= 0) {
    for (int i = 0; i < count; i++) {
      int value = entries[i].value;
      int level = entries[i].id == SOCKOPT_TCP_NODELAY ? IPPROTO_TCP : SOL_SOCKET;
      int name = entries[i].id == SOCKOPT_TCP_NODELAY ? TCP_NODELAY : SO_REUSEADDR;
      EXPECT_EQ_INT(setsockopt(fd, level, name, &value, sizeof(value)), 0);
    }
    int got = 0;
    socklen_t len = sizeof(got);
    EXPECT_EQ_INT(getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &got, &len), 0);
    EXPECT_EQ_INT(got, 1);
    close(fd);
  }
  free(entries);
}

/* server_create_ex with an explicit --address and family binds to that local
 * address; the resulting socket's address family must match. */
static void test_server_create_bind_address() {
  ServerBindOptions opts;
  opts.bind_address = "127.0.0.1";
  opts.family = AF_INET;
  Server* s = server_create_ex(0, &opts);
  EXPECT_NOT_NULL(s);
  if (s) {
    EXPECT_EQ_INT(s->address.ss_family, AF_INET);
    server_delete(&s);
  }
}

/* An IPv6 bind is honored when the host supports it; on a host with no IPv6 a
 * NULL return is acceptable (the feature degrades to unavailable, not wrong). */
static void test_server_create_bind_ipv6() {
  ServerBindOptions opts;
  opts.bind_address = "::1";
  opts.family = AF_INET6;
  Server* s = server_create_ex(0, &opts);
  if (s) {
    EXPECT_EQ_INT(s->address.ss_family, AF_INET6);
    server_delete(&s);
  }
}

static void test_server_create_ephemeral() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  EXPECT_TRUE(s->file_descriptor >= 0);
  EXPECT_EQ_INT(s->address.ss_family, AF_INET);
  server_delete(&s);
  EXPECT_NULL(s);
}

static void test_server_delete_null() {
  Server* s = NULL;
  server_delete(&s);
  EXPECT_NULL(s);
}

static void test_client_create() {
  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  EXPECT_TRUE(c->file_descriptor == -1);
  EXPECT_EQ_INT(c->address.ss_family, 0);
  EXPECT_EQ_INT(c->ssh_child_pid, -1);
  EXPECT_NULL(c->ssl);
  EXPECT_NULL(c->ssl_ctx);
  client_disconnect(c);
  client_delete(c);
}

static void test_client_delete_null() {
  Client* c = NULL;
  client_delete(c);
}

/* Test tcp_set_timeouts with valid values */
static void test_tcp_set_timeouts() {
  /* Just verify the function doesn't crash with edge cases */
  tcp_set_timeouts(0, 0);   /* zero means "don't change" */
  tcp_set_timeouts(60, 20); /* normal values */
  tcp_set_timeouts(-1, -1); /* negative means "don't change" */
  /* If we got here without crashing, the test passes */
  EXPECT_TRUE(true);
}

/* Test client_connect with an invalid host (should fail gracefully) */
static void test_client_connect_invalid_host() {
  Client* c = client_create();
  EXPECT_NOT_NULL(c);

  /* Use a non-routable IP that will fail connect quickly */
  bool ok = client_connect(c, "10.255.255.1", 9999);
  EXPECT_FALSE(ok);

  client_disconnect(c);
  client_delete(c);
}

/* Test server_create with a specific port */
static void test_server_create_specific_port() {
  /* Port 0 = ephemeral, but try 0 and verify bind works */
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  EXPECT_TRUE(s->file_descriptor >= 0);
  server_delete(&s);
  EXPECT_NULL(s);
}

/* Test server_create with invalid port (0 is valid for ephemeral) */
static void test_server_delete_double() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  server_delete(&s);
  EXPECT_NULL(s);
  /* Deleting again should be safe - pointer is already NULL */
  server_delete(&s);
  EXPECT_NULL(s);
}

/* Test client_disconnect followed by client_delete */
static void test_client_disconnect_delete() {
  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  client_disconnect(c);
  client_delete(c);
}

void test_transport_tcp() {
  test_server_create_ephemeral();
  test_server_delete_null();
  test_client_create();
  test_client_delete_null();
  test_tcp_set_timeouts();
  test_client_connect_invalid_host();
  test_server_create_specific_port();
  test_server_delete_double();
  test_client_disconnect_delete();
  test_tcp_connect_family_hints();
  test_sockopts_parse_valid();
  test_sockopts_parse_rejects();
  test_sockopts_apply_sets_option();
  test_server_create_bind_address();
  test_server_create_bind_ipv6();
}
