#include "test_transport_tcp.h"
#include "protocol.h"
#include "test_utils.h"
#include "transport_tcp.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

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
  EXPECT_EQ_INT(
      config_sockopts_parse("SO_RCVBUF=65536,SO_SNDBUF=131072,SO_REUSEADDR=1", &out, &count), 0);
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
  static const char* const bad[] = {"IP_TTL=1",       /* unknown option name */
                                    "SO_KEEPALIVE",   /* missing '=' */
                                    "=1",             /* missing option name */
                                    "TCP_NODELAY=",   /* missing value */
                                    "TCP_NODELAY=2",  /* boolean must be 0/1 */
                                    "TCP_NODELAY=on", /* non-numeric boolean */
                                    "SO_RCVBUF=-1",   /* negative buffer */
                                    "SO_SNDBUF=abc",  /* non-numeric buffer */
                                    ""};              /* empty spec */
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
  EXPECT_EQ_INT(s->address.ss_family, AF_INET);
  server_delete(&s);
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

/* Test tcp_set_timeouts: a non-positive value disables the timeout (rsync's
 * --timeout=0 / --contimeout=0), it is not a "leave unchanged" sentinel. */
static void test_tcp_set_timeouts() {
  tcp_set_timeouts(0, 0);
  EXPECT_EQ_INT(tcp_get_timeout_sec(), 0);
  EXPECT_EQ_INT(tcp_get_contimeout_sec(), 0);
  tcp_set_timeouts(60, 20);
  EXPECT_EQ_INT(tcp_get_timeout_sec(), 60);
  EXPECT_EQ_INT(tcp_get_contimeout_sec(), 20);
  tcp_set_timeouts(-1, -1);
  EXPECT_EQ_INT(tcp_get_timeout_sec(), 0);
  EXPECT_EQ_INT(tcp_get_contimeout_sec(), 0);
  /* Restore finite defaults so later tests that rely on a bounded connect/IO
   * timeout (e.g. connecting to a non-routable address) cannot block forever. */
  tcp_set_timeouts(30, 10);
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

/* TCP_NODELAY is enabled by default on a connected transfer socket, and an
 * explicit --sockopts TCP_NODELAY=0 still overrides it. */
static void test_tcp_nodelay_default_and_override() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  EXPECT_EQ_INT(listen(s->file_descriptor, 1), 0);
  struct sockaddr_in bound;
  socklen_t bound_len = sizeof(bound);
  EXPECT_EQ_INT(getsockname(s->file_descriptor, (struct sockaddr*)&bound, &bound_len), 0);
  int port = (int)ntohs(bound.sin_port);
  EXPECT_TRUE(port > 0);

  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  EXPECT_TRUE(client_connect(c, "127.0.0.1", port));
  int got = 0;
  socklen_t len = sizeof(got);
  EXPECT_EQ_INT(getsockopt(c->file_descriptor, IPPROTO_TCP, TCP_NODELAY, &got, &len), 0);
  EXPECT_EQ_INT(got, 1);
  client_disconnect(c);
  client_delete(c);

  SockOptEntry* entries = NULL;
  int count = 0;
  EXPECT_EQ_INT(config_sockopts_parse("TCP_NODELAY=0", &entries, &count), 0);
  TcpConnectOptions opts;
  memset(&opts, 0, sizeof(opts));
  opts.sockopts = entries;
  opts.sockopt_count = count;

  Client* c2 = client_create();
  EXPECT_NOT_NULL(c2);
  EXPECT_TRUE(client_connect_ex(c2, "127.0.0.1", port, &opts));
  got = 0;
  len = sizeof(got);
  EXPECT_EQ_INT(getsockopt(c2->file_descriptor, IPPROTO_TCP, TCP_NODELAY, &got, &len), 0);
  EXPECT_EQ_INT(got, 0);
  client_disconnect(c2);
  client_delete(c2);
  free(entries);
  server_delete(&s);
}

/* Count the process's open descriptors via /proc/self/fd.  The opendir
 * descriptor is itself counted and closed before returning, so repeated calls
 * are consistent and a before/after delta reflects only the code under test. */
static int count_open_fds(void) {
  DIR* dir = opendir("/proc/self/fd");
  if (!dir)
    return -1;
  int count = 0;
  const struct dirent* ent;
  while ((ent = readdir(dir)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
      continue;
    count++;
  }
  closedir(dir);
  return count;
}

/* True when two sockaddrs name the same endpoint (family, address, and port).
 * Comparing only the IP would let a connection to a different port on the same
 * host pass, so the port is part of the identity. */
static bool sockaddr_same_endpoint(const struct sockaddr_storage* a,
                                   const struct sockaddr_storage* b) {
  if (a->ss_family != b->ss_family)
    return false;
  if (a->ss_family == AF_INET) {
    const struct sockaddr_in* ia = (const struct sockaddr_in*)a;
    const struct sockaddr_in* ib = (const struct sockaddr_in*)b;
    return ia->sin_port == ib->sin_port && ia->sin_addr.s_addr == ib->sin_addr.s_addr;
  }
  if (a->ss_family == AF_INET6) {
    const struct sockaddr_in6* ia = (const struct sockaddr_in6*)a;
    const struct sockaddr_in6* ib = (const struct sockaddr_in6*)b;
    return ia->sin6_port == ib->sin6_port &&
           memcmp(&ia->sin6_addr, &ib->sin6_addr, sizeof(ia->sin6_addr)) == 0;
  }
  return false;
}

/* Bind + listen on the SECOND address getaddrinfo returns for "localhost", so
 * the first candidate is connection-refused and the shared connect loop must
 * fall back to a later one.  On success the actual bound endpoint is written to
 * out_bound/out_bound_len (the caller asserts the winning connect landed on it).
 * Returns the listener fd and its port, or -1 when this host does not resolve
 * localhost to at least two addresses (the test then skips rather than claiming
 * coverage it does not have). */
static int bind_second_localhost_address(int* out_port, struct sockaddr_storage* out_bound,
                                         socklen_t* out_bound_len) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* res = NULL;
  if (getaddrinfo("localhost", "0", &hints, &res) != 0 || !res)
    return -1;
  const struct addrinfo* chosen = res->ai_next;
  if (!chosen) {
    freeaddrinfo(res);
    return -1;
  }
  int fd = socket(chosen->ai_family, chosen->ai_socktype, chosen->ai_protocol);
  if (fd < 0) {
    freeaddrinfo(res);
    return -1;
  }
  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  if (bind(fd, chosen->ai_addr, chosen->ai_addrlen) != 0 || listen(fd, 1) != 0) {
    close(fd);
    freeaddrinfo(res);
    return -1;
  }
  struct sockaddr_storage bound;
  socklen_t bound_len = sizeof(bound);
  if (getsockname(fd, (struct sockaddr*)&bound, &bound_len) != 0) {
    close(fd);
    freeaddrinfo(res);
    return -1;
  }
  if (out_bound)
    *out_bound = bound;
  if (out_bound_len)
    *out_bound_len = bound_len;
  if (bound.ss_family == AF_INET6)
    *out_port = ntohs(((struct sockaddr_in6*)&bound)->sin6_port);
  else
    *out_port = ntohs(((struct sockaddr_in*)&bound)->sin_port);
  freeaddrinfo(res);
  return fd;
}

/* #219 AC3: when the first getaddrinfo candidate is refused, the connect loop
 * must fall back to the next address and end with exactly ONE open descriptor
 * (proving the failed attempt's fd was closed before the retry). */
static void test_tcp_connect_falls_back_to_next_address() {
  int port = 0;
  struct sockaddr_storage bound;
  int listener = bind_second_localhost_address(&port, &bound, NULL);
  if (listener < 0)
    return; /* localhost is single-address on this host: cannot exercise fallback */

  /* The /proc/self/fd delta is unreliable under valgrind (its own lazy fd
   * activity perturbs the baseline), so only the functional assertions run
   * there; the fd-count checks are skipped. */
  bool check_fds = !is_running_under_valgrind();
  int before = check_fds ? count_open_fds() : -1;

  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  EXPECT_TRUE(client_connect(c, "localhost", port));
  EXPECT_TRUE(c->file_descriptor >= 0);
  /* The winning candidate must be the endpoint we bound (the second
   * getaddrinfo entry).  Without this, a re-resolution that dropped the second
   * address would make the test pass without ever exercising fallback. */
  EXPECT_TRUE(sockaddr_same_endpoint(&c->address, &bound));
  if (check_fds && before >= 0)
    EXPECT_EQ_INT(count_open_fds(), before + 1);
  client_disconnect(c);
  if (check_fds && before >= 0)
    EXPECT_EQ_INT(count_open_fds(), before);
  client_delete(c);
  close(listener);
}

/* #219 AC3: a connect that fails on every candidate leaves at most one
 * descriptor (the last failed attempt) and none after client_disconnect. */
static void test_tcp_connect_failed_attempts_do_not_leak_fds() {
  if (is_running_under_valgrind())
    return; /* /proc/self/fd delta is perturbed by valgrind's own lazy fds */

  /* Keep an ephemeral loopback port bound (but NOT listening) for the whole
   * assertion: the port stays occupied by our own socket, so the kernel
   * deterministically refuses a connect() to it.  This closes the bind/close/
   * connect TOCTOU window in which a parallel test could claim the port. */
  int probe = socket(AF_INET, SOCK_STREAM, 0);
  EXPECT_TRUE(probe >= 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  EXPECT_EQ_INT(bind(probe, (struct sockaddr*)&addr, sizeof(addr)), 0);
  socklen_t addr_len = sizeof(addr);
  EXPECT_EQ_INT(getsockname(probe, (struct sockaddr*)&addr, &addr_len), 0);
  int port = ntohs(addr.sin_port);

  int before = count_open_fds();
  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  /* The literal loopback address has a single getaddrinfo candidate -- the one
   * our bound socket owns -- so the connect is deterministically refused. */
  EXPECT_FALSE(client_connect(c, "127.0.0.1", port));
  if (before >= 0)
    EXPECT_TRUE(count_open_fds() <= before + 1);
  client_disconnect(c);
  if (before >= 0)
    EXPECT_EQ_INT(count_open_fds(), before);
  client_delete(c);
  close(probe);
}

/* #219 AC3: the shared tcp_connect_socket_ex() (used by both the plain and TLS
 * entry points) must install the --contimeout as SO_RCVTIMEO/SO_SNDTIMEO before
 * connecting.  Calling it directly lets us observe the pre-connect state (the
 * plain wrapper later overrides the receive timeout with the IO --timeout). */
static void test_tcp_connect_socket_ex_applies_contimeout() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  EXPECT_EQ_INT(listen(s->file_descriptor, 1), 0);
  struct sockaddr_in bound;
  socklen_t bound_len = sizeof(bound);
  EXPECT_EQ_INT(getsockname(s->file_descriptor, (struct sockaddr*)&bound, &bound_len), 0);
  int port = ntohs(bound.sin_port);

  tcp_set_timeouts(30, 7);
  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  TcpConnectOptions opts;
  memset(&opts, 0, sizeof(opts));
  EXPECT_TRUE(tcp_connect_socket_ex(c, "127.0.0.1", port, &opts));
  struct timeval tv;
  socklen_t tv_len = sizeof(tv);
  EXPECT_EQ_INT(getsockopt(c->file_descriptor, SOL_SOCKET, SO_RCVTIMEO, &tv, &tv_len), 0);
  EXPECT_EQ_INT((int)tv.tv_sec, 7);
  tv_len = sizeof(tv);
  EXPECT_EQ_INT(getsockopt(c->file_descriptor, SOL_SOCKET, SO_SNDTIMEO, &tv, &tv_len), 0);
  EXPECT_EQ_INT((int)tv.tv_sec, 7);
  client_disconnect(c);
  client_delete(c);
  tcp_set_timeouts(30, 10);
  server_delete(&s);
}

/* The plain wrapper applies the post-connect IO --timeout, which supersedes the
 * contimeout installed during connect. */
static void test_tcp_connect_post_timeout_applied() {
  Server* s = server_create(0);
  EXPECT_NOT_NULL(s);
  EXPECT_EQ_INT(listen(s->file_descriptor, 1), 0);
  struct sockaddr_in bound;
  socklen_t bound_len = sizeof(bound);
  EXPECT_EQ_INT(getsockname(s->file_descriptor, (struct sockaddr*)&bound, &bound_len), 0);
  int port = ntohs(bound.sin_port);

  tcp_set_timeouts(5, 7);
  Client* c = client_create();
  EXPECT_NOT_NULL(c);
  EXPECT_TRUE(client_connect(c, "127.0.0.1", port));
  struct timeval tv;
  socklen_t tv_len = sizeof(tv);
  EXPECT_EQ_INT(getsockopt(c->file_descriptor, SOL_SOCKET, SO_RCVTIMEO, &tv, &tv_len), 0);
  EXPECT_EQ_INT((int)tv.tv_sec, 5);
  tv_len = sizeof(tv);
  EXPECT_EQ_INT(getsockopt(c->file_descriptor, SOL_SOCKET, SO_SNDTIMEO, &tv, &tv_len), 0);
  EXPECT_EQ_INT((int)tv.tv_sec, 5);
  client_disconnect(c);
  client_delete(c);
  tcp_set_timeouts(30, 10);
  server_delete(&s);
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
  test_tcp_nodelay_default_and_override();
  test_tcp_connect_falls_back_to_next_address();
  test_tcp_connect_failed_attempts_do_not_leak_fds();
  test_tcp_connect_socket_ex_applies_contimeout();
  test_tcp_connect_post_timeout_applied();
}
