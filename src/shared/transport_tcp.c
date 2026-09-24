#include "transport_tcp.h"
#include "daemon_limits.h"
#include "log.h"
#include "protocol.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t g_active_connections = 0;

/* Shared registry installed on the active server; the SIGCHLD handler needs a
 * file-scope pointer so it can reclaim the dead child's slot.  Set once by
 * accept_loop before the fork loop (single-threaded parent). */
static DaemonLimitRegistry* g_limit_registry = NULL;
/* Slot reserved by the parent for the connection child currently being forked.
 * Written before fork(), read by the child (which inherits the value). */
static int g_current_slot = DAEMON_LIMITS_NO_SLOT;

static void tcp_apply_socket_timeout(int fd);
static void tcp_enable_nodelay_default(int fd, int family);

static void sigchld_handler(int sig) {
  (void)sig;
  int saved_errno = errno;
  pid_t pid;
  while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
    if (g_active_connections > 0)
      g_active_connections--;
    daemon_limits_reclaim_pid(g_limit_registry, (long)pid);
  }
  /* Re-derive the occupancy counters once for the whole reap batch.  The slot
   * table is the source of truth, so this self-heals any count leaked by a child
   * SIGKILLed mid-registration.  Atomics only: async-signal-safe. */
  if (g_limit_registry)
    daemon_limits_recompute(g_limit_registry);
  errno = saved_errno;
}

/* Reset a signal to its default action with sigaction (preferred over
 * signal(3), whose semantics are implementation-defined).  Used in the forked
 * child before it can spawn any thread. */
static void reset_signal_default(int sig) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_DFL;
  sigemptyset(&action.sa_mask);
  sigaction(sig, &action, NULL);
}

/* Map a listen socket's address to its numeric port for logging, independent
 * of whether it is an IPv4 or IPv6 sockaddr. */
static unsigned short server_address_port(const struct sockaddr_storage* addr) {
  if (addr->ss_family == AF_INET6)
    return ntohs(((const struct sockaddr_in6*)addr)->sin6_port);
  if (addr->ss_family == AF_INET)
    return ntohs(((const struct sockaddr_in*)addr)->sin_port);
  return 0;
}

Server* server_create_ex(int port, const ServerBindOptions* bind_opts) {
  Server* server = (Server*)malloc(sizeof(Server));
  if (server == NULL) {
    log_perror("Could not allocate space for Server");
    return NULL;
  }

  /* Effective address family.  preserve the historical default (IPv4 wildcard)
   * when neither --address nor -4/-6 were given. */
  int family = (bind_opts && bind_opts->family != AF_UNSPEC) ? bind_opts->family : AF_INET;
  const char* bind_address = bind_opts ? bind_opts->bind_address : NULL;

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  struct addrinfo* result = NULL;
  int err = getaddrinfo(bind_address, port_str, &hints, &result);
  if (err != 0 || result == NULL) {
    char* escaped = bind_address ? output_escape(bind_address, false) : NULL;
    fprintf(stderr, "Could not resolve bind address %s (%s)\n", escaped ? escaped : "(wildcard)",
            gai_strerror(err));
    free(escaped);
    free(server);
    return NULL;
  }

  int file_descriptor = -1;
  struct addrinfo* rp;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    file_descriptor = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (file_descriptor < 0)
      continue;
    int opt = 1;
    if (setsockopt(file_descriptor, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
      log_perror("Error setting a socket option!");
      close(file_descriptor);
      file_descriptor = -1;
      continue;
    }
    if (bind(file_descriptor, rp->ai_addr, (socklen_t)rp->ai_addrlen) == 0) {
      memset(&server->address, 0, sizeof(server->address));
      memcpy(&server->address, rp->ai_addr, rp->ai_addrlen);
      server->address_length = rp->ai_addrlen;
      break;
    }
    log_perror("Could not bind server address");
    close(file_descriptor);
    file_descriptor = -1;
  }
  freeaddrinfo(result);

  if (file_descriptor < 0) {
    free(server);
    return NULL;
  }

  server->file_descriptor = file_descriptor;
  server->ssl_ctx = NULL;
  server->max_connections = SERVER_DEFAULT_MAX_CONNECTIONS;
  server->active_connections = 0;
  server->limit_registry = NULL;

  return server;
}

Server* server_create(int port) {
  return server_create_ex(port, NULL);
}

void server_set_max_connections(Server* server, unsigned int max_connections) {
  if (server && max_connections > 0)
    server->max_connections = max_connections;
}

void server_set_limit_registry(Server* server, struct DaemonLimitRegistry* registry) {
  if (server)
    server->limit_registry = registry;
}

int transport_tcp_current_slot(void) {
  return g_current_slot;
}

void server_delete(Server** server) {
  if (server == NULL || *server == NULL)
    return;
  close((*server)->file_descriptor);
  if ((*server)->ssl_ctx) {
    SSL_CTX_free((*server)->ssl_ctx);
    (*server)->ssl_ctx = NULL;
  }
  free(*server);
  *server = NULL;
}

static void accept_loop(Server* server, void (*child_fn)(int, void*), void* child_ctx,
                        const char* log_fmt) {
  if (listen(server->file_descriptor, SOMAXCONN) < 0) {
    log_perror("Could not listen on port!");
    return;
  }
  /* SIGCHLD via sigaction (not signal(3)); SA_RESTART keeps accept(2) from
   * failing with EINTR, and SA_NOCLDSTOP only notifies on child exit.  The
   * accept loop is single-threaded at this point, so installing here cannot race
   * a worker thread. */
  struct sigaction chld_action;
  memset(&chld_action, 0, sizeof(chld_action));
  chld_action.sa_handler = sigchld_handler;
  sigemptyset(&chld_action.sa_mask);
  chld_action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  sigaction(SIGCHLD, &chld_action, NULL);
  g_limit_registry = server->limit_registry;
  while (1) {
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    int fd = accept(server->file_descriptor, (struct sockaddr*)&client_addr, &client_len);
    if (fd < 0) {
      log_perror("Could not accept the connection");
      continue;
    }
    tcp_apply_socket_timeout(fd);
    tcp_enable_nodelay_default(fd, client_addr.ss_family);
    char peer[128];
    if (!utils_sockaddr_to_string((const struct sockaddr*)&client_addr, peer, sizeof(peer)))
      snprintf(peer, sizeof(peer), "unknown");
    if ((unsigned int)g_active_connections >= server->max_connections) {
      log_message(LOG_LEVEL_WARNING, "Max connections (%u) reached, rejecting %s",
                  server->max_connections, peer);
      close(fd);
      continue;
    }
    int slot = DAEMON_LIMITS_NO_SLOT;
    if (server->limit_registry) {
      slot = daemon_limits_claim_slot(server->limit_registry);
      if (slot == DAEMON_LIMITS_NO_SLOT) {
        /* The global cap bounds live children, so this only happens when the
         * fixed registry is smaller than the configured cap; fail closed. */
        log_message(LOG_LEVEL_WARNING, "Connection registry slots exhausted (max %u), rejecting %s",
                    server->max_connections, peer);
        close(fd);
        continue;
      }
    }
    log_message(LOG_LEVEL_INFO, "%s from %s", log_fmt, peer);
    g_current_slot = slot;
    /* Block SIGCHLD across fork() and the parent's pid publication: a child
     * that exits immediately must not be reaped before its slot records its
     * pid, which would leak the slot and its module/source counts.  Use
     * pthread_sigmask rather than sigprocmask so the behavior is well defined
     * even if this process ever gains threads: the mask is per-thread, the fork
     * copies only the calling thread, and the child inherits this thread's
     * blocked mask until it restores `previous` below.  No thread exists yet at
     * this point, and none is created before the mask is restored, so the
     * critical window is race-free. */
    sigset_t blocked;
    sigset_t previous;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &blocked, &previous);
    pid_t pid = fork();
    if (pid == 0) {
      pthread_sigmask(SIG_SETMASK, &previous, NULL);
      /* Connection children must not run the parent's global cleanup(): it
       * frees state (credentials / daemon conf) that the child's worker
       * threads may still be reading and closes fd numbers the child could
       * already have reused.  Reset the inherited handlers so a signal
       * terminates the child directly; SIGCHLD is reset too since a child
       * must never reap the parent's children.  This runs before the child
       * spawns any thread, so it cannot race one. */
      reset_signal_default(SIGINT);
      reset_signal_default(SIGTERM);
      reset_signal_default(SIGCHLD);
      close(server->file_descriptor);
      child_fn(fd, child_ctx);
      _exit(0);
    } else if (pid > 0) {
      g_active_connections++;
      if (server->limit_registry)
        daemon_limits_set_slot_pid(server->limit_registry, slot, (long)pid);
    } else if (server->limit_registry) {
      /* fork() failed: release the reservation so the slot is not leaked. */
      daemon_limits_reclaim_slot(server->limit_registry, slot);
    }
    pthread_sigmask(SIG_SETMASK, &previous, NULL);
    close(fd);
  }
}

struct plain_ctx {
  void (*handler)(int);
};

static void plain_child_fn(int fd, void* ctx) {
  ((struct plain_ctx*)ctx)->handler(fd);
  /* handler() never closes the connection fd; the child owns its single
   * close here after the handler has fully torn down. */
  close(fd);
}

bool server_listen(Server* server, void (*handler)(int file_descriptor)) {
  log_message(LOG_LEVEL_INFO, "Start Listening on Port: %d", server_address_port(&server->address));
  struct plain_ctx ctx = {handler};
  accept_loop(server, plain_child_fn, &ctx, "Received Connection");
  return true;
}

void server_accept_loop(Server* server, void (*child_fn)(int, void*), void* child_ctx,
                        const char* log_fmt) {
  log_message(LOG_LEVEL_INFO, "Start TLS Listening on Port: %d",
              server_address_port(&server->address));
  accept_loop(server, child_fn, child_ctx, log_fmt);
}

/* rsync defaults: --timeout=0 (disabled) and --contimeout=60.  A non-positive
 * value means "no timeout" rather than "leave the built-in value in place". */
static int g_timeout_sec = 0;
static int g_contimeout_sec = 60;

void tcp_set_timeouts(int timeout_sec, int contimeout_sec) {
  g_timeout_sec = timeout_sec > 0 ? timeout_sec : 0;
  g_contimeout_sec = contimeout_sec > 0 ? contimeout_sec : 0;
}

int tcp_get_contimeout_sec(void) {
  return g_contimeout_sec;
}

int tcp_get_timeout_sec(void) {
  return g_timeout_sec;
}

static void tcp_apply_socket_timeout(int fd) {
  /* timeout 0 means no timeout: leave the socket in its default (blocking)
   * mode instead of installing a zero SO_RCVTIMEO/SO_SNDTIMEO. */
  if (g_timeout_sec <= 0)
    return;
  struct timeval tv;
  tv.tv_sec = g_timeout_sec;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Enable TCP_NODELAY by default on a transfer socket: the protocol emits many
 * small messages and Nagle's algorithm would otherwise coalesce/delay them.
 * Best-effort only: the family guard keeps this to IP/TCP sockets, and a
 * setsockopt failure is ignored.  A caller-provided --sockopts TCP_NODELAY=0
 * is applied afterwards on the connect path, so an explicit user choice still
 * wins. */
static void tcp_enable_nodelay_default(int fd, int family) {
  if (family != AF_INET && family != AF_INET6)
    return;
  int value = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
}

Client* client_create() {
  Client* client = (Client*)malloc(sizeof(Client));
  if (client == NULL) {
    return NULL;
  }
  client->file_descriptor = -1;
  memset(&client->address, 0, sizeof(client->address));
  client->address_length = sizeof(client->address);
  client->ssh_child_pid = -1;
  client->ssl = NULL;
  client->ssl_ctx = NULL;
  return client;
}

int tcp_connect_family(bool ipv4, bool ipv6) {
  if (ipv4)
    return AF_INET;
  if (ipv6)
    return AF_INET6;
  return AF_UNSPEC;
}

/* The socket-option apply layer maps an allowlist SockOptId to the concrete
 * level/optname pair and applies it with the correct (int) value type.  The
 * allowlist bounds what can ever reach this point, so the id-to-name mapping
 * is total for every SOCKOPT_* value. */
static int tcp_sockopt_level(SockOptId id) {
  return id == SOCKOPT_TCP_NODELAY ? IPPROTO_TCP : SOL_SOCKET;
}

static int tcp_sockopt_name(SockOptId id) {
  switch (id) {
  case SOCKOPT_TCP_NODELAY:
    return TCP_NODELAY;
  case SOCKOPT_SO_KEEPALIVE:
    return SO_KEEPALIVE;
  case SOCKOPT_SO_RCVBUF:
    return SO_RCVBUF;
  case SOCKOPT_SO_SNDBUF:
    return SO_SNDBUF;
  case SOCKOPT_SO_REUSEADDR:
    return SO_REUSEADDR;
  default:
    return -1;
  }
}

static bool tcp_apply_sockopts(int fd, const SockOptEntry* sockopts, int sockopt_count) {
  for (int i = 0; i < sockopt_count; i++) {
    int name = tcp_sockopt_name(sockopts[i].id);
    if (name < 0) { /* unreachable for a validated allowlist, but stay defensive */
      log_message(LOG_LEVEL_ERROR, "Unsupported socket option requested");
      return false;
    }
    int value = sockopts[i].value;
    if (setsockopt(fd, tcp_sockopt_level(sockopts[i].id), name, &value, sizeof(value)) != 0) {
      log_perror("Could not apply socket option");
      return false;
    }
  }
  return true;
}

/* Resolve an explicit --address source/bind address into a sockaddr once, so
 * the per-candidate connect loop can bind() the outgoing socket to it.  The
 * family follows the same -4/-6 hints as the destination resolution, so a
 * forced family selects a matching local address; returns 0 on success. */
static int resolve_bind_address(const char* addr, int family, struct sockaddr_storage* out,
                                socklen_t* out_len, int* out_family) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family; /* AF_UNSPEC when no -4/-6 */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  struct addrinfo* result = NULL;
  int err = getaddrinfo(addr, NULL, &hints, &result);
  if (err != 0 || result == NULL) {
    char* escaped = output_escape(addr, false);
    fprintf(stderr, "Could not resolve --address %s (%s)\n",
            escaped ? escaped : "<allocation failed>", gai_strerror(err));
    free(escaped);
    return -1;
  }
  struct addrinfo* rp;
  bool found = false;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    if (family != AF_UNSPEC && rp->ai_family != family)
      continue;
    memcpy(out, rp->ai_addr, rp->ai_addrlen);
    *out_len = (socklen_t)rp->ai_addrlen;
    *out_family = rp->ai_family;
    found = true;
    break;
  }
  freeaddrinfo(result);
  return found ? 0 : -1;
}

bool tcp_connect_socket_ex(Client* client, const char* host, int port,
                           const TcpConnectOptions* opts) {
  struct addrinfo hints;
  struct addrinfo* result;
  memset(&hints, 0, sizeof(hints));
  /* TcpConnectOptions.family already encodes -4/-6 (or AF_UNSPEC); feed it
   * straight into the getaddrinfo hints so the destination resolution is
   * (optionally) pinned to one address family. */
  hints.ai_family = opts ? opts->family : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  int err = getaddrinfo(host, port_str, &hints, &result);
  if (err != 0 || result == NULL) {
    char* escaped_host = output_escape(host, false);
    fprintf(stderr, "Could not resolve host: %s (%s)\n",
            escaped_host ? escaped_host : "<allocation failed>", gai_strerror(err));
    free(escaped_host);
    return false;
  }

  /* Resolve the optional --address source address once up front. */
  struct sockaddr_storage bind_addr;
  socklen_t bind_addr_len = 0;
  int bind_addr_family = 0;
  if (opts && opts->bind_address) {
    if (resolve_bind_address(opts->bind_address, hints.ai_family, &bind_addr, &bind_addr_len,
                             &bind_addr_family) != 0) {
      freeaddrinfo(result);
      return false;
    }
  }

  struct addrinfo* rp;
  bool connected = false;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    if (client->file_descriptor >= 0)
      close(client->file_descriptor);

    client->file_descriptor = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (client->file_descriptor < 0)
      continue;

    /* Default first; a user --sockopts TCP_NODELAY=0 applied below overrides. */
    tcp_enable_nodelay_default(client->file_descriptor, rp->ai_family);

    if (opts && opts->sockopt_count > 0 &&
        !tcp_apply_sockopts(client->file_descriptor, opts->sockopts, opts->sockopt_count)) {
      close(client->file_descriptor);
      client->file_descriptor = -1;
      break;
    }

    /* --contimeout=0 disables the connect timeout: skip the pre-connect socket
     * timeouts entirely. */
    if (g_contimeout_sec > 0) {
      struct timeval ct;
      ct.tv_sec = g_contimeout_sec;
      ct.tv_usec = 0;
      setsockopt(client->file_descriptor, SOL_SOCKET, SO_RCVTIMEO, &ct, sizeof(ct));
      setsockopt(client->file_descriptor, SOL_SOCKET, SO_SNDTIMEO, &ct, sizeof(ct));
    }

    if (bind_addr_family != 0) {
      if (rp->ai_family != bind_addr_family) {
        close(client->file_descriptor);
        client->file_descriptor = -1;
        continue;
      }
      if (bind(client->file_descriptor, (struct sockaddr*)&bind_addr, bind_addr_len) != 0) {
        log_perror("Could not bind outgoing socket to --address");
        close(client->file_descriptor);
        client->file_descriptor = -1;
        break;
      }
    }

    memcpy(&client->address, rp->ai_addr, rp->ai_addrlen);
    client->address_length = rp->ai_addrlen;

    if (connect(client->file_descriptor, (struct sockaddr*)&client->address,
                client->address_length) == 0) {
      connected = true;
      break;
    }
  }
  freeaddrinfo(result);

  if (!connected) {
    log_perror("Could not connect to Server!");
    return false;
  }

  return true;
}

bool client_connect_ex(Client* client, const char* host, int port, const TcpConnectOptions* opts) {
  if (!tcp_connect_socket_ex(client, host, port, opts))
    return false;
  tcp_apply_socket_timeout(client->file_descriptor);
  return true;
}

bool client_connect(Client* client, const char* host, int port) {
  if (!tcp_connect_socket_ex(client, host, port, NULL))
    return false;
  tcp_apply_socket_timeout(client->file_descriptor);
  return true;
}

void client_disconnect(Client* client) {
  if (client->ssl) {
    SSL_shutdown(client->ssl);
    SSL_free(client->ssl);
    client->ssl = NULL;
    io_set_ssl(NULL);
  }
  if (client->file_descriptor >= 0) {
    close(client->file_descriptor);
    client->file_descriptor = -1;
  }
  if (client->ssh_child_pid > 0) {
    int status;
    waitpid(client->ssh_child_pid, &status, 0);
    client->ssh_child_pid = -1;
  }
}

void client_delete(Client* client) {
  if (client == NULL)
    return;
  if (client->ssl_ctx) {
    SSL_CTX_free(client->ssl_ctx);
    client->ssl_ctx = NULL;
  }
  free(client);
}
