#ifndef TRANSPORT_TCP_H
#define TRANSPORT_TCP_H

#include "config.h"
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct Server {
  struct sockaddr_storage address;
  unsigned int address_length;
  int file_descriptor;
  void* ssl_ctx;
  unsigned int max_connections;
  volatile unsigned int active_connections;
} Server;

typedef struct Client {
  struct sockaddr_storage address;
  unsigned int address_length;
  int file_descriptor;
  pid_t ssh_child_pid;
  void* ssl;
  void* ssl_ctx;
} Client;

/* Options controlling the server's listening bind (/--address, -4/-6).  When
 * bind_address is NULL and family is AF_UNSPEC the existing default is used:
 * an IPv4 wildcard (INADDR_ANY). */
typedef struct {
  const char* bind_address; /* explicit address to bind, or NULL for wildcard */
  int family;               /* AF_INET / AF_INET6, or AF_UNSPEC to use the default */
} ServerBindOptions;

/* Options controlling an outgoing client connect (--address, -4/-6,
 * --sockopts).  All fields are client/connection-level and never cross the
 * wire config frame. */
typedef struct {
  const char* bind_address;     /* --address: local source address to bind, or NULL */
  int family;                   /* AF_INET / AF_INET6 / AF_UNSPEC (from -4 / -6) */
  const SockOptEntry* sockopts; /* --sockopts allowlist entries */
  int sockopt_count;
} TcpConnectOptions;

Server* server_create_ex(int port, const ServerBindOptions* bind_opts);
Server* server_create(int port);
/* Override the listener's connection cap (the global daemon `max connections`
 * value).  A non-positive value is ignored so the default cap stands. */
void server_set_max_connections(Server* server, unsigned int max_connections);
bool server_listen(Server* server, void (*handler)(int file_descriptor));
void server_accept_loop(Server* server, void (*child_fn)(int, void*), void* child_ctx,
                        const char* log_fmt);
void server_delete(Server** server);
Client* client_create();
bool client_connect_ex(Client* client, const char* host, int port, const TcpConnectOptions* opts);
bool client_connect(Client* client, const char* host, int port);
bool tcp_connect_socket_ex(Client* client, const char* host, int port,
                           const TcpConnectOptions* opts);
void client_disconnect(Client* client);
void client_delete(Client* client);
void tcp_set_timeouts(int timeout_sec, int contimeout_sec);
int tcp_get_contimeout_sec(void);
int tcp_get_timeout_sec(void);

/* Resolve -4/-6 flags to a getaddrinfo ai_family value.  ipv4 wins over ipv6;
 * when neither is set it returns AF_UNSPEC.  0 means "no preference" and is
 * therefore never returned; callers that need the "no explicit flag" sentinel
 * compare the flags directly. */
int tcp_connect_family(bool ipv4, bool ipv6);

#endif
