#include "transport_tcp.h"
#include "log.h"
#include "protocol.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

bool set_socket_timeouts(int fd) {
  struct timeval tv;
  tv.tv_sec = 30;
  tv.tv_usec = 0;

  int keepalive = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
    perror("Could not set SO_KEEPALIVE");
    return false;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("Could not set SO_RCVTIMEO");
    return false;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
    perror("Could not set SO_SNDTIMEO");
    return false;
  }
  return true;
}

Server* server_create(int port) {
  Server* server = (Server*)malloc(sizeof(Server));
  if (server == NULL) {
    perror("Could not allocate space for Server");
    return NULL;
  }
  memset(&server->address, 0, sizeof(server->address));

  // Try IPv6 first, fall back to IPv4
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  sa_family_t domain = AF_INET6;
  if (fd < 0) {
    fd = socket(AF_INET, SOCK_STREAM, 0);
    domain = AF_INET;
  }
  if (fd < 0) {
    perror("Could not create Socket!");
    free(server);
    return NULL;
  }

  if (!set_socket_timeouts(fd)) {
    close(fd);
    free(server);
    return NULL;
  }

  server->file_descriptor = fd;
  server->ssl_ctx = NULL;
  int opt = 1;
  if (setsockopt(server->file_descriptor, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    perror("Error setting a socket option!");
    close(server->file_descriptor);
    free(server);
    return NULL;
  }

  // Use the domain from the socket we actually created
  struct sockaddr_storage* addr = &server->address;
  struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
  struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;

  if (domain == AF_INET6) {
    addr6->sin6_family = AF_INET6;
    addr6->sin6_addr = in6addr_any;
    addr6->sin6_port = htons(port);
    addr->ss_family = AF_INET6;
    server->address_length = sizeof(struct sockaddr_in6);
  } else {
    addr4->sin_family = AF_INET;
    addr4->sin_addr.s_addr = INADDR_ANY;
    addr4->sin_port = htons(port);
    addr->ss_family = AF_INET;
    server->address_length = sizeof(struct sockaddr_in);
  }

  if (bind(server->file_descriptor, (struct sockaddr*)&server->address, server->address_length) <
      0) {
    // If IPv6 bind failed (maybe no IPv6), try IPv4
    if (domain == AF_INET6) {
      close(fd);
      fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd < 0) {
        perror("Could not create IPv4 Socket!");
        free(server);
        return NULL;
      }
      if (!set_socket_timeouts(fd)) {
        close(fd);
        free(server);
        return NULL;
      }
      server->file_descriptor = fd;
      setsockopt(server->file_descriptor, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
      memset(addr, 0, sizeof(*addr));
      addr4->sin_family = AF_INET;
      addr4->sin_addr.s_addr = INADDR_ANY;
      addr4->sin_port = htons(port);
      server->address_length = sizeof(struct sockaddr_in);
      if (bind(server->file_descriptor, (struct sockaddr*)addr, server->address_length) < 0) {
        perror("Could not bind server");
        close(server->file_descriptor);
        free(server);
        return NULL;
      }
    } else {
      perror("Could not bind server");
      close(server->file_descriptor);
      free(server);
      return NULL;
    }
  }

  return server;
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

/* Flag set by server_request_shutdown() to request graceful shutdown
   of the accept loop. Accessed only from transport_tcp.c so it won't
   cause linker errors when this file is compiled into client/test targets. */
static volatile sig_atomic_t g_tcp_cleanup_requested = 0;

void server_request_shutdown(void) {
  g_tcp_cleanup_requested = 1;
}

static void accept_loop(Server* server, void (*child_fn)(int, void*), void* child_ctx,
                        const char* log_fmt) {
  if (listen(server->file_descriptor, SOMAXCONN) < 0) {
    perror("Could not listen on port!");
    return;
  }
  signal(SIGCHLD, SIG_IGN);
  while (!g_tcp_cleanup_requested) {
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    int fd = accept(server->file_descriptor, (struct sockaddr*)&client_addr, &client_len);
    if (fd < 0) {
      if (errno == EINTR)
        break;
      perror("Could not accept the connection");
      continue;
    }
    set_socket_timeouts(fd);
    log_message(LOG_LEVEL_INFO, "%s", log_fmt);
    pid_t pid = fork();
    if (pid == 0) {
      close(server->file_descriptor);
      child_fn(fd, child_ctx);
      close(fd);
      _exit(0);
    }
    close(fd);
  }
}

struct plain_ctx {
  void (*handler)(int);
};

static void plain_child_fn(int fd, void* ctx) {
  ((struct plain_ctx*)ctx)->handler(fd);
}

bool server_listen(Server* server, void (*handler)(int file_descriptor)) {
  struct sockaddr_in* addr4 = (struct sockaddr_in*)&server->address;
  int port = (server->address.ss_family == AF_INET6)
                 ? ntohs(((struct sockaddr_in6*)&server->address)->sin6_port)
                 : ntohs(addr4->sin_port);
  log_message(LOG_LEVEL_INFO, "Start Listening on Port: %d", port);
  struct plain_ctx ctx = {handler};
  accept_loop(server, plain_child_fn, &ctx, "Received Connection");
  return true;
}

void server_accept_loop(Server* server, void (*child_fn)(int, void*), void* child_ctx,
                        const char* log_fmt) {
  struct sockaddr_in* addr4 = (struct sockaddr_in*)&server->address;
  int port = (server->address.ss_family == AF_INET6)
                 ? ntohs(((struct sockaddr_in6*)&server->address)->sin6_port)
                 : ntohs(addr4->sin_port);
  log_message(LOG_LEVEL_INFO, "Start TLS Listening on Port: %d", port);
  accept_loop(server, child_fn, child_ctx, log_fmt);
}

Client* client_create() {
  Client* client = (Client*)malloc(sizeof(Client));
  if (client == NULL) {
    return NULL;
  }
  memset(&client->address, 0, sizeof(client->address));
  client->address.ss_family = AF_UNSPEC;
  client->address_length = sizeof(client->address);
  client->file_descriptor = -1;
  client->ssh_child_pid = -1;
  client->ssl = NULL;
  client->ssl_ctx = NULL;
  return client;
}

bool client_connect(Client* client, char* host, int port) {
  struct addrinfo hints, *res, *rp;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  int gai_err = getaddrinfo(host, port_str, &hints, &res);
  if (gai_err != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_err));
    return false;
  }

  // Try IPv6 first, then IPv4
  int fd = -1;
  for (rp = res; rp != NULL; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0)
      continue;
    if (!set_socket_timeouts(fd)) {
      close(fd);
      fd = -1;
      continue;
    }
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;
    close(fd);
    fd = -1;
  }

  if (fd < 0) {
    perror("Could not connect to Server!");
    freeaddrinfo(res);
    return false;
  }

  // Save the connected address
  socklen_t addr_len = rp->ai_addrlen;
  if (addr_len > sizeof(client->address))
    addr_len = sizeof(client->address);
  memcpy(&client->address, rp->ai_addr, addr_len);
  client->address_length = addr_len;
  freeaddrinfo(res);

  // Close old fd if any and set new one
  if (client->file_descriptor >= 0)
    close(client->file_descriptor);
  client->file_descriptor = fd;
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
  client_disconnect(client);
  if (client->ssl_ctx) {
    SSL_CTX_free(client->ssl_ctx);
    client->ssl_ctx = NULL;
  }
  free(client);
}
