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
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t g_active_connections = 0;

static void tcp_apply_socket_timeout(int fd);

static void sigchld_handler(int sig) {
  (void)sig;
  int saved_errno = errno;
  while (waitpid(-1, NULL, WNOHANG) > 0) {
    if (g_active_connections > 0)
      g_active_connections--;
  }
  errno = saved_errno;
}

Server* server_create(int port) {
  Server* server = (Server*)malloc(sizeof(Server));
  if (server == NULL) {
    log_perror("Could not allocate space for Server");
    return NULL;
  }

  int file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if (file_descriptor < 0) {
    log_perror("Could not create Socket!");
    free(server);
    return NULL;
  }
  server->file_descriptor = file_descriptor;
  int opt = 1;
  if (setsockopt(server->file_descriptor, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    log_perror("Error setting a socket option!");
    close(server->file_descriptor);
    free(server);
    return NULL;
  }

  server->address.sin_family = AF_INET;
  server->address.sin_addr.s_addr = INADDR_ANY;
  server->address.sin_port = htons(port);
  server->address_length = sizeof(server->address);
  server->ssl_ctx = NULL;
  server->max_connections = 100;
  server->active_connections = 0;

  if (bind(server->file_descriptor, (struct sockaddr*)&server->address, server->address_length) <
      0) {
    log_perror("Could not bind server");
    close(server->file_descriptor);
    free(server);
    return NULL;
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

static void accept_loop(Server* server, void (*child_fn)(int, void*), void* child_ctx,
                        const char* log_fmt) {
  if (listen(server->file_descriptor, SOMAXCONN) < 0) {
    log_perror("Could not listen on port!");
    return;
  }
  signal(SIGCHLD, sigchld_handler);
  while (1) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int fd = accept(server->file_descriptor, (struct sockaddr*)&client_addr, &client_len);
    if (fd < 0) {
      log_perror("Could not accept the connection");
      continue;
    }
    tcp_apply_socket_timeout(fd);
    if ((unsigned int)g_active_connections >= server->max_connections) {
      log_message(LOG_LEVEL_WARNING, "Max connections (%u) reached, rejecting",
                  server->max_connections);
      close(fd);
      continue;
    }
    log_message(LOG_LEVEL_INFO, "%s", log_fmt);
    pid_t pid = fork();
    if (pid == 0) {
      close(server->file_descriptor);
      child_fn(fd, child_ctx);
      close(fd);
      _exit(0);
    } else if (pid > 0) {
      g_active_connections++;
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
  log_message(LOG_LEVEL_INFO, "Start Listening on Port: %d", ntohs(server->address.sin_port));
  struct plain_ctx ctx = {handler};
  accept_loop(server, plain_child_fn, &ctx, "Received Connection");
  return true;
}

void server_accept_loop(Server* server, void (*child_fn)(int, void*), void* child_ctx,
                        const char* log_fmt) {
  log_message(LOG_LEVEL_INFO, "Start TLS Listening on Port: %d", ntohs(server->address.sin_port));
  accept_loop(server, child_fn, child_ctx, log_fmt);
}

static int g_timeout_sec = 30;
static int g_contimeout_sec = 10;

void tcp_set_timeouts(int timeout_sec, int contimeout_sec) {
  if (timeout_sec > 0)
    g_timeout_sec = timeout_sec;
  if (contimeout_sec > 0)
    g_contimeout_sec = contimeout_sec;
}

int tcp_get_contimeout_sec(void) {
  return g_contimeout_sec;
}

int tcp_get_timeout_sec(void) {
  return g_timeout_sec;
}

static void tcp_apply_socket_timeout(int fd) {
  struct timeval tv;
  tv.tv_sec = g_timeout_sec;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
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

bool tcp_connect_socket(Client* client, char* host, int port) {
  struct addrinfo hints;
  struct addrinfo* result;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  int err = getaddrinfo(host, port_str, &hints, &result);
  if (err != 0 || result == NULL) {
    fprintf(stderr, "Could not resolve host: %s (%s)\n", host, gai_strerror(err));
    return false;
  }

  struct addrinfo* rp;
  bool connected = false;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    if (client->file_descriptor >= 0)
      close(client->file_descriptor);

    client->file_descriptor = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (client->file_descriptor < 0)
      continue;

    struct timeval ct;
    ct.tv_sec = g_contimeout_sec;
    ct.tv_usec = 0;
    setsockopt(client->file_descriptor, SOL_SOCKET, SO_RCVTIMEO, &ct, sizeof(ct));
    setsockopt(client->file_descriptor, SOL_SOCKET, SO_SNDTIMEO, &ct, sizeof(ct));

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

bool client_connect(Client* client, char* host, int port) {
  if (!tcp_connect_socket(client, host, port))
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
