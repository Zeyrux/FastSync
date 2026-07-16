#include "transport_tcp.h"
#include "log.h"
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

Server *server_create(int port) {
  Server *server = (Server *)malloc(sizeof(Server));
  if (server == NULL) {
    perror("Could not allocate space for Server");
    return NULL;
  }

  int file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if (file_descriptor < 0) {
    perror("Could not create Socket!");
    free(server);
    return NULL;
  }
  server->file_descriptor = file_descriptor;
  int opt = 1;
  if (setsockopt(server->file_descriptor, SOL_SOCKET, SO_REUSEADDR, &opt,
                 sizeof(opt))) {
    perror("Error setting a socket option!");
    close(server->file_descriptor);
    free(server);
    return NULL;
  }

  server->address.sin_family = AF_INET;
  server->address.sin_addr.s_addr = INADDR_ANY;
  server->address.sin_port = htons(port);
  server->address_length = sizeof(server->address);
  server->ssl_ctx = NULL;

  if (bind(server->file_descriptor, (struct sockaddr *)&server->address,
           server->address_length) < 0) {
    perror("Could not bind server");
    close(server->file_descriptor);
    free(server);
    return NULL;
  }

  return server;
}

void server_delete(Server **server) {
  if (server == NULL || *server == NULL) return;
  close((*server)->file_descriptor);
  if ((*server)->ssl_ctx) {
    SSL_CTX_free((*server)->ssl_ctx);
    (*server)->ssl_ctx = NULL;
  }
  free(*server);
  *server = NULL;
}

static void accept_loop(Server *server, void (*child_fn)(int, void *),
                        void *child_ctx, const char *log_fmt) {
  if (listen(server->file_descriptor, SOMAXCONN) < 0) {
    perror("Could not listen on port!");
    return;
  }
  signal(SIGCHLD, SIG_IGN);
  while (1) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int fd = accept(server->file_descriptor, (struct sockaddr *)&client_addr,
                    &client_len);
    if (fd < 0) {
      perror("Could not accept the connection");
      continue;
    }
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

struct plain_ctx { void (*handler)(int); };

static void plain_child_fn(int fd, void *ctx) {
  ((struct plain_ctx *)ctx)->handler(fd);
}

bool server_listen(Server *server, void (*handler)(int file_descriptor)) {
  log_message(LOG_LEVEL_INFO, "Start Listening on Port: %d",
              ntohs(server->address.sin_port));
  struct plain_ctx ctx = {handler};
  accept_loop(server, plain_child_fn, &ctx, "Received Connection");
  return true;
}

void server_accept_loop(Server *server, void (*child_fn)(int, void *),
                        void *child_ctx, const char *log_fmt) {
  log_message(LOG_LEVEL_INFO, "Start TLS Listening on Port: %d",
              ntohs(server->address.sin_port));
  accept_loop(server, child_fn, child_ctx, log_fmt);
}

Client *client_create() {
  int file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if (file_descriptor < 0) {
    perror("Could not create Socket!");
    return NULL;
  }

  Client *client = (Client *)malloc(sizeof(Client));
  if (client == NULL) {
    close(file_descriptor);
    return NULL;
  }
  client->file_descriptor = file_descriptor;
  client->address.sin_family = AF_INET;
  client->address_length = sizeof(client->address);
  client->ssh_child_pid = -1;
  client->ssl = NULL;
  client->ssl_ctx = NULL;
  return client;
}

bool client_connect(Client *client, char *host, int port) {
  client->address.sin_port = htons(port);

  if (inet_pton(AF_INET, host, &client->address.sin_addr) <= 0) {
    perror("Could not convert host address!");
    return false;
  }

  if (connect(client->file_descriptor, (struct sockaddr *)&client->address,
              client->address_length) < 0) {
    perror("Could not connect to Server!");
    return false;
  }
  return true;
}

void client_disconnect(Client *client) {
  if (client->ssl) {
    SSL_shutdown(client->ssl);
    SSL_free(client->ssl);
    client->ssl = NULL;
  }
  close(client->file_descriptor);
  if (client->ssh_child_pid > 0) {
    int status;
    waitpid(client->ssh_child_pid, &status, 0);
    client->ssh_child_pid = -1;
  }
}

void client_delete(Client *client) {
  if (client == NULL) return;
  if (client->ssl_ctx) {
    SSL_CTX_free(client->ssl_ctx);
    client->ssl_ctx = NULL;
  }
  free(client);
}
