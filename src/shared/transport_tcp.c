#include "transport_tcp.h"
#include "log.h"
#include <arpa/inet.h>
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
    exit(EXIT_FAILURE);
  }

  int file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if (file_descriptor < 0) {
    perror("Could not create Socket!");
    exit(EXIT_FAILURE);
  }
  server->file_descriptor = file_descriptor;
  int opt = 1;
  if (setsockopt(server->file_descriptor, SOL_SOCKET, SO_REUSEADDR, &opt,
                 sizeof(opt))) {
    perror("Error setting a socket option!");
    close(server->file_descriptor);
    free(server);
    exit(EXIT_FAILURE);
  }

  server->address.sin_family = AF_INET;
  server->address.sin_addr.s_addr = INADDR_ANY;
  server->address.sin_port = htons(port);
  server->address_length = sizeof(server->address);

  if (bind(server->file_descriptor, (struct sockaddr *)&server->address,
           server->address_length) < 0) {
    perror("Could not bind server");
    close(server->file_descriptor);
    free(server);
    exit(EXIT_FAILURE);
  }

  return server;
}

void server_delete(Server **server) {
  if (server == NULL || *server == NULL) return;
  free(*server);
  *server = NULL;
}

void server_listen(Server *server, void (*handler)(int file_descriptor)) {
  log_message(LOG_LEVEL_INFO, "Start Listening on Port: %d",
              server->address.sin_port);
  if (listen(server->file_descriptor, 3) < 0) {
    perror("Could not listen on port!");
    exit(EXIT_FAILURE);
  }

  int file_descriptor =
      accept(server->file_descriptor, (struct sockaddr *)&server->address,
             &server->address_length);
  if (file_descriptor < 0) {
    perror("Could not accept the connection");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_LEVEL_INFO, "Received Connection");
  handler(file_descriptor);
  close(server->file_descriptor);
  close(file_descriptor);
}

Client *client_create() {
  int file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if (file_descriptor < 0) {
    perror("Could not create Socket!");
    exit(EXIT_FAILURE);
  }

  Client *client = (Client *)malloc(sizeof(Client));
  client->file_descriptor = file_descriptor;
  client->address.sin_family = AF_INET;
  client->address_length = sizeof(client->address);
  client->ssh_child_pid = -1;
  return client;
}

void client_connect(Client *client, char *host, int port) {
  client->address.sin_port = htons(port);

  if (inet_pton(AF_INET, host, &client->address.sin_addr) <= 0) {
    perror("Could not convert host address!");
    exit(EXIT_FAILURE);
  }

  if (connect(client->file_descriptor, (struct sockaddr *)&client->address,
              client->address_length) < 0) {
    perror("Could not connect to Server!");
    exit(EXIT_FAILURE);
  }
}

void client_disconnect(Client *client) {
  close(client->file_descriptor);
  if (client->ssh_child_pid > 0) {
    int status;
    waitpid(client->ssh_child_pid, &status, 0);
    client->ssh_child_pid = -1;
  }
}

void client_delete(Client *client) {
  if (client == NULL)
    return;
  free(client);
}
