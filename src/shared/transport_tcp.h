#ifndef TRANSPORT_TCP_H
#define TRANSPORT_TCP_H

#include <netinet/in.h>
#include <sys/types.h>

typedef struct Server {
  struct sockaddr_in address;
  unsigned int address_length;
  int file_descriptor;
} Server;

typedef struct Client {
  struct sockaddr_in address;
  unsigned int address_length;
  int file_descriptor;
  pid_t ssh_child_pid;
} Client;

Server *server_create(int port);
void server_listen(Server *server, void (*handler)(int file_descriptor));
void server_delete(Server **server);
Client *client_create();
void client_connect(Client *client, char *host, int port);
void client_disconnect(Client *client);
void client_delete(Client *client);

#endif
