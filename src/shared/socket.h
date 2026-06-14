#ifndef SOCKET_H
#define SOCKET_H

#include "data.h"
#include <netinet/in.h>

typedef int Status;
enum NET_STATUS { OK, ERROR, FINISHED, NEXT };

typedef struct Server {
  struct sockaddr_in address;
  unsigned int address_length;
  int file_descriptor;
} Server;

Server *server_create(int port);
void server_listen(Server *server, void (*handler)(int file_descriptor));
void server_delete(Server *server);

typedef struct Client {
  struct sockaddr_in address;
  unsigned int address_length;
  int file_descriptor;
} Client;

Client *client_create();
void client_disconnect(Client *client);
void client_delete(Client *client);
void client_connect(Client *client, char *host, int port);

void send_n_data(int file_descriptor, void *data, size_t data_size);
void receive_n_data(int file_descriptor, void *data, size_t data_size);
void send_str(int file_descriptor, char *data);
char *receive_str(int file_descriptor);
void send_data(int file_descriptor, void *data, unsigned long long data_size);
Data *receive_data(int file_descriptor);
void send_int(int file_descriptor, int data);
int receive_int(int file_descriptor);
void send_status(int file_descriptor, Status status);
Status receive_status(int file_descriptor);

#endif
