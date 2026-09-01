#ifndef TRANSPORT_TCP_H
#define TRANSPORT_TCP_H

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct Server {
  struct sockaddr_in address;
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

Server* server_create(int port);
bool server_listen(Server* server, void (*handler)(int file_descriptor));
void server_accept_loop(Server* server, void (*child_fn)(int, void*), void* child_ctx,
                        const char* log_fmt);
void server_delete(Server** server);
Client* client_create();
bool tcp_connect_socket(Client* client, const char* host, int port);
bool client_connect(Client* client, char* host, int port);
void client_disconnect(Client* client);
void client_delete(Client* client);
void tcp_set_timeouts(int timeout_sec, int contimeout_sec);
int tcp_get_contimeout_sec(void);

#endif
