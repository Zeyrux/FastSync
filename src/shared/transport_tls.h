#ifndef TRANSPORT_TLS_H
#define TRANSPORT_TLS_H

#include "transport_tcp.h"
#include <stdbool.h>

bool tls_global_init(void);

bool server_create_tls(Server* server, const char* cert_path, const char* key_path,
                       const char* ca_path);
bool server_listen_tls(Server* server, void (*handler)(int file_descriptor));
bool client_connect_tls(Client* client, char* host, int port, const char* cert_path,
                        const char* key_path, const char* ca_path);

#endif
