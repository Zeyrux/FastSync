#ifndef TRANSPORT_SSH_H
#define TRANSPORT_SSH_H

#include "transport_tcp.h"

Client* client_connect_ssh(const char* destination, int port, const char* server_path);

#endif
