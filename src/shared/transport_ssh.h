#ifndef TRANSPORT_SSH_H
#define TRANSPORT_SSH_H

#include "transport_tcp.h"

Client* client_connect_ssh(const char* destination, int port, const char* server_path,
                           bool old_args, char* const* remote_options, int remote_option_count);
char* ssh_build_remote_command(const char* server_path, bool old_args, char* const* remote_options,
                               int remote_option_count);

#endif
