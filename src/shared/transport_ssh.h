#ifndef TRANSPORT_SSH_H
#define TRANSPORT_SSH_H

#include "transport_tcp.h"

Client* client_connect_ssh(const char* destination, int port, const char* server_path,
                           bool old_args, const char* rsh_command, bool blocking_io,
                           char* const* remote_options, int remote_option_count);
/* Build the escaped remote-shell command string (the server program path always
 * quoted as one remote-shell word, followed by ` --stdio` and each
 * --remote-option value appended as an individually single-quoted shell word).
 * `old_args` is accepted for CLI/ABI compatibility but no longer disables
 * quoting: the path is always escaped so a metacharacter-bearing
 * --rsync-path can never be interpreted by the remote shell.  Every
 * --remote-option value is individually escaped with the '\'' sequence and
 * values with empty/control characters are rejected at the CLI parse layer. */
char* ssh_build_remote_command(const char* server_path, bool old_args, char* const* remote_options,
                               int remote_option_count);
/* Build the NULL-terminated child argv for the remote-shell client (argv[0] is
 * the exec/execvp program).  rsh_command is whitespace-split into leading argv
 * words (NULL or "" selects the default "ssh"); the standard -o family, the
 * optional -p port, the user@host and the remote command are appended.  Every
 * string (including argv[0]) is heap-owned; free with ssh_free_client_argv. */
char** ssh_build_client_argv(const char* rsh_command, int port, const char* userhost,
                             const char* remote_command);
void ssh_free_client_argv(char** argv);

#endif
