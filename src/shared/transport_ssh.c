#include "log.h"
#include "transport_ssh.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
  char* user;
  char* host;
  char* remote_path;
} RemoteDest;

static void remote_dest_destroy(RemoteDest* r) {
  free(r->user);
  free(r->host);
  free(r->remote_path);
}

static int parse_remote_dest(const char* dest, RemoteDest* r) {
  memset(r, 0, sizeof(*r));
  const char* colon = strchr(dest, ':');
  if (!colon)
    return -1;

  r->remote_path = str_dup(colon + 1);
  if (!r->remote_path)
    return -1;

  const char* at = memchr(dest, '@', colon - dest);
  if (at) {
    size_t user_len = at - dest;
    r->user = malloc(user_len + 1);
    if (!r->user) {
      remote_dest_destroy(r);
      return -1;
    }
    memcpy(r->user, dest, user_len);
    r->user[user_len] = '\0';

    size_t host_len = colon - at - 1;
    r->host = malloc(host_len + 1);
    if (!r->host) {
      remote_dest_destroy(r);
      return -1;
    }
    memcpy(r->host, at + 1, host_len);
    r->host[host_len] = '\0';
  } else {
    r->user = str_dup("");
    if (!r->user) {
      remote_dest_destroy(r);
      return -1;
    }
    size_t host_len = colon - dest;
    r->host = malloc(host_len + 1);
    if (!r->host) {
      remote_dest_destroy(r);
      return -1;
    }
    memcpy(r->host, dest, host_len);
    r->host[host_len] = '\0';
  }
  return 0;
}

char* ssh_build_remote_command(const char* server_path, bool old_args) {
  const char* path = server_path ? server_path : "fastsync-server";
  const char* suffix = " --stdio";
  size_t path_len = strlen(path);
  size_t suffix_len = strlen(suffix);

  if (old_args) {
    if (path_len > SIZE_MAX - suffix_len - 1)
      return NULL;
    char* command = malloc(path_len + suffix_len + 1);
    if (!command)
      return NULL;
    memcpy(command, path, path_len);
    memcpy(command + path_len, suffix, suffix_len + 1);
    return command;
  }

  /* Quote the executable as one remote-shell word. This is the default safety boundary. */
  size_t quote_count = 0;
  for (const char* p = path; *p; p++)
    if (*p == '\'')
      quote_count++;
  if (path_len > SIZE_MAX - suffix_len - 4 ||
      quote_count > (SIZE_MAX - path_len - suffix_len - 4) / 4)
    return NULL;
  size_t command_len = path_len + quote_count * 4 + suffix_len + 4;
  char* command = malloc(command_len + 1);
  if (!command)
    return NULL;
  char* out = command;
  *out++ = '\'';
  for (const char* p = path; *p; p++) {
    if (*p == '\'') {
      memcpy(out, "'\\''", 4);
      out += 4;
    } else {
      *out++ = *p;
    }
  }
  *out++ = '\'';
  memcpy(out, suffix, suffix_len + 1);
  return command;
}

Client* client_connect_ssh(const char* destination, int port, const char* server_path,
                           bool old_args) {
  RemoteDest r;
  if (parse_remote_dest(destination, &r) != 0) {
    fprintf(stderr, "Invalid remote destination: %s\n", destination);
    return NULL;
  }

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
    log_perror("socketpair failed");
    remote_dest_destroy(&r);
    return NULL;
  }

  int buf_size = 1024 * 1024;
  setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
  setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
  setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
  setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));

  int exec_pipe[2];
  if (pipe(exec_pipe) < 0) {
    log_perror("pipe failed");
    close(sv[0]);
    close(sv[1]);
    remote_dest_destroy(&r);
    return NULL;
  }

  pid_t pid = fork();
  if (pid < 0) {
    log_perror("fork failed");
    close(sv[0]);
    close(sv[1]);
    close(exec_pipe[0]);
    close(exec_pipe[1]);
    remote_dest_destroy(&r);
    return NULL;
  }

  if (pid == 0) {
    close(sv[0]);
    close(exec_pipe[0]);
    fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC);
    if (sv[1] != STDIN_FILENO)
      dup2(sv[1], STDIN_FILENO);
    if (sv[1] != STDOUT_FILENO)
      dup2(sv[1], STDOUT_FILENO);
    if (sv[1] > 1)
      close(sv[1]);

    size_t ssh_user_len;
    if (r.user && r.user[0] != '\0')
      ssh_user_len = strlen(r.user) + 1 + strlen(r.host) + 1;
    else
      ssh_user_len = strlen(r.host) + 1;
    char* ssh_user = malloc(ssh_user_len);
    if (!ssh_user)
      _exit(1);
    if (r.user && r.user[0] != '\0')
      snprintf(ssh_user, ssh_user_len, "%s@%s", r.user, r.host);
    else
      snprintf(ssh_user, ssh_user_len, "%s", r.host);

    char* ssh_argv[16];
    int ac = 0;
    char port_str[16];
    char* remote_command = ssh_build_remote_command(server_path, old_args);
    if (!remote_command)
      _exit(1);
    ssh_argv[ac++] = "ssh";
    ssh_argv[ac++] = "-o";
    ssh_argv[ac++] = "Compression=no";
    ssh_argv[ac++] = "-o";
    ssh_argv[ac++] = "ControlMaster=auto";
    ssh_argv[ac++] = "-o";
    ssh_argv[ac++] = "ControlPath=~/.cache/fastsync-%r@%h:%p";
    if (port > 0 && port != 22) {
      ssh_argv[ac++] = "-p";
      snprintf(port_str, sizeof(port_str), "%d", port);
      ssh_argv[ac++] = port_str;
    }
    ssh_argv[ac++] = ssh_user;
    ssh_argv[ac++] = remote_command;
    ssh_argv[ac] = NULL;
    execvp("ssh", ssh_argv);
    log_perror("exec of ssh failed");
    ssize_t wret = write(exec_pipe[1], "x", 1);
    (void)wret;
    _exit(1);
  }

  close(sv[1]);
  close(exec_pipe[1]);

  char exec_status;
  ssize_t n = read(exec_pipe[0], &exec_status, 1);
  close(exec_pipe[0]);

  if (n > 0) {
    close(sv[0]);
    waitpid(pid, NULL, 0);
    remote_dest_destroy(&r);
    fprintf(stderr, "Error: could not launch '%s --stdio' on remote\n",
            server_path ? server_path : "fastsync-server");
    return NULL;
  }

  remote_dest_destroy(&r);

  Client* client = malloc(sizeof(Client));
  if (client == NULL) {
    close(sv[0]);
    waitpid(pid, NULL, 0);
    return NULL;
  }
  client->file_descriptor = sv[0];
  client->address.ss_family = AF_UNIX;
  client->address_length = 0;
  client->ssh_child_pid = pid;
  client->ssl = NULL;
  client->ssl_ctx = NULL;
  return client;
}
