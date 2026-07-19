#include "transport_ssh.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
  char user[256];
  char host[256];
  char remote_path[4096];
} RemoteDest;

static int parse_remote_dest(const char* dest, RemoteDest* r) {
  const char* colon = strchr(dest, ':');
  if (!colon)
    return -1;

  size_t remote_path_len = strlen(colon + 1);
  if (remote_path_len >= sizeof(r->remote_path))
    return -1;
  memcpy(r->remote_path, colon + 1, remote_path_len + 1);

  const char* at = memchr(dest, '@', colon - dest);
  if (at) {
    size_t user_len = at - dest;
    if (user_len >= sizeof(r->user))
      return -1;
    memcpy(r->user, dest, user_len);
    r->user[user_len] = '\0';

    size_t host_len = colon - at - 1;
    if (host_len >= sizeof(r->host))
      return -1;
    memcpy(r->host, at + 1, host_len);
    r->host[host_len] = '\0';
  } else {
    r->user[0] = '\0';
    size_t host_len = colon - dest;
    if (host_len >= sizeof(r->host))
      return -1;
    memcpy(r->host, dest, host_len);
    r->host[host_len] = '\0';
  }
  return 0;
}

Client* client_connect_ssh(const char* destination, int port) {
  RemoteDest r;
  if (parse_remote_dest(destination, &r) != 0) {
    fprintf(stderr, "Invalid remote destination: %s\n", destination);
    return NULL;
  }

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
    perror("socketpair failed");
    return NULL;
  }

  int buf_size = 1024 * 1024;
  setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
  setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
  setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
  setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));

  int exec_pipe[2];
  if (pipe(exec_pipe) < 0) {
    perror("pipe failed");
    close(sv[0]);
    close(sv[1]);
    return NULL;
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork failed");
    close(sv[0]);
    close(sv[1]);
    close(exec_pipe[0]);
    close(exec_pipe[1]);
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

    char ssh_user[512];
    if (r.user[0] != '\0')
      snprintf(ssh_user, sizeof(ssh_user), "%s@%s", r.user, r.host);
    else
      snprintf(ssh_user, sizeof(ssh_user), "%s", r.host);

    char* ssh_argv[16];
    int ac = 0;
    char port_str[16];
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
    ssh_argv[ac++] = "fastsync-server";
    ssh_argv[ac++] = "--stdio";
    ssh_argv[ac] = NULL;
    execvp("ssh", ssh_argv);
    perror("exec of ssh failed");
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
    fprintf(stderr, "Error: could not launch 'fastsync-server --stdio' on remote\n");
    return NULL;
  }

  Client* client = malloc(sizeof(Client));
  if (client == NULL) {
    close(sv[0]);
    waitpid(pid, NULL, 0);
    return NULL;
  }
  client->file_descriptor = sv[0];
  client->address.sin_family = AF_UNIX;
  client->address_length = 0;
  client->ssh_child_pid = pid;
  client->ssl = NULL;
  client->ssl_ctx = NULL;
  return client;
}
