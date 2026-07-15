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

static int parse_remote_dest(const char *dest, RemoteDest *r) {
  const char *colon = strchr(dest, ':');
  if (!colon) return -1;

  size_t remote_path_len = strlen(colon + 1);
  if (remote_path_len >= sizeof(r->remote_path)) return -1;
  memcpy(r->remote_path, colon + 1, remote_path_len + 1);

  const char *at = memchr(dest, '@', colon - dest);
  if (at) {
    size_t user_len = at - dest;
    if (user_len >= sizeof(r->user)) return -1;
    memcpy(r->user, dest, user_len);
    r->user[user_len] = '\0';

    size_t host_len = colon - at - 1;
    if (host_len >= sizeof(r->host)) return -1;
    memcpy(r->host, at + 1, host_len);
    r->host[host_len] = '\0';
  } else {
    r->user[0] = '\0';
    size_t host_len = colon - dest;
    if (host_len >= sizeof(r->host)) return -1;
    memcpy(r->host, dest, host_len);
    r->host[host_len] = '\0';
  }
  return 0;
}

Client *client_connect_ssh(char *destination) {
  RemoteDest r;
  if (parse_remote_dest(destination, &r) != 0) {
    fprintf(stderr, "Invalid remote destination: %s\n", destination);
    exit(EXIT_FAILURE);
  }

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
    perror("socketpair failed");
    exit(EXIT_FAILURE);
  }

  int exec_pipe[2];
  if (pipe(exec_pipe) < 0) {
    perror("pipe failed");
    exit(EXIT_FAILURE);
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork failed");
    exit(EXIT_FAILURE);
  }

  if (pid == 0) {
    close(sv[0]);
    close(exec_pipe[0]);
    fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC);

    if (sv[1] != STDIN_FILENO)
      dup2(sv[1], STDIN_FILENO);
    if (sv[1] != STDOUT_FILENO)
      dup2(sv[1], STDOUT_FILENO);
    if (sv[1] > 1) close(sv[1]);

    char ssh_user[512];
    if (r.user[0] != '\0')
      snprintf(ssh_user, sizeof(ssh_user), "%s@%s", r.user, r.host);
    else
      snprintf(ssh_user, sizeof(ssh_user), "%s", r.host);

    execlp("ssh", "ssh", "-o", "Compression=no", "-o",
           "ControlMaster=no", ssh_user, "fastsync-server", "--stdio",
           (char *)NULL);
    perror("exec of ssh failed");
    (void)write(exec_pipe[1], "x", 1);
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
    exit(EXIT_FAILURE);
  }

  Client *client = malloc(sizeof(Client));
  client->file_descriptor = sv[0];
  client->address.sin_family = AF_UNIX;
  client->address_length = 0;
  client->ssh_child_pid = pid;
  return client;
}
