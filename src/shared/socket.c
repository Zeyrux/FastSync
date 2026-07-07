#include "socket.h"
#include "log.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static __thread int io_read_fd = -1;
static __thread int io_write_fd = -1;

void io_set_fds(int read_fd, int write_fd) {
  io_read_fd = read_fd;
  io_write_fd = write_fd;
}

static int io_fd(int dir_fd, int file_descriptor) {
  return (dir_fd != -1) ? dir_fd : file_descriptor;
}

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

Server *server_create(int port) {
  Server *server = (Server *)malloc(sizeof(Server));
  if (server == NULL) {
    perror("Could not allocate space for Server");
    exit(EXIT_FAILURE);
  }

  int file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if (file_descriptor < 0) {
    perror("Could not create Socket!");
    exit(EXIT_FAILURE);
  }
  server->file_descriptor = file_descriptor;
  int opt = 1;
  if (setsockopt(server->file_descriptor, SOL_SOCKET, SO_REUSEADDR, &opt,
                 sizeof(opt))) {
    perror("Error setting a socket option!");
    close(server->file_descriptor);
    free(server);
    exit(EXIT_FAILURE);
  }

  server->address.sin_family = AF_INET;
  server->address.sin_addr.s_addr = INADDR_ANY;
  server->address.sin_port = htons(port);
  server->address_length = sizeof(server->address);

  if (bind(server->file_descriptor, (struct sockaddr *)&server->address,
           server->address_length) < 0) {
    perror("Could not bind server");
    close(server->file_descriptor);
    free(server);
    exit(EXIT_FAILURE);
  }

  return server;
}

void server_delete(Server *server) {
  free(server);
  server = NULL;
};

void server_listen(Server *server, void (*handler)(int file_descriptor)) {
  log_message(LOG_LEVEL_INFO, "Start Listening on Port: %d",
              server->address.sin_port);
  if (listen(server->file_descriptor, 3) < 0) {
    perror("Could not listen on port!");
    exit(EXIT_FAILURE);
  }

  int file_descriptor =
      accept(server->file_descriptor, (struct sockaddr *)&server->address,
             &server->address_length);
  if (file_descriptor < 0) {
    perror("Could not accept the connection");
    exit(EXIT_FAILURE);
  }
  log_message(LOG_LEVEL_INFO, "Received Connection");
  handler(file_descriptor);
  close(server->file_descriptor);
  close(file_descriptor);
}

Client *client_create() {
  int file_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if (file_descriptor < 0) {
    perror("Could not create Socket!");
    exit(EXIT_FAILURE);
  };

  Client *client = (Client *)malloc(sizeof(Client));
  client->file_descriptor = file_descriptor;
  client->address.sin_family = AF_INET;
  client->address_length = sizeof(client->address);
  client->ssh_child_pid = -1;
  return client;
}

void client_connect(Client *client, char *host, int port) {
  client->address.sin_port = htons(port);

  if (inet_pton(AF_INET, host, &client->address.sin_addr) <= 0) {
    perror("Could not convert host address!");
    exit(EXIT_FAILURE);
  }

  if (connect(client->file_descriptor, (struct sockaddr *)&client->address,
              client->address_length) < 0) {
    perror("Could not connect to Server!");
    exit(EXIT_FAILURE);
  }
}

void client_disconnect(Client *client) {
  close(client->file_descriptor);
  if (client->ssh_child_pid > 0) {
    int status;
    waitpid(client->ssh_child_pid, &status, 0);
    client->ssh_child_pid = -1;
  }
}

void client_delete(Client *client) {
  if (client == NULL)
    return;
  free(client);
}

void send_n_data(int file_descriptor, void *data, size_t data_size) {
  log_message(LOG_LEVEL_DEBUG, "    Sending n Data: %zu", data_size);
  int fd = io_fd(io_write_fd, file_descriptor);
  ssize_t total_bytes_send = 0;
  while (total_bytes_send < data_size) {
    ssize_t bytes_send = write(fd, (char *)data + total_bytes_send,
                               data_size - total_bytes_send);
    if (bytes_send <= 0) {
      perror("Could not send data!");
      exit(EXIT_FAILURE);
    }
    total_bytes_send += bytes_send;
  }
  log_message(LOG_LEVEL_DEBUG, "    Send n Data: %zu", total_bytes_send);
}

void receive_n_data(int file_descriptor, void *data, size_t data_size) {
  log_message(LOG_LEVEL_DEBUG, "    Receiving n Data: %zu", data_size);
  int fd = io_fd(io_read_fd, file_descriptor);
  size_t total_bytes_received = 0;
  while (total_bytes_received < data_size) {
    ssize_t bytes_received =
        read(fd, (char *)data + total_bytes_received,
             data_size - total_bytes_received);
    if (bytes_received == -1 || bytes_received == 0) {
      perror("Could not receive bytes!");
      exit(EXIT_FAILURE);
    }
    total_bytes_received += bytes_received;
  }
  log_message(LOG_LEVEL_DEBUG, "    Received n Data: %zu", total_bytes_received);
}

void send_str(int file_descriptor, char *data) {
  size_t size = strlen(data);
  send_n_data(file_descriptor, &size, sizeof(size_t));
  send_n_data(file_descriptor, data, size);
  log_message(LOG_LEVEL_DEBUG, "Send String: %s", data);
}

char *receive_str(int file_descriptor) {
  size_t size;
  receive_n_data(file_descriptor, &size, sizeof(size_t));
  char *data = (char *)malloc(size + 1);
  receive_n_data(file_descriptor, data, size);
  data[size] = '\0';
  log_message(LOG_LEVEL_DEBUG, "Received String: %s", data);
  return data;
}

void send_data(int file_descriptor, void *data, unsigned long long data_size) {
  send_n_data(file_descriptor, &data_size, sizeof(unsigned long long));
  send_n_data(file_descriptor, data, data_size);
  log_message(LOG_LEVEL_DEBUG, "Send %lld data", data_size);
}

Data *receive_data(int file_descriptor) {
  size_t size = 0;
  receive_n_data(file_descriptor, &size, sizeof(unsigned long long));
  void *data = malloc(size);
  receive_n_data(file_descriptor, data, size);
  log_message(LOG_LEVEL_DEBUG, "Received %lld data", size);
  return data_create(data, size);
}

void send_int(int file_descriptor, int data) {
  send_n_data(file_descriptor, &data, sizeof(int));
  log_message(LOG_LEVEL_DEBUG, "Send Int: %d", data);
}

int receive_int(int file_descriptor) {
  int data;
  receive_n_data(file_descriptor, &data, sizeof(int));
  log_message(LOG_LEVEL_DEBUG, "Received Int: %d", data);
  return data;
}

const char *status_to_string(Status status) {
  switch (status) {
  case STATUS_OK:
    return "OK";
  case STATUS_ERROR:
    return "ERROR";
  case STATUS_FINISHED:
    return "FINISHED";
  case STATUS_NEXT:
    return "NEXT";
  case STATUS_CHUNK:
    return "CHUNK";
  default:
    return "UNKNOWN";
  }
}

void send_status(int file_descriptor, Status status) {
  send_n_data(file_descriptor, &status, sizeof(Status));
  log_message(LOG_LEVEL_DEBUG, "Send Status: %s", status_to_string(status));
}

Status receive_status(int file_descriptor) {
  Status data;
  receive_n_data(file_descriptor, &data, sizeof(Status));
  log_message(LOG_LEVEL_DEBUG, "Received Status: %s", status_to_string(data));
  return data;
}
