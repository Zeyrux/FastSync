#include "log.h"
#include "transport_ssh.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
  char* user;
  char* host;
  char* remote_path;
} RemoteDest;

/* Writes the exec-failure marker and exits the child.  Marked noreturn so
 * static analyzers prove the caller's error path never falls through. */
__attribute__((noreturn)) static void ssh_child_setup_failed(int status_fd) {
  ssize_t wret = write(status_fd, "x", 1);
  (void)wret;
  _exit(1);
}

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

char* ssh_build_remote_command(const char* server_path, bool old_args, char* const* remote_options,
                               int remote_option_count) {
  const char* path = server_path ? server_path : "fastsync-server";
  const char* suffix = " --stdio";

  /* Each --remote-option=OPT is appended after " --stdio" as one shell word,
     escaped with the SAME single-quote boundary used for the server path.  This
     stays safe even in --old-args mode (which leaves the server path unquoted):
     remote options are always single-quoted individually, so a value containing
     shell metacharacters (; & | ` $ ()) can never break out of the quoting to
     inject an unrelated remote command.  Values are already validated at CLI
     parse time (non-empty, no control characters); this layer only adds the
     escaping boundary. */
  size_t path_len = strlen(path);
  size_t suffix_len = strlen(suffix);

  /* The base command (server path, quoted unless --old-args, then " --stdio"). */
  size_t command_len;
  if (old_args) {
    if (path_len > SIZE_MAX - suffix_len - 1)
      return NULL;
    command_len = path_len + suffix_len + 1;
  } else {
    size_t quote_count = 0;
    for (const char* p = path; *p; p++)
      if (*p == '\'')
        quote_count++;
    if (path_len > SIZE_MAX - suffix_len - 4 ||
        quote_count > (SIZE_MAX - path_len - suffix_len - 4) / 4)
      return NULL;
    command_len = path_len + quote_count * 4 + suffix_len + 4;
  }

  /* Add each remote option, escaped as one single-quoted word:
     " '<body>'", i.e. 1 leading space + 1 open quote + body (len + 3 per
     embedded single quote) + 1 close quote = len + q*3 + 3 bytes.
     Defense-in-depth against a non-conforming caller: never forward an empty
     or control-character value, independent of the CLI validation. */
  for (int i = 0; i < remote_option_count; i++) {
    const char* opt = remote_options[i];
    if (!opt || opt[0] == '\0')
      return NULL;
    size_t len = 0, q = 0;
    for (const char* p = opt; *p; p++) {
      /* Defense-in-depth: never forward a control character (newline/CR/etc.)
         that could break the single-quoted shell word regardless of the remote
         shell, independent of the CLI validation. */
      if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f)
        return NULL;
      if (*p == '\'')
        q++;
      len++;
    }
    if (len > SIZE_MAX - q * 3 || len + q * 3 + 3 > SIZE_MAX - command_len)
      return NULL;
    command_len += len + q * 3 + 3;
  }
  command_len += 1; /* NUL */

  char* command = malloc(command_len);
  if (!command)
    return NULL;
  char* out = command;
  if (old_args) {
    memcpy(out, path, path_len);
    out += path_len;
    memcpy(out, suffix, suffix_len + 1);
    out += suffix_len;
  } else {
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
    out += suffix_len;
  }
  for (int i = 0; i < remote_option_count; i++) {
    const char* opt = remote_options[i];
    *out++ = ' ';
    *out++ = '\'';
    for (const char* p = opt; *p; p++) {
      if (*p == '\'') {
        memcpy(out, "'\\''", 4);
        out += 4;
      } else {
        *out++ = *p;
      }
    }
    *out++ = '\'';
  }
  *out = '\0';
  return command;
}

/* A heap-owned, NULL-terminated argv whose every string is separately malloc'd
 * (str_dup'd) so a caller can free arbitrary slots, including argv[0]. */
char** ssh_build_client_argv(const char* rsh_command, int port, const char* userhost,
                             const char* remote_command) {
  const char* rsh = (rsh_command && *rsh_command) ? rsh_command : "ssh";

  /* Whitespace-split the remote-shell command into the leading argv words so
   * "-e 'ssh -p 2222'" (or "--rsh=ssh -p 2222") works like rsync's rsh.  A
   * blank command falls back to the default "ssh". */
  char* copy = str_dup(rsh);
  if (!copy)
    return NULL;
  char* save = NULL;
  int nwords = 0;
  char** words = NULL;
  for (char* tok = strtok_r(copy, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
    char** grown = realloc(words, (size_t)(nwords + 1) * sizeof(char*));
    if (!grown) {
      for (int i = 0; i < nwords; i++)
        free(words[i]);
      free(words);
      free(copy);
      return NULL;
    }
    words = grown;
    words[nwords] = str_dup(tok);
    if (!words[nwords]) {
      for (int i = 0; i < nwords; i++)
        free(words[i]);
      free(words);
      free(copy);
      return NULL;
    }
    nwords++;
  }
  free(copy);
  if (nwords == 0) {
    words = malloc(sizeof(char*));
    if (!words)
      return NULL;
    words[0] = str_dup("ssh");
    if (!words[0]) {
      free(words);
      return NULL;
    }
    nwords = 1;
  }

  /* Fixed tail: three -o pairs (6) + optional -p/value (2) + user@host +
   * remote command + terminating NULL. */
  int port_extra = (port > 0 && port != 22) ? 2 : 0;
  size_t total = (size_t)nwords + 6 + (size_t)port_extra + 3;
  char** argv = calloc(total, sizeof(char*));
  if (!argv) {
    for (int i = 0; i < nwords; i++)
      free(words[i]);
    free(words);
    return NULL;
  }
  int ac = 0;
  for (int i = 0; i < nwords; i++)
    argv[ac++] = words[i];
  free(words);

  char* tail[] = {"-o", "Compression=no",
                  "-o", "ControlMaster=auto",
                  "-o", "ControlPath=~/.cache/fastsync-%r@%h:%p"};
  for (size_t i = 0; i < sizeof(tail) / sizeof(tail[0]); i++) {
    argv[ac] = str_dup(tail[i]);
    if (!argv[ac])
      goto fail_argv;
    ac++;
  }
  if (port_extra) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    argv[ac] = str_dup("-p");
    if (!argv[ac])
      goto fail_argv;
    ac++;
    argv[ac] = str_dup(port_str);
    if (!argv[ac])
      goto fail_argv;
    ac++;
  }
  argv[ac] = str_dup(userhost);
  if (!argv[ac])
    goto fail_argv;
  ac++;
  argv[ac] = str_dup(remote_command);
  if (!argv[ac])
    goto fail_argv;
  ac++;
  argv[ac] = NULL;
  return argv;

fail_argv:
  for (int i = 0; i < ac; i++)
    free(argv[i]);
  free(argv);
  return NULL;
}

void ssh_free_client_argv(char** argv) {
  if (!argv)
    return;
  for (int i = 0; argv[i]; i++)
    free(argv[i]);
  free(argv);
}

Client* client_connect_ssh(const char* destination, int port, const char* server_path,
                           bool old_args, const char* rsh_command, bool blocking_io,
                           char* const* remote_options, int remote_option_count) {
  RemoteDest r;
  if (parse_remote_dest(destination, &r) != 0) {
    char* escaped = output_escape(destination, false);
    fprintf(stderr, "Invalid remote destination: %s\n", escaped ? escaped : "<allocation failed>");
    free(escaped);
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

  /* By default the SSH transport socket gets the same read/write timeout as
   * the TCP transport so a wedged remote shell cannot hang forever.  With
   * --blocking-io the timeouts are skipped and the socket blocks naturally. */
  if (!blocking_io) {
    struct timeval tv;
    tv.tv_sec = tcp_get_timeout_sec();
    tv.tv_usec = 0;
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  }

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
    if (fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC) < 0)
      ssh_child_setup_failed(exec_pipe[1]);
    if (sv[1] != STDIN_FILENO && dup2(sv[1], STDIN_FILENO) < 0)
      ssh_child_setup_failed(exec_pipe[1]);
    if (sv[1] != STDOUT_FILENO && dup2(sv[1], STDOUT_FILENO) < 0)
      ssh_child_setup_failed(exec_pipe[1]);
    if (sv[1] > 1)
      close(sv[1]);

    size_t ssh_user_len;
    if (r.user && r.user[0] != '\0')
      ssh_user_len = strlen(r.user) + 1 + strlen(r.host) + 1;
    else
      ssh_user_len = strlen(r.host) + 1;
    char* ssh_user = malloc(ssh_user_len);
    if (!ssh_user)
      ssh_child_setup_failed(exec_pipe[1]);
    if (r.user && r.user[0] != '\0')
      snprintf(ssh_user, ssh_user_len, "%s@%s", r.user, r.host);
    else
      snprintf(ssh_user, ssh_user_len, "%s", r.host);

    char* remote_command =
        ssh_build_remote_command(server_path, old_args, remote_options, remote_option_count);
    if (!remote_command)
      ssh_child_setup_failed(exec_pipe[1]);
    char** ssh_argv = ssh_build_client_argv(rsh_command, port, ssh_user, remote_command);
    free(ssh_user);
    free(remote_command);
    if (!ssh_argv)
      ssh_child_setup_failed(exec_pipe[1]);
    execvp(ssh_argv[0], ssh_argv);
    log_perror("exec of remote shell failed");
    ssh_free_client_argv(ssh_argv);
    ssh_child_setup_failed(exec_pipe[1]);
  }

  close(sv[1]);
  close(exec_pipe[1]);

  char exec_status;
  ssize_t n = read(exec_pipe[0], &exec_status, 1);
  close(exec_pipe[0]);

  if (n != 0) {
    close(sv[0]);
    waitpid(pid, NULL, 0);
    remote_dest_destroy(&r);
    const char* path = server_path ? server_path : "fastsync-server";
    char* escaped = output_escape(path, false);
    fprintf(stderr, "Error: could not launch '%s --stdio' on remote\n",
            escaped ? escaped : "<allocation failed>");
    free(escaped);
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
