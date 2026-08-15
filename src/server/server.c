#include "config.h"
#include "file.h"
#include "log.h"
#include "multiprocessing.h"
#include "queue.h"
#include "receiver.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include "unistd.h"
#include "utils.h"
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static char* authorized_root;
static int authorized_root_fd = -1;
static bool allow_delete;

static bool path_is_within(const char* root, const char* path) {
  size_t n = strlen(root);
  return strncmp(root, path, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static bool __attribute__((unused)) configure_authorization(const char* root) {
  char resolved[PATH_MAX];
  if (!root || !realpath(root, resolved))
    return false;
  authorized_root = str_dup(resolved);
  if (!authorized_root)
    return false;
  authorized_root_fd = open(resolved, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (authorized_root_fd < 0) {
    free(authorized_root);
    authorized_root = NULL;
    return false;
  }
  if (!file_set_authorized_root(authorized_root_fd, authorized_root)) {
    close(authorized_root_fd);
    authorized_root_fd = -1;
    free(authorized_root);
    authorized_root = NULL;
    return false;
  }
  utils_set_authorized_root_fd(authorized_root_fd);
  return true;
}

void handler(int file_descriptor) {
  SSL* ssl = io_get_ssl();
  ProtocolSession session;
  protocol_session_init(&session, file_descriptor, file_descriptor);
  protocol_session_set_ssl(&session, ssl);
  protocol_session_bind(&session);
  Config* config = config_receive(file_descriptor);
  if (config == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to receive config");
    close(file_descriptor);
    protocol_session_unbind();
    return;
  }
  if (!authorized_root) {
    log_message(LOG_LEVEL_ERROR, "No server-side destination root configured");
    config_delete(config);
    close(file_descriptor);
    protocol_session_unbind();
    return;
  }
  char resolved_destination[PATH_MAX];
  char* canonical_destination = realpath(config->receive_root_directory, NULL);
  const char* destination =
      canonical_destination ? canonical_destination : config->receive_root_directory;
  if (has_path_traversal(destination) || !path_is_within(authorized_root, destination)) {
    log_message(LOG_LEVEL_ERROR, "Rejected destination outside authorized root");
    free(canonical_destination);
    config_delete(config);
    close(file_descriptor);
    protocol_session_unbind();
    return;
  }
  if (canonical_destination)
    snprintf(resolved_destination, sizeof(resolved_destination), "%s", canonical_destination);
  else
    snprintf(resolved_destination, sizeof(resolved_destination), "%s", destination);
  free(canonical_destination);
  free(config->receive_root_directory);
  config->receive_root_directory = str_dup(resolved_destination);
  if (!config->receive_root_directory) {
    config_delete(config);
    close(file_descriptor);
    protocol_session_unbind();
    return;
  }
  config->use_delete = config->use_delete && allow_delete;
  if (config->use_multithreading) {
    Queue* q = queue_create(100, file_destroy);
    if (q == NULL) {
      config_delete(config);
      close(file_descriptor);
      protocol_session_unbind();
      return;
    }
    PipelineContextReceiver* context =
        pipeline_context_receiver_create(config, q, file_descriptor, ssl);
    if (context == NULL) {
      queue_destroy(q);
      config_delete(config);
      close(file_descriptor);
      protocol_session_unbind();
      return;
    }
    context->session.total_allocated_bytes = session.total_allocated_bytes;
    thrd_t receiver, writer;
    bool receiver_created = thrd_create(&receiver, receive_thread, context) == thrd_success;
    bool writer_created = false;
    if (receiver_created)
      writer_created = thrd_create(&writer, write_thread, context) == thrd_success;
    if (!receiver_created || !writer_created) {
      perror("Error creating Threads");
      if (receiver_created) {
        mtx_lock(&context->mutex);
        atomic_store(&context->cancelled, true);
        cnd_broadcast(&context->condition_not_full);
        cnd_broadcast(&context->condition_not_empty);
        mtx_unlock(&context->mutex);
        close(file_descriptor);
        thrd_join(receiver, NULL);
      } else {
        close(file_descriptor);
      }
      if (writer_created)
        thrd_join(writer, NULL);
      pipeline_context_receiver_destroy(context);
      protocol_session_unbind();
      return;
    }
    int receiver_result;
    int writer_result;
    thrd_join(receiver, &receiver_result);
    thrd_join(writer, &writer_result);
    send_status(file_descriptor, receiver_result == thrd_success && writer_result == thrd_success
                                     ? STATUS_OK
                                     : STATUS_ERROR);
    pipeline_context_receiver_destroy(context);
  } else {
    if (receiver_receive_files(config, file_descriptor) != 0)
      log_message(LOG_LEVEL_ERROR, "Transfer failed");
    config_delete(config);
  }
  protocol_session_unbind();
  close(file_descriptor);
}

#ifndef FASTSYNC_SERVER_AS_LIB
static Server* g_server = NULL;

static void cleanup(int sig) {
  (void)sig;
  if (g_server)
    server_delete(&g_server);
  _exit(0);
}

static void print_server_usage(void) {
  printf("FastSync Server\n");
  printf("Usage: fastsync-server [options]\n\n");
  printf("Options:\n");
  printf("  --stdio             Run in stdio mode (SSH transport)\n");
  printf("  -p <port>           TCP port (default: 8080, range: 1-65535)\n");
  printf("  --tls               Enable TLS encryption\n");
  printf("  --cert <path>       TLS certificate file (PEM)\n");
  printf("  --key <path>        TLS private key file (PEM)\n");
  printf("  --ca <path>         TLS CA certificate file (PEM)\n");
  printf("  --destination-root <path>  Authorized destination root (default: .)\n");
  printf("  --allow-delete      Permit manifest deletion\n");
  printf("  -v, --verbose       Enable debug logging\n");
  printf("  --help              Show this help\n");
}

int main(int argc, char* argv[]) {
  bool use_tls = false;
  char *tls_cert = NULL, *tls_key = NULL, *tls_ca = NULL;
  int port = 8080;
  const char* destination_root = ".";
  bool stdio_mode = false;

  signal(SIGPIPE, SIG_IGN);
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      print_server_usage();
      return 0;
    } else if (strcmp(argv[i], "--stdio") == 0) {
      stdio_mode = true;
    } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
      set_log_level(LOG_LEVEL_DEBUG);
    } else if (strcmp(argv[i], "--tls") == 0) {
      use_tls = true;
    } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      tls_cert = argv[++i];
    } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      tls_key = argv[++i];
    } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
      tls_ca = argv[++i];
    } else if (strcmp(argv[i], "--destination-root") == 0 && i + 1 < argc) {
      destination_root = argv[++i];
    } else if (strcmp(argv[i], "--allow-delete") == 0) {
      allow_delete = true;
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      char* end;
      long p = strtol(argv[++i], &end, 10);
      if (*end || p <= 0 || p > 65535) {
        fprintf(stderr, "Error: invalid port '%s' (must be 1-65535)\n", argv[i]);
        return 1;
      }
      port = (int)p;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_server_usage();
      return 1;
    }
  }
  if (tls_ca && !use_tls)
    log_message(LOG_LEVEL_WARNING, "--ca has no effect without --tls");
  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);
  if (!configure_authorization(destination_root)) {
    fprintf(stderr, "Error: invalid destination root '%s'\n", destination_root);
    return 1;
  }
  if (stdio_mode) {
    io_set_fds(STDIN_FILENO, STDOUT_FILENO);
    handler(STDIN_FILENO);
    file_set_authorized_root(-1, NULL);
    utils_set_authorized_root_fd(-1);
    close(authorized_root_fd);
    free(authorized_root);
    return 0;
  }
  g_server = server_create(port);
  if (!g_server) {
    log_message(LOG_LEVEL_ERROR, "Failed to create server");
    return 1;
  }
  if (use_tls) {
    if (!tls_cert || !tls_key) {
      fprintf(stderr, "Error: --tls requires --cert and --key\n");
      server_delete(&g_server);
      return 1;
    }
    tls_global_init();
    if (!server_create_tls(g_server, tls_cert, tls_key, tls_ca)) {
      log_message(LOG_LEVEL_ERROR, "Failed to set up TLS");
      server_delete(&g_server);
      return 1;
    }
    server_listen_tls(g_server, handler);
  } else {
    server_listen(g_server, handler);
  }
  return 0;
}
#endif
