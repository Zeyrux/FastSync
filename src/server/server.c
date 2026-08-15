#include "array_list.h"
#include "chunk.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include "unistd.h"
#include "utils.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/x509.h>

static char* authorized_root;
static int authorized_root_fd = -1;
static bool allow_delete;
static bool allow_unauthenticated;
static const char* required_client_cn;

static bool tls_client_identity_allowed(SSL* ssl) {
  if (!ssl || !required_client_cn)
    return false;
  X509* certificate = SSL_get1_peer_certificate(ssl);
  if (!certificate)
    return false;
  char common_name[256];
  int length = X509_NAME_get_text_by_NID(X509_get_subject_name(certificate), NID_commonName,
                                         common_name, sizeof(common_name));
  bool allowed = length >= 0 && (size_t)length < sizeof(common_name) &&
                 strcmp(common_name, required_client_cn) == 0;
  X509_free(certificate);
  return allowed;
}

static bool path_is_within(const char* root, const char* path) {
  size_t n = strlen(root);
  return strncmp(root, path, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static bool valid_batch_path(const char* path) {
  return path && path[0] != '\0' && path[0] != '/' && !has_path_traversal(path) &&
         strchr(path, '\0') == path + strlen(path);
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
  file_set_authorized_root(authorized_root_fd, authorized_root);
  utils_set_authorized_root(authorized_root_fd, authorized_root);
  return true;
}

int receive_files(Config* config, int fd) {
  Status status;
  if (!receive_status(fd, &status))
    return -1;

  while (status == STATUS_NEXT || status == STATUS_CHUNK || status == STATUS_CHECK ||
         status == STATUS_KEEPALIVE || status == STATUS_ABORT || status == STATUS_CHECK_BATCH) {
    if (status == STATUS_KEEPALIVE) {
      send_status(fd, STATUS_KEEPALIVE);
      goto next;
    }
    if (status == STATUS_ABORT) {
      log_message(LOG_LEVEL_INFO, "Received abort from client, cleaning up");
      return -1;
    }
    if (status == STATUS_CHECK) {
      bool skipped;
      File* file = receive_incremental_check(fd, config, &skipped);
      if (skipped)
        goto next;
      if (file == NULL && !skipped)
        return -1;
      if (config->save_to_disk &&
          !file_save_to_disk(config->receive_root_directory, file, config)) {
        file_destroy(file);
        send_status(fd, STATUS_ERROR);
        return -1;
      }
      file_destroy(file);
    } else if (status == STATUS_CHUNK) {
      Chunk* chunk = receive_chunk_data(fd, config);
      if (chunk == NULL) {
        send_status(fd, STATUS_ERROR);
        return -1;
      }
      for (int i = 0; i < chunk->element_count; i++) {
        if (config->save_to_disk &&
            !file_save_to_disk(config->receive_root_directory, chunk->items[i], config)) {
          chunk_destroy(chunk);
          send_status(fd, STATUS_ERROR);
          return -1;
        }
      }
      chunk_destroy(chunk);
    } else if (status == STATUS_CHECK_BATCH) {
      int count;
      /* Batch framing has no checksum field yet; never silently downgrade a
         checksum-enabled transfer into mtime-only matching. */
      if (config->checksum || !receive_int(fd, &count) || count < 0 || count > MAX_MANIFEST_ENTRIES)
        return -1;
      for (int i = 0; i < count; i++) {
        char* check_path = receive_str(fd);
        if (!check_path)
          return -1;
        unsigned long long check_size;
        long long check_mtime;
        if (!receive_n_data(fd, &check_size, sizeof(check_size)) ||
            !receive_n_data(fd, &check_mtime, sizeof(check_mtime))) {
          free(check_path);
          return -1;
        }
        if (!valid_batch_path(check_path)) {
          free(check_path);
          send_status(fd, STATUS_ERROR);
          return -1;
        }
        struct stat st;
        char* full_path = path_cat(config->receive_root_directory, check_path);
        bool has_old = full_path && file_stat_secure(full_path, &st);
        bool match = has_old && (unsigned long long)st.st_size == check_size &&
                     (long long)st.st_mtime == check_mtime;
        bool sent = send_status(fd, match ? STATUS_OK : STATUS_NEXT);
        free(full_path);
        free(check_path);
        if (!sent)
          return -1;
      }
      goto next;
    } else {
      File* file = file_receive(config, fd);
      if (file == NULL) {
        log_message(LOG_LEVEL_ERROR, "Failed to receive file");
        send_status(fd, STATUS_ERROR);
        return -1;
      }
      if (config->save_to_disk &&
          !file_save_to_disk(config->receive_root_directory, file, config)) {
        file_destroy(file);
        send_status(fd, STATUS_ERROR);
        return -1;
      }
      file_destroy(file);
    }
  next:
    if (!receive_status(fd, &status)) {
      send_status(fd, STATUS_ERROR);
      return -1;
    }
  }

  if (status == STATUS_MANIFEST) {
    if (receive_manifest(fd, config, &status) != 0)
      return -1;
  }
  if (status != STATUS_FINISHED) {
    log_message(LOG_LEVEL_ERROR, "Did not receive FINISHED Status");
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  send_status(fd, STATUS_OK);
  return 0;
}

void handler(int file_descriptor) {
  SSL* ssl = io_get_ssl();
  Config* config = config_receive(file_descriptor);
  if (config == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to receive config");
    close(file_descriptor);
    return;
  }
  if (!authorized_root) {
    log_message(LOG_LEVEL_ERROR, "No server-side destination root configured");
    config_delete(config);
    close(file_descriptor);
    return;
  }
  if (!allow_unauthenticated && ssl == NULL) {
    log_message(LOG_LEVEL_ERROR, "Rejected unauthenticated plaintext connection");
    config_delete(config);
    close(file_descriptor);
    return;
  }
  if (ssl && required_client_cn && !tls_client_identity_allowed(ssl)) {
    log_message(LOG_LEVEL_ERROR, "Rejected TLS client with unauthorized identity");
    config_delete(config);
    close(file_descriptor);
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
    return;
  }
  config->use_delete = config->use_delete && allow_delete;
  if (config->use_multithreading) {
    Queue* q = queue_create(100, file_destroy);
    if (q == NULL) {
      config_delete(config);
      close(file_descriptor);
      return;
    }
    PipelineContextReceiver* context =
        pipeline_context_receiver_create(config, q, file_descriptor, ssl);
    if (context == NULL) {
      queue_destroy(q);
      config_delete(config);
      close(file_descriptor);
      return;
    }
    thrd_t receiver, writer;
    bool receiver_created = false;
    bool writer_created = false;
    receiver_created = (thrd_create(&receiver, receive_thread, context) == thrd_success);
    if (receiver_created)
      writer_created = (thrd_create(&writer, write_thread, context) == thrd_success);
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
      return;
    }
    int receiver_result;
    int writer_result;
    thrd_join(receiver, &receiver_result);
    thrd_join(writer, &writer_result);
    if (receiver_result == thrd_success && writer_result == thrd_success)
      send_status(file_descriptor, STATUS_OK);
    else
      send_status(file_descriptor, STATUS_ERROR);
    pipeline_context_receiver_destroy(context);
  } else {
    if (receive_files(config, file_descriptor) != 0)
      log_message(LOG_LEVEL_ERROR, "Transfer failed");
    config_delete(config);
  }
  close(file_descriptor);
}

#ifndef FASTSYNC_SERVER_AS_LIB
static Server* g_server = NULL;

static void cleanup(int sig) {
  (void)sig;
  if (g_server) {
    server_delete(&g_server);
  }
  _exit(0);
}

static void print_server_usage(void) {
  printf("FastSync Server\n");
  printf("Usage: fastsync-server [options]\n");
  printf("\n");
  printf("Options:\n");
  printf("  --stdio             Run in stdio mode (SSH transport)\n");
  printf("  -p <port>           TCP port (default: 8080, range: 1-65535)\n");
  printf("  --tls               Enable TLS encryption\n");
  printf("  --cert <path>       TLS certificate file (PEM)\n");
  printf("  --key <path>        TLS private key file (PEM)\n");
  printf("  --ca <path>         TLS CA certificate file (PEM)\n");
  printf("  --client-cn <name>  Required TLS client certificate CN\n");
  printf("  --destination-root <path>  Authorized destination root (default: .)\n");
  printf("  --allow-delete      Permit manifest deletion\n");
  printf("  --allow-unauthenticated  Allow plaintext/anonymous network clients\n");
  printf("  -v, --verbose       Enable debug logging\n");
  printf("  --help              Show this help\n");
}

int main(int argc, char* argv[]) {
  bool use_tls = false;
  char* tls_cert = NULL;
  char* tls_key = NULL;
  char* tls_ca = NULL;
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
    } else if (strcmp(argv[i], "--client-cn") == 0 && i + 1 < argc) {
      required_client_cn = argv[++i];
    } else if (strcmp(argv[i], "--destination-root") == 0 && i + 1 < argc) {
      destination_root = argv[++i];
    } else if (strcmp(argv[i], "--allow-delete") == 0) {
      allow_delete = true;
    } else if (strcmp(argv[i], "--allow-unauthenticated") == 0) {
      allow_unauthenticated = true;
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

  if (tls_ca && !use_tls) {
    log_message(LOG_LEVEL_WARNING, "--ca has no effect without --tls");
  }

  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);
  if (!configure_authorization(destination_root)) {
    fprintf(stderr, "Error: invalid destination root '%s'\n", destination_root);
    return 1;
  }
  if (stdio_mode) {
    /* SSH authenticates the stdio transport outside of FastSync. */
    allow_unauthenticated = true;
    io_set_fds(STDIN_FILENO, STDOUT_FILENO);
    handler(STDIN_FILENO);
    file_set_authorized_root(-1, NULL);
    utils_set_authorized_root(-1, NULL);
    close(authorized_root_fd);
    free(authorized_root);
    return 0;
  }
  g_server = server_create(port);
  if (g_server == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to create server");
    return 1;
  }
  if (use_tls) {
    if (!tls_cert || !tls_key || !tls_ca || !required_client_cn) {
      fprintf(stderr, "Error: --tls requires --cert, --key, --ca, and --client-cn\n");
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
#endif /* !FASTSYNC_SERVER_AS_LIB */
