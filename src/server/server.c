#include "config.h"
#include "delay_updates.h"
#include "file.h"
#include "log.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "receiver.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include "utils.h"
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/x509.h>

static char* authorized_root;
static int authorized_root_fd = -1;
static bool allow_delete;
static bool allow_unauthenticated;
static const char* required_client_cn;

/* Aggregate payload bytes the multithreaded receiver may buffer ahead of the
   slow disk writer.  Receiving one more chunk adds up to ~2 * MAX_CHUNK_SIZE
   of transient wire/decompression buffers on top of the queued payloads, so
   this ceiling keeps total per-connection receive memory (decompressed and
   per-file copied chunk buffers included) within MAX_CONNECTION_MEMORY. */
#define RECEIVER_QUEUE_MAX_BYTES (MAX_CONNECTION_MEMORY - 2 * MAX_CHUNK_SIZE)

static bool tls_client_identity_allowed(SSL* ssl) {
  if (!ssl || !required_client_cn)
    return false;
  X509* certificate = SSL_get1_peer_certificate(ssl);
  if (!certificate)
    return false;
  char common_name[256];
  int length = X509_NAME_get_text_by_NID(X509_get_subject_name(certificate), NID_commonName,
                                         common_name, sizeof(common_name));
  size_t required_length = strlen(required_client_cn);
  bool allowed = length >= 0 && (size_t)length == required_length &&
                 required_length < sizeof(common_name) &&
                 memcmp(common_name, required_client_cn, required_length) == 0;
  X509_free(certificate);
  return allowed;
}

static void release_authorization(void) {
  file_set_authorized_root(-1, NULL);
  utils_set_authorized_root_fd(-1);
  if (authorized_root_fd >= 0)
    close(authorized_root_fd);
  authorized_root_fd = -1;
  free(authorized_root);
  authorized_root = NULL;
}

static bool path_is_within(const char* root, const char* path) {
  size_t n = strlen(root);
  return strncmp(root, path, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

/* --mkpath contract: when the client's destination root directory does not
   exist yet on the server side, --mkpath tells the server to create it (and
   any missing leading components) below the authorized root at connection
   start.  Without --mkpath the destination root must already exist: a missing
   root is rejected up front instead of being silently invented by a later
   write.  Both paths are confined to the authorized root by the secure file
   helpers. */
static bool ensure_receive_root(const Config* config) {
  if (!config || !config->receive_root_directory)
    return false;
  if (config->mkpath)
    return file_ensure_directory_secure(config->receive_root_directory);
  return file_directory_exists_secure(config->receive_root_directory);
}

static bool __attribute__((unused)) configure_authorization(const char* root) {
  char resolved[PATH_MAX];
  if (!root) {
    file_set_authorized_root(-1, NULL);
    utils_set_authorized_root(-1, NULL);
    return false;
  }
  int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root_fd < 0) {
    file_set_authorized_root(-1, NULL);
    utils_set_authorized_root(-1, NULL);
    return false;
  }
  char fd_path[64];
  int fd_path_length = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", root_fd);
  if (fd_path_length < 0 || (size_t)fd_path_length >= sizeof(fd_path) ||
      !realpath(fd_path, resolved)) {
    close(root_fd);
    file_set_authorized_root(-1, NULL);
    utils_set_authorized_root(-1, NULL);
    return false;
  }
  authorized_root = str_dup(resolved);
  if (!authorized_root) {
    close(root_fd);
    file_set_authorized_root(-1, NULL);
    utils_set_authorized_root(-1, NULL);
    return false;
  }
  authorized_root_fd = root_fd;
  if (!file_set_authorized_root(authorized_root_fd, authorized_root) ||
      !utils_set_authorized_root(authorized_root_fd, authorized_root)) {
    file_set_authorized_root(-1, NULL);
    utils_set_authorized_root(-1, NULL);
    close(authorized_root_fd);
    authorized_root_fd = -1;
    free(authorized_root);
    authorized_root = NULL;
    return false;
  }
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
  protocol_set_8_bit_output(config->eight_bit_output);
  if (!authorized_root) {
    log_message(LOG_LEVEL_ERROR, "No server-side destination root configured");
    config_delete(config);
    close(file_descriptor);
    protocol_session_unbind();
    return;
  }
  if (!allow_unauthenticated && ssl == NULL) {
    log_message(LOG_LEVEL_ERROR, "Rejected unauthenticated plaintext connection");
    config_delete(config);
    close(file_descriptor);
    protocol_session_unbind();
    return;
  }
  if (ssl && required_client_cn && !tls_client_identity_allowed(ssl)) {
    log_message(LOG_LEVEL_ERROR, "Rejected TLS client with unauthorized identity");
    config_delete(config);
    close(file_descriptor);
    return;
  }
  char* destination = config->receive_root_directory;
  char* joined_destination = NULL;
  if (destination && destination[0] != '/')
    joined_destination = path_cat(authorized_root, destination);
  if (joined_destination)
    destination = joined_destination;
  if (!destination || has_path_traversal(destination) ||
      !path_is_within(authorized_root, destination)) {
    log_message(LOG_LEVEL_ERROR, "Rejected destination outside authorized root");
    free(joined_destination);
    config_delete(config);
    close(file_descriptor);
    return;
  }
  if (joined_destination) {
    free(config->receive_root_directory);
    config->receive_root_directory = joined_destination;
  }
  if (!config->receive_root_directory) {
    config_delete(config);
    close(file_descriptor);
    protocol_session_unbind();
    return;
  }
  config->use_delete = config->use_delete && allow_delete;
  /* --delete-missing-args deletes destination mirrors receiver-side, so it is
     deletion and stays gated by the same --allow-delete server policy.  When
     the server policy is off the flag is inert (the missing entries are still
     skipped via its implied --ignore-missing-args, but nothing is deleted). */
  config->delete_missing_args = config->delete_missing_args && allow_delete;
  /* --mkpath: create the destination root (and its missing leading components)
     before anything else; without it the root must pre-exist.  A failure here
     aborts the connection cleanly before any file data is exchanged. */
  if (!ensure_receive_root(config)) {
    log_message(LOG_LEVEL_ERROR, "destination root is not available: %s",
                config->receive_root_directory);
    config_delete(config);
    close(file_descriptor);
    protocol_session_unbind();
    return;
  }
  /* A --delay-updates transfer stages under a private 0700 directory inside
     the receive root.  Create it up front (wiping leftovers of any previously
     interrupted delayed transfer) so a fully-skipped run also starts clean. */
  if (config->delay_updates) {
    config->delay_context = delay_updates_context_create(config->receive_root_directory);
    if (!config->delay_context || !delay_updates_prepare(config->delay_context)) {
      log_message(LOG_LEVEL_ERROR, "Failed to initialize --delay-updates staging area");
      delay_updates_cleanup(config->delay_context);
      config_delete(config);
      close(file_descriptor);
      protocol_session_unbind();
      return;
    }
  }
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
    protocol_session_set_max_alloc(&context->session, config->max_alloc);
    atomic_store(&context->session.total_allocated_bytes,
                 atomic_load(&session.total_allocated_bytes));
    pipeline_context_receiver_set_queue_byte_limit(context, RECEIVER_QUEUE_MAX_BYTES);
    thrd_t receiver, writer;
    bool receiver_created = thrd_create(&receiver, receive_thread, context) == thrd_success;
    bool writer_created = false;
    if (receiver_created)
      writer_created = thrd_create(&writer, write_thread, context) == thrd_success;
    if (!receiver_created || !writer_created) {
      log_perror("Error creating Threads");
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
    bool transfer_ok = receiver_result == thrd_success && writer_result == thrd_success;
    if (transfer_ok) {
      /* Commit-style (late) deletion: receive_thread handed the keep-set
         manifest here instead of deleting while write_thread might still be
         draining, so by now every file is on disk and the whole transfer is
         known to have succeeded.  Remove the extras before publishing a
         --delay-updates run; the walker skips the staging directory. */
      if (context->deferred_manifest) {
        if (!manifest_delete_all(config, context->deferred_manifest)) {
          transfer_ok = false;
        }
        delete_manifest_free(context->deferred_manifest);
        context->deferred_manifest = NULL;
      }
    }
    if (transfer_ok) {
      /* --delay-updates: receive_thread has finished the whole protocol stream
         (including manifest/delete handling) and write_thread has drained its
         queue, so every staged file is complete.  Publish atomically before the
         success/outcome frame so a --remove-source-files sender only learns of
         files that were actually installed. */
      if (config->delay_updates && config->delay_context &&
          !delay_updates_publish(config->delay_context, config)) {
        transfer_ok = false;
      }
    }
    if (transfer_ok) {
      if (!receiver_send_final_success(file_descriptor, config, &context->outcomes))
        transfer_ok = false;
    } else {
      send_status(file_descriptor, STATUS_ERROR);
    }
    if (!transfer_ok) {
      log_message(LOG_LEVEL_ERROR, "Transfer failed");
      if (config->delay_updates && config->delay_context)
        delay_updates_cleanup(config->delay_context);
    }
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
  printf("  --client-cn <name>  Required TLS client certificate CN\n");
  printf("  --destination-root <path>  Authorized destination root (default: .)\n");
  printf("  --allow-delete      Permit manifest deletion\n");
  printf("  --allow-unauthenticated  Allow plaintext/anonymous network clients\n");
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
      set_log_debug_flags(LOG_DEBUG_ALL);
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
        char* escaped = output_escape(argv[i], false);
        fprintf(stderr, "Error: invalid port '%s' (must be 1-65535)\n",
                escaped ? escaped : "<allocation failed>");
        free(escaped);
        return 1;
      }
      port = (int)p;
    } else if (argv[i][0] == '-') {
      char* escaped = output_escape(argv[i], false);
      fprintf(stderr, "Unknown option: %s\n", escaped ? escaped : "<allocation failed>");
      free(escaped);
      print_server_usage();
      return 1;
    }
  }
  if (tls_ca && !use_tls)
    log_message(LOG_LEVEL_WARNING, "--ca has no effect without --tls");
  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);
  if (!configure_authorization(destination_root)) {
    char* escaped = output_escape(destination_root, false);
    fprintf(stderr, "Error: invalid destination root '%s'\n",
            escaped ? escaped : "<allocation failed>");
    free(escaped);
    return 1;
  }
  if (stdio_mode) {
    /* SSH authenticates the stdio transport outside of FastSync. */
    allow_unauthenticated = true;
    io_set_fds(STDIN_FILENO, STDOUT_FILENO);
    handler(STDIN_FILENO);
    release_authorization();
    return 0;
  }
  g_server = server_create(port);
  if (!g_server) {
    log_message(LOG_LEVEL_ERROR, "Failed to create server");
    release_authorization();
    return 1;
  }
  if (use_tls) {
    if (!tls_cert || !tls_key || !tls_ca || !required_client_cn) {
      fprintf(stderr, "Error: --tls requires --cert, --key, --ca, and --client-cn\n");
      server_delete(&g_server);
      release_authorization();
      return 1;
    }
    tls_global_init();
    if (!server_create_tls(g_server, tls_cert, tls_key, tls_ca)) {
      log_message(LOG_LEVEL_ERROR, "Failed to set up TLS");
      server_delete(&g_server);
      release_authorization();
      return 1;
    }
    server_listen_tls(g_server, handler);
  } else {
    server_listen(g_server, handler);
  }
  server_delete(&g_server);
  release_authorization();
  return 0;
}
#endif
