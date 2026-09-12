#include "config.h"
#include "charset.h"
#include "credentials.h"
#include "daemon_conf.h"
#include "delay_updates.h"
#include "file.h"
#include "identity.h"
#include "log.h"
#include "motd.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "receiver.h"
#include "server_cli.h"
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
#include <errno.h>
#include <sys/stat.h>
#include <openssl/x509.h>

static char* authorized_root;
static int authorized_root_fd = -1;
static bool allow_delete;
static bool trust_sender;
static bool allow_unauthenticated;
static const char* required_client_cn;
/* --iconv CONVERT_SPEC the server was itself started with (borrowed argv
 * pointer).  Its LOCAL half may override the local charset the client assumed;
 * see charset_wire_init_receiver. */
static const char* server_iconv_spec;

/* Non-NULL exactly when the listener runs in --daemon mode.  Loaded once in
 * main before any accept-loop fork, then shared read-only by every forked
 * connection child (and their threads). */
static DaemonConf* g_daemon_conf = NULL;

/* Daemon credential store (Wave B), loaded once in main from --password-file /
 * --early-input and shared read-only by every forked connection child.  When a
 * module declares `auth users` but no store was configured, the daemon refuses
 * to start (fail closed); the store is never NULL after a successful start when
 * such a module exists. */
static CredentialStore* g_credentials = NULL;

/* Opaque context threaded through to the config-frame gate: the connection's
 * SSL object (NULL over plaintext) so the gate can warn when a credential
 * exchange is not encrypted. */
typedef struct ModuleGateContext {
  SSL* ssl;
} ModuleGateContext;

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

static bool configure_authorization(const char* root) {
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

/* Config-frame gate (runs inside config_receive_with_validate, BEFORE the
 * STATUS_OK ack, so a rejected connection is refused at the config handshake
 * and no file data is ever exchanged).
 *
 * Plain mode: a connection that carries a daemon module name is refused (the
 * standalone server simply does not offer modules; honouring one would silently
 * change what the destination means).  Empty module -> accept.
 *
 * Daemon mode: the client MUST select a module (host::module/path).  The
 * requested module is looked up in the daemon config and its configured `path`
 * becomes the authorized root via configure_authorization -- exactly the same
 * root confinement the standalone server applies to its single
 * --destination-root, but per-module and NEVER client-chosen.  The module is
 * refused (with a clear log) when it is unknown, when it is `read only` (every
 * FastSync network transfer writes; there is no read-only wire operation yet),
 * or when the presented daemon credentials fail for a module that declares
 * `auth users`.  Wave A refused every auth-required module (auth was not yet
 * implemented); Wave B authenticates the client instead (see below). */
static const char* server_module_gate(const Config* config, void* context) {
  ModuleGateContext* gate_ctx = (ModuleGateContext*)context;
  if (!config)
    return "missing config frame";
  /* --iconv (protocol 2.16.0): the receiver's exact conversion direction (the
     client spec's wire charset into this server's local charset, including a
     server-side --iconv override) must be usable BEFORE the STATUS_OK ack, so
     an impossible conversion is refused at the handshake instead of failing
     the first file mid-transfer.  The client spec itself was already sanity
     checked by validate_received_config. */
  if (config->iconv_spec &&
      !charset_wire_receiver_spec_valid(config->iconv_spec, server_iconv_spec))
    return "client --iconv conversion cannot be honored by this server";
  bool is_daemon = g_daemon_conf != NULL;
  bool has_module = config->module != NULL && config->module[0] != '\0';

  if (!is_daemon) {
    if (has_module)
      return "client requested a daemon module but this server is not running "
             "with --daemon";
    return NULL;
  }
  if (!has_module)
    return "daemon connection did not select a module (expected a "
           "host::module/path destination)";

  const DaemonModule* module = daemon_conf_find_module(g_daemon_conf, config->module);
  if (module == NULL) {
    char* escaped_module = output_escape(config->module, config->eight_bit_output);
    log_message(LOG_LEVEL_ERROR, "unknown daemon module '%s' requested",
                escaped_module ? escaped_module : "<allocation failed>");
    free(escaped_module);
    return "requested daemon module does not exist";
  }
  if (module->read_only) {
    log_message(LOG_LEVEL_ERROR, "daemon module '%s' is read only; refusing write transfer",
                config->module);
    return "requested daemon module is read only";
  }
  if (module->auth_user_count > 0) {
    /* Auth-required module (Wave B): verify the presented credentials against
     * the store BEFORE the module root is installed and before any data moves.
     * Fail closed: no store -> refuse; no/invalid credentials -> refuse.  The
     * username may be logged (never the digest/password). */
    if (g_credentials == NULL) {
      log_message(LOG_LEVEL_ERROR,
                  "daemon module '%s' requires authentication but no credential store is "
                  "configured (--password-file/--early-input); refusing",
                  config->module);
      return "requested daemon module requires authentication and no credential "
             "store is configured";
    }
    if (!config->auth_user || !config->auth_password_hash) {
      log_message(LOG_LEVEL_ERROR,
                  "daemon module '%s' requires authentication; the client "
                  "presented no credentials",
                  config->module);
      return "requested daemon module requires authentication";
    }
    if (gate_ctx && !gate_ctx->ssl) {
      log_message(LOG_LEVEL_WARNING,
                  "daemon module '%s' is authenticating over a plaintext connection (no --tls); "
                  "the credential exchange is not encrypted",
                  config->module);
    }
    if (!credentials_gate_allows(g_credentials, (const char* const*)module->auth_users,
                                 module->auth_user_count, config->auth_user,
                                 config->auth_password_hash)) {
      char* escaped_user = output_escape(config->auth_user, config->eight_bit_output);
      log_message(LOG_LEVEL_ERROR, "daemon module '%s': authentication failed for user '%s'",
                  config->module, escaped_user ? escaped_user : "<allocation failed>");
      free(escaped_user);
      return "authentication failed for the requested daemon module";
    }
    char* escaped_user = output_escape(config->auth_user, config->eight_bit_output);
    log_message(LOG_LEVEL_INFO, "daemon module '%s': user '%s' authenticated", config->module,
                escaped_user ? escaped_user : "<allocation failed>");
    free(escaped_user);
  }
  if (!configure_authorization(module->path)) {
    log_message(LOG_LEVEL_ERROR, "daemon module '%s' path '%s' is not usable", config->module,
                module->path ? module->path : "(null)");
    return "requested daemon module root is not usable";
  }
  return NULL; /* accepted; authorized root is now the module's path */
}

void handler(int file_descriptor) {
  SSL* ssl = io_get_ssl();
  ProtocolSession session;
  protocol_session_init(&session, file_descriptor, file_descriptor);
  protocol_session_set_ssl(&session, ssl);
  protocol_session_bind(&session);
  ModuleGateContext gate_ctx;
  gate_ctx.ssl = ssl;
  Config* config = config_receive_with_validate(file_descriptor, server_module_gate, &gate_ctx);
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
  /* Daemon mode: the module's root is the authorized root (installed by
     server_module_gate), and the client's destination is a MODULE-RELATIVE
     path.  Reject an absolute destination up front so the module-relative
     confinement contract is never eroded by a client that tries to address the
     module root by absolute path. */
  if (g_daemon_conf && config->receive_root_directory && config->receive_root_directory[0] == '/') {
    log_message(LOG_LEVEL_ERROR, "Rejected absolute daemon destination (must be relative to the "
                                 "selected module root)");
    config_delete(config);
    close(file_descriptor);
    protocol_session_unbind();
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
  /* --iconv (protocol 2.16.0): install the receiver-side wire->local conversion
     now that the client's full CONVERT_SPEC has been received and validated,
     before any received file name is decoded.  The server's own --iconv (if
     any) may override the local charset; a spec the client is known to have
     validated cannot fail here unless the server's override names an
     unsupported charset. */
  if (config->iconv_spec && !charset_wire_init_receiver(config->iconv_spec, server_iconv_spec)) {
    log_message(LOG_LEVEL_ERROR,
                "--iconv: unsupported charset conversion requested (LOCAL[,REMOTE])");
    config_delete(config);
    close(file_descriptor);
    protocol_session_unbind();
    return;
  }
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
  /* Preserve the negotiated identity policy for the fd-relative ownership
     apply path.  Each connection is its own forked process, so this
     per-process snapshot never races another connection. */
  identity_set_active(config);
  /* Persist the negotiated --keep-dirlinks policy once, here at config-accept,
     before any multithreaded receiver/writer threads are spawned, so the
     fd-walk reads a stable value during the whole transfer (and never bleeds
     across the per-connection forked processes). */
  file_set_keep_dirlinks(config->keep_dirlinks);
  /* --trust-sender is a LOCAL receiver policy: it never crosses the wire (so a
     wire peer can never enable it).  The standalone server only honours it when
     its own CLI was started with --trust-sender (the client forwards that switch
     into the remote argv via --remote-option=--trust-sender; the server then
     parses it here and applies the policy below).  Set before any multithreaded
     receiver/writer threads are spawned so the fd-walk reads a stable value
     during the whole transfer, and never bleeds across the per-connection
     forked processes.  Off by default. */
  file_set_trust_sender(trust_sender);
  /* Wave C MOTD: on the daemon listener path only, once the module gate + auth
     have accepted and every destination check has passed, send the configured
     `motd file` as the first server->client frame before any transfer data
     (rsync sends its MOTD as the first thing from the server on a daemon
     connection).  Every daemon connection gets the frame -- an unset or
     unreadable motd file sends an empty string -- so the client's read is
     deterministic and an absent file is never an error.  The --stdio SSH path
     has no MOTD (g_daemon_conf is NULL there).  No PROTOCOL_VERSION bump: the
     frame is symmetric server->client in every 2.15.0 daemon build (see the
     Wave C note in config.h). */
  if (g_daemon_conf) {
    char* motd = motd_read_file(g_daemon_conf->global.motd_file);
    if (!motd_send(file_descriptor, motd ? motd : "")) {
      free(motd);
      log_message(LOG_LEVEL_ERROR, "Failed to send daemon MOTD");
      config_delete(config);
      close(file_descriptor);
      protocol_session_unbind();
      identity_clear_active();
      return;
    }
    free(motd);
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
      identity_clear_active();
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
      identity_clear_active();
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
      /* P7 Wave D: all writers have joined and the late deletion (and
         --delay-updates publication) has committed above, so it is finally safe
         to stamp directory times; a directory's mtime must not be clobbered by
         its children or by an extra removal. */
      if (transfer_ok)
        dir_time_list_apply(&context->dir_times, config->receive_root_directory);
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
  identity_clear_active();
  charset_wire_free();
  close(file_descriptor);
}

#ifndef FASTSYNC_SERVER_AS_LIB
static Server* g_server = NULL;

static void cleanup(int sig) {
  (void)sig;
  if (g_server)
    server_delete(&g_server);
  daemon_conf_free(g_daemon_conf);
  g_daemon_conf = NULL;
  credentials_free(g_credentials);
  g_credentials = NULL;
  _exit(0);
}

static void print_server_usage(void) {
  printf("FastSync Server\n");
  printf("Usage: fastsync-server [options]\n\n");
  printf("Options:\n");
  printf("  --stdio             Run in stdio mode (SSH transport)\n");
  printf("  --daemon            Run as a persistent daemon listener using a module\n");
  printf("                      config file (-p/config port; default 873)\n");
  printf("  --config=FILE       Daemon config file (default: ~/.config/fastsync/\n");
  printf("                      fastsyncd.conf, else /etc/fastsyncd.conf)\n");
  printf("  --dparam=KEY=VALUE  Override one global config key on the command line\n");
  printf("                      (port, motd file, address)\n");
  printf("  --no-detach         Stay in the foreground (default detaches to\n");
  printf("                      background when running --daemon)\n");
  printf("  --password-file=FILE  Credential store for modules that declare\n");
  printf("                      'auth users' (line format: user:SHA256HEX where\n");
  printf("                      SHA256HEX is the lowercase hex SHA-256 of the\n");
  printf("                      user's password).  Requires --daemon; an auth-\n");
  printf("                      required module with no store refuses to start\n");
  printf("  --early-input=FILE  Second credential store layered over\n");
  printf("                      --password-file (same format); usually a secrets-\n");
  printf("                      manager/process-substitution file.  Requires --daemon\n");
  printf("  -p <port>           TCP port (default: 8080, range: 1-65535)\n");
  printf("  --tls               Enable TLS encryption\n");
  printf("  --cert <path>       TLS certificate file (PEM)\n");
  printf("  --key <path>        TLS private key file (PEM)\n");
  printf("  --ca <path>         TLS CA certificate file (PEM)\n");
  printf("  --client-cn <name>  Required TLS client certificate CN\n");
  printf("  --destination-root <path>  Authorized destination root (default: .)\n");
  printf("  --address <addr>    Bind the listening socket to this address\n");
  printf("  -4, --ipv4          Bind an IPv4 socket (default)\n");
  printf("  -6, --ipv6          Bind an IPv6 socket\n");
  printf("  --allow-delete      Permit manifest deletion\n");
  printf("  --trust-sender      Trust the remote sender's file list\n");
  printf("  --iconv=LOCAL[,REMOTE]  Declare this server's LOCAL charset for file-name\n");
  printf("                      conversion: received names are translated to this\n");
  printf("                      charset (the wire charset still comes from the\n");
  printf("                      client's CONVERT_SPEC).  A name that cannot be\n");
  printf("                      represented fails the run cleanly\n");
  printf("  --allow-unauthenticated  Allow plaintext/anonymous network clients\n");
  printf("  -v, --verbose       Enable debug logging\n");
  printf("  --help              Show this help\n");
}

/* Resolve the daemon config default: ~/.config/fastsync/fastsyncd.conf when it
 * exists (or when HOME is set), otherwise /etc/fastsyncd.conf.  Returns a
 * pointer to a static buffer (never NULL). */
static const char* default_daemon_config_path(void) {
  const char* home = getenv("HOME");
  if (home && *home) {
    static char user_path[PATH_MAX];
    int n = snprintf(user_path, sizeof(user_path), "%s/.config/fastsync/fastsyncd.conf", home);
    if (n > 0 && (size_t)n < sizeof(user_path) && access(user_path, R_OK) == 0)
      return user_path;
  }
  /* Fall back to the traditional system path. */
  return "/etc/fastsyncd.conf";
}

/* Detach from the controlling terminal: fork, exit the parent, and make the
 * surviving child a session leader (setsid) with stdio redirected to
 * /dev/null.  The listening socket is already open (bound in main before this
 * runs), so it is inherited by the background daemon.  Returns true on
 * success (in the daemon's own process). */
static bool daemonize(void) {
  pid_t pid = fork();
  if (pid < 0)
    return false;
  if (pid > 0)
    _exit(0);
  if (setsid() < 0)
    return false;
  pid = fork();
  if (pid < 0)
    return false;
  if (pid > 0)
    _exit(0);
  int devnull = open("/dev/null", O_RDWR);
  if (devnull >= 0) {
    dup2(devnull, STDIN_FILENO);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    if (devnull > STDERR_FILENO)
      close(devnull);
  }
  /* Do not pin the launch CWD (module-relative 'path' entries would resolve
   * against an unstable working directory) and drop the restrictive host umask
   * so modules can create files/dirs with the modes the config requests. */
  if (chdir("/") != 0)
    log_message(LOG_LEVEL_WARNING, "daemon: chdir to / failed: %s", strerror(errno));
  umask(0);
  return true;
}

int main(int argc, char* argv[]) {
  ServerCliOptions opts;
  char cli_err[512];
  int parse_result = server_cli_parse(argc, argv, &opts, cli_err, sizeof(cli_err));
  if (parse_result == 1) {
    print_server_usage();
    return 0;
  }
  if (parse_result < 0) {
    server_cli_options_free(&opts);
    fprintf(stderr, "Error: %s\n", cli_err);
    print_server_usage();
    return 1;
  }

  int exit_code = 0;
  signal(SIGPIPE, SIG_IGN);
  if (opts.verbose) {
    set_log_level(LOG_LEVEL_DEBUG);
    set_log_debug_flags(LOG_DEBUG_ALL);
  }
  if (opts.tls_ca && !opts.use_tls)
    log_message(LOG_LEVEL_WARNING, "--ca has no effect without --tls");
  /* Persist the parsed server policies into the process-global policy state
   * BEFORE the stdio branch: an SSH-launched `--stdio` server (whose argv came
   * from the client via --remote-option and friends) must honor --allow-delete,
   * --trust-sender and --client-cn exactly like the standalone listener. */
  required_client_cn = opts.client_cn;
  allow_delete = opts.allow_delete;
  trust_sender = opts.trust_sender;
  allow_unauthenticated = opts.allow_unauthenticated;
  server_iconv_spec = opts.iconv_spec;
  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);

  if (opts.stdio_mode) {
    /* SSH authenticates the stdio transport outside of FastSync. */
    allow_unauthenticated = true;
    if (!configure_authorization(opts.destination_root)) {
      char* escaped = output_escape(opts.destination_root, false);
      fprintf(stderr, "Error: invalid destination root '%s'\n",
              escaped ? escaped : "<allocation failed>");
      free(escaped);
      server_cli_options_free(&opts);
      return 1;
    }
    io_set_fds(STDIN_FILENO, STDOUT_FILENO);
    handler(STDIN_FILENO);
    release_authorization();
    server_cli_options_free(&opts);
    return 0;
  }

  int port = opts.port;
  int bind_family = opts.bind_family;
  const char* bind_address = opts.bind_address;

  if (opts.daemon_mode) {
    const char* config_path = opts.config_path ? opts.config_path : default_daemon_config_path();
    g_daemon_conf = daemon_conf_load(config_path, cli_err, sizeof(cli_err));
    if (!g_daemon_conf) {
      server_cli_options_free(&opts);
      fprintf(stderr, "Error: %s\n", cli_err);
      return 1;
    }
    for (int i = 0; i < opts.dparam_count; i++) {
      if (daemon_conf_apply_dparam(g_daemon_conf, opts.dparams[i], cli_err, sizeof(cli_err)) != 0) {
        fprintf(stderr, "Error: --dparam: %s\n", cli_err);
        exit_code = 1;
        goto out;
      }
    }
    /* Effective port: -p (highest) > --dparam port > config port (default 873). */
    if (!opts.port_set)
      port = g_daemon_conf->global.port;
    if (!bind_address)
      bind_address = g_daemon_conf->global.address;
    if (g_daemon_conf->module_count == 0)
      log_message(LOG_LEVEL_WARNING,
                  "daemon config has no modules; every connection will be refused");
    /* Daemon credential store (Wave B).  --password-file and --early-input
     * feed the same store, loaded BEFORE the listener forks so every
     * connection child shares one read-only store.  Fail closed at startup: a
     * module that declares `auth users` without a store (or with an empty
     * store) refuses to start rather than serving a module whose credentials
     * can never be verified. */
    g_credentials =
        credentials_load(opts.password_file, opts.early_input_file, cli_err, sizeof(cli_err));
    if (!g_credentials) {
      server_cli_options_free(&opts);
      fprintf(stderr, "Error: %s\n", cli_err);
      return 1;
    }
    bool credential_source_given = opts.password_file != NULL || opts.early_input_file != NULL;
    for (int i = 0; i < g_daemon_conf->module_count; i++) {
      const DaemonModule* module = &g_daemon_conf->modules[i];
      if (module->auth_user_count == 0)
        continue;
      if (!credential_source_given) {
        fprintf(stderr,
                "Error: module '%s' declares 'auth users' but no credential store was given "
                "(--password-file or --early-input); refusing to start (fail closed)\n",
                module->name);
        server_cli_options_free(&opts);
        return 1;
      }
      if (credentials_store_size(g_credentials) == 0) {
        fprintf(stderr,
                "Error: module '%s' declares 'auth users' but the credential store is empty; "
                "refusing to start (fail closed)\n",
                module->name);
        server_cli_options_free(&opts);
        return 1;
      }
      for (int j = 0; j < module->auth_user_count; j++) {
        if (!credentials_store_has(g_credentials, module->auth_users[j]))
          log_message(LOG_LEVEL_WARNING,
                      "daemon module '%s': auth user '%s' has no credential store entry; that "
                      "user can never authenticate",
                      module->name, module->auth_users[j]);
      }
    }
  } else {
    if (!configure_authorization(opts.destination_root)) {
      char* escaped = output_escape(opts.destination_root, false);
      fprintf(stderr, "Error: invalid destination root '%s'\n",
              escaped ? escaped : "<allocation failed>");
      free(escaped);
      server_cli_options_free(&opts);
      return 1;
    }
  }

  ServerBindOptions bind_opts;
  bind_opts.bind_address = bind_address;
  bind_opts.family = bind_family;
  g_server = server_create_ex(port, &bind_opts);
  if (!g_server) {
    log_message(LOG_LEVEL_ERROR, "Failed to create server");
    release_authorization();
    exit_code = 1;
    goto out;
  }
  if (opts.use_tls) {
    if (!opts.tls_cert || !opts.tls_key || !opts.tls_ca || !opts.client_cn) {
      fprintf(stderr, "Error: --tls requires --cert, --key, --ca, and --client-cn\n");
      server_delete(&g_server);
      release_authorization();
      exit_code = 1;
      goto out;
    }
    tls_global_init();
    if (!server_create_tls(g_server, opts.tls_cert, opts.tls_key, opts.tls_ca)) {
      log_message(LOG_LEVEL_ERROR, "Failed to set up TLS");
      server_delete(&g_server);
      release_authorization();
      exit_code = 1;
      goto out;
    }
  }

  /* Detach after the listening socket (and TLS context) exist so the
   * background daemon inherits a fully-bound listener.  --no-detach runs in
   * the foreground, which is how tests drive the daemon. */
  if (opts.daemon_mode && !opts.no_detach) {
    if (!daemonize()) {
      log_message(LOG_LEVEL_ERROR, "Failed to daemonize");
      server_delete(&g_server);
      release_authorization();
      exit_code = 1;
      goto out;
    }
  }

  if (opts.use_tls)
    server_listen_tls(g_server, handler);
  else
    server_listen(g_server, handler);
  server_delete(&g_server);
  release_authorization();

out:
  daemon_conf_free(g_daemon_conf);
  g_daemon_conf = NULL;
  credentials_free(g_credentials);
  g_credentials = NULL;
  server_cli_options_free(&opts);
  return exit_code;
}
#endif
