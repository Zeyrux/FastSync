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
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/x509.h>

static char* authorized_root;
static int authorized_root_fd = -1;
static bool allow_delete;
static bool trust_sender;
static bool allow_unauthenticated;
/* --no-super operator veto: forces SUPER_MODE_OFF for every connection (even
 * root), so no super-user activity is attempted and any client --copy-as is
 * refused.  Set once in main before the accept loop / stdio handler. */
static bool server_no_super;
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
 * exchange is not encrypted, plus the super-mode override the gate decides on.
 * The gate never mutates the received (const) Config; it records a forced
 * SUPER_MODE_OFF here and the handler applies it exactly once after acceptance. */
typedef struct ModuleGateContext {
  SSL* ssl;
  /* The connection descriptor, so the gate can drive the SCRAM auth handshake
   * while it still owns the config-frame exchange (before the STATUS_OK ack). */
  int fd;
  /* SUPER_MODE_OFF when this connection must not attempt any super-user
     activity (operator --no-super, or a daemon module without the
     `client owner = yes` opt-in); -1 when the config's own mode stands. */
  int super_mode_override;
  /* Numeric peer address (INET6_ADDRSTRLEN is always enough), filled once by
   * server_module_gate.  has_peer_ip is false when getpeername/inet_ntop could
   * not classify the peer; an ACL-configured module then fails closed. */
  bool has_peer_ip;
  char peer_ip[INET6_ADDRSTRLEN];
} ModuleGateContext;

/* Server half of the SCRAM challenge/response (A7 remediation, protocol
 * 2.19.0).  Sends STATUS_AUTH_CHALLENGE (iteration count, base64 salt, base64
 * server nonce), expects STATUS_AUTH_RESPONSE (base64 client nonce, base64
 * ClientProof), verifies the proof constant-time and answers STATUS_AUTH_OK
 * with the base64 ServerSignature.  On any failure BEFORE the success response
 * it sends exactly one generic STATUS_AUTH_FAILED and returns false; a failure
 * while writing the success signature cannot send a status and just drops an
 * already-broken connection.  The verifier for an unknown/off-list
 * user is a dummy (deterministic per-username salt, store-wide iterations, dummy
 * keys, found=false) so the same math runs and no user-enumeration/timing oracle
 * is exposed. */
static bool server_auth_handshake(int fd, const Config* config, const DaemonModule* module) {
  bool result = false;
  CredentialVerifier verifier;
  memset(&verifier, 0, sizeof(verifier));
  uint8_t snonce[CREDENTIAL_NONCE_LEN] = {0};
  char salt_b64[25] = {0};
  char snonce_b64[45] = {0};
  char* cnonce_b64 = NULL;
  char* proof_b64 = NULL;
  uint8_t cnonce[CREDENTIAL_NONCE_LEN] = {0};
  uint8_t proof[CREDENTIAL_KEY_LEN] = {0};
  uint8_t server_sig[CREDENTIAL_KEY_LEN] = {0};
  char sig_b64[45] = {0};
  size_t cnonce_len = 0;
  size_t proof_len = 0;

  if (!config->auth_user)
    goto fail; /* no username: generic failure, no challenge */
  if (!credentials_get_verifier(g_credentials, config->auth_user,
                                (const char* const*)module->auth_users, module->auth_user_count,
                                &verifier))
    goto fail; /* a crypto failure still owes the gate a terminal frame */
  if (!(credentials_random_bytes(snonce, sizeof(snonce)) &&
        credentials_b64_encode(verifier.salt, CREDENTIAL_SALT_LEN, salt_b64, sizeof(salt_b64)) &&
        credentials_b64_encode(snonce, sizeof(snonce), snonce_b64, sizeof(snonce_b64))))
    goto fail;
  if (!(send_status(fd, STATUS_AUTH_CHALLENGE) && send_int(fd, (int)verifier.iters) &&
        send_str(fd, salt_b64) && send_str(fd, snonce_b64)))
    goto fail;

  Status status = STATUS_ERROR;
  if (!(receive_status(fd, &status) && status == STATUS_AUTH_RESPONSE))
    goto fail;
  cnonce_b64 = receive_str_redacted(fd);
  proof_b64 = receive_str_redacted(fd);
  if (!(cnonce_b64 && proof_b64 &&
        credentials_b64_decode(cnonce_b64, cnonce, sizeof(cnonce), &cnonce_len) &&
        cnonce_len == CREDENTIAL_NONCE_LEN &&
        credentials_b64_decode(proof_b64, proof, sizeof(proof), &proof_len) &&
        proof_len == CREDENTIAL_KEY_LEN))
    goto fail;
  if (!credentials_verify_response(&verifier, config->auth_user, snonce, cnonce, proof, server_sig))
    goto fail;

  /* Success writes exactly one terminal frame (STATUS_AUTH_OK).  A broken pipe
   * while sending the signature just drops the connection; it must never emit a
   * second terminal status. */
  result = credentials_b64_encode(server_sig, sizeof(server_sig), sig_b64, sizeof(sig_b64)) &&
           send_status(fd, STATUS_AUTH_OK) && send_str_redacted(fd, sig_b64);
  goto cleanup;

fail:
  /* Every failure path writes exactly one generic terminal status, satisfying
   * the gate's CONFIG_VALIDATE_ALREADY_TERMINATED contract. */
  send_status(fd, STATUS_AUTH_FAILED);

cleanup:
  credentials_burn(cnonce_b64, cnonce_b64 ? strlen(cnonce_b64) : 0);
  credentials_burn(proof_b64, proof_b64 ? strlen(proof_b64) : 0);
  free(cnonce_b64);
  free(proof_b64);
  credentials_burn((char*)snonce, sizeof(snonce));
  credentials_burn(salt_b64, sizeof(salt_b64));
  credentials_burn(snonce_b64, sizeof(snonce_b64));
  credentials_burn((char*)cnonce, sizeof(cnonce));
  credentials_burn((char*)proof, sizeof(proof));
  credentials_burn((char*)server_sig, sizeof(server_sig));
  credentials_burn(sig_b64, sizeof(sig_b64));
  credentials_burn((char*)verifier.salt, sizeof(verifier.salt));
  credentials_burn((char*)verifier.stored_key, sizeof(verifier.stored_key));
  credentials_burn((char*)verifier.server_key, sizeof(verifier.server_key));
  return result;
}

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
                 credentials_secure_equal(common_name, required_client_cn, required_length);
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

/* Discriminates the outcome of the A7 auth gate so the dispatcher can map it
 * back to the config_receive_with_validate contract: accepted (including
 * "module needs no auth"), a config-level refusal carrying an error string, or
 * a handshake that already wrote its own terminal status frame. */
typedef enum {
  MODULE_AUTH_ACCEPTED = 0,
  MODULE_AUTH_REFUSED,
  MODULE_AUTH_TERMINATED,
} ModuleAuthResult;

/* Looks up the daemon module selected by the client's config frame and rejects
 * a `read only` one (every FastSync network transfer writes; there is no
 * read-only wire operation yet).  Returns the module, or NULL with *error set
 * to the caller-facing rejection message. */
static const DaemonModule* module_gate_lookup_module(const Config* config, const char** error) {
  const DaemonModule* module = daemon_conf_find_module(g_daemon_conf, config->module);
  if (module == NULL) {
    char* escaped_module = output_escape(config->module, config->eight_bit_output);
    log_message(LOG_LEVEL_ERROR, "unknown daemon module '%s' requested",
                escaped_module ? escaped_module : "<allocation failed>");
    free(escaped_module);
    *error = "requested daemon module does not exist";
    return NULL;
  }
  if (module->read_only) {
    log_message(LOG_LEVEL_ERROR, "daemon module '%s' is read only; refusing write transfer",
                config->module);
    *error = "requested daemon module is read only";
    return NULL;
  }
  return module;
}

/* Per-module client-chosen ownership / super-user policy (P7 Wave E hardening):
 * a daemon module refuses EVERY ownership-affecting request (--numeric-ids,
 * --chown, --usermap/--groupmap, --fake-super, --copy-as, explicit --super)
 * unless the operator opted THIS module in with `client owner = yes`.
 * Otherwise any client could force arbitrary ownership inside the module root.
 * The ownership check is evaluated against the ORIGINAL config so an explicit
 * --super is refused even when an operator --no-super veto already forced the
 * effective copy to OFF (the veto must not silently convert a refusal into an
 * accept); when no ownership flag is present, super-user DEVICE activities are
 * forced off for this connection instead.  Returns an error string on refusal,
 * NULL on acceptance. */
static const char* module_gate_check_ownership(const Config* config, const DaemonModule* module,
                                               ModuleGateContext* gate_ctx) {
  if (module->client_owner)
    return NULL;
  /* Ownership: refuse the whole transfer up front (a clear failure). */
  if (identity_ownership_requested(config)) {
    log_message(LOG_LEVEL_ERROR,
                "daemon module '%s' refuses client-chosen ownership/super-user activities "
                "(no `client owner = yes` opt-in); refusing",
                config->module);
    return "client-chosen ownership is not permitted by this daemon module";
  }
  /* Super-user DEVICE activities (char/block mknod and --write-devices) are
     permitted under the default AUTO mode, so without this override a root
     daemon would still let a non-opted module create arbitrary device nodes
     and write raw devices.  Force them off for this connection: those entries
     are skipped (never mknod'ed) while an ordinary `-a` push still succeeds
     without device nodes, matching the operator's least-privilege choice.
     The operator-level --no-super veto is already folded into this. */
  if (gate_ctx)
    gate_ctx->super_mode_override = SUPER_MODE_OFF;
  return NULL;
}

/* Online-guessing throttle: sleep the configured `auth failure delay`
 * milliseconds after a failed authentication.  Runs in the per-connection
 * forked child, so it never blocks the accept loop or another connection.  0
 * disables it; the parser already caps it at DAEMON_CONF_MAX_AUTH_FAILURE_DELAY_MS.
 * Resumes after EINTR so a signal cannot cut the delay short. */
static void daemon_auth_failure_delay(void) {
  if (!g_daemon_conf || g_daemon_conf->global.auth_failure_delay_ms <= 0)
    return;
  int ms = g_daemon_conf->global.auth_failure_delay_ms;
  struct timespec delay;
  delay.tv_sec = ms / 1000;
  delay.tv_nsec = (long)(ms % 1000) * 1000000L;
  while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
    ;
}

/* Host access control (global then per-module).  A configured list makes an
 * unprovable peer fail closed.  Deny always takes precedence over allow, and a
 * non-empty allow list rejects a peer that matches none of its entries.  The
 * audit line names the peer, the module and the outcome.  Returns an
 * error string on refusal, NULL on acceptance. */
static const char* module_gate_check_hosts(const Config* config, const DaemonModule* module,
                                           ModuleGateContext* gate_ctx) {
  bool global_restricted = daemon_hosts_restricted(
      g_daemon_conf->global.hosts_allow, g_daemon_conf->global.hosts_allow_count,
      g_daemon_conf->global.hosts_deny, g_daemon_conf->global.hosts_deny_count);
  bool module_restricted = daemon_hosts_restricted(module->hosts_allow, module->hosts_allow_count,
                                                   module->hosts_deny, module->hosts_deny_count);
  if (!global_restricted && !module_restricted)
    return NULL;
  if (!gate_ctx || !gate_ctx->has_peer_ip) {
    log_message(LOG_LEVEL_WARNING,
                "daemon module '%s': cannot determine peer address with host ACLs configured; "
                "refusing (fail closed)",
                config->module);
    return "cannot verify the client host against host access controls";
  }
  const char* peer = gate_ctx->peer_ip;
  if (global_restricted && !daemon_hosts_allowed(peer, g_daemon_conf->global.hosts_allow,
                                                 g_daemon_conf->global.hosts_allow_count,
                                                 g_daemon_conf->global.hosts_deny,
                                                 g_daemon_conf->global.hosts_deny_count)) {
    log_message(LOG_LEVEL_WARNING,
                "daemon module '%s': peer %s denied by global 'hosts allow'/'hosts deny'; "
                "refusing",
                config->module, peer);
    return "client host is not permitted by this daemon";
  }
  if (module_restricted &&
      !daemon_hosts_allowed(peer, module->hosts_allow, module->hosts_allow_count,
                            module->hosts_deny, module->hosts_deny_count)) {
    log_message(LOG_LEVEL_WARNING,
                "daemon module '%s': peer %s denied by module 'hosts allow'/'hosts deny'; "
                "refusing",
                config->module, peer);
    return "client host is not permitted by this daemon module";
  }
  return NULL;
}

/* A7 auth gate: runs the SCRAM challenge/response for an auth-required module
 * BEFORE the module root is installed and before any data moves.  Returns
 * MODULE_AUTH_ACCEPTED when the module needs no auth or the handshake succeeds,
 * MODULE_AUTH_REFUSED with *error set on a config-level rejection, or
 * MODULE_AUTH_TERMINATED when the handshake already wrote a terminal status. */
static ModuleAuthResult module_gate_authenticate(const Config* config, const DaemonModule* module,
                                                 ModuleGateContext* gate_ctx, const char** error) {
  if (module->auth_user_count == 0)
    return MODULE_AUTH_ACCEPTED;
  /* Fail closed: no store -> refuse (server misconfiguration, STATUS_ERROR). */
  if (g_credentials == NULL) {
    log_message(LOG_LEVEL_ERROR,
                "daemon module '%s' requires authentication but no credential store is "
                "configured (--password-file/--early-input); refusing",
                config->module);
    *error = "requested daemon module requires authentication and no credential "
             "store is configured";
    return MODULE_AUTH_REFUSED;
  }
  /* Transport policy (A7-3/S1): an auth-required module only accepts
   * credentials over (a) an encrypted, verified TLS connection whose client
   * certificate matches --client-cn, or (b) an actual PLAINTEXT connection
   * from a loopback peer that the operator explicitly opted into with
   * --allow-unauthenticated.  A remote plaintext peer, an un-flagged loopback
   * plaintext peer, and a loopback TLS peer whose certificate does not match
   * --client-cn are all refused HERE, before the challenge is sent, so an
   * unverified client never receives a nonce: the loopback allowance requires
   * !gate_ctx->ssl, so --tls + --allow-unauthenticated can never be used to
   * bypass the client-CN check.  The operator flag never permits REMOTE
   * plaintext auth: remote peers still require verified TLS regardless. */
  bool tls_ok = gate_ctx && gate_ctx->ssl && SSL_get_verify_result(gate_ctx->ssl) == X509_V_OK &&
                tls_client_identity_allowed(gate_ctx->ssl);
  bool local_ok = allow_unauthenticated && gate_ctx && !gate_ctx->ssl && gate_ctx->fd >= 0 &&
                  utils_fd_peer_is_local(gate_ctx->fd);
  if (!tls_ok && !local_ok) {
    log_message(LOG_LEVEL_ERROR,
                "daemon module '%s' requires authentication over an encrypted, verified TLS "
                "connection (or an opted-in loopback plaintext transport); refusing",
                config->module);
    *error = "daemon module requires authentication over an encrypted, verified TLS "
             "connection";
    return MODULE_AUTH_REFUSED;
  }
  /* Belt-and-braces: the transport policy above already guarantees a context
   * with a usable socket (verified TLS implies a live SSL object and loopback
   * allowance requires gate_ctx->fd >= 0), so this is unreachable today; keep
   * the guard so the handshake can never be driven over an invalid fd. */
  if (!gate_ctx || gate_ctx->fd < 0) {
    log_message(LOG_LEVEL_ERROR, "daemon module '%s': no auth transport available", config->module);
    *error = "authentication failed for the requested daemon module";
    return MODULE_AUTH_REFUSED;
  }
  /* The handshake writes exactly one terminal status on failure and signals so
   * via MODULE_AUTH_TERMINATED; the username may be logged (never the password
   * or any derived proof). */
  if (!server_auth_handshake(gate_ctx->fd, config, module)) {
    const char* peer = gate_ctx->has_peer_ip ? gate_ctx->peer_ip : "unknown";
    char* escaped_user =
        config->auth_user ? output_escape(config->auth_user, config->eight_bit_output) : NULL;
    log_message(LOG_LEVEL_WARNING,
                "daemon module '%s': authentication failed for user '%s' from %s; refusing",
                config->module, escaped_user ? escaped_user : "(none)", peer);
    free(escaped_user);
    /* Rate-limit online guessing per connection (no delay on success). */
    daemon_auth_failure_delay();
    return MODULE_AUTH_TERMINATED;
  }
  char* escaped_user = output_escape(config->auth_user, config->eight_bit_output);
  log_message(LOG_LEVEL_INFO, "daemon module '%s': user '%s' from %s authenticated", config->module,
              escaped_user ? escaped_user : "<allocation failed>",
              gate_ctx->has_peer_ip ? gate_ctx->peer_ip : "unknown");
  free(escaped_user);
  return MODULE_AUTH_ACCEPTED;
}

/* Installs the module's configured path as the connection's authorized root.
 * Returns an error string when the root is unusable, NULL on success. */
static const char* module_gate_install_root(const Config* config, const DaemonModule* module) {
  if (!configure_authorization(module->path)) {
    log_message(LOG_LEVEL_ERROR, "daemon module '%s' path '%s' is not usable", config->module,
                module->path ? module->path : "(null)");
    return "requested daemon module root is not usable";
  }
  return NULL;
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
 * when it requests client-chosen ownership without the module's
 * `client owner = yes` opt-in (P7 Wave E hardening), or when the presented
 * daemon credentials fail for a module that declares `auth users`.  Wave A
 * refused every auth-required module (auth was not yet implemented); Wave B
 * authenticates the client instead (see below). */
static const char* server_module_gate(const Config* config, void* context) {
  ModuleGateContext* gate_ctx = (ModuleGateContext*)context;
  if (!config)
    return "missing config frame";
  /* Operator veto: --no-super forces SUPER_MODE_OFF for this connection before
     the copy-as gate is evaluated.  The received config is const, so the gates
     below evaluate a shallow effective copy (only super_mode differs); the
     handler applies the recorded override to the accepted config exactly once. */
  Config effective = *config;
  if (server_no_super) {
    effective.super_mode = SUPER_MODE_OFF;
    if (gate_ctx)
      gate_ctx->super_mode_override = SUPER_MODE_OFF;
  }
  /* --copy-as (P7 Wave E, protocol 2.18.0): FastSync's safe subset forces the
     ownership of every written entry to the requested ids, which needs a
     privileged (root) receiver.  An unprivileged receiver REFUSES the whole
     transfer here, at the config handshake and BEFORE the STATUS_OK ack, so no
     file data is exchanged and there is never a silent wrong-ownership result.
     The daemon's per-module client-chosen-ownership refusal is enforced after
     the module lookup below (it needs the module's opt-in) and covers --copy-as
     like every other ownership flag. */
  if (identity_copy_as_refused(&effective)) {
    if (geteuid() != 0)
      log_message(LOG_LEVEL_ERROR, "--copy-as requires a privileged receiver (root); refusing");
    else
      log_message(LOG_LEVEL_ERROR,
                  "--copy-as refused: super-user activities are disabled by the server "
                  "(--no-super); refusing");
    return "cannot perform --copy-as on this receiver";
  }
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

  const char* error = NULL;
  const DaemonModule* module = module_gate_lookup_module(config, &error);
  if (!module)
    return error;
  /* Resolve the peer once, before any auth or ownership work, so the host ACL
   * and the audit lines all use the same address.  A module with ACLs fails
   * closed when the peer cannot be classified; an ACL-free module continues
   * (the accept loop still logged the address). */
  if (gate_ctx) {
    gate_ctx->has_peer_ip =
        utils_fd_peer_ip(gate_ctx->fd, gate_ctx->peer_ip, sizeof(gate_ctx->peer_ip));
    if (!gate_ctx->has_peer_ip)
      log_message(LOG_LEVEL_DEBUG, "daemon module '%s': peer address unavailable", config->module);
  }
  error = module_gate_check_hosts(config, module, gate_ctx);
  if (error)
    return error;
  error = module_gate_check_ownership(config, module, gate_ctx);
  if (error)
    return error;
  switch (module_gate_authenticate(config, module, gate_ctx, &error)) {
  case MODULE_AUTH_REFUSED:
    return error;
  case MODULE_AUTH_TERMINATED:
    return CONFIG_VALIDATE_ALREADY_TERMINATED;
  case MODULE_AUTH_ACCEPTED:
    break;
  }
  /* accepted; the authorized root is now the module's path */
  return module_gate_install_root(config, module);
}

void handler(int file_descriptor) {
  SSL* ssl = io_get_ssl();
  ProtocolSession session;
  protocol_session_init(&session, file_descriptor, file_descriptor);
  protocol_session_set_ssl(&session, ssl);
  protocol_session_bind(&session);
  ModuleGateContext gate_ctx;
  gate_ctx.ssl = ssl;
  gate_ctx.fd = file_descriptor;
  gate_ctx.super_mode_override = -1;
  gate_ctx.has_peer_ip = false;
  gate_ctx.peer_ip[0] = '\0';
  /* All teardown state starts empty so the single `done` epilogue is safe to
   * reach from any error path (including before the config frame arrives). */
  Config* config = NULL;
  PipelineContextReceiver* context = NULL;
  char* joined_destination = NULL;
  bool charset_ready = false;
  config = config_receive_with_validate(file_descriptor, server_module_gate, &gate_ctx);
  if (config == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to receive config");
    goto done;
  }
  /* Apply the super-mode veto the gate decided on (operator --no-super, or a
   * daemon module without the `client owner = yes` opt-in) exactly once, so
   * every downstream gate (identity_apply_ownership via privilege_super_permitted,
   * device-node creation) sees SUPER_MODE_OFF.  The gate never mutated the
   * received config. */
  if (gate_ctx.super_mode_override != -1)
    config->super_mode = (SuperMode)gate_ctx.super_mode_override;
  protocol_set_8_bit_output(config->eight_bit_output);
  /* Honor the negotiated --timeout for every protocol frame from here on (the
   * config handshake itself used the built-in 60 s window).  A positive value
   * also tightens the socket SO_RCVTIMEO/SO_SNDTIMEO already applied by the
   * transport; 0 leaves both built-in defaults in place. */
  protocol_session_set_io_timeout(&session, config->timeout);
  if (!authorized_root) {
    log_message(LOG_LEVEL_ERROR, "No server-side destination root configured");
    goto done;
  }
  if (!allow_unauthenticated && ssl == NULL) {
    log_message(LOG_LEVEL_ERROR, "Rejected unauthenticated plaintext connection");
    goto done;
  }
  if (ssl && required_client_cn && !tls_client_identity_allowed(ssl)) {
    log_message(LOG_LEVEL_ERROR, "Rejected TLS client with unauthorized identity");
    goto done;
  }
  /* Daemon mode: the module's root is the authorized root (installed by
     server_module_gate), and the client's destination is a MODULE-RELATIVE
     path.  Reject an absolute destination up front so the module-relative
     confinement contract is never eroded by a client that tries to address the
     module root by absolute path. */
  if (g_daemon_conf && config->receive_root_directory && config->receive_root_directory[0] == '/') {
    log_message(LOG_LEVEL_ERROR, "Rejected absolute daemon destination (must be relative to the "
                                 "selected module root)");
    goto done;
  }
  char* destination = config->receive_root_directory;
  if (destination && destination[0] != '/')
    joined_destination = path_cat(authorized_root, destination);
  if (joined_destination)
    destination = joined_destination;
  if (!destination || has_path_traversal(destination) ||
      !path_is_within(authorized_root, destination)) {
    log_message(LOG_LEVEL_ERROR, "Rejected destination outside authorized root");
    free(joined_destination);
    joined_destination = NULL;
    goto done;
  }
  if (joined_destination) {
    free(config->receive_root_directory);
    config->receive_root_directory = joined_destination;
    joined_destination = NULL;
  }
  if (!config->receive_root_directory) {
    goto done;
  }
  config->use_delete = config->use_delete && allow_delete;
  /* --iconv (protocol 2.16.0): install the receiver-side wire->local conversion
     now that the client's full CONVERT_SPEC has been received and validated,
     before any received file name is decoded.  The server's own --iconv (if
     any) may override the local charset; a spec the client is known to have
     validated cannot fail here unless the server's override names an
     unsupported charset. */
  if (config->iconv_spec) {
    if (!charset_wire_init_receiver(config->iconv_spec, server_iconv_spec)) {
      log_message(LOG_LEVEL_ERROR,
                  "--iconv: unsupported charset conversion requested (LOCAL[,REMOTE])");
      goto done;
    }
    charset_ready = true;
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
    char* escaped_root = output_escape(config->receive_root_directory, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "destination root is not available: %s",
                escaped_root ? escaped_root : "<allocation failed>");
    free(escaped_root);
    goto done;
  }
  /* A --delay-updates transfer stages under a private 0700 directory inside
     the receive root.  Create it up front (wiping leftovers of any previously
     interrupted delayed transfer) so a fully-skipped run also starts clean. */
  if (config->delay_updates) {
    config->delay_context = delay_updates_context_create(config->receive_root_directory);
    if (!config->delay_context || !delay_updates_prepare(config->delay_context)) {
      log_message(LOG_LEVEL_ERROR, "Failed to initialize --delay-updates staging area");
      goto done;
    }
  }
  /* Preserve the negotiated identity policy for the fd-relative ownership
     apply path.  Each connection is its own forked process, so this
     per-process snapshot never races another connection.  A failed deep copy
     (allocation failure) leaves the snapshot cleared, so refuse the connection
     rather than silently applying the wrong ownership policy. */
  if (!identity_set_active(config)) {
    log_message(LOG_LEVEL_ERROR, "Failed to activate identity policy");
    goto done;
  }
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
      goto done;
    }
    free(motd);
  }
  if (config->use_multithreading) {
    Queue* q = queue_create(100, file_destroy);
    if (q == NULL)
      goto done;
    context = pipeline_context_receiver_create(config, q, file_descriptor, ssl);
    if (context == NULL) {
      queue_destroy(q);
      goto done;
    }
    protocol_session_set_max_alloc(&context->session, config->max_alloc);
    protocol_session_set_io_timeout(&context->session, config->timeout);
    atomic_store(&context->session.total_allocated_bytes,
                 atomic_load(&session.total_allocated_bytes));
    pipeline_context_receiver_set_queue_byte_limit(context, RECEIVER_QUEUE_MAX_BYTES);
    thrd_t receiver = {0};
    thrd_t writer = {0};
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
        /* Unblock a worker parked in socket I/O without closing the fd (the
         * child owns the single close).  shutdown() only affects sockets; for
         * the --stdio pipe the receiver's per-message poll timeout still
         * bounds the join, so do nothing there rather than close a descriptor
         * another thread may still be using. */
        struct stat fd_stat;
        if (fstat(file_descriptor, &fd_stat) == 0 && S_ISSOCK(fd_stat.st_mode))
          shutdown(file_descriptor, SHUT_RDWR);
        thrd_join(receiver, NULL);
      }
      if (writer_created)
        thrd_join(writer, NULL);
      goto done;
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
    if (!transfer_ok)
      log_message(LOG_LEVEL_ERROR, "Transfer failed");
  } else {
    if (receiver_receive_files(config, file_descriptor) != 0)
      log_message(LOG_LEVEL_ERROR, "Transfer failed");
  }

done:
  /* Single cleanup epilogue: every error path jumps here, so the iconv
   * receiver conversion is released, the identity snapshot cleared, the
   * protocol session unbound and the config freed exactly once.  The
   * connection fd is deliberately NOT closed here -- the child functions own
   * its single close (plain_child_fn / tls_child_fn), and the --stdio call
   * site must leave stdin/stdout open. */
  if (charset_ready)
    charset_wire_free();
  /* The delay-updates staging tree is released by config_delete (which the
     branch below always reaches), so it is cleaned exactly once. */
  identity_clear_active();
  protocol_session_unbind();
  if (context != NULL) {
    /* context owns both the config and the queue it was created with. */
    pipeline_context_receiver_destroy(context);
    context = NULL;
    config = NULL;
  } else {
    config_delete(config);
    config = NULL;
  }
  free(joined_destination);
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
  printf("                      (port, motd file, address, max connections,\n");
  printf("                      auth failure delay, hosts allow, hosts deny)\n");
  printf("  --no-detach         Stay in the foreground (default detaches to\n");
  printf("                      background when running --daemon)\n");
  printf("  --password-file=FILE  Credential store for modules that declare\n");
  printf("                      'auth users' (line format:\n");
  printf("                      user:$fastsync$1$pbkdf2-sha256$iters$salt$stored$server,\n");
  printf("                      generated by --hash-credentials).  Legacy\n");
  printf("                      user:SHA256HEX lines are rejected.  Requires\n");
  printf("                      --daemon; an auth-required module with no store\n");
  printf("                      refuses to start\n");
  printf("  --early-input=FILE  Second credential store layered over\n");
  printf("                      --password-file (same format); usually a secrets-\n");
  printf("                      manager/process-substitution file.  Requires --daemon\n");
  printf("  -p <port>           TCP port (default: 8080, range: 1-65535)\n");
  printf("  --tls               Enable TLS encryption\n");
  printf("  --cert <path>       TLS certificate file (PEM)\n");
  printf("  --key <path>        TLS private key file (PEM)\n");
  printf("  --ca <path>         TLS CA certificate file (PEM)\n");
  printf("  --client-cn <name>  TLS client certificate CN (mandatory with --tls)\n");
  printf("  --destination-root <path>  Authorized destination root (default: .)\n");
  printf("  --address <addr>    Bind the listening socket to this address\n");
  printf("  -4, --ipv4          Bind an IPv4 socket (default)\n");
  printf("  -6, --ipv6          Bind an IPv6 socket\n");
  printf("  --allow-delete      Permit manifest deletion\n");
  printf("  --trust-sender      Trust the remote sender's file list\n");
  printf("  --no-super          Operator veto: never attempt super-user activities\n");
  printf("                      (ownership, device nodes) even as root, and refuse\n");
  printf("                      any client --copy-as/--super request\n");
  printf("  --iconv=LOCAL[,REMOTE]  Declare this server's LOCAL charset for file-name\n");
  printf("                      conversion: received names are translated to this\n");
  printf("                      charset (the wire charset still comes from the\n");
  printf("                      client's CONVERT_SPEC).  A name that cannot be\n");
  printf("                      represented fails the run cleanly\n");
  printf("  --allow-unauthenticated  Allow plaintext/anonymous network clients\n");
  printf("                      (an auth-required module still accepts only opted-in\n");
  printf("                      loopback plaintext; remote auth requires verified TLS)\n");
  printf("  --hash-credentials <file>  Read <file>'s user:password lines and print\n");
  printf("                      PBKDF2 credential-store lines to stdout, then exit.\n");
  printf("                      Use the output as --password-file for --daemon;\n");
  printf("                      redirect it to an owner-only (0600) file\n");
  printf("  --iterations N      PBKDF2 iteration count for --hash-credentials\n");
  printf("                      (default %u, range %u-%u)\n", CREDENTIAL_DEFAULT_ITERS,
         CREDENTIAL_MIN_ITERS, CREDENTIAL_MAX_ITERS);
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

  /* --hash-credentials: standalone offline tool; read user:password lines and
   * emit new-format credential-store lines, then exit. */
  if (opts.hash_credentials_file) {
    uint32_t iters = opts.hash_iterations_set ? opts.hash_iterations : CREDENTIAL_DEFAULT_ITERS;
    /* The output is secret material: if it is redirected to a regular file,
     * warn when that file is group/other-accessible (the store must be 0600). */
    struct stat out_st;
    if (fstat(STDOUT_FILENO, &out_st) == 0 && S_ISREG(out_st.st_mode) &&
        (out_st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
      fprintf(stderr,
              "Warning: credential-store output is a group/other-accessible file; restrict it to "
              "mode 0600 (chmod 600)\n");
    char hash_err[512];
    if (credentials_hash_file(opts.hash_credentials_file, iters, stdout, hash_err,
                              sizeof(hash_err)) != 0) {
      fprintf(stderr, "Error: %s\n", hash_err);
      server_cli_options_free(&opts);
      return 1;
    }
    server_cli_options_free(&opts);
    return 0;
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
  server_no_super = opts.no_super;
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
    /* handler() does not own the stdio fds: it never closes its descriptor
     * argument, so STDIN/STDOUT stay open for this (single-shot) SSH session
     * and are released by process exit. */
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
    /* Surface the operator's client-chosen-ownership opt-in prominently: an
       opted-in module lets its clients request arbitrary owner ids inside that
       module root. */
    for (int i = 0; i < g_daemon_conf->module_count; i++) {
      if (g_daemon_conf->modules[i].client_owner)
        log_message(LOG_LEVEL_WARNING,
                    "daemon module '%s' allows client-chosen ownership and super-user device "
                    "activities (`client owner = yes`); clients may request arbitrary owner ids "
                    "and device nodes within that module root -- pair it with `auth users` "
                    "unless the module is intentionally open to the network",
                    g_daemon_conf->modules[i].name);
      if (g_daemon_conf->modules[i].max_connections > 0)
        log_message(LOG_LEVEL_WARNING,
                    "daemon module '%s': per-module 'max connections' is stored but not enforced "
                    "per module; the global 'max connections' cap (%d) applies to the whole "
                    "listener",
                    g_daemon_conf->modules[i].name, g_daemon_conf->global.max_connections);
    }
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
  if (g_daemon_conf)
    server_set_max_connections(g_server, (unsigned int)g_daemon_conf->global.max_connections);
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
