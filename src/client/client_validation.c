#include "client_validation.h"
#include "log.h"
#include "usage.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>

/* Validate config after parsing. Returns true if valid. */
bool validate_config(const Config* config) {
  /* Phase 6 residual-batch modes relax the normal source+destination pair: the
     batch driver is local and needs only what it consumes.  --only-write-batch
     emits a batch from the source (no destination, no server);
     --read-batch applies a batch to the destination (no source, no server);
     --write-batch runs the live transfer AND emits a batch, so it keeps the
     full pair. */
  bool write_batch = config->write_batch != NULL;
  bool only_write_batch = config->only_write_batch != NULL;
  bool read_batch = config->read_batch != NULL;
  if ((write_batch && only_write_batch) || (write_batch && read_batch) ||
      (only_write_batch && read_batch)) {
    log_message(LOG_LEVEL_ERROR,
                "--write-batch, --only-write-batch, and --read-batch are mutually exclusive");
    return false;
  }
  /* A dry-run of a local batch apply is not meaningful: --read-batch bypasses
     the client-side scan/server decision entirely, so dry-run would have no
     wire state to report (and must not be used as a mutation escape hatch).
     --only-write-batch likewise never contacts a receiver.  --write-batch DOES
     run a live transfer but additionally mutates the filesystem by emitting the
     batch file, so a dry-run must not write it either.  Reject all three up
     front instead of silently ignoring --dry-run. */
  if (config->dry_run && (read_batch || only_write_batch || write_batch)) {
    log_message(LOG_LEVEL_ERROR,
                "--dry-run cannot be combined with --read-batch, --only-write-batch, or "
                "--write-batch; a dry-run must not mutate anything, including batch files");
    return false;
  }
  if (read_batch) {
    if (!config->receive_root_directory) {
      log_message(LOG_LEVEL_ERROR, "--read-batch requires a destination directory");
      print_usage();
      return false;
    }
  } else if (only_write_batch) {
    if (!config->send_directory) {
      log_message(LOG_LEVEL_ERROR, "--only-write-batch requires a source directory");
      print_usage();
      return false;
    }
  } else if (!config->send_directory || !config->receive_root_directory) {
    log_message(LOG_LEVEL_ERROR, "source and destination directories are required");
    print_usage();
    return false;
  }
  if (config->compression_threads > 0 && !config->use_compression) {
    log_message(LOG_LEVEL_ERROR, "--compress-threads requires compression (-z/--compress)");
    return false;
  }
  if (config->transport == TRANSPORT_SSH && config->use_sendfile) {
    log_message(LOG_LEVEL_ERROR, "-f/--sendfile is not supported with SSH transport");
    return false;
  }
  /* -M/--remote-option appends an option to the REMOTE server's argv, which
   * only exists on the SSH (user@host:path) transport.  A daemon
   * (host::module/path) or local TCP destination has no remote command line,
   * so the option would be silently ignored; reject it by name instead. */
  if (config->remote_option_count > 0 && config->transport != TRANSPORT_SSH) {
    log_message(LOG_LEVEL_ERROR,
                "-M/--remote-option is only valid with the SSH transport (user@host:path); it "
                "cannot be used with a daemon (host::module/path) or local TCP destination");
    return false;
  }
  /* -4 and -6 are mutually exclusive: a socket address family cannot be both. */
  if (config->ipv4 && config->ipv6) {
    log_message(LOG_LEVEL_ERROR, "-4/--ipv4 and -6/--ipv6 are mutually exclusive");
    return false;
  }
  if (config->log_file_format && !config->log_file) {
    log_message(LOG_LEVEL_ERROR, "--log-file-format requires --log-file");
    return false;
  }
  if (config->use_tls) {
    if (!config->tls_cert || !config->tls_key || !config->tls_ca) {
      log_message(LOG_LEVEL_ERROR, "--tls requires --cert, --key, and --ca");
      return false;
    }
  }
  /* Daemon credentials (A7, protocol 2.19.0): a --password-file would send the
     username in the clear and derive a SCRAM proof a network sniffer could
     attack offline, so it is only allowed over TLS (which itself mandates a
     verified --cert/--key/--ca set above) or to a loopback destination.  A
     remote plaintext daemon is refused here, before any network I/O. */
  if (config->password_file && !config->use_tls && !utils_host_is_loopback(config->server_host)) {
    log_message(LOG_LEVEL_ERROR, "sending daemon credentials to a non-local server requires --tls");
    return false;
  }
  /* Every cross-field invariant the receiver enforces lives in one shared
     predicate so the client and the server can never disagree.  The client
     reports the specific reason here, before any network I/O. */
  const char* invariants_error = config_invariants_error(config);
  if (invariants_error) {
    log_message(LOG_LEVEL_ERROR, "%s", invariants_error);
    return false;
  }
  /* The receiver rejects a protect-rule block with more than MAX_FILTER_RULES
     entries as an opaque protocol error; reject an over-limit --filter set here,
     before any network I/O, with an actionable message.  send_protect_entries()
     re-checks the final built count because cvs-exclude / merge rules can
     expand it beyond config->filters->size. */
  if (config->filters && config->filters->size > MAX_FILTER_RULES) {
    log_message(LOG_LEVEL_ERROR, "too many filter rules: %d (maximum %d)", config->filters->size,
                MAX_FILTER_RULES);
    return false;
  }
  /* --protocol: FastSync has exactly one wire format, so the forced version
     must equal the current PROTOCOL_VERSION exactly.  Rejected here, before any
     network I/O, rather than letting the server hit its own mismatch check. */
  if (strcmp(config->version, PROTOCOL_VERSION) != 0) {
    log_message(LOG_LEVEL_ERROR,
                "--protocol must be %s (FastSync supports only its current wire "
                "protocol version and cannot speak an older or virtual one)",
                PROTOCOL_VERSION);
    return false;
  }
  return true;
}
