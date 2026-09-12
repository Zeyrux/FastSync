#include "client_validation.h"
#include "charset.h"
#include "delay_updates.h"
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
  if (config_has_basis(config) && config->use_chunk_serialization) {
    log_message(LOG_LEVEL_ERROR,
                "--compare-dest/--copy-dest/--link-dest require per-file incremental checks and "
                "cannot be combined with -s (chunk serialization)");
    return false;
  }
  if (config->use_sendfile && (config->use_chunk_serialization || config->use_compression)) {
    log_message(LOG_LEVEL_ERROR, "-f/--sendfile cannot be combined with -c (compression) or -s "
                                 "(chunk serialization)");
    return false;
  }
  if (config->compression_threads > 0 && !config->use_compression) {
    log_message(LOG_LEVEL_ERROR, "--compress-threads requires compression (-c or -z)");
    return false;
  }
  if (config->transport == TRANSPORT_SSH && config->use_sendfile) {
    log_message(LOG_LEVEL_ERROR, "-f/--sendfile is not supported with SSH transport");
    return false;
  }
  if (config->use_incremental && config->use_chunk_serialization) {
    log_message(LOG_LEVEL_ERROR, "--incremental is not supported with -s (chunk serialization)");
    return false;
  }
  /* -4 and -6 are mutually exclusive: a socket address family cannot be both. */
  if (config->ipv4 && config->ipv6) {
    log_message(LOG_LEVEL_ERROR, "-4/--ipv4 and -6/--ipv6 are mutually exclusive");
    return false;
  }
  if (config->skip_compress_set && config->use_chunk_serialization) {
    log_message(LOG_LEVEL_ERROR,
                "--skip-compress cannot be combined with -s (chunk serialization)");
    return false;
  }
  if (config->use_delta && !config->whole_file && !config->use_incremental) {
    log_message(LOG_LEVEL_ERROR, "--delta requires --incremental");
    return false;
  }
  if (config->use_delta && !config->whole_file && config->use_chunk_serialization) {
    log_message(LOG_LEVEL_ERROR, "--delta cannot be combined with -s (chunk serialization)");
    return false;
  }
  if (config->use_delta && !config->whole_file && config->use_sendfile) {
    log_message(LOG_LEVEL_ERROR, "--delta cannot be combined with -f (sendfile)");
    return false;
  }
  /* --append / --append-verify resume a shorter existing destination by
     transmitting only the tail.  The resume needs the per-file STATUS_CHECK
     handshake (so the dest length is learned), which chunk serialization -s
     disables; and whole-file is the opposite intent (send everything), so the
     two would silently make the resume pointless.  Both are rejected up front
     rather than silently degrading to a full transfer. */
  if ((config->append || config->append_verify) && config->use_chunk_serialization) {
    log_message(LOG_LEVEL_ERROR,
                "--append/--append-verify require the per-file incremental check and cannot be "
                "combined with -s (chunk serialization)");
    return false;
  }
  if ((config->append || config->append_verify) && config->whole_file) {
    log_message(LOG_LEVEL_ERROR,
                "--append/--append-verify are incompatible with --whole-file (which forces a "
                "full transfer)");
    return false;
  }
  /* --hard-links/-H transmits each later group member as a dedicated per-file
     STATUS_HARDLINK frame, which chunk serialization -s does not support; and a
     hard-links sibling carries no payload, so the tail-resume of --append is
     meaningless for it.  Both combinations are rejected up front rather than
     silently degrading. */
  if (config->preserve_hard_links && config->use_chunk_serialization) {
    log_message(LOG_LEVEL_ERROR,
                "--hard-links/-H cannot be combined with -s (chunk serialization)");
    return false;
  }
  /* -X/-A ride the per-file metadata frame; the buffer-based chunk-serialization
     wire format does not carry the xattr block, so the pair is rejected up front
     (mirroring -H + -s) rather than silently dropping attributes. */
  if ((config->preserve_xattrs || config->preserve_acls) && config->use_chunk_serialization) {
    log_message(LOG_LEVEL_ERROR,
                "--xattrs/-X and --acls/-A cannot be combined with -s (chunk serialization)");
    return false;
  }
  if (config->preserve_hard_links && (config->append || config->append_verify)) {
    log_message(LOG_LEVEL_ERROR,
                "--hard-links/-H cannot be combined with --append/--append-verify");
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
  if (config->delay_updates && config->inplace) {
    log_message(LOG_LEVEL_ERROR, "--delay-updates does not work with --inplace");
    return false;
  }
  if (config->delay_updates && delay_updates_staging_name_conflict(config->backup_dir)) {
    log_message(LOG_LEVEL_ERROR,
                "--backup-dir is reserved when --delay-updates is active (used for the internal "
                "staging directory)");
    return false;
  }
  if (!config_has_valid_delete_timing(config)) {
    log_message(LOG_LEVEL_ERROR,
                "--delete-before/--delete-during/--delete-delay/--delete-after select the delete "
                "timing; at most one may be given and each implies --delete");
    return false;
  }
  /* --iconv: reject a malformed CONVERT_SPEC or an unsupported charset name at
     startup (a probe iconv_open is attempted), so a typo'd charset never fails
     the run mid-transfer with per-file errors. */
  if (!charset_spec_valid(config->iconv_spec)) {
    log_message(LOG_LEVEL_ERROR,
                "--iconv requires LOCAL[,REMOTE] charset names supported by iconv");
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
  /* --copy-as pushes the source ids through the metadata path (it implies
     --preserve).  A later --no-preserve would clear use_metadata, leaving the
     transfer with nothing to chown while the receiver gate would still pass.
     Refuse the combination up front rather than silently chowning nothing. */
  if (config->copy_as_set && !config->use_metadata) {
    log_message(LOG_LEVEL_ERROR,
                "--copy-as requires metadata preservation and cannot be combined with "
                "--no-preserve");
    return false;
  }
  return true;
}
