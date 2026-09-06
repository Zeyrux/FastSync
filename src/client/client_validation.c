#include "client_validation.h"
#include "delay_updates.h"
#include "log.h"
#include "usage.h"
#include <stdio.h>

/* Validate config after parsing. Returns true if valid. */
bool validate_config(const Config* config) {
  if (!config->send_directory || !config->receive_root_directory) {
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
  if (config->log_file_format && !config->log_file) {
    log_message(LOG_LEVEL_ERROR, "--log-file-format requires --log-file");
    return false;
  }
  if (config->append || config->append_verify) {
    fprintf(
        stderr,
        "Error: --append and --append-verify are not supported yet; refusing to ignore option\n");
    return false;
  }
  if (config->use_tls) {
    if (!config->tls_cert || !config->tls_key || !config->tls_ca) {
      log_message(LOG_LEVEL_ERROR, "--tls requires --cert, --key, and --ca");
      return false;
    }
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
  return true;
}
