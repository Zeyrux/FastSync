#include "client_validation.h"
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
  if (config->use_delta && !config->use_incremental) {
    log_message(LOG_LEVEL_ERROR, "--delta requires --incremental");
    return false;
  }
  if (config->use_delta && config->use_chunk_serialization) {
    log_message(LOG_LEVEL_ERROR, "--delta cannot be combined with -s (chunk serialization)");
    return false;
  }
  if (config->use_delta && config->use_sendfile) {
    log_message(LOG_LEVEL_ERROR, "--delta cannot be combined with -f (sendfile)");
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
  return true;
}
