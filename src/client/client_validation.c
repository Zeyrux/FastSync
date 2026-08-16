#include "client_validation.h"
#include "usage.h"
#include <stdio.h>

/* Validate config after parsing. Returns true if valid. */
bool validate_config(const Config* config) {
  if (!config->send_directory || !config->receive_root_directory) {
    fprintf(stderr, "Error: source and destination directories are required\n");
    print_usage();
    return false;
  }
  if (config->use_sendfile && (config->use_chunk_serialization || config->use_compression)) {
    fprintf(stderr, "Error: -f/--sendfile cannot be combined with -c (compression) or -s (chunk "
                    "serialization)\n");
    return false;
  }
  if (config->transport == TRANSPORT_SSH && config->use_sendfile) {
    fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
    return false;
  }
  if (config->use_incremental && config->use_chunk_serialization) {
    fprintf(stderr, "Error: --incremental is not supported with -s (chunk serialization)\n");
    return false;
  }
  if (config->use_delta && !config->use_incremental) {
    fprintf(stderr, "Error: --delta requires --incremental\n");
    return false;
  }
  if (config->use_delta && config->use_chunk_serialization) {
    fprintf(stderr, "Error: --delta cannot be combined with -s (chunk serialization)\n");
    return false;
  }
  if (config->use_delta && config->use_sendfile) {
    fprintf(stderr, "Error: --delta cannot be combined with -f (sendfile)\n");
    return false;
  }
  if (config->append || config->append_verify) {
    fprintf(
        stderr,
        "Error: --append and --append-verify are not supported yet; refusing to ignore option\n");
    return false;
  }
  if (config->use_tls) {
    if (!config->tls_cert || !config->tls_key) {
      fprintf(stderr, "Error: --tls requires --cert and --key\n");
      return false;
    }
  }
  return true;
}
