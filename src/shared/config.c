#include "config.h"
#include "delta.h"
#include "log.h"
#include "protocol.h"
#include "utils.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Config* config_create(char* version, char* send_directory, char* receive_directory,
                      bool save_to_disk, bool use_multithreading, bool use_chunk_serialization,
                      bool use_compression, bool use_metadata, int compression_level,
                      bool use_sendfile, unsigned long long chunk_size) {

  Config* config = malloc(sizeof(Config));
  if (config == NULL)
    return NULL;
  config->version = version;
  config->send_directory = send_directory;
  config->receive_root_directory = receive_directory;
  config->save_to_disk = save_to_disk;
  config->use_multithreading = use_multithreading;
  config->use_chunk_serialization = use_chunk_serialization;
  config->use_compression = use_compression;
  config->use_metadata = use_metadata;
  config->show_progress = false;
  config->dry_run = false;
  config->use_delete = false;
  config->compression_level = compression_level;
  config->use_sendfile = use_sendfile;
  config->chunk_size = chunk_size > 0 ? chunk_size : DEFAULT_CHUNK_SIZE;
  config->ssh_port = 22;
  config->transport = TRANSPORT_TCP;
  config->ssh_destination = NULL;
  config->exclude_patterns = NULL;
  config->exclude_count = 0;
  config->include_patterns = NULL;
  config->include_count = 0;
  config->max_size = 0;
  config->min_size = 0;
  config->use_incremental = false;
  config->use_delta = false;
  config->delta_block_size = DELTA_BLOCK_SIZE_DEFAULT;
  config->delta_max_file_size = DELTA_MAX_FILE_SIZE;
  config->use_tls = false;
  config->tls_cert = NULL;
  config->tls_key = NULL;
  config->tls_ca = NULL;
  config->follow_symlinks = false;
  config->partial = false;
  config->server_host = str_dup("127.0.0.1");
  config->server_port = 8080;
  return config;
}

bool is_remote_dest(const char* s) {
  if (s == NULL)
    return false;
  const char* colon = strchr(s, ':');
  if (colon == NULL)
    return false;
  if (colon == s)
    return false;
  for (const char* p = s; p < colon; p++) {
    if (*p == '/')
      return false;
  }
  return true;
}

void config_parse_ssh_dest(Config* config) {
  if (!is_remote_dest(config->receive_root_directory))
    return;
  config->transport = TRANSPORT_SSH;
  config->ssh_destination = str_dup(config->receive_root_directory);
  const char* colon = strchr(config->receive_root_directory, ':');
  char* path = str_dup(colon + 1);
  free(config->receive_root_directory);
  config->receive_root_directory = path;
}

void config_delete(Config* config) {
  if (config == NULL)
    return;
  free(config->version);
  free(config->send_directory);
  free(config->receive_root_directory);
  free(config->ssh_destination);
  for (int i = 0; i < config->exclude_count; i++)
    free(config->exclude_patterns[i]);
  free(config->exclude_patterns);
  for (int i = 0; i < config->include_count; i++)
    free(config->include_patterns[i]);
  free(config->include_patterns);
  free(config->tls_cert);
  free(config->tls_key);
  free(config->tls_ca);
  free(config->server_host);
  free(config);
}

bool config_send(int file_descriptor, const Config* config) {
  if (!send_str(file_descriptor, config->version))
    return false;
  if (!send_str(file_descriptor, config->send_directory))
    return false;
  if (!send_str(file_descriptor, config->receive_root_directory))
    return false;
  if (!send_int(file_descriptor, config->save_to_disk))
    return false;
  if (!send_int(file_descriptor, config->use_multithreading))
    return false;
  if (!send_int(file_descriptor, config->use_chunk_serialization))
    return false;
  if (!send_int(file_descriptor, config->use_compression))
    return false;
  if (!send_int(file_descriptor, config->use_metadata))
    return false;
  if (!send_int(file_descriptor, config->compression_level))
    return false;
  if (!send_n_data(file_descriptor, &config->chunk_size, sizeof(config->chunk_size)))
    return false;
  if (!send_int(file_descriptor, config->use_sendfile))
    return false;
  if (!send_int(file_descriptor, config->use_delete))
    return false;
  if (!send_int(file_descriptor, config->use_incremental))
    return false;
  if (!send_int(file_descriptor, config->use_delta))
    return false;
  if (!send_int(file_descriptor, (int)config->delta_block_size))
    return false;
  if (!send_n_data(file_descriptor, &config->delta_max_file_size, sizeof(unsigned long long)))
    return false;
  if (!send_int(file_descriptor, config->exclude_count))
    return false;
  for (int i = 0; i < config->exclude_count; i++) {
    if (!send_str(file_descriptor, config->exclude_patterns[i]))
      return false;
  }
  if (!send_int(file_descriptor, config->include_count))
    return false;
  for (int i = 0; i < config->include_count; i++) {
    if (!send_str(file_descriptor, config->include_patterns[i]))
      return false;
  }
  if (!send_n_data(file_descriptor, &config->max_size, sizeof(config->max_size)))
    return false;
  if (!send_n_data(file_descriptor, &config->min_size, sizeof(config->min_size)))
    return false;
  if (!send_int(file_descriptor, config->follow_symlinks))
    return false;
  if (!send_int(file_descriptor, config->partial))
    return false;
  Status status;
  if (!receive_status(file_descriptor, &status))
    return false;
  if (status != STATUS_OK) {
    log_message(LOG_LEVEL_ERROR, "Error transmitting config");
    return false;
  }
  return true;
}

Config* config_receive(int file_descriptor) {
  Config* config = (Config*)malloc(sizeof(Config));
  if (config == NULL)
    return NULL;
  memset(config, 0, sizeof(*config));
  config->version = receive_str(file_descriptor);
  if (!config->version) {
    free(config);
    return NULL;
  }
  if (strcmp(config->version, PROTOCOL_VERSION) != 0) {
    fprintf(stderr, "Protocol version mismatch: client=%s, server=%s\n", config->version,
            PROTOCOL_VERSION);
    free(config->version);
    free(config);
    send_status(file_descriptor, STATUS_ERROR);
    return NULL;
  }
  config->send_directory = receive_str(file_descriptor);
  if (!config->send_directory) {
    free(config->version);
    free(config);
    return NULL;
  }
  config->receive_root_directory = receive_str(file_descriptor);
  if (!config->receive_root_directory) {
    free(config->version);
    free(config->send_directory);
    free(config);
    return NULL;
  }
  int tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->save_to_disk = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->use_multithreading = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->use_chunk_serialization = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->use_compression = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->use_metadata = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->compression_level = tmp;
  if (!receive_n_data(file_descriptor, &config->chunk_size, sizeof(config->chunk_size)))
    goto error;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->use_sendfile = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->use_delete = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->use_incremental = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->use_delta = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->delta_block_size = (uint32_t)tmp;
  if (!receive_n_data(file_descriptor, &config->delta_max_file_size, sizeof(unsigned long long)))
    goto error;
  config->show_progress = false;
  config->dry_run = false;
  config->ssh_port = 22;
  config->transport = TRANSPORT_TCP;
  config->ssh_destination = NULL;
  config->exclude_patterns = NULL;
  config->exclude_count = 0;
  config->include_patterns = NULL;
  config->include_count = 0;
  config->max_size = 0;
  config->min_size = 0;
  config->use_tls = false;
  config->tls_cert = NULL;
  config->tls_key = NULL;
  config->tls_ca = NULL;
  config->follow_symlinks = false;
  config->partial = false;

#define MAX_PATTERN_COUNT 10000

  // Receive exclude patterns
  int ec;
  if (!receive_int(file_descriptor, &ec))
    goto error;
  if (ec > MAX_PATTERN_COUNT) {
    log_message(LOG_LEVEL_ERROR, "Exclude pattern count %d exceeds maximum %d", ec,
                MAX_PATTERN_COUNT);
    goto error;
  }
  config->exclude_count = ec;
  if (ec > 0) {
    config->exclude_patterns = malloc((size_t)ec * sizeof(char*));
    if (!config->exclude_patterns) {
      config->exclude_count = 0;
      goto error;
    }
    for (int i = 0; i < ec; i++) {
      config->exclude_patterns[i] = receive_str(file_descriptor);
      if (!config->exclude_patterns[i]) {
        for (int j = 0; j < i; j++)
          free(config->exclude_patterns[j]);
        free(config->exclude_patterns);
        config->exclude_patterns = NULL;
        config->exclude_count = 0;
        goto error;
      }
    }
  }

  // Receive include patterns
  int ic;
  if (!receive_int(file_descriptor, &ic))
    goto error;
  if (ic > MAX_PATTERN_COUNT) {
    log_message(LOG_LEVEL_ERROR, "Include pattern count %d exceeds maximum %d", ic,
                MAX_PATTERN_COUNT);
    goto error;
  }
  config->include_count = ic;
  if (ic > 0) {
    config->include_patterns = malloc((size_t)ic * sizeof(char*));
    if (!config->include_patterns) {
      config->include_count = 0;
      goto error;
    }
    for (int i = 0; i < ic; i++) {
      config->include_patterns[i] = receive_str(file_descriptor);
      if (!config->include_patterns[i]) {
        for (int j = 0; j < i; j++)
          free(config->include_patterns[j]);
        free(config->include_patterns);
        config->include_patterns = NULL;
        config->include_count = 0;
        goto error;
      }
    }
  }

  if (!receive_n_data(file_descriptor, &config->max_size, sizeof(config->max_size)))
    goto error;
  if (!receive_n_data(file_descriptor, &config->min_size, sizeof(config->min_size)))
    goto error;
  int tmp_follow;
  if (!receive_int(file_descriptor, &tmp_follow))
    goto error;
  config->follow_symlinks = tmp_follow;
  int tmp_partial;
  if (!receive_int(file_descriptor, &tmp_partial))
    goto error;
  config->partial = tmp_partial;

  config->server_host = str_dup("127.0.0.1");
  config->server_port = 8080;
  if (!send_status(file_descriptor, STATUS_OK))
    goto error;
  return config;

error:
  free(config->version);
  free(config->send_directory);
  free(config->receive_root_directory);
  for (int i = 0; i < config->exclude_count; i++)
    free(config->exclude_patterns[i]);
  free(config->exclude_patterns);
  for (int i = 0; i < config->include_count; i++)
    free(config->include_patterns[i]);
  free(config->include_patterns);
  free(config->tls_cert);
  free(config->tls_key);
  free(config->tls_ca);
  free(config->ssh_destination);
  free(config->server_host);
  free(config);
  return NULL;
}
