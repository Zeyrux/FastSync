#include "config.h"
#include "delta.h"
#include "log.h"
#include "protocol.h"
#include "utils.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void config_set_defaults(Config* config) {
  config->version = str_dup(PROTOCOL_VERSION);
  config->send_directory = NULL;
  config->receive_root_directory = NULL;
  config->save_to_disk = false;
  config->use_multithreading = false;
  config->use_chunk_serialization = false;
  config->use_compression = false;
  config->use_metadata = false;
  config->show_progress = false;
  config->dry_run = false;
  config->use_delete = false;
  config->compression_level = 5;
  config->use_sendfile = false;
  config->chunk_size = DEFAULT_CHUNK_SIZE;
  config->ssh_port = 22;
  config->transport = TRANSPORT_TCP;
  config->ssh_destination = NULL;
  config->fastsync_server_path = NULL;
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
  config->server_host = str_dup("127.0.0.1");
  config->server_port = 8080;
  config->timeout = 30;
  config->contimeout = 10;
  config->quiet = false;
  config->backup = false;
  config->backup_dir = NULL;
  config->stats = false;
  config->max_depth = 0;
  config->log_file = NULL;
  config->queue_size = 100;
  config->follow_symlinks = false;
  config->partial = false;
  config->copy_links = false;
  config->safe_links = false;
  config->copy_unsafe_links = false;
  config->preserve_hard_links = false;
  config->preserve_acls = false;
  config->preserve_xattrs = false;
  config->preserve_devices = false;
  config->preserve_sparse = false;
  config->itemize_changes = false;
  config->out_format = NULL;
  config->info_level = 0;
  config->debug_level = 0;
  config->list_only = false;
  config->human_readable = false;
  config->update = false;
  config->inplace = false;
  config->append = false;
  config->append_verify = false;
  config->delete_excluded = false;
  config->delete_after = false;
  config->max_delete = 0;
  config->filters = NULL;
  config->files_from = NULL;
  config->cvs_exclude = false;
  config->prune_empty_dirs = false;
  config->relative = false;
  config->rsh_command = NULL;
  config->rsync_path = NULL;
  config->temp_dir = NULL;
  config->compare_dest = NULL;
  config->copy_dest = NULL;
  config->link_dest = NULL;
  config->partial_dir = NULL;
  config->suffix = NULL;
  config->delete_before = false;
  config->address = NULL;
  config->bind_address = NULL;
  config->ipv6 = false;
  config->ipv4 = false;
  config->daemon = false;
  config->daemon_config = NULL;
  config->server_mode = false;
  config->checksum = false;
  config->compress_choice = NULL;
}

Config* config_create(void) {
  Config* config = malloc(sizeof(Config));
  if (!config)
    return NULL;
  config_set_defaults(config);
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
  free(config->fastsync_server_path);
  for (int i = 0; i < config->exclude_count; i++)
    free(config->exclude_patterns[i]);
  free(config->exclude_patterns);
  for (int i = 0; i < config->include_count; i++)
    free(config->include_patterns[i]);
  free(config->include_patterns);
  free(config->tls_cert);
  free(config->tls_key);
  free(config->tls_ca);
  free(config->backup_dir);
  free(config->server_host);
  free(config->out_format);
  free(config->files_from);
  free(config->rsh_command);
  free(config->rsync_path);
  free(config->temp_dir);
  free(config->compare_dest);
  free(config->copy_dest);
  free(config->link_dest);
  free(config->partial_dir);
  free(config->suffix);
  free(config->address);
  free(config->bind_address);
  free(config->daemon_config);
  free(config->compress_choice);
  if (config->filters) {
    array_list_delete(config->filters);
  }
  free(config);
}

static bool config_send_string(int file_descriptor, const char* value, bool optional) {
  return send_str(file_descriptor, value ? value : (optional ? "" : NULL));
}

#define CONFIG_SEND_VERSION(field)                                                                 \
  do {                                                                                             \
    if (!config_send_string(file_descriptor, config->field, false))                                \
      return false;                                                                                \
  } while (0);
#define CONFIG_SEND_STRING(field)                                                                  \
  do {                                                                                             \
    if (!config_send_string(file_descriptor, config->field, false))                                \
      return false;                                                                                \
  } while (0);
#define CONFIG_SEND_OPTIONAL_STRING(field)                                                         \
  do {                                                                                             \
    if (!config_send_string(file_descriptor, config->field, true))                                 \
      return false;                                                                                \
  } while (0);
#define CONFIG_SEND_INTEGER(field)                                                                 \
  do {                                                                                             \
    if (!send_int(file_descriptor, config->field))                                                 \
      return false;                                                                                \
  } while (0);
#define CONFIG_SEND_DATA(field)                                                                    \
  do {                                                                                             \
    if (!send_n_data(file_descriptor, &config->field, sizeof(config->field)))                      \
      return false;                                                                                \
  } while (0);

bool config_send(int file_descriptor, const Config* config) {
  CONFIG_WIRE_FIELDS(CONFIG_SEND_VERSION, CONFIG_SEND_STRING, CONFIG_SEND_OPTIONAL_STRING,
                     CONFIG_SEND_INTEGER, CONFIG_SEND_DATA)
  Status status;
  if (!receive_status(file_descriptor, &status))
    return false;
  if (status != STATUS_OK) {
    log_message(LOG_LEVEL_ERROR, "Error transmitting config");
    return false;
  }
  return true;
}

#undef CONFIG_SEND_VERSION
#undef CONFIG_SEND_STRING
#undef CONFIG_SEND_OPTIONAL_STRING
#undef CONFIG_SEND_INTEGER
#undef CONFIG_SEND_DATA

static bool config_receive_string(int file_descriptor, char** destination) {
  char* value = receive_str(file_descriptor);
  if (!value)
    return false;
  *destination = value;
  return true;
}

#define CONFIG_RECEIVE_VERSION(field)                                                              \
  do {                                                                                             \
    free(config->field);                                                                           \
    config->field = receive_str(file_descriptor);                                                  \
    if (!config->field)                                                                            \
      goto error;                                                                                  \
    if (strcmp(config->field, PROTOCOL_VERSION) != 0) {                                            \
      fprintf(stderr, "Protocol version mismatch: client=%s, server=%s\n", config->field,          \
              PROTOCOL_VERSION);                                                                   \
      config_delete(config);                                                                       \
      send_status(file_descriptor, STATUS_ERROR);                                                  \
      return NULL;                                                                                 \
    }                                                                                              \
  } while (0);
#define CONFIG_RECEIVE_STRING(field)                                                               \
  do {                                                                                             \
    if (!config_receive_string(file_descriptor, &config->field))                                   \
      goto error;                                                                                  \
  } while (0);
#define CONFIG_RECEIVE_OPTIONAL_STRING(field) CONFIG_RECEIVE_STRING(field)
#define CONFIG_RECEIVE_INTEGER(field)                                                              \
  do {                                                                                             \
    if (!receive_int(file_descriptor, &tmp))                                                       \
      goto error;                                                                                  \
    config->field = tmp;                                                                           \
  } while (0);
#define CONFIG_RECEIVE_DATA(field)                                                                 \
  do {                                                                                             \
    if (!receive_n_data(file_descriptor, &config->field, sizeof(config->field)))                   \
      goto error;                                                                                  \
  } while (0);

Config* config_receive(int file_descriptor) {
  Config* config = (Config*)malloc(sizeof(Config));
  if (config == NULL)
    return NULL;
  config_set_defaults(config);
  int tmp;
  CONFIG_WIRE_FIELDS(CONFIG_RECEIVE_VERSION, CONFIG_RECEIVE_STRING, CONFIG_RECEIVE_OPTIONAL_STRING,
                     CONFIG_RECEIVE_INTEGER, CONFIG_RECEIVE_DATA)
  if (config->compress_choice[0] != '\0' && strcmp(config->compress_choice, "zstd") != 0 &&
      strcmp(config->compress_choice, "none") != 0) {
    fprintf(stderr, "Unsupported compression choice: %s\n", config->compress_choice);
    send_status(file_descriptor, STATUS_ERROR);
    goto error;
  }
  if (!send_status(file_descriptor, STATUS_OK))
    goto error;
  return config;

error:
  config_delete(config);
  return NULL;
}

#undef CONFIG_RECEIVE_VERSION
#undef CONFIG_RECEIVE_STRING
#undef CONFIG_RECEIVE_OPTIONAL_STRING
#undef CONFIG_RECEIVE_INTEGER
#undef CONFIG_RECEIVE_DATA
