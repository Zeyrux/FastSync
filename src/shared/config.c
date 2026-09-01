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

bool config_is_remote_dest(const char* s) {
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
  if (!config_is_remote_dest(config->receive_root_directory))
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

/* Each helper is deliberately ordered to match the wire format. Keep the
 * helper call order in config_send and config_receive unchanged when adding
 * fields. */
static bool send_core_fields(int fd, const Config* c) {
  return send_str(fd, c->version) && send_str(fd, c->send_directory) &&
         send_str(fd, c->receive_root_directory) && send_int(fd, c->save_to_disk) &&
         send_int(fd, c->use_multithreading) && send_int(fd, c->use_chunk_serialization) &&
         send_int(fd, c->use_compression) && send_int(fd, c->use_metadata) &&
         send_int(fd, c->compression_level) &&
         send_n_data(fd, &c->chunk_size, sizeof(c->chunk_size)) && send_int(fd, c->use_sendfile);
}

static bool send_delta_fields(int fd, const Config* c) {
  return send_int(fd, c->use_delete) && send_int(fd, c->use_incremental) &&
         send_int(fd, c->use_delta) &&
         send_n_data(fd, &c->delta_block_size, sizeof(c->delta_block_size)) &&
         send_n_data(fd, &c->delta_max_file_size, sizeof(unsigned long long));
}

static bool send_file_options(int fd, const Config* c) {
  return send_int(fd, c->backup) && send_str(fd, c->backup_dir ? c->backup_dir : "") &&
         send_int(fd, c->follow_symlinks) && send_int(fd, c->copy_links) &&
         send_int(fd, c->safe_links) && send_int(fd, c->copy_unsafe_links) &&
         send_int(fd, c->preserve_hard_links) && send_int(fd, c->preserve_acls) &&
         send_int(fd, c->preserve_xattrs) && send_int(fd, c->preserve_devices) &&
         send_int(fd, c->preserve_sparse);
}

static bool send_selection_options(int fd, const Config* c) {
  return send_int(fd, c->update) && send_int(fd, c->inplace) && send_int(fd, c->append) &&
         send_int(fd, c->append_verify) && send_int(fd, c->delete_excluded) &&
         send_int(fd, c->delete_after) && send_n_data(fd, &c->max_delete, sizeof(c->max_delete)) &&
         send_int(fd, c->relative) && send_int(fd, c->prune_empty_dirs);
}

static bool send_resume_options(int fd, const Config* c) {
  return send_str(fd, c->temp_dir ? c->temp_dir : "") && send_int(fd, c->partial) &&
         send_str(fd, c->partial_dir ? c->partial_dir : "") &&
         send_str(fd, c->suffix ? c->suffix : "") && send_int(fd, c->delete_before) &&
         send_int(fd, c->checksum) && send_str(fd, c->compress_choice ? c->compress_choice : "");
}

static bool receive_core_fields(int fd, Config* c) {
  int value;
  c->send_directory = receive_str(fd);
  c->receive_root_directory = receive_str(fd);
  if (!c->send_directory || !c->receive_root_directory)
    return false;
  if (!receive_int(fd, &value))
    return false;
  c->save_to_disk = value;
  if (!receive_int(fd, &value))
    return false;
  c->use_multithreading = value;
  if (!receive_int(fd, &value))
    return false;
  c->use_chunk_serialization = value;
  if (!receive_int(fd, &value))
    return false;
  c->use_compression = value;
  if (!receive_int(fd, &value))
    return false;
  c->use_metadata = value;
  if (!receive_int(fd, &value))
    return false;
  c->compression_level = value;
  if (!receive_n_data(fd, &c->chunk_size, sizeof(c->chunk_size)))
    return false;
  if (!receive_int(fd, &value))
    return false;
  c->use_sendfile = value;
  return true;
}

static bool receive_delta_fields(int fd, Config* c) {
  int value;
  if (!receive_int(fd, &value))
    return false;
  c->use_delete = value;
  if (!receive_int(fd, &value))
    return false;
  c->use_incremental = value;
  if (!receive_int(fd, &value))
    return false;
  c->use_delta = value;
  return receive_n_data(fd, &c->delta_block_size, sizeof(c->delta_block_size)) &&
         receive_n_data(fd, &c->delta_max_file_size, sizeof(unsigned long long));
}

static bool receive_file_options(int fd, Config* c) {
  int value;
  if (!receive_int(fd, &value))
    return false;
  c->backup = value;
  c->backup_dir = receive_str(fd);
  if (!c->backup_dir)
    return false;
  bool* flags[] = {&c->follow_symlinks,   &c->copy_links,          &c->safe_links,
                   &c->copy_unsafe_links, &c->preserve_hard_links, &c->preserve_acls,
                   &c->preserve_xattrs,   &c->preserve_devices,    &c->preserve_sparse};
  for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    if (!receive_int(fd, &value))
      return false;
    *flags[i] = value;
  }
  return true;
}

static bool receive_selection_options(int fd, Config* c) {
  int value;
  bool* flags[] = {&c->update,        &c->inplace,         &c->append,
                   &c->append_verify, &c->delete_excluded, &c->delete_after};
  for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    if (!receive_int(fd, &value))
      return false;
    *flags[i] = value;
  }
  if (!receive_n_data(fd, &c->max_delete, sizeof(c->max_delete)))
    return false;
  if (!receive_int(fd, &value))
    return false;
  c->relative = value;
  if (!receive_int(fd, &value))
    return false;
  c->prune_empty_dirs = value;
  return true;
}

static bool receive_resume_options(int fd, Config* c) {
  int value;
  c->temp_dir = receive_str(fd);
  if (!c->temp_dir || !receive_int(fd, &value))
    return false;
  c->partial = value;
  c->partial_dir = receive_str(fd);
  c->suffix = c->partial_dir ? receive_str(fd) : NULL;
  if (!c->partial_dir || !c->suffix || !receive_int(fd, &value))
    return false;
  c->delete_before = value;
  if (!receive_int(fd, &value))
    return false;
  c->checksum = value;
  c->compress_choice = receive_str(fd);
  return c->compress_choice != NULL;
}

bool config_send(int file_descriptor, const Config* config) {
  if (!send_core_fields(file_descriptor, config) || !send_delta_fields(file_descriptor, config) ||
      !send_file_options(file_descriptor, config) ||
      !send_selection_options(file_descriptor, config) ||
      !send_resume_options(file_descriptor, config))
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
  Config* config = config_create();
  if (!config)
    return NULL;
  free(config->version);
  config->version = receive_str(file_descriptor);
  if (!config->version)
    goto error;
  if (strcmp(config->version, PROTOCOL_VERSION) != 0) {
    fprintf(stderr, "Protocol version mismatch: client=%s, server=%s\n", config->version,
            PROTOCOL_VERSION);
    send_status(file_descriptor, STATUS_ERROR);
    goto error;
  }
  if (!receive_core_fields(file_descriptor, config) ||
      !receive_delta_fields(file_descriptor, config) ||
      !receive_file_options(file_descriptor, config) ||
      !receive_selection_options(file_descriptor, config) ||
      !receive_resume_options(file_descriptor, config))
    goto error;
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
