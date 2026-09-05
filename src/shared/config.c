#include "config.h"
#include "chmod.h"
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
  config->use_executability = false;
  config->show_progress = false;
  config->dry_run = false;
  config->remove_source_files = false;
  config->use_delete = false;
  config->compression_level = 5;
  config->compression_threads = 0;
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
  config->max_alloc = DEFAULT_MAX_ALLOC;
  config->use_incremental = false;
  config->ignore_times = false;
  config->size_only = false;
  config->use_delta = false;
  config->whole_file = false;
  config->modify_window = 0;
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
  config->eight_bit_output = false;
  config->existing = false;
  config->ignore_existing = false;
  config->update = false;
  config->inplace = false;
  config->use_fsync = false;
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
  config->chmod_spec = NULL;
  config->skip_compress_suffixes = NULL;
  config->skip_compress_count = 0;
  config->skip_compress_set = false;
}

static bool valid_wire_bool(int value) {
  return value == 0 || value == 1;
}

static bool receive_wire_bool(int fd, bool* value) {
  int wire_value;
  if (!receive_int(fd, &wire_value) || !valid_wire_bool(wire_value))
    return false;
  *value = wire_value != 0;
  return true;
}

static bool validate_received_config(const Config* config) {
  return valid_wire_bool(config->save_to_disk) && valid_wire_bool(config->use_multithreading) &&
         valid_wire_bool(config->use_chunk_serialization) &&
         valid_wire_bool(config->use_compression) && valid_wire_bool(config->use_metadata) &&
         valid_wire_bool(config->use_executability) && valid_wire_bool(config->use_sendfile) &&
         valid_wire_bool(config->use_delete) && valid_wire_bool(config->use_incremental) &&
         valid_wire_bool(config->size_only) && valid_wire_bool(config->ignore_times) &&
         valid_wire_bool(config->use_delta) && valid_wire_bool(config->backup) &&
         valid_wire_bool(config->follow_symlinks) && valid_wire_bool(config->copy_links) &&
         valid_wire_bool(config->safe_links) && valid_wire_bool(config->copy_unsafe_links) &&
         valid_wire_bool(config->preserve_hard_links) && valid_wire_bool(config->preserve_acls) &&
         valid_wire_bool(config->preserve_xattrs) && valid_wire_bool(config->preserve_devices) &&
         valid_wire_bool(config->preserve_sparse) && valid_wire_bool(config->ignore_existing) &&
         valid_wire_bool(config->existing) &&
         valid_wire_bool(config->update) && valid_wire_bool(config->inplace) &&
         valid_wire_bool(config->append) && valid_wire_bool(config->use_fsync) &&
         valid_wire_bool(config->append_verify) &&
         valid_wire_bool(config->delete_excluded) && valid_wire_bool(config->delete_after) &&
         valid_wire_bool(config->relative) && valid_wire_bool(config->prune_empty_dirs) &&
         valid_wire_bool(config->partial) && valid_wire_bool(config->delete_before) &&
         valid_wire_bool(config->checksum) && valid_wire_bool(config->eight_bit_output) &&
         !(config->skip_compress_set && config->use_chunk_serialization) &&
         (!config->use_compression ||
          (config->compression_level >= 1 && config->compression_level <= 22)) &&
         config->chunk_size > 0 && config->chunk_size <= MAX_CHUNK_SIZE &&
         config->delta_block_size >= DELTA_BLOCK_SIZE_MIN &&
         config->delta_block_size <= DELTA_BLOCK_SIZE_MAX &&
config->delta_max_file_size <= DELTA_MAX_FILE_SIZE && config->modify_window >= 0 &&
         config->max_delete >= 0 && config->skip_compress_count >= 0 &&
         config->skip_compress_count <= 10000 && config->max_alloc > 0 &&
         (!config->chmod_spec || !*config->chmod_spec ||
          chmod_apply(0, config->chmod_spec, &(mode_t){0}));
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
  if (config->log_file) {
    fclose(config->log_file);
    config->log_file = NULL;
  }
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
  free(config->chmod_spec);
  if (config->skip_compress_suffixes) {
    for (int i = 0; i < config->skip_compress_count; i++)
      free(config->skip_compress_suffixes[i]);
    free(config->skip_compress_suffixes);
  }
  if (config->filters) {
    array_list_delete(config->filters);
  }
  free(config);
}

/* Each helper is deliberately ordered to match the wire format. Keep the
 * helper call order in config_send and config_receive unchanged when adding
 * fields. */
static bool send_core_fields(int fd, const Config* c) {
  if (!send_str(fd, c->version) || !send_int(fd, c->eight_bit_output))
    return false;
  protocol_set_8_bit_output(c->eight_bit_output);
  if (!send_n_data(fd, &c->max_alloc, sizeof(c->max_alloc)))
    return false;
  return send_str(fd, c->send_directory) && send_str(fd, c->receive_root_directory) &&
         send_int(fd, c->save_to_disk) && send_int(fd, c->use_multithreading) &&
         send_int(fd, c->use_chunk_serialization) && send_int(fd, c->use_compression) &&
         send_int(fd, c->use_metadata) && send_int(fd, c->use_executability) &&
         send_int(fd, c->compression_level) &&
         send_n_data(fd, &c->chunk_size, sizeof(c->chunk_size)) && send_int(fd, c->use_sendfile);
}

static bool send_delta_fields(int fd, const Config* c) {
  return send_int(fd, c->use_delete) && send_int(fd, c->use_incremental) &&
         send_int(fd, c->size_only) && send_int(fd, c->ignore_times) &&
         send_int(fd, c->use_delta && !c->whole_file) &&
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
  return send_int(fd, c->ignore_existing) && send_int(fd, c->existing) && send_int(fd, c->update) && send_int(fd, c->inplace) &&
         send_int(fd, c->append) && send_int(fd, c->use_fsync) &&
         send_int(fd, c->append_verify) &&
         send_int(fd, c->delete_excluded) && send_int(fd, c->delete_after) &&
         send_n_data(fd, &c->max_delete, sizeof(c->max_delete)) && send_int(fd, c->relative) &&
         send_int(fd, c->prune_empty_dirs);
}

static bool send_skip_compress_options(int fd, const Config* c) {
  if (!send_int(fd, c->skip_compress_set) || !send_int(fd, c->skip_compress_count))
    return false;
  for (int i = 0; i < c->skip_compress_count; i++) {
    if (!send_str(fd, c->skip_compress_suffixes[i]))
      return false;
  }
  return true;
}

static bool send_resume_options(int fd, const Config* c) {
  return send_str(fd, c->temp_dir ? c->temp_dir : "") && send_int(fd, c->partial) &&
         send_str(fd, c->partial_dir ? c->partial_dir : "") &&
         send_str(fd, c->suffix ? c->suffix : "") && send_int(fd, c->delete_before) &&
         send_int(fd, c->checksum) && send_int(fd, c->modify_window) &&
         send_str(fd, c->compress_choice ? c->compress_choice : "") &&
         send_str(fd, c->chmod_spec ? c->chmod_spec : "") &&
         send_skip_compress_options(fd, c);
}

static bool receive_core_fields(int fd, Config* c) {
  int value;
  if (!receive_wire_bool(fd, &c->eight_bit_output))
    return false;
  protocol_set_8_bit_output(c->eight_bit_output);
  if (!receive_n_data(fd, &c->max_alloc, sizeof(c->max_alloc)) || c->max_alloc == 0)
    return false;
  if (c->max_alloc > MAX_SERVER_ALLOC)
    c->max_alloc = MAX_SERVER_ALLOC;
  protocol_session_set_max_alloc(NULL, c->max_alloc);
  c->send_directory = receive_str(fd);
  c->receive_root_directory = receive_str(fd);
  if (!c->send_directory || !c->receive_root_directory)
    return false;
  if (!receive_wire_bool(fd, &c->save_to_disk) || !receive_wire_bool(fd, &c->use_multithreading) ||
      !receive_wire_bool(fd, &c->use_chunk_serialization) ||
      !receive_wire_bool(fd, &c->use_compression) || !receive_wire_bool(fd, &c->use_metadata) ||
      !receive_wire_bool(fd, &c->use_executability))
    return false;
  if (!receive_int(fd, &value))
    return false;
  c->compression_level = value;
  if (!receive_n_data(fd, &c->chunk_size, sizeof(c->chunk_size)))
    return false;
  if (!receive_wire_bool(fd, &c->use_sendfile))
    return false;
  return true;
}

static bool receive_delta_fields(int fd, Config* c) {
  if (!receive_wire_bool(fd, &c->use_delete))
    return false;
  if (!receive_wire_bool(fd, &c->use_incremental))
    return false;
  if (!receive_wire_bool(fd, &c->size_only))
    return false;
  if (!receive_wire_bool(fd, &c->ignore_times))
    return false;
  if (!receive_wire_bool(fd, &c->use_delta))
    return false;
  return receive_n_data(fd, &c->delta_block_size, sizeof(c->delta_block_size)) &&
         receive_n_data(fd, &c->delta_max_file_size, sizeof(unsigned long long));
}

static bool receive_file_options(int fd, Config* c) {
  if (!receive_wire_bool(fd, &c->backup))
    return false;
  c->backup_dir = receive_str(fd);
  if (!c->backup_dir)
    return false;
  bool* flags[] = {&c->follow_symlinks,   &c->copy_links,          &c->safe_links,
                   &c->copy_unsafe_links, &c->preserve_hard_links, &c->preserve_acls,
                   &c->preserve_xattrs,   &c->preserve_devices,    &c->preserve_sparse};
  for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    if (!receive_wire_bool(fd, flags[i]))
      return false;
  }
  return true;
}

static bool receive_selection_options(int fd, Config* c) {
  bool* flags[] = {&c->ignore_existing, &c->existing,   &c->update,          &c->inplace,     &c->append,
                   &c->use_fsync,
                   &c->append_verify,   &c->delete_excluded, &c->delete_after};
  for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    if (!receive_wire_bool(fd, flags[i]))
      return false;
  }
  if (!receive_n_data(fd, &c->max_delete, sizeof(c->max_delete)))
    return false;
  if (!receive_wire_bool(fd, &c->relative))
    return false;
  if (!receive_wire_bool(fd, &c->prune_empty_dirs))
    return false;
  return true;
}

static bool receive_resume_options(int fd, Config* c) {
  c->temp_dir = receive_str(fd);
  if (!c->temp_dir || !receive_wire_bool(fd, &c->partial))
    return false;
  c->partial_dir = receive_str(fd);
  c->suffix = c->partial_dir ? receive_str(fd) : NULL;
  if (!c->partial_dir || !c->suffix || !receive_wire_bool(fd, &c->delete_before))
    return false;
  if (!receive_wire_bool(fd, &c->checksum))
    return false;
  if (!receive_n_data(fd, &c->modify_window, sizeof(c->modify_window)))
    return false;
  c->compress_choice = receive_str(fd);
  if (!c->compress_choice)
    return false;
  c->chmod_spec = receive_str(fd);
  if (!c->chmod_spec ||
      !receive_wire_bool(fd, &c->skip_compress_set) ||
      !receive_int(fd, &c->skip_compress_count) || c->skip_compress_count < 0 ||
      c->skip_compress_count > 10000)
    return false;
  if (c->skip_compress_count > 0) {
    c->skip_compress_suffixes = calloc((size_t)c->skip_compress_count, sizeof(char*));
    if (!c->skip_compress_suffixes)
      return false;
    for (int i = 0; i < c->skip_compress_count; i++) {
      c->skip_compress_suffixes[i] = receive_str(fd);
      if (!c->skip_compress_suffixes[i])
        return false;
    }
  }
  return true;
}

bool config_send(int file_descriptor, const Config* config) {
  protocol_session_set_max_alloc(NULL, config->max_alloc);
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
    char* escaped_version = output_escape(config->version, false);
    fprintf(stderr, "Protocol version mismatch: client=%s, server=%s\n",
            escaped_version ? escaped_version : "<allocation failed>", PROTOCOL_VERSION);
    free(escaped_version);
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
    char* escaped_choice = output_escape(config->compress_choice, config->eight_bit_output);
    fprintf(stderr, "Unsupported compression choice: %s\n",
            escaped_choice ? escaped_choice : "<allocation failed>");
    free(escaped_choice);
    send_status(file_descriptor, STATUS_ERROR);
    goto error;
  }
  if (!validate_received_config(config)) {
    fprintf(stderr, "Invalid configuration received from client\n");
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
