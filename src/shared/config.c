#include "config.h"
#include "delta.h"
#include "log.h"
#include "protocol.h"
#include "utils.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Config* config_create(void) {
  Config* config = malloc(sizeof(Config));
  if (!config)
    return NULL;
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

/* Wire format order (must match config_receive and be updated when PROTOCOL_VERSION bumps):
 * version, send_directory, receive_root_directory, save_to_disk, use_multithreading,
 * use_chunk_serialization, use_compression, use_metadata, compression_level, chunk_size,
 * use_sendfile, use_delete, use_incremental, use_delta, delta_block_size, delta_max_file_size,
 * backup, backup_dir, follow_symlinks, copy_links, safe_links, copy_unsafe_links,
 * preserve_hard_links, preserve_acls, preserve_xattrs, preserve_devices, preserve_sparse,
 * update, inplace, append, append_verify, delete_excluded, delete_after, max_delete, relative,
 * prune_empty_dirs, temp_dir, partial, partial_dir, suffix, delete_before, checksum,
 * compress_choice, status
 */
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
  if (!send_int(file_descriptor, config->backup))
    return false;
  if (!send_str(file_descriptor, config->backup_dir ? config->backup_dir : ""))
    return false;
  if (!send_int(file_descriptor, config->follow_symlinks))
    return false;
  if (!send_int(file_descriptor, config->copy_links))
    return false;
  if (!send_int(file_descriptor, config->safe_links))
    return false;
  if (!send_int(file_descriptor, config->copy_unsafe_links))
    return false;
  if (!send_int(file_descriptor, config->preserve_hard_links))
    return false;
  if (!send_int(file_descriptor, config->preserve_acls))
    return false;
  if (!send_int(file_descriptor, config->preserve_xattrs))
    return false;
  if (!send_int(file_descriptor, config->preserve_devices))
    return false;
  if (!send_int(file_descriptor, config->preserve_sparse))
    return false;
  if (!send_int(file_descriptor, config->update))
    return false;
  if (!send_int(file_descriptor, config->inplace))
    return false;
  if (!send_int(file_descriptor, config->append))
    return false;
  if (!send_int(file_descriptor, config->append_verify))
    return false;
  if (!send_int(file_descriptor, config->delete_excluded))
    return false;
  if (!send_int(file_descriptor, config->delete_after))
    return false;
  if (!send_n_data(file_descriptor, &config->max_delete, sizeof(config->max_delete)))
    return false;
  if (!send_int(file_descriptor, config->relative))
    return false;
  if (!send_int(file_descriptor, config->prune_empty_dirs))
    return false;
  if (!send_str(file_descriptor, config->temp_dir ? config->temp_dir : ""))
    return false;
  if (!send_int(file_descriptor, config->partial))
    return false;
  if (!send_str(file_descriptor, config->partial_dir ? config->partial_dir : ""))
    return false;
  if (!send_str(file_descriptor, config->suffix ? config->suffix : ""))
    return false;
  if (!send_int(file_descriptor, config->delete_before))
    return false;
  if (!send_int(file_descriptor, config->checksum))
    return false;
  if (!send_str(file_descriptor, config->compress_choice ? config->compress_choice : ""))
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

/* Wire format order: see the comment above config_send. */
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
  config->fastsync_server_path = NULL;
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
  config->timeout = 30;
  config->contimeout = 10;
  config->quiet = false;
  config->stats = false;
  config->max_depth = 0;
  config->log_file = NULL;
  config->queue_size = 100;
  config->follow_symlinks = false;
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
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->backup = tmp;
  config->backup_dir = receive_str(file_descriptor);
  if (config->backup_dir == NULL)
    goto error;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->follow_symlinks = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->copy_links = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->safe_links = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->copy_unsafe_links = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->preserve_hard_links = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->preserve_acls = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->preserve_xattrs = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->preserve_devices = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->preserve_sparse = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->update = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->inplace = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->append = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->append_verify = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->delete_excluded = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->delete_after = tmp;
  if (!receive_n_data(file_descriptor, &config->max_delete, sizeof(config->max_delete)))
    goto error;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->relative = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->prune_empty_dirs = tmp;
  config->temp_dir = receive_str(file_descriptor);
  if (config->temp_dir == NULL)
    goto error;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->partial = tmp;
  config->partial_dir = receive_str(file_descriptor);
  if (config->partial_dir == NULL)
    goto error;
  config->suffix = receive_str(file_descriptor);
  if (config->suffix == NULL)
    goto error;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->delete_before = tmp;
  if (!receive_int(file_descriptor, &tmp))
    goto error;
  config->checksum = tmp;
  config->compress_choice = receive_str(file_descriptor);
  if (config->compress_choice == NULL)
    goto error;
  config->address = NULL;
  config->bind_address = NULL;
  config->ipv6 = false;
  config->ipv4 = false;
  config->daemon = false;
  config->daemon_config = NULL;
  config->server_mode = false;
  config->server_host = str_dup("127.0.0.1");
  config->server_port = 8080;
  if (!send_status(file_descriptor, STATUS_OK))
    goto error;
  return config;

error:
  free(config->version);
  free(config->send_directory);
  free(config->receive_root_directory);
  free(config->server_host);
  free(config->backup_dir);
  free(config->temp_dir);
  free(config->partial_dir);
  free(config->suffix);
  free(config->compress_choice);
  free(config);
  return NULL;
}
