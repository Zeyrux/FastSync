#include "config.h"
#include "protocol.h"
#include "utils.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Config *config_create(char *version, char *send_directory,
                      char *receive_directory, bool save_to_disk,
                      bool use_multithreading, bool use_chunk_serialization,
                       bool use_compression, bool use_metadata,
                       int compression_level, bool use_sendfile,
                       unsigned long long chunk_size) {

  Config *config = malloc(sizeof(Config));
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
  return config;
}

bool is_remote_dest(const char *s) {
  if (s == NULL) return false;
  const char *colon = strchr(s, ':');
  if (colon == NULL) return false;
  if (colon == s) return false;
  for (const char *p = s; p < colon; p++) {
    if (*p == '/') return false;
  }
  return true;
}

void config_parse_ssh_dest(Config *config) {
  if (!is_remote_dest(config->receive_root_directory)) return;
  config->transport = TRANSPORT_SSH;
  config->ssh_destination = str_dup(config->receive_root_directory);
  char *colon = strchr(config->receive_root_directory, ':');
  char *path = str_dup(colon + 1);
  free(config->receive_root_directory);
  config->receive_root_directory = path;
}

void config_delete(Config *config) {
  free(config->version);
  free(config->send_directory);
  free(config->receive_root_directory);
  free(config->ssh_destination);
  for (int i = 0; i < config->exclude_count; i++)
    free(config->exclude_patterns[i]);
  free(config->exclude_patterns);
  free(config);
}

void config_send(int file_descriptor, Config *config) {
  send_str(file_descriptor, config->version);
  send_str(file_descriptor, config->send_directory);
  send_str(file_descriptor, config->receive_root_directory);
  send_int(file_descriptor, config->save_to_disk);
  send_int(file_descriptor, config->use_multithreading);
  send_int(file_descriptor, config->use_chunk_serialization);
  send_int(file_descriptor, config->use_compression);
  send_int(file_descriptor, config->use_metadata);
  send_int(file_descriptor, config->compression_level);
  send_int(file_descriptor, (int)config->chunk_size);
  send_int(file_descriptor, config->use_sendfile);
  send_int(file_descriptor, config->use_delete);
  if (receive_status(file_descriptor) != STATUS_OK) {
    perror("Error transmitting config!");
    exit(EXIT_FAILURE);
  }
}

Config *config_receive(int file_descriptor) {
  Config *config = (Config *)malloc(sizeof(Config));
  config->version = receive_str(file_descriptor);
  config->send_directory = receive_str(file_descriptor);
  config->receive_root_directory = receive_str(file_descriptor);
  config->save_to_disk = receive_int(file_descriptor);
  config->use_multithreading = receive_int(file_descriptor);
  config->use_chunk_serialization = receive_int(file_descriptor);
  config->use_compression = receive_int(file_descriptor);
  config->use_metadata = receive_int(file_descriptor);
  config->compression_level = receive_int(file_descriptor);
  config->chunk_size = (unsigned long long)receive_int(file_descriptor);
  config->use_sendfile = receive_int(file_descriptor);
  config->use_delete = receive_int(file_descriptor);
  config->show_progress = false;
  config->dry_run = false;
  config->ssh_port = 22;
  config->transport = TRANSPORT_TCP;
  config->ssh_destination = NULL;
  config->exclude_patterns = NULL;
  config->exclude_count = 0;
  send_status(file_descriptor, STATUS_OK);
  return config;
}
