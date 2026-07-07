#include "config.h"
#include "socket.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

Config *config_create(char *version, char *send_directory,
                      char *receive_directory, bool save_to_disk,
                      bool use_multithreading, bool use_chunk_serialization,
                       bool use_compression, bool use_metadata,
                       int compression_level, int num_connections, bool use_sendfile) {

  Config *config = malloc(sizeof(Config));
  config->version = version;
  config->send_directory = send_directory;
  config->receive_root_directory = receive_directory;
  config->save_to_disk = save_to_disk;
  config->use_multithreading = use_multithreading;
  config->use_chunk_serialization = use_chunk_serialization;
  config->use_compression = use_compression;
  config->use_metadata = use_metadata;
  config->compression_level = compression_level;
  config->num_connections = num_connections;
  config->use_sendfile = use_sendfile;
  config->transport = TRANSPORT_TCP;
  config->ssh_destination = NULL;
  return config;
}

void config_delete(Config *config) {
  free(config->version);
  free(config->send_directory);
  free(config->receive_root_directory);
  free(config->ssh_destination);
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
  send_int(file_descriptor, config->num_connections);
  send_int(file_descriptor, config->use_sendfile);
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
  config->num_connections = receive_int(file_descriptor);
  config->use_sendfile = receive_int(file_descriptor);
  config->transport = TRANSPORT_TCP;
  config->ssh_destination = NULL;
  send_status(file_descriptor, STATUS_OK);
  return config;
}
