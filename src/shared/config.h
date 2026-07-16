#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

typedef enum {
  TRANSPORT_TCP,
  TRANSPORT_SSH
} TransportType;

typedef struct Config {
  char *version;
  char *send_directory;
  char *receive_root_directory;
  bool save_to_disk;
  bool use_multithreading;
  bool use_chunk_serialization;
  bool use_compression;
  bool use_sendfile;
  bool use_metadata;
  int compression_level;
  int num_connections;
  TransportType transport;
  char *ssh_destination;
} Config;

Config *config_create(char *version, char *send_directory,
                      char *receive_directory, bool save_to_disk,
                      bool use_multithreading, bool use_chunk_serialization,
                       bool use_compression, bool use_metadata,
                       int compression_level, int num_connections, bool use_sendfile);
void config_delete(Config *config);
void config_send(int file_descriptor, Config *config);
Config *config_receive(int file_descriptor);
bool is_remote_dest(const char *s);
void config_parse_ssh_dest(Config *config);

#endif
