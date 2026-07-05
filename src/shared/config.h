#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

typedef struct Config {
  char *version;
  char *send_directory;
  char *receive_root_directory;
  bool save_to_disk;
  bool use_multithreading;
  bool use_chunk_serialization;
  bool use_compression;
  bool use_sendfile;
  bool use_single_send_per_file;
  int compression_level;
  int num_connections;
} Config;

Config *config_create(char *version, char *send_directory,
                      char *receive_directory, bool save_to_disk,
                      bool use_multithreading, bool use_chunk_serialization,
                      bool use_compression, int compression_level,
                      int num_connections, bool use_sendfile);
void config_delete(Config *config);
void config_send(int file_descriptor, Config *config);
Config *config_receive(int file_descriptor);

#endif
