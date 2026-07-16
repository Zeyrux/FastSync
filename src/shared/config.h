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
  bool show_progress;
  bool dry_run;
  bool use_delete;
  int compression_level;
  unsigned long long chunk_size;
  int ssh_port;
  TransportType transport;
  char *ssh_destination;
  char **exclude_patterns;
  int exclude_count;
} Config;

#define PROTOCOL_VERSION "1.0.0"
#define DEFAULT_CHUNK_SIZE (10 * 1024 * 1024)

Config *config_create(char *version, char *send_directory,
                      char *receive_directory, bool save_to_disk,
                      bool use_multithreading, bool use_chunk_serialization,
                       bool use_compression, bool use_metadata,
                       int compression_level, bool use_sendfile,
                       unsigned long long chunk_size);
void config_delete(Config *config);
void config_send(int file_descriptor, Config *config);
Config *config_receive(int file_descriptor);
bool is_remote_dest(const char *s);
void config_parse_ssh_dest(Config *config);

#endif
