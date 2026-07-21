#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stdint.h>

typedef enum { TRANSPORT_TCP, TRANSPORT_SSH } TransportType;

typedef struct Config {
  char* version;
  char* send_directory;
  char* receive_root_directory;
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
  char* ssh_destination;
  char** exclude_patterns;
  int exclude_count;
  char** include_patterns;
  int include_count;
  unsigned long long max_size;
  unsigned long long min_size;
  bool use_incremental;
  bool use_delta;
  uint32_t delta_block_size;
  unsigned long long delta_max_file_size;
  bool use_tls;
  char* server_host;
  int server_port;
  char* tls_cert;
  char* tls_key;
  char* tls_ca;
  bool follow_symlinks;
  bool partial;
} Config;

#define PROTOCOL_VERSION "1.3.0"
#define DEFAULT_CHUNK_SIZE (10 * 1024 * 1024)

Config* config_create(char* version, char* send_directory, char* receive_directory,
                      bool save_to_disk, bool use_multithreading, bool use_chunk_serialization,
                      bool use_compression, bool use_metadata, int compression_level,
                      bool use_sendfile, unsigned long long chunk_size);
void config_delete(Config* config);
bool config_send(int file_descriptor, const Config* config);
Config* config_receive(int file_descriptor);
bool is_remote_dest(const char* s);
void config_parse_ssh_dest(Config* config);

#endif
