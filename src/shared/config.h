#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

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
  char* fastsync_server_path;
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
  int timeout;
  int contimeout;
  bool backup;
  char* backup_dir;
  bool stats;
  int max_depth;
  FILE* log_file;
  bool follow_symlinks;
  bool partial;

  // Issue #120: Symlink handling
  bool copy_links;
  bool safe_links;
  bool copy_unsafe_links;

  bool preserve_sparse;

  bool inplace;

  // PR #174: Partial transfer resumption
  char* partial_dir;

  // PR #178: Backup versioning
  char* suffix;

} Config;

/* This version must be bumped whenever config_send / config_receive wire format changes. */
#define PROTOCOL_VERSION "2.1.0"
#define DEFAULT_CHUNK_SIZE (10 * 1024 * 1024)

Config* config_create(void);
void config_delete(Config* config);
bool config_send(int file_descriptor, const Config* config);
Config* config_receive(int file_descriptor);
bool is_remote_dest(const char* s);
void config_parse_ssh_dest(Config* config);

#endif
