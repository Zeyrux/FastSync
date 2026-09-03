#ifndef CONFIG_H
#define CONFIG_H

#include "array_list.h"
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
  bool size_only;
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
  bool quiet;
  bool backup;
  char* backup_dir;
  bool stats;
  int max_depth;
  FILE* log_file;
  int queue_size;
  bool follow_symlinks;
  bool partial;

  // Issue #120: Symlink handling
  bool copy_links;
  bool safe_links;
  bool copy_unsafe_links;

  // Issue #121: Extended metadata preservation
  bool preserve_hard_links;
  bool preserve_acls;
  bool preserve_xattrs;
  bool preserve_devices;
  bool preserve_sparse;

  // Issue #122: Output/logging options
  bool itemize_changes;
  char* out_format;
  int info_level;
  int debug_level;
  bool list_only;
  bool human_readable;

  // Issue #127: Transfer modes
  bool update;
  bool inplace;
  bool append;
  bool append_verify;

  // Issue #128: Extended delete options
  bool delete_excluded;
  bool delete_after;
  int max_delete;

  // Issue #129: Advanced file selection
  ArrayList* filters;
  char* files_from;
  bool cvs_exclude;
  bool prune_empty_dirs;
  bool relative;

  // Issue #130: Remote shell/connection options
  char* rsh_command;
  char* rsync_path;
  char* temp_dir;
  char* compare_dest;
  char* copy_dest;
  char* link_dest;

  // PR #174: Partial transfer resumption
  char* partial_dir;

  // PR #178: Backup versioning
  char* suffix;

  // PR #179: Delete policies
  bool delete_before;

  // PR #181: IPv6 and bind address
  char* address;
  char* bind_address;
  bool ipv6;
  bool ipv4;

  // PR #182: Daemon/server mode
  bool daemon;
  char* daemon_config;
  bool server_mode;

  // PR #183: Checksum comparison
  bool checksum;

  // PR #184: Compression algorithm negotiation
  char* compress_choice;
} Config;

#define PROTOCOL_VERSION "2.3.0"
#define DEFAULT_CHUNK_SIZE (10 * 1024 * 1024)

Config* config_create(void);
void config_delete(Config* config);
bool config_send(int file_descriptor, const Config* config);
Config* config_receive(int file_descriptor);
bool config_is_remote_dest(const char* s);
void config_parse_ssh_dest(Config* config);

#endif
