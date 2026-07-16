#include "client_send.h"
#include "config.h"
#include "log.h"
#include "protocol.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *server_host = "127.0.0.1";
int server_port = 8080;

static void print_usage(void) {
  printf("Usage:\n");
  printf("  fastsync [options] <source> <destination>\n");
  printf("  fastsync [options] --source-dir <src> --dest-dir <dst>\n");
  printf("\n");
  printf("Destination formats:\n");
  printf("  user@host:/path     SSH transport (rsync-style)\n");
  printf("  host:/path          SSH transport (current user)\n");
  printf("  /local/path         TCP transport (requires server on localhost:8080)\n");
  printf("\n");
  printf("Options:\n");
  printf("  -c [level]          Enable compression (level 1-22, default 5)\n");
  printf("  -z [level]          Alias for -c\n");
  printf("  -a, --archive       Archive mode (-c -m -M)\n");
  printf("  -n, --dry-run       Show what would be transferred\n");
  printf("  -p <port>           SSH port (default: 22)\n");
  printf("  --progress          Show transfer progress\n");
  printf("  --delete            Delete files on receiver not in source\n");
  printf("  --exclude <pattern> Exclude files matching pattern\n");
  printf("  --include <pattern> Only include files matching pattern\n");
  printf("  --max-size <n>      Skip files larger than n bytes\n");
  printf("  --min-size <n>      Skip files smaller than n bytes\n");
  printf("  -m                  Enable multithreading\n");
  printf("  -s                  Enable chunk serialization\n");
  printf("  -f                  Enable sendfile (TCP only, not with -c or -s)\n");
  printf("  -v, --verbose       Enable debug logging\n");
  printf("  -M, --preserve      Preserve file metadata\n");
  printf("  --chunk-size <n>    Chunk size in bytes (default: %d)\n", DEFAULT_CHUNK_SIZE);
  printf("  --source-dir <path> Source directory\n");
  printf("  --dest-dir <path>   Destination directory\n");
  printf("  --save-to-disk      Write received files to disk\n");
  printf("  --server-host <ip>  Server IP address (default: 127.0.0.1)\n");
  printf("  --server-port <n>   Server port (default: 8080)\n");
  printf("  --bwlimit <KB/s>    Bandwidth limit in kilobytes per second\n");
  printf("  --help              Show this help\n");
}

int main(int argc, char *argv[]) {
  const char *env_source = getenv("FASTSYNC_SOURCE_DIR");
  const char *env_dest = getenv("FASTSYNC_DEST_DIR");
  const char *env_save = getenv("FASTSYNC_SAVE_TO_DISK");

  bool save_to_disk = false;
  if (env_save &&
      (strcmp(env_save, "true") == 0 || strcmp(env_save, "1") == 0)) {
    save_to_disk = true;
  }

  Config *config = config_create(str_dup(PROTOCOL_VERSION), NULL, NULL,
                                 save_to_disk, false, false, false, false, 5, false, 0);

  int positional_args[2];
  int positional_count = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      print_usage();
      return 0;
    } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--archive") == 0) {
      config->use_compression = true;
      config->use_multithreading = true;
      config->use_metadata = true;
      log_message(LOG_LEVEL_INFO, "Enabled archive mode (-c -m -M)");
    } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0) {
      config->dry_run = true;
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      config->ssh_port = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--delete") == 0) {
      config->use_delete = true;
    } else if (strcmp(argv[i], "--exclude") == 0 && i + 1 < argc) {
      int idx = config->exclude_count++;
      config->exclude_patterns = realloc(config->exclude_patterns, config->exclude_count * sizeof(char *));
      config->exclude_patterns[idx] = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--include") == 0 && i + 1 < argc) {
      int idx = config->include_count++;
      config->include_patterns = realloc(config->include_patterns, config->include_count * sizeof(char *));
      config->include_patterns[idx] = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--max-size") == 0 && i + 1 < argc) {
      config->max_size = strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--min-size") == 0 && i + 1 < argc) {
      config->min_size = strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-z") == 0) {
      config->use_compression = true;
      log_message(LOG_LEVEL_INFO, "Enabled Compression");
      if (i + 1 < argc) {
        char *end_ptr;
        int level = strtol(argv[i + 1], &end_ptr, 10);
        if (*end_ptr == '\0') {
          config->compression_level = level;
          log_message(LOG_LEVEL_INFO, "Set Compression level to %d",
                      config->compression_level);
          i++;
        }
      }
    } else if (strcmp(argv[i], "--source-dir") == 0 && i + 1 < argc) {
      free(config->send_directory);
      config->send_directory = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--dest-dir") == 0 && i + 1 < argc) {
      free(config->receive_root_directory);
      config->receive_root_directory = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--save-to-disk") == 0) {
      config->save_to_disk = true;
    } else if (strcmp(argv[i], "-M") == 0 || strcmp(argv[i], "--preserve") == 0) {
      config->use_metadata = true;
      log_message(LOG_LEVEL_INFO, "Enabled metadata preservation");
    } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--sendfile") == 0) {
      config->use_sendfile = true;
      log_message(LOG_LEVEL_INFO, "Enabled sendfile");
    } else if (strcmp(argv[i], "-m") == 0) {
      config->use_multithreading = true;
      log_message(LOG_LEVEL_INFO, "Enabled Multithreading");
    } else if (strcmp(argv[i], "-s") == 0) {
      config->use_chunk_serialization = true;
      log_message(LOG_LEVEL_INFO, "Enabled Chunk Serialization");
    } else if (strcmp(argv[i], "--server-host") == 0 && i + 1 < argc) {
      free(server_host);
      server_host = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--server-port") == 0 && i + 1 < argc) {
      server_port = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--bwlimit") == 0 && i + 1 < argc) {
      unsigned long long kbps = strtoull(argv[++i], NULL, 10);
      io_set_bwlimit(kbps * 1024);
      log_message(LOG_LEVEL_INFO, "Set bandwidth limit to %llu KB/s", kbps);
    } else if (strcmp(argv[i], "--progress") == 0) {
      config->show_progress = true;
    } else if (strcmp(argv[i], "--chunk-size") == 0 && i + 1 < argc) {
      unsigned long long val = strtoull(argv[++i], NULL, 10);
      if (val > 0)
        config->chunk_size = val;
    } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
      set_log_level(LOG_LEVEL_DEBUG);
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_usage();
      return 1;
    } else {
      if (positional_count < 2)
        positional_args[positional_count++] = i;
      else {
        fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
        print_usage();
        return 1;
      }
    }
  }

  if (positional_count == 2) {
    free(config->send_directory);
    free(config->receive_root_directory);
    config->send_directory = str_dup(argv[positional_args[0]]);
    config->receive_root_directory = str_dup(argv[positional_args[1]]);
    config->save_to_disk = true;

    config_parse_ssh_dest(config);
  } else if (positional_count == 1) {
    fprintf(stderr, "Error: missing destination argument\n");
    print_usage();
    return 1;
  } else {
    if (!config->send_directory && env_source)
      config->send_directory = str_dup((char *)env_source);
    if (!config->receive_root_directory && env_dest)
      config->receive_root_directory = str_dup((char *)env_dest);
  }

  if (!config->send_directory || !config->receive_root_directory) {
    fprintf(stderr, "Error: source and destination directories are required\n");
    print_usage();
    return 1;
  }
  if (config->use_sendfile && (config->use_chunk_serialization || config->use_compression)) {
    fprintf(stderr, "Error: -f/--sendfile cannot be combined with -c (compression) or -s (chunk serialization)\n");
    return 1;
  }

  if (config->transport == TRANSPORT_SSH && config->use_sendfile) {
    fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
    return 1;
  }

  if (config->use_multithreading)
    return send_files_multithreaded(config);
  return send_files(config);
}
