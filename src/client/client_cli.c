#include "client_send.h"
#include "config.h"
#include "delta.h"
#include "log.h"
#include "protocol.h"
#include "transport_tls.h"
#include "utils.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  printf("  --incremental       Skip files unchanged since last transfer\n");
  printf("  --delta             Delta transfer for changed files (requires --incremental)\n");
  printf("  --delta-block <n>   Delta block size in bytes (default: %d)\n",
         DELTA_BLOCK_SIZE_DEFAULT);
  printf("  --delta-max <n>     Max file size for delta transfer (default: %llu)\n",
         DELTA_MAX_FILE_SIZE);
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
  printf("  --tls               Enable TLS encryption\n");
  printf("  --cert <path>       TLS certificate file (PEM)\n");
  printf("  --key <path>        TLS private key file (PEM)\n");
  printf("  --ca <path>         TLS CA certificate file (PEM)\n");
  printf("  --help              Show this help\n");
}

int main(int argc, char* argv[]) {
  const char* env_source = getenv("FASTSYNC_SOURCE_DIR");
  const char* env_dest = getenv("FASTSYNC_DEST_DIR");
  const char* env_save = getenv("FASTSYNC_SAVE_TO_DISK");

  bool save_to_disk = false;
  if (env_save && (strcmp(env_save, "true") == 0 || strcmp(env_save, "1") == 0)) {
    save_to_disk = true;
  }

  Config* config = config_create(str_dup(PROTOCOL_VERSION), NULL, NULL, save_to_disk, false, false,
                                 false, false, 5, false, 0);
  int exit_code = 0;
  bool config_owned_by_pipeline = false;

  int positional_args[2];
  int positional_count = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      print_usage();
      goto cleanup;
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
      char** tmp = realloc(config->exclude_patterns, (config->exclude_count + 1) * sizeof(char*));
      if (!tmp) {
        fprintf(stderr, "Error: memory allocation failed for --exclude\n");
        exit_code = 1;
        goto cleanup;
      }
      config->exclude_patterns = tmp;
      config->exclude_patterns[config->exclude_count++] = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--include") == 0 && i + 1 < argc) {
      char** tmp = realloc(config->include_patterns, (config->include_count + 1) * sizeof(char*));
      if (!tmp) {
        fprintf(stderr, "Error: memory allocation failed for --include\n");
        exit_code = 1;
        goto cleanup;
      }
      config->include_patterns = tmp;
      config->include_patterns[config->include_count++] = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--max-size") == 0 && i + 1 < argc) {
      config->max_size = strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--min-size") == 0 && i + 1 < argc) {
      config->min_size = strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--incremental") == 0) {
      config->use_incremental = true;
    } else if (strcmp(argv[i], "--delta") == 0) {
      config->use_delta = true;
    } else if (strcmp(argv[i], "--delta-block") == 0 && i + 1 < argc) {
      unsigned long long val = strtoull(argv[++i], NULL, 10);
      if (val >= DELTA_BLOCK_SIZE_MIN && val <= DELTA_BLOCK_SIZE_MAX)
        config->delta_block_size = (uint32_t)val;
      else
        fprintf(stderr, "Warning: --delta-block value %llu out of range, using default\n", val);
    } else if (strcmp(argv[i], "--delta-max") == 0 && i + 1 < argc) {
      unsigned long long val = strtoull(argv[++i], NULL, 10);
      if (val >= DELTA_MIN_FILE_SIZE)
        config->delta_max_file_size = val;
      else
        fprintf(stderr, "Warning: --delta-max value %llu too small, using default\n", val);
    } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-z") == 0) {
      config->use_compression = true;
      log_message(LOG_LEVEL_INFO, "Enabled Compression");
      if (i + 1 < argc) {
        char* end_ptr;
        int level = strtol(argv[i + 1], &end_ptr, 10);
        if (*end_ptr == '\0') {
          config->compression_level = level;
          log_message(LOG_LEVEL_INFO, "Set Compression level to %d", config->compression_level);
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
      free(config->server_host);
      config->server_host = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--server-port") == 0 && i + 1 < argc) {
      config->server_port = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--bwlimit") == 0 && i + 1 < argc) {
      char* end;
      errno = 0;
      unsigned long long kbps = strtoull(argv[++i], &end, 10);
      if (errno != 0 || *end != '\0' || kbps == 0) {
        fprintf(stderr, "Error: --bwlimit must be a positive integer\n");
        exit_code = 1;
        goto cleanup;
      }
      if (kbps > ULLONG_MAX / 1024) {
        fprintf(stderr, "Error: --bwlimit value too large\n");
        exit_code = 1;
        goto cleanup;
      }
      io_set_bwlimit(kbps * 1024);
      log_message(LOG_LEVEL_INFO, "Set bandwidth limit to %llu KB/s", kbps);
    } else if (strcmp(argv[i], "--progress") == 0) {
      config->show_progress = true;
    } else if (strcmp(argv[i], "--chunk-size") == 0 && i + 1 < argc) {
      unsigned long long val = strtoull(argv[++i], NULL, 10);
      if (val > 0)
        config->chunk_size = val;
    } else if (strcmp(argv[i], "--tls") == 0) {
      config->use_tls = true;
    } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      free(config->tls_cert);
      config->tls_cert = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      free(config->tls_key);
      config->tls_key = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
      free(config->tls_ca);
      config->tls_ca = str_dup(argv[++i]);
    } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
      set_log_level(LOG_LEVEL_DEBUG);
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_usage();
      exit_code = 1;
      goto cleanup;
    } else {
      if (positional_count < 2)
        positional_args[positional_count++] = i;
      else {
        fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
        print_usage();
        exit_code = 1;
        goto cleanup;
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
    exit_code = 1;
    goto cleanup;
  } else {
    if (!config->send_directory && env_source)
      config->send_directory = str_dup((char*)env_source);
    if (!config->receive_root_directory && env_dest)
      config->receive_root_directory = str_dup((char*)env_dest);
  }

  if (!config->send_directory || !config->receive_root_directory) {
    fprintf(stderr, "Error: source and destination directories are required\n");
    print_usage();
    exit_code = 1;
    goto cleanup;
  }
  if (config->use_sendfile && (config->use_chunk_serialization || config->use_compression)) {
    fprintf(stderr, "Error: -f/--sendfile cannot be combined with -c (compression) or -s (chunk "
                    "serialization)\n");
    exit_code = 1;
    goto cleanup;
  }

  if (config->transport == TRANSPORT_SSH && config->use_sendfile) {
    fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
    exit_code = 1;
    goto cleanup;
  }

  if (config->use_incremental && config->use_chunk_serialization) {
    fprintf(stderr, "Error: --incremental is not supported with -s (chunk serialization)\n");
    exit_code = 1;
    goto cleanup;
  }

  if (config->use_incremental && !config->use_metadata) {
    log_message(LOG_LEVEL_INFO, "Enabling metadata preservation for --incremental");
    config->use_metadata = true;
  }

  if (config->use_delta && !config->use_incremental) {
    fprintf(stderr, "Error: --delta requires --incremental\n");
    exit_code = 1;
    goto cleanup;
  }
  if (config->use_delta && config->use_chunk_serialization) {
    fprintf(stderr, "Error: --delta cannot be combined with -s (chunk serialization)\n");
    exit_code = 1;
    goto cleanup;
  }
  if (config->use_delta && config->use_sendfile) {
    fprintf(stderr, "Error: --delta cannot be combined with -f (sendfile)\n");
    exit_code = 1;
    goto cleanup;
  }
  if (config->use_delta && !config->use_metadata) {
    log_message(LOG_LEVEL_INFO, "Enabling metadata preservation for --delta");
    config->use_metadata = true;
  }

  if (config->use_tls) {
    if (!config->tls_cert || !config->tls_key) {
      fprintf(stderr, "Error: --tls requires --cert and --key\n");
      exit_code = 1;
      goto cleanup;
    }
    tls_global_init();
  }

  if (config->use_multithreading) {
    config_owned_by_pipeline = true;
    exit_code = send_files_multithreaded(config);
  } else {
    exit_code = send_files(config);
  }

cleanup:
  if (!config_owned_by_pipeline)
    config_delete(config);
  return exit_code;
}
