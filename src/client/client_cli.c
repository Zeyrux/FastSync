#include "client_send.h"
#include "config.h"
#include "delta.h"
#include "log.h"
#include "protocol.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include "utils.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "usage.c"

#ifndef FASTSYNC_TEST_BUILD
/* Parse environment variables for source/destination directories and save-to-disk flag. */
static void parse_environment(const char** out_env_source, const char** out_env_dest,
                              bool* out_save_to_disk) {
  *out_env_source = getenv("FASTSYNC_SOURCE_DIR");
  *out_env_dest = getenv("FASTSYNC_DEST_DIR");
  const char* env_save = getenv("FASTSYNC_SAVE_TO_DISK");
  *out_save_to_disk = false;
  if (env_save && (strcmp(env_save, "true") == 0 || strcmp(env_save, "1") == 0))
    *out_save_to_disk = true;
}
#endif

/* Parse a string as a non-negative integer, returning true on success. */
static bool parse_nonneg_int(const char* s, int* out_val) {
  if (!s || *s == '\0')
    return false;
  char* endptr;
  errno = 0;
  long val = strtol(s, &endptr, 10);
  if (errno != 0 || *endptr != '\0' || val < 0 || val > INT_MAX)
    return false;
  *out_val = (int)val;
  return true;
}

/* Parse a string as a positive integer, returning true on success. */
static bool parse_positive_int(const char* s, int* out_val) {
  int temp;
  if (!parse_nonneg_int(s, &temp)) {
    return false;
  }
  if (temp == 0) {
    return false;
  }
  *out_val = temp;
  return true;
}

/* Duplicate a string argument into *dest, freeing the old value. Returns true on success, false on
 * failure. */
static int set_string_option(char** dest, const char* value, const char* option_name) {
  char* dup = str_dup(value);
  if (!dup) {
    fprintf(stderr, "Error: memory allocation failed for %s\n", option_name);
    return -1;
  }
  free(*dest);
  *dest = dup;
  return 0;
}

/* Parse a string as a positive integer into *dest. Returns true on success, false on error. */
static int set_positive_int_option(int* dest, const char* value, const char* option_name) {
  if (!parse_positive_int(value, dest)) {
    fprintf(stderr, "Error: %s must be a positive integer\n", option_name);
    return -1;
  }
  return 0;
}

/* Parse a string as a non-negative integer into *dest. Returns true on success, false on error. */
static int set_nonneg_int_option(int* dest, const char* value, const char* option_name) {
  if (!parse_nonneg_int(value, dest)) {
    fprintf(stderr, "Error: %s must be a non-negative integer\n", option_name);
    return -1;
  }
  return 0;
}

static int read_patterns_from_file(const char* filepath, char*** patterns, int* count);

/* Parse CLI arguments into config. Returns 0 on success, -1 on error, 1 for help/clean-exit. */
int parse_args(Config* config, int argc, char* argv[], int* positional_args,
               int* positional_count) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      print_usage();
      return 1;
    } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
      printf("fastsync version %s\n", PROTOCOL_VERSION);
      return 1;
    } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--archive") == 0) {
      config->use_compression = true;
      config->use_multithreading = true;
      config->use_metadata = true;
      log_message(LOG_LEVEL_INFO, "Enabled archive mode (-c -m -M)");
    } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0) {
      config->dry_run = true;
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      if (set_positive_int_option(&config->ssh_port, argv[++i], "-p") != 0)
        return -1;
      if (config->ssh_port > 65535) {
        log_message(LOG_LEVEL_ERROR, "SSH port must be 1-65535\n");
        return -1;
      }
    } else if (strcmp(argv[i], "--delete") == 0) {
      config->use_delete = true;
    } else if (strcmp(argv[i], "--exclude") == 0 && i + 1 < argc) {
      char** tmp = realloc(config->exclude_patterns, (config->exclude_count + 1) * sizeof(char*));
      if (!tmp) {
        fprintf(stderr, "Error: memory allocation failed for --exclude\n");
        return -1;
      }
      config->exclude_patterns = tmp;
      char* dup = str_dup(argv[++i]);
      if (!dup) {
        fprintf(stderr, "Error: memory allocation failed for --exclude\n");
        return -1;
      }
      config->exclude_patterns[config->exclude_count++] = dup;
    } else if (strcmp(argv[i], "--include") == 0 && i + 1 < argc) {
      char** tmp = realloc(config->include_patterns, (config->include_count + 1) * sizeof(char*));
      if (!tmp) {
        fprintf(stderr, "Error: memory allocation failed for --include\n");
        return -1;
      }
      config->include_patterns = tmp;
      char* dup = str_dup(argv[++i]);
      if (!dup) {
        fprintf(stderr, "Error: memory allocation failed for --include\n");
        return -1;
      }
      config->include_patterns[config->include_count++] = dup;
    } else if (strcmp(argv[i], "--max-size") == 0 && i + 1 < argc) {
      char* end;
      errno = 0;
      unsigned long long val = strtoull(argv[++i], &end, 10);
      if (errno != 0 || *end != '\0') {
        fprintf(stderr, "Error: --max-size must be a non-negative integer\n");
        return -1;
      }
      config->max_size = val;
    } else if (strcmp(argv[i], "--min-size") == 0 && i + 1 < argc) {
      char* end;
      errno = 0;
      unsigned long long val = strtoull(argv[++i], &end, 10);
      if (errno != 0 || *end != '\0') {
        fprintf(stderr, "Error: --min-size must be a non-negative integer\n");
        return -1;
      }
      config->min_size = val;
    } else if (strcmp(argv[i], "--incremental") == 0) {
      config->use_incremental = true;
    } else if (strcmp(argv[i], "--delta") == 0) {
      config->use_delta = true;
    } else if (strcmp(argv[i], "--delta-block") == 0 && i + 1 < argc) {
      char* end;
      errno = 0;
      unsigned long long val = strtoull(argv[++i], &end, 10);
      if (errno != 0 || *end != '\0') {
        fprintf(stderr, "Error: --delta-block must be a positive integer\n");
        return -1;
      }
      if (val >= DELTA_BLOCK_SIZE_MIN && val <= DELTA_BLOCK_SIZE_MAX)
        config->delta_block_size = (uint32_t)val;
      else
        fprintf(stderr, "Warning: --delta-block value %llu out of range, using default\n", val);
    } else if (strcmp(argv[i], "--delta-max") == 0 && i + 1 < argc) {
      char* end;
      errno = 0;
      unsigned long long val = strtoull(argv[++i], &end, 10);
      if (errno != 0 || *end != '\0') {
        fprintf(stderr, "Error: --delta-max must be a positive integer\n");
        return -1;
      }
      if (val >= DELTA_MIN_FILE_SIZE)
        config->delta_max_file_size = val;
      else
        fprintf(stderr, "Warning: --delta-max value %llu too small, using default\n", val);
    } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-z") == 0) {
      config->use_compression = true;
      log_message(LOG_LEVEL_INFO, "Enabled Compression");
      if (i + 1 < argc) {
        char* end_ptr;
        long level = strtol(argv[i + 1], &end_ptr, 10);
        if (*end_ptr == '\0') {
          if (level < 1 || level > 22) {
            fprintf(stderr, "Error: compression level must be 1-22\n");
            return -1;
          }
          config->compression_level = (int)level;
          log_message(LOG_LEVEL_INFO, "Set Compression level to %ld", level);
          i++;
        }
      }
    } else if (strcmp(argv[i], "--source-dir") == 0 && i + 1 < argc) {
      if (set_string_option(&config->send_directory, argv[++i], "--source-dir") != 0)
        return -1;
    } else if (strcmp(argv[i], "--dest-dir") == 0 && i + 1 < argc) {
      if (set_string_option(&config->receive_root_directory, argv[++i], "--dest-dir") != 0)
        return -1;
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
      if (set_string_option(&config->server_host, argv[++i], "--server-host") != 0)
        return -1;
    } else if (strcmp(argv[i], "--server-port") == 0 && i + 1 < argc) {
      if (!parse_positive_int(argv[++i], &config->server_port)) {
        fprintf(stderr, "Error: invalid --server-port value: %s\n", argv[i]);
        return -1;
      }
      if (config->server_port > 65535) {
        fprintf(stderr, "Error: server port must be 1-65535\n");
        return -1;
      }
    } else if (strcmp(argv[i], "--bwlimit") == 0 && i + 1 < argc) {
      char* end;
      errno = 0;
      unsigned long long kbps = strtoull(argv[++i], &end, 10);
      if (errno != 0 || *end != '\0' || kbps == 0) {
        fprintf(stderr, "Error: --bwlimit must be a positive integer\n");
        return -1;
      }
      if (kbps > ULLONG_MAX / 1024) {
        fprintf(stderr, "Error: --bwlimit value too large\n");
        return -1;
      }
      io_set_bwlimit(kbps * 1024);
      log_message(LOG_LEVEL_INFO, "Set bandwidth limit to %llu KB/s", kbps);
    } else if (strcmp(argv[i], "--progress") == 0) {
      config->show_progress = true;
    } else if (strcmp(argv[i], "--chunk-size") == 0 && i + 1 < argc) {
      char* end;
      errno = 0;
      unsigned long long val = strtoull(argv[++i], &end, 10);
      if (errno != 0 || *end != '\0' || val == 0) {
        fprintf(stderr, "Error: --chunk-size must be a positive integer\n");
        return -1;
      }
      config->chunk_size = val;
    } else if (strcmp(argv[i], "--tls") == 0) {
      config->use_tls = true;
    } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      if (set_string_option(&config->tls_cert, argv[++i], "--cert") != 0)
        return -1;
    } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      if (set_string_option(&config->tls_key, argv[++i], "--key") != 0)
        return -1;
    } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
      if (set_string_option(&config->tls_ca, argv[++i], "--ca") != 0)
        return -1;
    } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
      if (set_positive_int_option(&config->timeout, argv[++i], "--timeout") != 0)
        return -1;
    } else if (strcmp(argv[i], "--contimeout") == 0 && i + 1 < argc) {
      if (set_positive_int_option(&config->contimeout, argv[++i], "--contimeout") != 0)
        return -1;
    } else if (strcmp(argv[i], "--backup") == 0) {
      config->backup = true;
    } else if (strcmp(argv[i], "--backup-dir") == 0 && i + 1 < argc) {
      if (set_string_option(&config->backup_dir, argv[++i], "--backup-dir") != 0)
        return -1;
    } else if (strcmp(argv[i], "--stats") == 0) {
      config->stats = true;
    } else if (strcmp(argv[i], "--max-depth") == 0 && i + 1 < argc) {
      if (set_nonneg_int_option(&config->max_depth, argv[++i], "--max-depth") != 0)
        return -1;
    } else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc) {
      if (config->log_file) {
        fclose(config->log_file);
        config->log_file = NULL;
        log_set_file(NULL);
      }
      FILE* lf = fopen(argv[++i], "a");
      if (!lf) {
        fprintf(stderr, "Error: could not open log file '%s': %s\n", argv[i], strerror(errno));
        return -1;
      }
      config->log_file = lf;
      log_set_file(lf);
    } else if (strcmp(argv[i], "--exclude-from") == 0 && i + 1 < argc) {
      if (read_patterns_from_file(argv[++i], &config->exclude_patterns, &config->exclude_count) !=
          0)
        return -1;
    } else if (strcmp(argv[i], "--include-from") == 0 && i + 1 < argc) {
      if (read_patterns_from_file(argv[++i], &config->include_patterns, &config->include_count) !=
          0)
        return -1;
    } else if (strcmp(argv[i], "--partial") == 0) {
      config->partial = true;
    } else if (strcmp(argv[i], "--fastsync-server-path") == 0 && i + 1 < argc) {
      if (set_string_option(&config->fastsync_server_path, argv[++i], "--fastsync-server-path") !=
          0)
        return -1;
    } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
      set_log_level(LOG_LEVEL_DEBUG);
    } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--links") == 0) {
      config->follow_symlinks = true;
    } else if (strcmp(argv[i], "--copy-links") == 0) {
      config->copy_links = true;
    } else if (strcmp(argv[i], "--safe-links") == 0) {
      config->safe_links = true;
    } else if (strcmp(argv[i], "--copy-unsafe-links") == 0) {
      config->copy_unsafe_links = true;
    } else if (strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "--sparse") == 0) {
      config->preserve_sparse = true;
    } else if (strcmp(argv[i], "--inplace") == 0) {
      config->inplace = true;
    } else if (strcmp(argv[i], "--partial-dir") == 0 && i + 1 < argc) {
      if (set_string_option(&config->partial_dir, argv[++i], "--partial-dir") != 0)
        return -1;
    } else if (strcmp(argv[i], "--suffix") == 0 && i + 1 < argc) {
      if (set_string_option(&config->suffix, argv[++i], "--suffix") != 0)
        return -1;
    } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
      if (set_positive_int_option(&config->timeout, argv[++i], "-T") != 0)
        return -1;
    } else if (strcmp(argv[i], "--checksum") == 0) {
      config->checksum = true;
    } else if (strcmp(argv[i], "--compress-level") == 0 && i + 1 < argc) {
      if (set_positive_int_option(&config->compression_level, argv[++i], "--compress-level") != 0)
        return -1;
      if (config->compression_level < 1 || config->compression_level > 22) {
        fprintf(stderr, "Error: --compress-level must be between 1 and 22\n");
        return -1;
      }
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_usage();
      return -1;
    } else {
      if (*positional_count < 2)
        positional_args[(*positional_count)++] = i;
      else {
        fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
        print_usage();
        return -1;
      }
    }
  }
  return 0;
}

#ifndef FASTSYNC_TEST_BUILD
/* Validate config after parsing. Returns true if valid. */
static bool validate_config(const Config* config) {
  if (!config->send_directory || !config->receive_root_directory) {
    fprintf(stderr, "Error: source and destination directories are required\n");
    print_usage();
    return false;
  }
  if (config->use_sendfile && (config->use_chunk_serialization || config->use_compression)) {
    fprintf(stderr, "Error: -f/--sendfile cannot be combined with -c (compression) or -s (chunk "
                    "serialization)\n");
    return false;
  }
  if (config->transport == TRANSPORT_SSH && config->use_sendfile) {
    fprintf(stderr, "Error: -f/--sendfile is not supported with SSH transport\n");
    return false;
  }
  if (config->use_incremental && config->use_chunk_serialization) {
    fprintf(stderr, "Error: --incremental is not supported with -s (chunk serialization)\n");
    return false;
  }
  if (config->use_delta && !config->use_incremental) {
    fprintf(stderr, "Error: --delta requires --incremental\n");
    return false;
  }
  if (config->use_delta && config->use_chunk_serialization) {
    fprintf(stderr, "Error: --delta cannot be combined with -s (chunk serialization)\n");
    return false;
  }
  if (config->use_delta && config->use_sendfile) {
    fprintf(stderr, "Error: --delta cannot be combined with -f (sendfile)\n");
    return false;
  }
  if (config->append || config->append_verify) {
    fprintf(
        stderr,
        "Error: --append and --append-verify are not supported yet; refusing to ignore option\n");
    return false;
  }
  if (config->use_tls) {
    if (!config->tls_cert || !config->tls_key || !config->tls_ca) {
      fprintf(stderr, "Error: --tls requires --cert, --key, and --ca\n");
      return false;
    }
  }
  return true;
}
#endif /* FASTSYNC_TEST_BUILD */

static int read_patterns_from_file(const char* filepath, char*** patterns, int* count) {
  FILE* fp = fopen(filepath, "r");
  if (!fp) {
    fprintf(stderr, "Error: could not open pattern file '%s': %s\n", filepath, strerror(errno));
    return -1;
  }
  char* line = NULL;
  size_t line_size = 0;
  ssize_t n;
  while ((n = getline(&line, &line_size, fp)) != -1) {
    char* p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    if (*p == '#' || *p == '\n' || *p == '\0')
      continue;
    size_t len = strlen(p);
    while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == '\r'))
      p[--len] = '\0';
    if (len == 0)
      continue;
    char** tmp = realloc(*patterns, (*count + 1) * sizeof(char*));
    if (!tmp) {
      fprintf(stderr, "Error: memory allocation failed for pattern file\n");
      free(line);
      fclose(fp);
      return -1;
    }
    *patterns = tmp;
    char* dup = str_dup(p);
    if (!dup) {
      fprintf(stderr, "Error: memory allocation failed for pattern file\n");
      free(line);
      fclose(fp);
      return -1;
    }
    (*patterns)[(*count)++] = dup;
  }
  free(line);
  fclose(fp);
  return 0;
}

#ifndef FASTSYNC_TEST_BUILD
int main(int argc, char* argv[]) {
  const char* env_source = NULL;
  const char* env_dest = NULL;
  bool save_to_disk = false;
  parse_environment(&env_source, &env_dest, &save_to_disk);

  int exit_code = 0;
  bool config_owned_by_pipeline = false;
  Config* config = config_create();
  if (!config) {
    fprintf(stderr, "Error: failed to allocate config\n");
    return 1;
  }
  config->save_to_disk = save_to_disk;

  int positional_args[2];
  int positional_count = 0;

  int parse_ret = parse_args(config, argc, argv, positional_args, &positional_count);
  if (parse_ret != 0) {
    if (parse_ret < 0)
      exit_code = 1;
    goto cleanup;
  }

  /* Handle positional arguments or fall back to environment variables */
  if (positional_count == 2) {
    free(config->send_directory);
    free(config->receive_root_directory);
    config->send_directory = str_dup(argv[positional_args[0]]);
    if (!config->send_directory) {
      fprintf(stderr, "Error: memory allocation failed\n");
      exit_code = 1;
      goto cleanup;
    }
    config->receive_root_directory = str_dup(argv[positional_args[1]]);
    if (!config->receive_root_directory) {
      fprintf(stderr, "Error: memory allocation failed\n");
      exit_code = 1;
      goto cleanup;
    }
    config->save_to_disk = true;
    config_parse_ssh_dest(config);
  } else if (positional_count == 1) {
    fprintf(stderr, "Error: missing destination argument\n");
    print_usage();
    exit_code = 1;
    goto cleanup;
  } else {
    if (!config->send_directory && env_source) {
      config->send_directory = str_dup(env_source);
      if (!config->send_directory) {
        fprintf(stderr, "Error: memory allocation failed\n");
        exit_code = 1;
        goto cleanup;
      }
    }
    if (!config->receive_root_directory && env_dest) {
      config->receive_root_directory = str_dup(env_dest);
      if (!config->receive_root_directory) {
        fprintf(stderr, "Error: memory allocation failed\n");
        exit_code = 1;
        goto cleanup;
      }
    }
  }

  if (!validate_config(config)) {
    exit_code = 1;
    goto cleanup;
  }

  /* Enable implicit flags */
  if (config->use_incremental && !config->use_metadata) {
    log_message(LOG_LEVEL_INFO, "Enabling metadata preservation for --incremental");
    config->use_metadata = true;
  }
  if (config->use_delta && !config->use_metadata) {
    log_message(LOG_LEVEL_INFO, "Enabling metadata preservation for --delta");
    config->use_metadata = true;
  }

  /* Initialize TLS if needed */
  if (config->use_tls)
    tls_global_init();

  tcp_set_timeouts(config->timeout, config->contimeout);

  /* Execute transfer */
  if (config->use_multithreading) {
    config_owned_by_pipeline = true;
    exit_code = send_files_multithreaded(config);
  } else {
    exit_code = send_files(config);
  }

cleanup:
  if (config) {
    if (config->log_file)
      fclose(config->log_file);
    if (!config_owned_by_pipeline)
      config_delete(config);
  }
  return exit_code;
}
#endif /* FASTSYNC_TEST_BUILD */
