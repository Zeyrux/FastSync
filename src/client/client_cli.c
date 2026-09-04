#include "client_send.h"
#include "client_validation.h"
#include "config.h"
#include "delta.h"
#include "log.h"
#include "protocol.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include "usage.h"
#include "utils.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for %s", option_name);
    return -1;
  }
  free(*dest);
  *dest = dup;
  return 0;
}

/* Parse a string as a positive integer into *dest. Returns true on success, false on error. */
static int set_positive_int_option(int* dest, const char* value, const char* option_name) {
  if (!parse_positive_int(value, dest)) {
    log_message(LOG_LEVEL_ERROR, "%s must be a positive integer", option_name);
    return -1;
  }
  return 0;
}

/* Parse a string as a non-negative integer into *dest. Returns true on success, false on error. */
static int set_nonneg_int_option(int* dest, const char* value, const char* option_name) {
  if (!parse_nonneg_int(value, dest)) {
    log_message(LOG_LEVEL_ERROR, "%s must be a non-negative integer", option_name);
    return -1;
  }
  return 0;
}

static int set_stderr_mode(const char* value) {
  if (strcmp(value, "errors") == 0 || strcmp(value, "e") == 0)
    log_set_stderr_mode(LOG_STDERR_ERRORS);
  else if (strcmp(value, "all") == 0 || strcmp(value, "a") == 0)
    log_set_stderr_mode(LOG_STDERR_ALL);
  else if (strcmp(value, "client") == 0 || strcmp(value, "c") == 0) {
    log_message(LOG_LEVEL_ERROR,
                "--stderr=client is not supported: FastSync has no client message channel");
    return -1;
  } else {
    log_message(LOG_LEVEL_ERROR, "--stderr must be errors or all");
    return -1;
  }
  return 0;
}

static int read_patterns_from_file(const char* filepath, char*** patterns, int* count);

static int parse_debug_flags(const char* value, Config* config) {
  if (!value || value[0] == '\0' || value[0] == ',' || value[strlen(value) - 1] == ',' ||
      strstr(value, ",,")) {
    log_message(LOG_LEVEL_ERROR, "--debug requires at least one flag");
    return -1;
  }

  char* flags = str_dup(value);
  if (!flags) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for --debug");
    return -1;
  }
  uint32_t parsed = (uint32_t)config->debug_level;
  char* saveptr = NULL;
  for (char* token = strtok_r(flags, ",", &saveptr); token != NULL;
       token = strtok_r(NULL, ",", &saveptr)) {
    uint32_t flag = 0;
    if (strcmp(token, "help") == 0) {
      print_debug_usage();
      free(flags);
      return 1;
    } else if (strcmp(token, "all") == 0) {
      parsed = LOG_DEBUG_ALL;
      continue;
    } else if (strcmp(token, "none") == 0) {
      parsed = 0;
      continue;
    } else if (strcmp(token, "io") == 0) {
      flag = LOG_DEBUG_IO;
    } else if (strcmp(token, "proto") == 0) {
      flag = LOG_DEBUG_PROTO;
    } else if (strcmp(token, "pack") == 0) {
      flag = LOG_DEBUG_PACK;
    } else if (strcmp(token, "util") == 0) {
      flag = LOG_DEBUG_UTIL;
    } else {
      log_message(LOG_LEVEL_ERROR, "unsupported --debug flag: %s", token);
      free(flags);
      return -1;
    }
    parsed |= flag;
  }
  free(flags);
  config->debug_level = (int)parsed;
  set_log_debug_flags(parsed);
  set_log_level(LOG_LEVEL_DEBUG);
  return 0;
}

/* Parse a string as an unsigned long long. Returns 0 on success, -1 on error. */
static int parse_ull_arg(const char* val, unsigned long long* out, const char* optname) {
  char* end;
  errno = 0;
  unsigned long long v = strtoull(val, &end, 10);
  if (errno != 0 || *end != '\0') {
    log_message(LOG_LEVEL_ERROR, "%s must be a non-negative integer", optname);
    return -1;
  }
  *out = v;
  return 0;
}

/* Append a duplicated pattern to a growable pattern array. Returns 0 on success, -1 on error. */
static int config_add_pattern(char*** patterns, int* count, const char* value,
                              const char* optname) {
  char** tmp = realloc(*patterns, (*count + 1) * sizeof(char*));
  if (!tmp) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for %s", optname);
    return -1;
  }
  *patterns = tmp;
  char* dup = str_dup(value);
  if (!dup) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for %s", optname);
    return -1;
  }
  (*patterns)[(*count)++] = dup;
  return 0;
}

typedef enum {
  OPT_FLAG,
  OPT_NOOP,
  OPT_STRING,
  OPT_POS_INT,
  OPT_NONNEG_INT,
  OPT_ULL,
} OptKind;

typedef struct {
  const char* name;
  const char* alias;
  OptKind kind;
  size_t offset; /* offsetof of the target field in Config, or 0 for OPT_NOOP */
} OptionEntry;

/* Options parsed directly into Config, plus compatibility options with no effect. */
static const OptionEntry OPTION_TABLE[] = {
    {"--dry-run", "-n", OPT_FLAG, offsetof(Config, dry_run)},
    {"--remove-source-files", NULL, OPT_FLAG, offsetof(Config, remove_source_files)},
    {"--delete", NULL, OPT_FLAG, offsetof(Config, use_delete)},
    {"--incremental", NULL, OPT_FLAG, offsetof(Config, use_incremental)},
    {"--size-only", NULL, OPT_FLAG, offsetof(Config, size_only)},
    {"--ignore-times", "-I", OPT_FLAG, offsetof(Config, ignore_times)},
    {"--modify-window", "-@", OPT_NONNEG_INT, offsetof(Config, modify_window)},
    {"--delta", NULL, OPT_FLAG, offsetof(Config, use_delta)},
    {"--whole-file", "-W", OPT_FLAG, offsetof(Config, whole_file)},
    {"--save-to-disk", NULL, OPT_FLAG, offsetof(Config, save_to_disk)},
    {"--progress", NULL, OPT_FLAG, offsetof(Config, show_progress)},
    {"--tls", NULL, OPT_FLAG, offsetof(Config, use_tls)},
    {"--backup", NULL, OPT_FLAG, offsetof(Config, backup)},
    {"--stats", NULL, OPT_FLAG, offsetof(Config, stats)},
    {"--human-readable", "-h", OPT_FLAG, offsetof(Config, human_readable)},
    {"--partial", NULL, OPT_FLAG, offsetof(Config, partial)},
    {"--secluded-args", NULL, OPT_NOOP, 0},
    {"--update", "-u", OPT_FLAG, offsetof(Config, update)},
    {"--links", "-l", OPT_FLAG, offsetof(Config, follow_symlinks)},
    {"--copy-links", NULL, OPT_FLAG, offsetof(Config, copy_links)},
    {"--safe-links", NULL, OPT_FLAG, offsetof(Config, safe_links)},
    {"--copy-unsafe-links", NULL, OPT_FLAG, offsetof(Config, copy_unsafe_links)},
    {"--sparse", "-S", OPT_FLAG, offsetof(Config, preserve_sparse)},
    {"--inplace", NULL, OPT_FLAG, offsetof(Config, inplace)},
    {"--fsync", NULL, OPT_FLAG, offsetof(Config, use_fsync)},
    {"--checksum", NULL, OPT_FLAG, offsetof(Config, checksum)},
    {"--8-bit-output", "-8", OPT_FLAG, offsetof(Config, eight_bit_output)},
    {"--existing", NULL, OPT_FLAG, offsetof(Config, existing)},

    {"--source-dir", NULL, OPT_STRING, offsetof(Config, send_directory)},
    {"--dest-dir", NULL, OPT_STRING, offsetof(Config, receive_root_directory)},
    {"--server-host", NULL, OPT_STRING, offsetof(Config, server_host)},
    {"--cert", NULL, OPT_STRING, offsetof(Config, tls_cert)},
    {"--key", NULL, OPT_STRING, offsetof(Config, tls_key)},
    {"--ca", NULL, OPT_STRING, offsetof(Config, tls_ca)},
    {"--backup-dir", NULL, OPT_STRING, offsetof(Config, backup_dir)},
    {"--fastsync-server-path", NULL, OPT_STRING, offsetof(Config, fastsync_server_path)},
    {"--partial-dir", NULL, OPT_STRING, offsetof(Config, partial_dir)},
    {"--suffix", NULL, OPT_STRING, offsetof(Config, suffix)},

    {"--timeout", NULL, OPT_POS_INT, offsetof(Config, timeout)},
    {"--contimeout", NULL, OPT_POS_INT, offsetof(Config, contimeout)},
    {"--max-depth", NULL, OPT_NONNEG_INT, offsetof(Config, max_depth)},

    {"--max-size", NULL, OPT_ULL, offsetof(Config, max_size)},
    {"--min-size", NULL, OPT_ULL, offsetof(Config, min_size)},
};

static bool opt_is(const char* arg, const char* name, const char* alias) {
  return strcmp(arg, name) == 0 || (alias && strcmp(arg, alias) == 0);
}

static const OptionEntry* find_table_option(const char* arg) {
  for (size_t i = 0; i < sizeof(OPTION_TABLE) / sizeof(OPTION_TABLE[0]); i++)
    if (opt_is(arg, OPTION_TABLE[i].name, OPTION_TABLE[i].alias))
      return &OPTION_TABLE[i];
  return NULL;
}

static int apply_table_option(Config* config, const OptionEntry* entry, const char* value) {
  if (entry->kind == OPT_NOOP)
    return 0;

  void* field = (char*)config + entry->offset;
  switch (entry->kind) {
  case OPT_FLAG:
    *(bool*)field = true;
    if (entry->offset == offsetof(Config, update))
      config->use_metadata = true;
    return 0;
  case OPT_NOOP:
    return 0;
  case OPT_STRING:
    return set_string_option((char**)field, value, entry->name);
  case OPT_POS_INT:
    return set_positive_int_option((int*)field, value, entry->name);
  case OPT_NONNEG_INT:
    return set_nonneg_int_option((int*)field, value, entry->name);
  case OPT_ULL: {
    unsigned long long v;
    if (parse_ull_arg(value, &v, entry->name) != 0)
      return -1;
    *(unsigned long long*)field = v;
    return 0;
  }
  }
  return -1;
}

/* Parse CLI arguments into config. Returns 0 on success, -1 on error, 1 for help/clean-exit. */
int parse_args(Config* config, int argc, char* argv[], int* positional_args,
               int* positional_count) {
  bool verbose = false;
  protocol_set_8_bit_output(config->eight_bit_output);
  for (int i = 1; i < argc; i++) {
    const char* modify_window_prefix = "--modify-window=";
    if (strncmp(argv[i], modify_window_prefix, strlen(modify_window_prefix)) == 0) {
      if (set_nonneg_int_option(&config->modify_window, argv[i] + strlen(modify_window_prefix),
                                "--modify-window") != 0)
        return -1;
      continue;
    }
    if (strncmp(argv[i], "-@", 2) == 0 && argv[i][2] != '\0') {
      if (set_nonneg_int_option(&config->modify_window, argv[i] + 2, "-@") != 0)
        return -1;
      continue;
    }
    const OptionEntry* entry = find_table_option(argv[i]);
    if (entry) {
      if (entry->kind != OPT_FLAG) {
        if (i + 1 >= argc) {
          log_message(LOG_LEVEL_ERROR, "missing argument for %s", entry->name);
          return -1;
        }
        if (apply_table_option(config, entry, argv[++i]) != 0)
          return -1;
      } else if (apply_table_option(config, entry, NULL) != 0) {
        return -1;
      }
      if (entry->offset == offsetof(Config, eight_bit_output))
        protocol_set_8_bit_output(true);
      continue;
    }

    if (opt_is(argv[i], "--help", NULL)) {
      print_usage();
      return 1;
    } else if (opt_is(argv[i], "-V", "--version")) {
      printf("fastsync version %s\n", PROTOCOL_VERSION);
      return 1;
    } else if (opt_is(argv[i], "-a", "--archive")) {
      config->use_compression = true;
      config->use_multithreading = true;
      config->use_metadata = true;
      log_message(LOG_LEVEL_INFO, "Enabled archive mode (-c -m -M)");
    } else if (opt_is(argv[i], "-p", NULL) && i + 1 < argc) {
      if (set_positive_int_option(&config->ssh_port, argv[++i], "-p") != 0)
        return -1;
      if (config->ssh_port > 65535) {
        log_message(LOG_LEVEL_ERROR, "SSH port must be 1-65535");
        return -1;
      }
    } else if (opt_is(argv[i], "--exclude", NULL) && i + 1 < argc) {
      if (config_add_pattern(&config->exclude_patterns, &config->exclude_count, argv[++i],
                             "--exclude") != 0)
        return -1;
    } else if (opt_is(argv[i], "--include", NULL) && i + 1 < argc) {
      if (config_add_pattern(&config->include_patterns, &config->include_count, argv[++i],
                             "--include") != 0)
        return -1;
    } else if (opt_is(argv[i], "--delta-block", NULL) && i + 1 < argc) {
      unsigned long long val;
      if (parse_ull_arg(argv[++i], &val, "--delta-block") != 0)
        return -1;
      if (val >= DELTA_BLOCK_SIZE_MIN && val <= DELTA_BLOCK_SIZE_MAX)
        config->delta_block_size = (uint32_t)val;
      else
        log_message(LOG_LEVEL_WARNING, "--delta-block value %llu out of range, using default", val);
    } else if (opt_is(argv[i], "--delta-max", NULL) && i + 1 < argc) {
      unsigned long long val;
      if (parse_ull_arg(argv[++i], &val, "--delta-max") != 0)
        return -1;
      if (val >= DELTA_MIN_FILE_SIZE)
        config->delta_max_file_size = val;
      else
        log_message(LOG_LEVEL_WARNING, "--delta-max value %llu too small, using default", val);
    } else if (opt_is(argv[i], "-c", "-z")) {
      config->use_compression = true;
      log_message(LOG_LEVEL_INFO, "Enabled Compression");
      if (i + 1 < argc) {
        char* end_ptr;
        long level = strtol(argv[i + 1], &end_ptr, 10);
        if (*end_ptr == '\0') {
          if (level < 1 || level > 22) {
            log_message(LOG_LEVEL_ERROR, "compression level must be 1-22");
            return -1;
          }
          config->compression_level = (int)level;
          log_message(LOG_LEVEL_INFO, "Set Compression level to %ld", level);
          i++;
        }
      }
    } else if (opt_is(argv[i], "-M", "--preserve")) {
      config->use_metadata = true;
      log_message(LOG_LEVEL_INFO, "Enabled metadata preservation");
    } else if (opt_is(argv[i], "-f", "--sendfile")) {
      config->use_sendfile = true;
      log_message(LOG_LEVEL_INFO, "Enabled sendfile");
    } else if (opt_is(argv[i], "-m", NULL)) {
      config->use_multithreading = true;
      log_message(LOG_LEVEL_INFO, "Enabled Multithreading");
    } else if (opt_is(argv[i], "-s", NULL)) {
      config->use_chunk_serialization = true;
      log_message(LOG_LEVEL_INFO, "Enabled Chunk Serialization");
    } else if (opt_is(argv[i], "--server-port", NULL) && i + 1 < argc) {
      if (!parse_positive_int(argv[++i], &config->server_port)) {
        char* escaped = output_escape(argv[i], false);
        log_message(LOG_LEVEL_ERROR, "invalid --server-port value: %s",
                    escaped ? escaped : "<allocation failed>");
        free(escaped);
        return -1;
      }
      if (config->server_port > 65535) {
        log_message(LOG_LEVEL_ERROR, "server port must be 1-65535");
        return -1;
      }
    } else if (opt_is(argv[i], "--bwlimit", NULL) && i + 1 < argc) {
      unsigned long long kbps;
      if (parse_ull_arg(argv[++i], &kbps, "--bwlimit") != 0)
        return -1;
      if (kbps == 0) {
        log_message(LOG_LEVEL_ERROR, "--bwlimit must be a positive integer");
        return -1;
      }
      if (kbps > ULLONG_MAX / 1024) {
        log_message(LOG_LEVEL_ERROR, "--bwlimit value too large");
        return -1;
      }
      io_set_bwlimit(kbps * 1024);
      log_message(LOG_LEVEL_INFO, "Set bandwidth limit to %llu KB/s", kbps);
    } else if (opt_is(argv[i], "--chunk-size", NULL) && i + 1 < argc) {
      unsigned long long val;
      if (parse_ull_arg(argv[++i], &val, "--chunk-size") != 0)
        return -1;
      if (val == 0) {
        log_message(LOG_LEVEL_ERROR, "--chunk-size must be a positive integer");
        return -1;
      }
      config->chunk_size = val;
    } else if (opt_is(argv[i], "--log-file", NULL) && i + 1 < argc) {
      if (config->log_file) {
        fclose(config->log_file);
        config->log_file = NULL;
        log_set_file(NULL);
      }
      FILE* lf = fopen(argv[++i], "a");
      if (!lf) {
        char* escaped = output_escape(argv[i], false);
        log_message(LOG_LEVEL_ERROR, "could not open log file '%s': %s",
                    escaped ? escaped : "<allocation failed>", strerror(errno));
        free(escaped);
        return -1;
      }
      config->log_file = lf;
      log_set_file(lf);
    } else if (strncmp(argv[i], "--stderr=", 9) == 0) {
      if (set_stderr_mode(argv[i] + 9) != 0)
        return -1;
    } else if (opt_is(argv[i], "--stderr", NULL)) {
      if (i + 1 >= argc || set_stderr_mode(argv[++i]) != 0)
        return -1;
    } else if (opt_is(argv[i], "--exclude-from", NULL) && i + 1 < argc) {
      if (read_patterns_from_file(argv[++i], &config->exclude_patterns, &config->exclude_count) !=
          0)
        return -1;
    } else if (opt_is(argv[i], "--include-from", NULL) && i + 1 < argc) {
      if (read_patterns_from_file(argv[++i], &config->include_patterns, &config->include_count) !=
          0)
        return -1;
    } else if (opt_is(argv[i], "-v", "--verbose")) {
      verbose = true;
    } else if (opt_is(argv[i], "-q", "--quiet")) {
      config->quiet = true;
    } else if (strncmp(argv[i], "--debug=", 8) == 0) {
      int debug_ret = parse_debug_flags(argv[i] + 8, config);
      if (debug_ret != 0)
        return debug_ret;
    } else if (opt_is(argv[i], "--debug", NULL)) {
      if (i + 1 >= argc)
        return parse_debug_flags(NULL, config);
      int debug_ret = parse_debug_flags(argv[++i], config);
      if (debug_ret != 0)
        return debug_ret;
    } else if (opt_is(argv[i], "-T", NULL) && i + 1 < argc) {
      if (set_positive_int_option(&config->timeout, argv[++i], "-T") != 0)
        return -1;
    } else if (opt_is(argv[i], "--compress-level", NULL) && i + 1 < argc) {
      if (set_positive_int_option(&config->compression_level, argv[++i], "--compress-level") != 0)
        return -1;
      if (config->compression_level < 1 || config->compression_level > 22) {
        log_message(LOG_LEVEL_ERROR, "--compress-level must be between 1 and 22");
        return -1;
      }
    } else if (argv[i][0] == '-') {
      char* escaped = output_escape(argv[i], false);
      fprintf(stderr, "Unknown option: %s\n", escaped ? escaped : "<allocation failed>");
      free(escaped);
      print_usage();
      return -1;
    } else {
      if (*positional_count < 2)
        positional_args[(*positional_count)++] = i;
      else {
        char* escaped = output_escape(argv[i], false);
        fprintf(stderr, "Unexpected argument: %s\n", escaped ? escaped : "<allocation failed>");
        free(escaped);
        print_usage();
        return -1;
      }
    }
  }
  set_log_level(config->quiet ? LOG_LEVEL_ERROR : (verbose ? LOG_LEVEL_DEBUG : LOG_LEVEL_WARNING));
  return 0;
}

static int read_patterns_from_file(const char* filepath, char*** patterns, int* count) {
  FILE* fp = fopen(filepath, "r");
  if (!fp) {
    char* escaped = output_escape(filepath, false);
    log_message(LOG_LEVEL_ERROR, "could not open pattern file '%s': %s",
                escaped ? escaped : "<allocation failed>", strerror(errno));
    free(escaped);
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
    if (config_add_pattern(patterns, count, p, "pattern file") != 0) {
      free(line);
      fclose(fp);
      return -1;
    }
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
  Config* config = config_create();
  if (!config) {
    log_message(LOG_LEVEL_ERROR, "failed to allocate config");
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
      log_message(LOG_LEVEL_ERROR, "memory allocation failed");
      exit_code = 1;
      goto cleanup;
    }
    config->receive_root_directory = str_dup(argv[positional_args[1]]);
    if (!config->receive_root_directory) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed");
      exit_code = 1;
      goto cleanup;
    }
    config->save_to_disk = true;
    config_parse_ssh_dest(config);
  } else if (positional_count == 1) {
    log_message(LOG_LEVEL_ERROR, "missing destination argument");
    print_usage();
    exit_code = 1;
    goto cleanup;
  } else {
    if (!config->send_directory && env_source) {
      config->send_directory = str_dup(env_source);
      if (!config->send_directory) {
        log_message(LOG_LEVEL_ERROR, "memory allocation failed");
        exit_code = 1;
        goto cleanup;
      }
    }
    if (!config->receive_root_directory && env_dest) {
      config->receive_root_directory = str_dup(env_dest);
      if (!config->receive_root_directory) {
        log_message(LOG_LEVEL_ERROR, "memory allocation failed");
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
    exit_code = send_files_multithreaded(&config);
  } else {
    exit_code = send_files(config);
  }

cleanup:
  if (config) {
    config_delete(config);
  }
  return exit_code;
}
#endif /* FASTSYNC_TEST_BUILD */
