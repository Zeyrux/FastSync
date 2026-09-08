#include "client_send.h"
#include "client_validation.h"
#include "chmod.h"
#include "compression.h"
#include "config.h"
#include "delta.h"
#include "file.h"
#include "file_list.h"
#include "filter.h"
#include "identity.h"
#include "log.h"
#include "protocol.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include "usage.h"
#include "utils.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
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

/* Duplicate a string argument into *dest, freeing the old value. Returns 0 on success, -1 on
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

/* Parse a string as a positive integer into *dest. Returns 0 on success, -1 on error. */
static int set_positive_int_option(int* dest, const char* value, const char* option_name) {
  if (!parse_positive_int(value, dest)) {
    log_message(LOG_LEVEL_ERROR, "%s must be a positive integer", option_name);
    return -1;
  }
  return 0;
}

/* Set and validate the compression algorithm selected by the client. */
static int set_compression_choice(Config* config, const char* value) {
  if (strcmp(value, "zstd") != 0 && strcmp(value, "none") != 0) {
    log_message(LOG_LEVEL_ERROR, "--compress-choice must be zstd or none");
    return -1;
  }
  if (set_string_option(&config->compress_choice, value, "--compress-choice") != 0)
    return -1;
  config->use_compression = strcmp(value, "zstd") == 0;
  return 0;
}

/* Validate and store the --checksum-choice/--cc algorithm.  Only the algorithms
 * the engine genuinely supports are accepted (xxHash64 and md5); anything else
 * is a clear error, never a silent no-op.  "xxhash" is accepted as rsync's
 * spelling of xxHash64. */
static int set_checksum_choice(Config* config, const char* value) {
  int algo = checksum_algo_from_name(value);
  if (algo < 0) {
    log_message(LOG_LEVEL_ERROR, "--checksum-choice must be xxh64 (or xxhash) or md5 (got '%s')",
                value);
    return -1;
  }
  config->checksum_algo = algo;
  return 0;
}

/* parse_ull_arg is defined later in this file; declared here for the seed
   parser below. */
static int parse_ull_arg(const char* val, unsigned long long* out, const char* optname);

/* Parse --checksum-seed=NUM as a strict decimal 0..UINT64_MAX.  A blank value,
 * a sign, or any non-digit (which parse_ull_arg's strtoull would silently
 * coerce) is rejected: an explicit seed must be an exact unsigned integer or
 * the run fails with a clear error rather than quietly ignoring the value. */
static int set_checksum_seed(Config* config, const char* value) {
  if (!value || *value == '\0') {
    log_message(LOG_LEVEL_ERROR, "--checksum-seed must be a non-negative integer");
    return -1;
  }
  for (const char* p = value; *p; p++) {
    if (*p < '0' || *p > '9') {
      log_message(LOG_LEVEL_ERROR, "--checksum-seed must be a non-negative integer");
      return -1;
    }
  }
  unsigned long long seed;
  if (parse_ull_arg(value, &seed, "--checksum-seed") != 0)
    return -1;
  config->checksum_seed = seed;
  return 0;
}

static int set_compression_threads_option(int* dest, const char* value) {
  if (set_positive_int_option(dest, value, "--compress-threads") != 0)
    return -1;
  if (*dest > COMPRESSION_MAX_THREADS) {
    log_message(LOG_LEVEL_ERROR, "--compress-threads must be between 1 and %d",
                COMPRESSION_MAX_THREADS);
    return -1;
  }
  return 0;
}

/* Parse a string as a non-negative integer into *dest. Returns 0 on success, -1 on error. */
static int set_nonneg_int_option(int* dest, const char* value, const char* option_name) {
  if (!parse_nonneg_int(value, dest)) {
    log_message(LOG_LEVEL_ERROR, "%s must be a non-negative integer", option_name);
    return -1;
  }
  return 0;
}

/* Validate and append one --compare-dest/--copy-dest/--link-dest directory.
 * The path is interpreted on the receiver relative to the destination root,
 * so it must be a non-empty relative path with no "." / ".." components (an
 * absolute or escaping path is rejected up front instead of failing on the
 * server). Returns 0 on success, -1 on error. */
static int set_basis_dest_option(Config* config, BasisDestType type, const char* value,
                                 const char* option_name) {
  if (!value || !value[0]) {
    log_message(LOG_LEVEL_ERROR, "missing argument for %s", option_name);
    return -1;
  }
  if (config_basis_append(config, type, value) != 0) {
    log_message(LOG_LEVEL_ERROR,
                "%s requires a non-empty relative directory name with no '.', '..', or absolute "
                "path (resolved below the destination root)",
                option_name);
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

static int parse_info_flags(const char* value, Config* config) {
  if (!value || value[0] == '\0' || value[0] == ',' || value[strlen(value) - 1] == ',' ||
      strstr(value, ",,")) {
    log_message(LOG_LEVEL_ERROR, "--info requires at least one flag");
    return -1;
  }
  char* flags = str_dup(value);
  if (!flags) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for --info");
    return -1;
  }

  uint32_t parsed = (uint32_t)config->info_level;
  char* saveptr = NULL;
  for (char* token = strtok_r(flags, ",", &saveptr); token != NULL;
       token = strtok_r(NULL, ",", &saveptr)) {
    uint32_t flag = 0;
    if (strcmp(token, "all") == 0) {
      parsed = LOG_INFO_ALL;
      continue;
    }
    if (strcmp(token, "none") == 0) {
      parsed = 0;
      continue;
    }
    if (strcmp(token, "copy") == 0)
      flag = LOG_INFO_COPY;
    else if (strcmp(token, "misc") == 0)
      flag = LOG_INFO_MISC;
    else if (strcmp(token, "skip") == 0)
      flag = LOG_INFO_SKIP;
    else if (strcmp(token, "stats") == 0)
      flag = LOG_INFO_STATS;
    else {
      log_message(LOG_LEVEL_ERROR, "unsupported --info flag: %s", token);
      free(flags);
      return -1;
    }
    parsed |= flag;
  }
  free(flags);
  config->info_level = (int)parsed;
  set_log_info_flags(parsed);
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

/* Parse a byte count with an optional single-letter binary suffix (K/M/G/T/P/E).
 * When allow_zero is false, a bare 0 is rejected (size limits use true, since 0
 * means "no limit"). Returns 0 on success, -1 on error. */
static int parse_size_arg_allow_zero(const char* value, unsigned long long* out, bool allow_zero) {
  if (!value || *value < '0' || *value > '9')
    return -1;
  char* end;
  errno = 0;
  unsigned long long number = strtoull(value, &end, 10);
  if (errno != 0 || end == value)
    return -1;
  unsigned long long multiplier = 1;
  if (*end != '\0') {
    if (end[1] != '\0')
      return -1;
    switch (*end) {
    case 'b':
    case 'B':
      break;
    case 'k':
    case 'K':
      multiplier = 1024ULL;
      break;
    case 'm':
    case 'M':
      multiplier = 1024ULL * 1024;
      break;
    case 'g':
    case 'G':
      multiplier = 1024ULL * 1024 * 1024;
      break;
    case 't':
    case 'T':
      multiplier = 1024ULL * 1024 * 1024 * 1024;
      break;
    case 'p':
    case 'P':
      multiplier = 1024ULL * 1024 * 1024 * 1024 * 1024;
      break;
    case 'e':
    case 'E':
      multiplier = 1024ULL * 1024 * 1024 * 1024 * 1024 * 1024;
      break;
    default:
      return -1;
    }
  }
  if ((!allow_zero && number == 0) || number > ULLONG_MAX / multiplier)
    return -1;
  *out = number * multiplier;
  return 0;
}

static int parse_size_arg(const char* value, unsigned long long* out) {
  return parse_size_arg_allow_zero(value, out, false);
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

/* Validate and append one --filter=RULE string. Returns 0 on success, -1 on error. */
static int config_add_filter(Config* config, const char* rule) {
  char err[160];
  FilterRule* parsed = filter_rule_parse(rule, err, sizeof(err));
  if (!parsed) {
    log_message(LOG_LEVEL_ERROR, "invalid --filter rule '%s': %s", rule, err);
    return -1;
  }
  filter_rule_free(parsed);
  if (!config->filters) {
    config->filters = array_list_create(free);
    if (!config->filters) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed for --filter");
      return -1;
    }
  }
  char* dup = str_dup(rule);
  if (!dup || !array_list_add(config->filters, dup)) {
    free(dup);
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for --filter");
    return -1;
  }
  return 0;
}

static int parse_skip_compress(Config* config, const char* value) {
  char* list = str_dup(value);
  if (!list)
    return -1;
  config->skip_compress_set = true;
  for (char* token = strtok(list, ","); token; token = strtok(NULL, ",")) {
    while (*token == ' ' || *token == '\t')
      token++;
    size_t len = strlen(token);
    while (len > 0 && (token[len - 1] == ' ' || token[len - 1] == '\t'))
      token[--len] = '\0';
    if (len == 0)
      continue;
    if (config_add_pattern(&config->skip_compress_suffixes, &config->skip_compress_count, token,
                           "--skip-compress") != 0) {
      free(list);
      return -1;
    }
  }
  free(list);
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
typedef struct {
  const char* name;
  const char* alias;
  size_t offset; /* offsetof of the boolean target field in Config */
} NegatableOption;

/* Options that map directly onto a Config field with no side effects. */
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
    {"--fuzzy", "-y", OPT_FLAG, offsetof(Config, fuzzy)},
    {"--save-to-disk", NULL, OPT_FLAG, offsetof(Config, save_to_disk)},
    {"--progress", NULL, OPT_FLAG, offsetof(Config, show_progress)},
    {"--tls", NULL, OPT_FLAG, offsetof(Config, use_tls)},
    {"--backup", NULL, OPT_FLAG, offsetof(Config, backup)},
    {"--stats", NULL, OPT_FLAG, offsetof(Config, stats)},
    {"--human-readable", "-h", OPT_FLAG, offsetof(Config, human_readable)},
    {"--partial", NULL, OPT_FLAG, offsetof(Config, partial)},
    {"--secluded-args", NULL, OPT_NOOP, 0},
    {"--update", "-u", OPT_FLAG, offsetof(Config, update)},
    {"--old-args", NULL, OPT_FLAG, offsetof(Config, old_args)},
    {"--links", "-l", OPT_FLAG, offsetof(Config, follow_symlinks)},
    {"--copy-links", NULL, OPT_FLAG, offsetof(Config, copy_links)},
    {"--safe-links", NULL, OPT_FLAG, offsetof(Config, safe_links)},
    {"--copy-unsafe-links", NULL, OPT_FLAG, offsetof(Config, copy_unsafe_links)},
    {"--hard-links", "-H", OPT_FLAG, offsetof(Config, preserve_hard_links)},
    {"--sparse", "-S", OPT_FLAG, offsetof(Config, preserve_sparse)},
    {"--inplace", NULL, OPT_FLAG, offsetof(Config, inplace)},
    {"--preallocate", NULL, OPT_FLAG, offsetof(Config, preallocate)},
    {"--append", NULL, OPT_FLAG, offsetof(Config, append)},
    {"--append-verify", NULL, OPT_FLAG, offsetof(Config, append_verify)},
    {"--fsync", NULL, OPT_FLAG, offsetof(Config, use_fsync)},
    {"--checksum", NULL, OPT_FLAG, offsetof(Config, checksum)},
    {"--8-bit-output", "-8", OPT_FLAG, offsetof(Config, eight_bit_output)},
    {"--itemize-changes", "-i", OPT_FLAG, offsetof(Config, itemize_changes)},
    {"--list-only", NULL, OPT_FLAG, offsetof(Config, list_only)},
    {"--out-format", NULL, OPT_STRING, offsetof(Config, out_format)},
    {"--log-file-format", NULL, OPT_STRING, offsetof(Config, log_file_format)},
    {"--existing", NULL, OPT_FLAG, offsetof(Config, existing)},
    {"--ignore-existing", NULL, OPT_FLAG, offsetof(Config, ignore_existing)},
    {"--delay-updates", NULL, OPT_FLAG, offsetof(Config, delay_updates)},
    {"--chmod", NULL, OPT_STRING, offsetof(Config, chmod_spec)},
    {"--dirs", "-d", OPT_FLAG, offsetof(Config, dirs)},
    {"--old-dirs", NULL, OPT_FLAG, offsetof(Config, dirs)},
    {"--old-d", NULL, OPT_FLAG, offsetof(Config, dirs)},
    {"--relative", "-R", OPT_FLAG, offsetof(Config, relative)},
    {"--mkpath", NULL, OPT_FLAG, offsetof(Config, mkpath)},
    {"--delete-before", NULL, OPT_FLAG, offsetof(Config, delete_before)},
    {"--delete-during", "--del", OPT_FLAG, offsetof(Config, delete_during)},
    {"--delete-delay", NULL, OPT_FLAG, offsetof(Config, delete_delay)},
    {"--delete-after", NULL, OPT_FLAG, offsetof(Config, delete_after)},
    {"--delete-excluded", NULL, OPT_FLAG, offsetof(Config, delete_excluded)},
    {"--max-delete", NULL, OPT_NONNEG_INT, offsetof(Config, max_delete)},
    {"--ignore-errors", NULL, OPT_FLAG, offsetof(Config, ignore_errors)},
    {"--force", NULL, OPT_FLAG, offsetof(Config, force_delete)},
    {"--prune-empty-dirs", NULL, OPT_FLAG, offsetof(Config, prune_empty_dirs)},
    {"--ignore-missing-args", NULL, OPT_FLAG, offsetof(Config, ignore_missing_args)},
    {"--delete-missing-args", NULL, OPT_FLAG, offsetof(Config, delete_missing_args)},

    {"--source-dir", NULL, OPT_STRING, offsetof(Config, send_directory)},
    {"--dest-dir", NULL, OPT_STRING, offsetof(Config, receive_root_directory)},
    {"--server-host", NULL, OPT_STRING, offsetof(Config, server_host)},
    {"--cert", NULL, OPT_STRING, offsetof(Config, tls_cert)},
    {"--key", NULL, OPT_STRING, offsetof(Config, tls_key)},
    {"--ca", NULL, OPT_STRING, offsetof(Config, tls_ca)},
    {"--backup-dir", NULL, OPT_STRING, offsetof(Config, backup_dir)},
    {"--fastsync-server-path", NULL, OPT_STRING, offsetof(Config, fastsync_server_path)},
    {"--temp-dir", NULL, OPT_STRING, offsetof(Config, temp_dir)},
    {"--partial-dir", NULL, OPT_STRING, offsetof(Config, partial_dir)},
    {"--suffix", NULL, OPT_STRING, offsetof(Config, suffix)},
    {"--compress-choice", "--zc", OPT_STRING, offsetof(Config, compress_choice)},
    {"--compress-level", "--zl", OPT_POS_INT, offsetof(Config, compression_level)},

    {"--timeout", NULL, OPT_POS_INT, offsetof(Config, timeout)},
    {"--contimeout", NULL, OPT_POS_INT, offsetof(Config, contimeout)},
    {"--max-depth", NULL, OPT_NONNEG_INT, offsetof(Config, max_depth)},

    {"--max-size", NULL, OPT_ULL, offsetof(Config, max_size)},
    {"--min-size", NULL, OPT_ULL, offsetof(Config, min_size)},
    {"--one-file-system", "-x", OPT_FLAG, offsetof(Config, one_file_system)},
    {"--from0", "-0", OPT_FLAG, offsetof(Config, from0)},
    {"--cvs-exclude", "-C", OPT_FLAG, offsetof(Config, cvs_exclude)},
    {"-F", NULL, OPT_FLAG, offsetof(Config, per_dir_filter)},
    {"--numeric-ids", NULL, OPT_FLAG, offsetof(Config, numeric_ids)},
    {"--atimes", "-U", OPT_FLAG, offsetof(Config, preserve_atimes)},
    {"--crtimes", "-N", OPT_FLAG, offsetof(Config, preserve_crtimes)},
    /* -D is handled separately (it implies both --devices and --specials). */
    {"--devices", NULL, OPT_FLAG, offsetof(Config, preserve_devices)},
    {"--specials", NULL, OPT_FLAG, offsetof(Config, preserve_specials)},
    {"--copy-devices", NULL, OPT_FLAG, offsetof(Config, copy_devices)},
    {"--write-devices", NULL, OPT_FLAG, offsetof(Config, write_devices)},
    {"--omit-dir-times", "-O", OPT_FLAG, offsetof(Config, omit_dir_times)},
    {"--omit-link-times", "-J", OPT_FLAG, offsetof(Config, omit_link_times)},
    {"--open-noatime", NULL, OPT_FLAG, offsetof(Config, open_noatime)},
};

/* Only boolean options with no required argument are safe to negate. */
static const NegatableOption NEGATABLE_OPTIONS[] = {
    {"dry-run", "n", offsetof(Config, dry_run)},
    {"delete", NULL, offsetof(Config, use_delete)},
    {"incremental", NULL, offsetof(Config, use_incremental)},
    {"delta", NULL, offsetof(Config, use_delta)},
    {"fuzzy", NULL, offsetof(Config, fuzzy)},
    {"save-to-disk", NULL, offsetof(Config, save_to_disk)},
    {"progress", NULL, offsetof(Config, show_progress)},
    {"tls", NULL, offsetof(Config, use_tls)},
    {"backup", NULL, offsetof(Config, backup)},
    {"stats", NULL, offsetof(Config, stats)},
    {"partial", NULL, offsetof(Config, partial)},
    {"links", "l", offsetof(Config, follow_symlinks)},
    {"copy-links", NULL, offsetof(Config, copy_links)},
    {"safe-links", NULL, offsetof(Config, safe_links)},
    {"copy-unsafe-links", NULL, offsetof(Config, copy_unsafe_links)},
    {"hard-links", "H", offsetof(Config, preserve_hard_links)},
    {"sparse", "S", offsetof(Config, preserve_sparse)},
    {"inplace", NULL, offsetof(Config, inplace)},
    {"preallocate", NULL, offsetof(Config, preallocate)},
    {"checksum", NULL, offsetof(Config, checksum)},
    {"from0", NULL, offsetof(Config, from0)},
    {"cvs-exclude", NULL, offsetof(Config, cvs_exclude)},

    /* These options are also implied by --archive or handled outside the table. */
    {"compress", "c", offsetof(Config, use_compression)},
    {"compress", "z", offsetof(Config, use_compression)},
    {"multithreading", "m", offsetof(Config, use_multithreading)},
    {"preserve", "M", offsetof(Config, use_metadata)},
    {"sendfile", "f", offsetof(Config, use_sendfile)},
    {"chunk-serialization", "s", offsetof(Config, use_chunk_serialization)},
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

/* Match a "--opt=value" argument against table options that take a value. Flags,
 * no-ops, and unsupported options do not accept an inline "=" value. */
static const OptionEntry* find_table_option_with_equals(const char* arg, const char** value) {
  const char* equals = strchr(arg, '=');
  if (!equals || equals == arg)
    return NULL;
  size_t name_len = (size_t)(equals - arg);
  for (size_t i = 0; i < sizeof(OPTION_TABLE) / sizeof(OPTION_TABLE[0]); i++) {
    const OptionEntry* entry = &OPTION_TABLE[i];
    if ((strlen(entry->name) == name_len && strncmp(arg, entry->name, name_len) == 0) ||
        (entry->alias && strlen(entry->alias) == name_len &&
         strncmp(arg, entry->alias, name_len) == 0)) {
      if (entry->kind == OPT_STRING || entry->kind == OPT_POS_INT ||
          entry->kind == OPT_NONNEG_INT || entry->kind == OPT_ULL) {
        *value = equals + 1;
        return entry;
      }
    }
  }
  return NULL;
}

static const NegatableOption* find_negatable_option(const char* name) {
  for (size_t i = 0; i < sizeof(NEGATABLE_OPTIONS) / sizeof(NEGATABLE_OPTIONS[0]); i++)
    if (strcmp(name, NEGATABLE_OPTIONS[i].name) == 0 ||
        (NEGATABLE_OPTIONS[i].alias && strcmp(name, NEGATABLE_OPTIONS[i].alias) == 0))
      return &NEGATABLE_OPTIONS[i];
  return NULL;
}

static int apply_negation(Config* config, const char* arg) {
  const char* name = arg + strlen("--no-");
  if (*name == '\0') {
    fprintf(stderr, "Cannot negate an empty option name: %s\n", arg);
    return -1;
  }
  const NegatableOption* entry = find_negatable_option(name);
  if (!entry) {
    fprintf(stderr, "Cannot negate unsupported or unsafe option: %s\n", arg);
    return -1;
  }
  *(bool*)((char*)config + entry->offset) = false;
  if (entry->offset == offsetof(Config, use_metadata))
    config->metadata_explicitly_disabled = true;
  return 0;
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
    /* Size-limit options accept rsync-style suffixes (e.g. --max-size=2G); a
     * plain byte count, including 0 ("no limit"), stays valid. */
    if (parse_size_arg_allow_zero(value, &v, true) != 0) {
      log_message(LOG_LEVEL_ERROR, "%s must be a non-negative size (B, K, M, G, T, P, or E)",
                  entry->name);
      return -1;
    }
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
  /* Explicit --no-delta / --no-incremental seen on the command line: the user
     switched part of the delta machinery off, so the --fuzzy implication must
     not silently turn it back on. */
  bool no_delta = false;
  bool no_incremental = false;
  protocol_set_8_bit_output(config->eight_bit_output);

  /* Apply output controls before processing other options so their order is irrelevant. */
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
      set_log_level(LOG_LEVEL_DEBUG);
    } else if (strncmp(argv[i], "--info=", 7) == 0) {
      if (parse_info_flags(argv[i] + 7, config) != 0)
        return -1;
    } else if (strcmp(argv[i], "--info") == 0) {
      if (i + 1 >= argc || parse_info_flags(argv[++i], config) != 0)
        return -1;
    }
  }

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-P") == 0) {
      config->partial = true;
      config->show_progress = true;
      continue;
    }
    /* "--no-implied-dirs" is a real rsync option name, not a negation of
     * "--implied-dirs", so it must be handled before the generic --no-*
     * negation branch. */
    if (strcmp(argv[i], "--no-implied-dirs") == 0) {
      config->no_implied_dirs = true;
      continue;
    }
    if (strncmp(argv[i], "--no-", strlen("--no-")) == 0) {
      if (strcmp(argv[i], "--no-delta") == 0)
        no_delta = true;
      else if (strcmp(argv[i], "--no-incremental") == 0)
        no_incremental = true;
      if (apply_negation(config, argv[i]) != 0)
        return -1;
      continue;
    }
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
    const char* threads_prefix = "--compress-threads=";
    if (strncmp(argv[i], threads_prefix, strlen(threads_prefix)) == 0) {
      if (set_compression_threads_option(&config->compression_threads,
                                         argv[i] + strlen(threads_prefix)) != 0)
        return -1;
      continue;
    }
    if (strncmp(argv[i], "--max-alloc=", 12) == 0 || strcmp(argv[i], "--max-alloc") == 0) {
      const char* value = strcmp(argv[i], "--max-alloc") == 0 ? "" : argv[i] + 12;
      if (*value == '\0') {
        if (i + 1 >= argc) {
          log_message(LOG_LEVEL_ERROR, "missing argument for --max-alloc");
          return -1;
        }
        value = argv[++i];
      }
      if (parse_size_arg(value, &config->max_alloc) != 0) {
        log_message(LOG_LEVEL_ERROR,
                    "--max-alloc must be a positive size (B, K, M, G, T, P, or E)");
        return -1;
      }
      continue;
    }

    const OptionEntry* entry = find_table_option(argv[i]);
    const char* inline_value = NULL;
    if (!entry)
      entry = find_table_option_with_equals(argv[i], &inline_value);
    if (entry) {
      const char* value = NULL;
      if (entry->kind != OPT_FLAG) {
        value = inline_value;
        if (!value && i + 1 < argc)
          value = argv[++i];
        if (!value) {
          log_message(LOG_LEVEL_ERROR, "missing argument for %s", entry->name);
          return -1;
        }
        if (strcmp(entry->name, "--compress-choice") == 0) {
          if (set_compression_choice(config, value) != 0)
            return -1;
        } else {
          if (apply_table_option(config, entry, value) != 0)
            return -1;
          if (strcmp(entry->name, "--compress-level") == 0 &&
              (config->compression_level < 1 || config->compression_level > 22)) {
            log_message(LOG_LEVEL_ERROR, "--compress-level must be between 1 and 22");
            return -1;
          }
          if (entry->offset == offsetof(Config, chmod_spec)) {
            mode_t ignored;
            if (!chmod_apply(0, config->chmod_spec, &ignored)) {
              log_message(LOG_LEVEL_ERROR, "--chmod has invalid permission changes");
              return -1;
            }
            config->use_metadata = true;
          }
        }
      } else if (apply_table_option(config, entry, NULL) != 0) {
        return -1;
      }
      if (entry->offset == offsetof(Config, eight_bit_output))
        protocol_set_8_bit_output(true);
      /* A delete-timing flag selects when --delete removes extras, so it
         implies --delete exactly like the rsync options do. */
      if (entry->offset == offsetof(Config, delete_before) ||
          entry->offset == offsetof(Config, delete_during) ||
          entry->offset == offsetof(Config, delete_delay) ||
          entry->offset == offsetof(Config, delete_after))
        config->use_delete = true;
      /* --delete-missing-args implies --ignore-missing-args (missing entries
         are skipped for deletion instead of failing the run).  The implication
         is order-independent because it is applied over the final parsed
         config. */
      if (entry->offset == offsetof(Config, delete_missing_args))
        config->ignore_missing_args = true;
      /* -U/--atimes and -N/--crtimes carry their times inside the metadata
         payload, which is only transmitted when use_metadata is set, so either
         one implies metadata transmission.  This is FastSync's broad -M bundle
         (mode/mtime travel too); it does NOT enable ownership application,
         which stays opt-in via the identity flags. */
      if (entry->offset == offsetof(Config, preserve_atimes) ||
          entry->offset == offsetof(Config, preserve_crtimes))
        config->use_metadata = true;
      continue;
    }

    if (strncmp(argv[i], "--chmod=", 8) == 0) {
      if (set_string_option(&config->chmod_spec, argv[i] + 8, "--chmod") != 0)
        return -1;
      mode_t ignored;
      if (!chmod_apply(0, config->chmod_spec, &ignored)) {
        log_message(LOG_LEVEL_ERROR, "--chmod has invalid permission changes");
        return -1;
      }
      config->use_metadata = true;
      continue;
    }

    if (opt_is(argv[i], "--help", NULL)) {
      print_usage();
      return 1;
    } else if (opt_is(argv[i], "-V", "--version")) {
      printf("fastsync version %s\n", PROTOCOL_VERSION);
      return 1;
    } else if (opt_is(argv[i], "-D", NULL)) {
      /* rsync -D == --devices --specials.  -D is otherwise unassigned in
         FastSync (verified: no collision), so it is free to imply both. */
      config->preserve_devices = true;
      config->preserve_specials = true;
      log_info_message(LOG_INFO_MISC, "Enabled preservation of device and special files (-D)");
    } else if (opt_is(argv[i], "-a", "--archive")) {
      config->use_compression =
          !config->compress_choice || strcmp(config->compress_choice, "zstd") == 0;
      config->use_multithreading = true;
      config->use_metadata = true;
      log_info_message(LOG_INFO_MISC, "Enabled archive mode (-c -m -M)");
    } else if (opt_is(argv[i], "-p", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (set_positive_int_option(&config->ssh_port, argv[++i], "-p") != 0)
        return -1;
      if (config->ssh_port > 65535) {
        log_message(LOG_LEVEL_ERROR, "SSH port must be 1-65535");
        return -1;
      }
    } else if (opt_is(argv[i], "--exclude", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (config_add_pattern(&config->exclude_patterns, &config->exclude_count, argv[++i],
                             "--exclude") != 0)
        return -1;
    } else if (opt_is(argv[i], "--include", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (config_add_pattern(&config->include_patterns, &config->include_count, argv[++i],
                             "--include") != 0)
        return -1;
    } else if (opt_is(argv[i], "--delta-block", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      unsigned long long val;
      if (parse_ull_arg(argv[++i], &val, "--delta-block") != 0)
        return -1;
      if (val >= DELTA_BLOCK_SIZE_MIN && val <= DELTA_BLOCK_SIZE_MAX)
        config->delta_block_size = (uint32_t)val;
      else
        log_message(LOG_LEVEL_WARNING, "--delta-block value %llu out of range, using default", val);
    } else if (opt_is(argv[i], "--delta-max", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      unsigned long long val;
      if (parse_ull_arg(argv[++i], &val, "--delta-max") != 0)
        return -1;
      if (val >= DELTA_MIN_FILE_SIZE)
        config->delta_max_file_size = val;
      else
        log_message(LOG_LEVEL_WARNING, "--delta-max value %llu too small, using default", val);
    } else if (opt_is(argv[i], "-c", "-z")) {
      config->use_compression =
          !config->compress_choice || strcmp(config->compress_choice, "zstd") == 0;
      log_info_message(LOG_INFO_MISC, "Enabled Compression");
      if (i + 1 < argc) {
        char* end_ptr;
        long level = strtol(argv[i + 1], &end_ptr, 10);
        if (*end_ptr == '\0') {
          if (level < 1 || level > 22) {
            log_message(LOG_LEVEL_ERROR, "compression level must be 1-22");
            return -1;
          }
          config->compression_level = (int)level;
          log_info_message(LOG_INFO_MISC, "Set Compression level to %ld", level);
          i++;
        }
      }
    } else if (opt_is(argv[i], "-M", "--preserve")) {
      config->use_metadata = true;
      log_info_message(LOG_INFO_MISC, "Enabled metadata preservation");
    } else if (opt_is(argv[i], "-E", "--executability")) {
      config->use_metadata = true;
      config->use_executability = true;
      log_info_message(LOG_INFO_MISC, "Enabled executable permission preservation");
    } else if (opt_is(argv[i], "-f", "--sendfile")) {
      config->use_sendfile = true;
      log_info_message(LOG_INFO_MISC, "Enabled sendfile");
    } else if (opt_is(argv[i], "-m", NULL)) {
      config->use_multithreading = true;
      log_info_message(LOG_INFO_MISC, "Enabled Multithreading");
    } else if (opt_is(argv[i], "-s", NULL)) {
      config->use_chunk_serialization = true;
      log_info_message(LOG_INFO_MISC, "Enabled Chunk Serialization");
    } else if (opt_is(argv[i], "--server-port", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
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
    } else if (opt_is(argv[i], "--bwlimit", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
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
      log_info_message(LOG_INFO_MISC, "Set bandwidth limit to %llu KB/s", kbps);
    } else if (opt_is(argv[i], "--chunk-size", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      unsigned long long val;
      if (parse_ull_arg(argv[++i], &val, "--chunk-size") != 0)
        return -1;
      if (val == 0) {
        log_message(LOG_LEVEL_ERROR, "--chunk-size must be a positive integer");
        return -1;
      }
      config->chunk_size = val;
    } else if (opt_is(argv[i], "--log-file", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
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
    } else if (opt_is(argv[i], "--exclude-from", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (read_patterns_from_file(argv[++i], &config->exclude_patterns, &config->exclude_count) !=
          0)
        return -1;
    } else if (opt_is(argv[i], "--include-from", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (read_patterns_from_file(argv[++i], &config->include_patterns, &config->include_count) !=
          0)
        return -1;
    } else if (strncmp(argv[i], "--filter=", 9) == 0) {
      if (config_add_filter(config, argv[i] + 9) != 0)
        return -1;
    } else if (opt_is(argv[i], "--filter", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (config_add_filter(config, argv[++i]) != 0)
        return -1;
    } else if (strncmp(argv[i], "--files-from=", 13) == 0) {
      if (set_string_option(&config->files_from, argv[i] + 13, "--files-from") != 0)
        return -1;
    } else if (opt_is(argv[i], "--files-from", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (set_string_option(&config->files_from, argv[++i], "--files-from") != 0)
        return -1;
    } else if (opt_is(argv[i], "-v", "--verbose")) {
      verbose = true;
      set_log_level(LOG_LEVEL_DEBUG);
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
    } else if (strncmp(argv[i], "--info=", 7) == 0) {
      if (parse_info_flags(argv[i] + 7, config) != 0)
        return -1;
    } else if (opt_is(argv[i], "--info", NULL)) {
      if (i + 1 >= argc || parse_info_flags(argv[++i], config) != 0)
        return -1;
    } else if (opt_is(argv[i], "-T", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (set_positive_int_option(&config->timeout, argv[++i], "-T") != 0)
        return -1;
    } else if (strncmp(argv[i], "--skip-compress=", 16) == 0) {
      if (parse_skip_compress(config, argv[i] + 16) != 0)
        return -1;
    } else if (opt_is(argv[i], "--skip-compress", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (parse_skip_compress(config, argv[++i]) != 0)
        return -1;
    } else if (opt_is(argv[i], "--compress-threads", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (set_compression_threads_option(&config->compression_threads, argv[++i]) != 0)
        return -1;
    } else if (opt_is(argv[i], "--checksum-choice", "--cc")) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (set_checksum_choice(config, argv[++i]) != 0)
        return -1;
    } else if (strncmp(argv[i], "--checksum-choice=", 18) == 0) {
      if (set_checksum_choice(config, argv[i] + 18) != 0)
        return -1;
    } else if (strncmp(argv[i], "--cc=", 5) == 0) {
      if (set_checksum_choice(config, argv[i] + 5) != 0)
        return -1;
    } else if (strncmp(argv[i], "--checksum-seed=", 16) == 0) {
      if (set_checksum_seed(config, argv[i] + 16) != 0)
        return -1;
    } else if (opt_is(argv[i], "--checksum-seed", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for --checksum-seed");
        return -1;
      }
      if (set_checksum_seed(config, argv[++i]) != 0)
        return -1;
    } else if (strncmp(argv[i], "--compare-dest=", 15) == 0) {
      if (set_basis_dest_option(config, BASIS_DEST_COMPARE, argv[i] + 15, "--compare-dest") != 0)
        return -1;
    } else if (opt_is(argv[i], "--compare-dest", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (set_basis_dest_option(config, BASIS_DEST_COMPARE, argv[++i], "--compare-dest") != 0)
        return -1;
    } else if (strncmp(argv[i], "--copy-dest=", 12) == 0) {
      if (set_basis_dest_option(config, BASIS_DEST_COPY, argv[i] + 12, "--copy-dest") != 0)
        return -1;
    } else if (opt_is(argv[i], "--copy-dest", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (set_basis_dest_option(config, BASIS_DEST_COPY, argv[++i], "--copy-dest") != 0)
        return -1;
    } else if (strncmp(argv[i], "--link-dest=", 12) == 0) {
      if (set_basis_dest_option(config, BASIS_DEST_LINK, argv[i] + 12, "--link-dest") != 0)
        return -1;
    } else if (opt_is(argv[i], "--link-dest", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (set_basis_dest_option(config, BASIS_DEST_LINK, argv[++i], "--link-dest") != 0)
        return -1;
    } else if (strncmp(argv[i], "--usermap=", 10) == 0) {
      if (identity_parse_map(config, argv[i] + 10, false) != 0)
        return -1;
      config->use_metadata = true;
    } else if (opt_is(argv[i], "--usermap", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (identity_parse_map(config, argv[++i], false) != 0)
        return -1;
      config->use_metadata = true;
    } else if (strncmp(argv[i], "--groupmap=", 11) == 0) {
      if (identity_parse_map(config, argv[i] + 11, true) != 0)
        return -1;
      config->use_metadata = true;
    } else if (opt_is(argv[i], "--groupmap", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (identity_parse_map(config, argv[++i], true) != 0)
        return -1;
      config->use_metadata = true;
    } else if (strncmp(argv[i], "--chown=", 8) == 0) {
      if (identity_parse_chown(config, argv[i] + 8) != 0)
        return -1;
      config->use_metadata = true;
    } else if (opt_is(argv[i], "--chown", NULL)) {
      if (i + 1 >= argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for %s", argv[i]);
        return -1;
      }
      if (identity_parse_chown(config, argv[++i]) != 0)
        return -1;
      config->use_metadata = true;
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
  if (config->compress_choice)
    config->use_compression = strcmp(config->compress_choice, "zstd") == 0;

  /* --files-from is loaded after every argument is seen so that -0/--from0 may
   * appear anywhere on the command line. A missing or unreadable file, and
   * invalid (absolute / traversal) entries, are hard CLI errors. */
  if (config->files_from) {
    char err[256];
    FileListSet* set = file_list_load(config->files_from, config->from0, err, sizeof(err));
    if (!set) {
      log_message(LOG_LEVEL_ERROR, "--files-from: %s", err);
      return -1;
    }
    file_list_destroy((FileListSet*)config->files_from_set);
    config->files_from_set = set;
  }

  /* Device/special preservation recreates a node from its metadata mode (whose
     S_IFMT bits carry the node kind), so --devices/--specials/-D imply metadata
     transmission.  --copy-devices/--write-devices treat the entry as data but a
     mtime/mode-preserving transfer still benefits from metadata, so all four
     imply it (FastSync's broad -M bundle; ownership stays opt-in). */
  if (config->preserve_devices || config->preserve_specials || config->copy_devices ||
      config->write_devices)
    config->use_metadata = true;

  /* The "unchanged" decision for --compare-dest/--copy-dest/--link-dest must
   * be made on the receiver against the basis directories, which requires the
   * per-file STATUS_CHECK handshake: basis-dir options therefore imply
   * --incremental (and, via the block below, metadata) on the sender. */
  if (config_has_basis(config))
    config->use_incremental = true;

  /* -y/--fuzzy reuses an existing similar-named destination file as the delta
   * basis, so it is meaningless without the receiver-driven delta path:
   * imply --incremental and --delta unless --whole-file or an explicit
   * --no-delta / --no-incremental switched the machinery off.  FastSync has
   * delta OFF by default (unlike rsync), so a bare --fuzzy must turn it on or
   * it would be a silent no-op.  -W/--no-delta/--no-incremental therefore
   * leave fuzzy inert, matching rsync where --whole-file makes fuzzy
   * irrelevant (note: unlike the basis-dir options, --fuzzy honors an
   * explicit --no-incremental instead of forcing the handshake back on). */
  if (config->fuzzy) {
    if (!no_incremental)
      config->use_incremental = true;
    /* Delta needs the incremental per-file handshake, so an explicit
     * --no-incremental also suppresses the delta implication. */
    if (!config->whole_file && !no_delta && !no_incremental)
      config->use_delta = true;
  }

  /* --append / --append-verify resume a shorter existing destination file.
   * The receiver must run the per-file STATUS_CHECK handshake to learn the
   * destination length and reply STATUS_APPEND, so an append mode forces
   * --incremental on (exactly like the basis-dir options: the handshake is
   * required, not optional).  The resume itself is a dedicated tail-only
   * exchange, not the block delta, so no delta implication is made.  When both
   * spelling are given the safer --append-verify semantics win. */
  if (config->append || config->append_verify) {
    config->use_incremental = true;
  }

  /* Incremental and delta transfers need metadata unless the user disabled it. */
  if ((config->use_incremental || config->use_delta) && !config->use_metadata &&
      !config->metadata_explicitly_disabled) {
    log_message(LOG_LEVEL_INFO, "Enabling metadata preservation for incremental/delta transfer");
    config->use_metadata = true;
  }
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
  /* The server may close a connection mid-stream (e.g. when it rejects an
     oversized delta).  Ignore SIGPIPE so that a broken TCP connection
     surfaces as a clean write error instead of killing the client. */
  signal(SIGPIPE, SIG_IGN);
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

  /* --open-noatime is a sender-side policy: install it for every source read
     (scan + data path) without touching the receiver. */
  file_set_open_noatime(config->open_noatime);

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
