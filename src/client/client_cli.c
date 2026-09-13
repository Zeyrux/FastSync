#include "client_send.h"
#include "client_validation.h"
#include "charset.h"
#include "chmod.h"
#include "compression.h"
#include "config.h"
#include "credentials.h"
#include "delta.h"
#include "file.h"
#include "file_list.h"
#include "filter.h"
#include "identity.h"
#include "log.h"
#include "protocol.h"
#include "stop_condition.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include "usage.h"
#include "utils.h"
#include <errno.h>
#include <limits.h>
#include <time.h>
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

/* Parse and validate --sockopts=OPTIONS into the config.  The strict allowlist
 * (config_sockopts_parse) rejects an unknown option name or an invalid value
 * up front, so a typo never silently disables a socket option. */
static int set_sockopts_option(Config* config, const char* value) {
  SockOptEntry* entries = NULL;
  int count = 0;
  if (config_sockopts_parse(value, &entries, &count) != 0) {
    log_message(LOG_LEVEL_ERROR,
                "--sockopts must be a comma-separated OPT=VAL list of supported options "
                "(TCP_NODELAY, SO_KEEPALIVE, SO_RCVBUF, SO_SNDBUF, SO_REUSEADDR)");
    return -1;
  }
  free(config->sockopts);
  config->sockopt_count = count;
  config->sockopts = entries;
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

/* Forward decl: config_add_pattern is defined below, but the --remote-option
 * helper above needs it. */
static int config_add_pattern(char*** patterns, int* count, const char* value, const char* optname);

/* Validate and append one --remote-option=OPT value.  OPT is forwarded to the
 * remote server invocation (over SSH) by appending it to the remote command
 * line, so it must be a single safe shell word: it must be non-empty and must
 * contain no control characters that could break the single-quoted command
 * word ssh_build_remote_command wraps it in (newline/CR and other ASCII
 * control chars are rejected up front).  Ordinary shell metacharacters
 * (; & | ` $ () etc.) need not be rejected because they are neutralized by the
 * single-quoting boundary, but rejecting control characters keeps the
 * quoting scheme airtight regardless of the remote shell.  Returns 0 on
 * success, -1 on a rejected value. */
static int config_add_remote_option(Config* config, const char* value, const char* optname) {
  if (!value || value[0] == '\0') {
    log_message(LOG_LEVEL_ERROR, "%s requires a non-empty option value", optname);
    return -1;
  }
  for (const unsigned char* p = (const unsigned char*)value; *p; p++) {
    if (*p < 0x20 || *p == 0x7f) {
      log_message(LOG_LEVEL_ERROR,
                  "%s value contains a control character that could break the remote shell "
                  "quoting; rejecting",
                  optname);
      return -1;
    }
  }
  if (config_add_pattern(&config->remote_options, &config->remote_option_count, value, optname) !=
      0)
    return -1;
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

/* Parse --outbuf=N|L|B into the config's OutbufMode.  N=none (unbuffered),
 * L=line-buffered, B=block-buffered (the stdio default).  Anything else is a
 * clear error, never a silent fallback. */
static int set_outbuf_option(Config* config, const char* value) {
  if (strcmp(value, "N") == 0 || strcmp(value, "n") == 0)
    config->outbuf = OUTBUF_NONE;
  else if (strcmp(value, "L") == 0 || strcmp(value, "l") == 0)
    config->outbuf = OUTBUF_LINE;
  else if (strcmp(value, "B") == 0 || strcmp(value, "b") == 0)
    config->outbuf = OUTBUF_BLOCK;
  else {
    log_message(LOG_LEVEL_ERROR, "--outbuf must be N (none), L (line), or B (block)");
    return -1;
  }
  return 0;
}

#ifndef FASTSYNC_TEST_BUILD
/* Apply the parsed --outbuf style to stdout/stderr via setvbuf, matching stdio
 * semantics: N -> _IONBF (unbuffered), L -> _IOLBF (line), B -> _IOFBF (block,
 * the default). */
static void apply_output_buffering(const Config* config) {
  int mode = config->outbuf;
  int stdio_mode = (mode == OUTBUF_NONE) ? _IONBF : (mode == OUTBUF_LINE) ? _IOLBF : _IOFBF;
  setvbuf(stdout, NULL, stdio_mode, 0);
  setvbuf(stderr, NULL, stdio_mode, 0);
}
#endif

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

/* Apply a --delta-block/--block-size value (both spellings and both the inline
 * and separate argument forms share this one range check).  An out-of-range
 * value warns once and leaves the configured default untouched.  Returns 0 on
 * success, -1 on a non-numeric value. */
static int set_delta_block_size(Config* config, const char* value) {
  unsigned long long val;
  if (parse_ull_arg(value, &val, "--block-size/--delta-block") != 0)
    return -1;
  if (val >= DELTA_BLOCK_SIZE_MIN && val <= DELTA_BLOCK_SIZE_MAX)
    config->delta_block_size = (uint32_t)val;
  else
    log_message(LOG_LEVEL_WARNING, "block size value %llu out of range, using default", val);
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
    if (config->skip_compress_count >= MAX_SKIP_COMPRESS_SUFFIXES) {
      fprintf(stderr, "--skip-compress supports at most %d suffixes\n", MAX_SKIP_COMPRESS_SUFFIXES);
      free(list);
      return -1;
    }
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
    {"--secluded-args", "-s", OPT_NOOP, 0},
    {"--update", "-u", OPT_FLAG, offsetof(Config, update)},
    {"--old-args", NULL, OPT_FLAG, offsetof(Config, old_args)},
    {"--rsh", "-e", OPT_STRING, offsetof(Config, rsh_command)},
    {"--blocking-io", NULL, OPT_FLAG, offsetof(Config, blocking_io)},
    {"--links", "-l", OPT_FLAG, offsetof(Config, follow_symlinks)},
    {"--copy-links", NULL, OPT_FLAG, offsetof(Config, copy_links)},
    {"--safe-links", NULL, OPT_FLAG, offsetof(Config, safe_links)},
    {"--copy-unsafe-links", NULL, OPT_FLAG, offsetof(Config, copy_unsafe_links)},
    {"--copy-dirlinks", "-k", OPT_FLAG, offsetof(Config, copy_dirlinks)},
    {"--keep-dirlinks", "-K", OPT_FLAG, offsetof(Config, keep_dirlinks)},
    {"--munge-links", NULL, OPT_FLAG, offsetof(Config, munge_links)},
    {"--hard-links", "-H", OPT_FLAG, offsetof(Config, preserve_hard_links)},
    {"--sparse", "-S", OPT_FLAG, offsetof(Config, preserve_sparse)},
    {"--inplace", NULL, OPT_FLAG, offsetof(Config, inplace)},
    {"--preallocate", NULL, OPT_FLAG, offsetof(Config, preallocate)},
    {"--append", NULL, OPT_FLAG, offsetof(Config, append)},
    {"--append-verify", NULL, OPT_FLAG, offsetof(Config, append_verify)},
    {"--fsync", NULL, OPT_FLAG, offsetof(Config, use_fsync)},
    {"--checksum", "-c", OPT_FLAG, offsetof(Config, checksum)},
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
    /* --password-file: client-only path to a `user:password` secret file used
     * to authenticate a daemon (host::module/path) destination.  Stored as a
     * path; main() reads it (after the destination form is known) and derives
     * the wire credentials.  Never crosses the wire. */
    {"--password-file", NULL, OPT_STRING, offsetof(Config, password_file)},
    /* --iconv (protocol 2.16.0): convert file-NAME charsets at the wire
     * boundary.  The CONVERT_SPEC (LOCAL[,REMOTE]) is validated for real iconv
     * charsets at startup (client_validation.c) and the full spec rides the
     * config frame so the receiver derives the wire charset symmetrically. */
    {"--iconv", NULL, OPT_STRING, offsetof(Config, iconv_spec)},
    /* --protocol=NUM: rsync-compatible flag that forces the wire protocol
     * version to the current value.  FastSync has exactly one wire format, so
     * any value other than PROTOCOL_VERSION is rejected at validation, before
     * any network I/O.  Client-only: the server does not negotiate, it just
     * enforces an exact match. */
    {"--protocol", NULL, OPT_STRING, offsetof(Config, version)},
    /* Phase 6 residual-batch (client-only): --write-batch=FILE runs the normal
     * live transfer AND also emits the self-contained batch FILE;
     * --only-write-batch=FILE emits FILE only (no destination, no server);
     * --read-batch=FILE applies FILE to the destination (no source, no server).
     * All three are LOCAL driver flags and never cross the wire. */
    {"--write-batch", NULL, OPT_STRING, offsetof(Config, write_batch)},
    {"--only-write-batch", NULL, OPT_STRING, offsetof(Config, only_write_batch)},
    {"--read-batch", NULL, OPT_STRING, offsetof(Config, read_batch)},
    {"--delete-before", NULL, OPT_FLAG, offsetof(Config, delete_before)},
    {"--delete-during", "--del", OPT_FLAG, offsetof(Config, delete_during)},
    {"--delete-delay", NULL, OPT_FLAG, offsetof(Config, delete_delay)},
    {"--delete-after", NULL, OPT_FLAG, offsetof(Config, delete_after)},
    {"--delete-excluded", NULL, OPT_FLAG, offsetof(Config, delete_excluded)},
    {"--max-delete", NULL, OPT_NONNEG_INT, offsetof(Config, max_delete)},
    {"--ignore-errors", NULL, OPT_FLAG, offsetof(Config, ignore_errors)},
    {"--force", NULL, OPT_FLAG, offsetof(Config, force_delete)},
    {"--prune-empty-dirs", "-m", OPT_FLAG, offsetof(Config, prune_empty_dirs)},
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
    /* --rsync-path is rsync's spelling for the same "server program path"; it
     * is a pure alias for fastsync_server_path (never a distinct field). */
    {"--rsync-path", NULL, OPT_STRING, offsetof(Config, fastsync_server_path)},
    {"--temp-dir", "-T", OPT_STRING, offsetof(Config, temp_dir)},
    {"--partial-dir", NULL, OPT_STRING, offsetof(Config, partial_dir)},
    {"--suffix", NULL, OPT_STRING, offsetof(Config, suffix)},
    {"--compress-choice", "--zc", OPT_STRING, offsetof(Config, compress_choice)},
    {"--compress-level", "--zl", OPT_POS_INT, offsetof(Config, compression_level)},

    {"--timeout", NULL, OPT_POS_INT, offsetof(Config, timeout)},
    {"--contimeout", NULL, OPT_POS_INT, offsetof(Config, contimeout)},
    {"--max-depth", NULL, OPT_NONNEG_INT, offsetof(Config, max_depth)},
    {"--address", NULL, OPT_STRING, offsetof(Config, address)},
    {"--ipv4", "-4", OPT_FLAG, offsetof(Config, ipv4)},
    {"--ipv6", "-6", OPT_FLAG, offsetof(Config, ipv6)},

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
    {"--xattrs", "-X", OPT_FLAG, offsetof(Config, preserve_xattrs)},
    {"--acls", "-A", OPT_FLAG, offsetof(Config, preserve_acls)},
    {"--fake-super", NULL, OPT_FLAG, offsetof(Config, fake_super)},
    /* rsync's -M/--remote-option: -M is now the short alias for --remote-option
     * (metadata mode is long-only --preserve), handled in the parse loop where
     * --remote-option is parsed.  --trust-sender is a local receiver policy and
     * never travels to the remote peer. */
    {"--trust-sender", NULL, OPT_FLAG, offsetof(Config, trust_sender)},
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
    {"checksum", "c", offsetof(Config, checksum)},
    {"from0", NULL, offsetof(Config, from0)},
    {"cvs-exclude", NULL, offsetof(Config, cvs_exclude)},

    /* These options are also implied by --archive or handled outside the table. */
    {"compress", NULL, offsetof(Config, use_compression)},
    {"compress", "z", offsetof(Config, use_compression)},
    {"multithreading", "j", offsetof(Config, use_multithreading)},
    {"preserve", NULL, offsetof(Config, use_metadata)},
    {"sendfile", NULL, offsetof(Config, use_sendfile)},
    {"chunk-serialization", NULL, offsetof(Config, use_chunk_serialization)},
    {"xattrs", "X", offsetof(Config, preserve_xattrs)},
    {"acls", "A", offsetof(Config, preserve_acls)},
    {"fake-super", NULL, offsetof(Config, fake_super)},
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

/* Shared state for the parse_args helper functions.  Keeping the cursor and the
 * mutable parse flags here avoids threading a long parameter list through every
 * option handler while preserving the original single-pass control flow. */
typedef struct {
  Config* config;
  int argc;
  char** argv;
  int i;               /* index of the argument currently being examined */
  int exit_code;       /* nonzero when a matched handler wants parse_args to return */
  bool verbose;        /* "-v"/"--verbose" seen (drives the final log level) */
  bool no_delta;       /* explicit "--no-delta" seen */
  bool no_incremental; /* explicit "--no-incremental" seen */
} CliParseCtx;

/* Apply output controls before processing other options so their order is
 * irrelevant.  Returns 0 on success, -1 on error. */
static int cli_apply_output_controls(Config* config, int argc, char* argv[]) {
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
  return 0;
}

/* Options handled before the generic --no-* negation branch: -P and the real
 * rsync option names that merely start with "--no-" (--no-implied-dirs,
 * --no-motd, --no-super), plus the generic negation itself.  Returns true when
 * the argument was consumed. */
static bool cli_handle_pre_negation(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (strcmp(arg, "-P") == 0) {
    config->partial = true;
    config->show_progress = true;
    return true;
  }
  /* "--no-implied-dirs" is a real rsync option name, not a negation of
   * "--implied-dirs", so it must be handled before the generic --no-*
   * negation branch. */
  if (strcmp(arg, "--no-implied-dirs") == 0) {
    config->no_implied_dirs = true;
    return true;
  }
  /* "--no-motd" is a real rsync option name (client-side daemon MOTD display
   * suppression), not a negation of a "--motd" flag, so it is handled before
   * the generic --no-* negation branch. */
  if (strcmp(arg, "--no-motd") == 0) {
    config->no_motd = true;
    return true;
  }
  /* "--super" / "--no-super" are real rsync option names controlling the
   * receiver's super-user activity policy (ownership, device nodes), not a
   * Boolean pair for the generic --no-* negation branch: both map onto the
   * Config->super_mode tri-state.  Handle them explicitly (exact match only,
   * so a malformed "--super=x" still falls through to the unknown-option
   * error) before the generic negation branch would mis-reject "--no-super". */
  if (strcmp(arg, "--super") == 0) {
    config->super_mode = SUPER_MODE_ON;
    return true;
  }
  if (strcmp(arg, "--no-super") == 0) {
    config->super_mode = SUPER_MODE_OFF;
    return true;
  }
  if (strncmp(arg, "--no-", strlen("--no-")) == 0) {
    if (strcmp(arg, "--no-delta") == 0)
      ctx->no_delta = true;
    else if (strcmp(arg, "--no-incremental") == 0)
      ctx->no_incremental = true;
    if (apply_negation(config, arg) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    return true;
  }
  return false;
}

/* Numeric/range/time options with dedicated prefixes: --modify-window, -@,
 * --stop-after, --stop-at, --compress-threads and --max-alloc.  Returns true
 * when the argument was consumed. */
static bool cli_handle_range_time_options(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  const char* modify_window_prefix = "--modify-window=";
  if (strncmp(arg, modify_window_prefix, strlen(modify_window_prefix)) == 0) {
    if (set_nonneg_int_option(&config->modify_window, arg + strlen(modify_window_prefix),
                              "--modify-window") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "-@", 2) == 0 && arg[2] != '\0') {
    if (set_nonneg_int_option(&config->modify_window, arg + 2, "-@") != 0)
      ctx->exit_code = -1;
    return true;
  }
  /* --stop-after/--stop-at are client-only sender-side stop deadlines.  They
   * are parsed by stop_condition (so the unit tests exercise the same validate
   * that production uses) and never serialized into the config frame. */
  if (strncmp(arg, "--stop-after=", 13) == 0) {
    if (!stop_parse_after_minutes(arg + 13, &config->stop_after_mins)) {
      log_message(LOG_LEVEL_ERROR, "--stop-after must be a positive number of minutes");
      ctx->exit_code = -1;
    }
    return true;
  }
  if (strcmp(arg, "--stop-after") == 0) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for --stop-after");
      ctx->exit_code = -1;
      return true;
    }
    if (!stop_parse_after_minutes(ctx->argv[++ctx->i], &config->stop_after_mins)) {
      log_message(LOG_LEVEL_ERROR, "--stop-after must be a positive number of minutes");
      ctx->exit_code = -1;
    }
    return true;
  }
  if (strncmp(arg, "--stop-at=", 10) == 0) {
    if (!stop_parse_at_time(arg + 10, time(NULL), &config->stop_at)) {
      log_message(LOG_LEVEL_ERROR, "--stop-at must be HH:MM[:SS] or now+N[smhd]");
      ctx->exit_code = -1;
      return true;
    }
    config->stop_at_set = true;
    return true;
  }
  if (strcmp(arg, "--stop-at") == 0) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for --stop-at");
      ctx->exit_code = -1;
      return true;
    }
    if (!stop_parse_at_time(ctx->argv[++ctx->i], time(NULL), &config->stop_at)) {
      log_message(LOG_LEVEL_ERROR, "--stop-at must be HH:MM[:SS] or now+N[smhd]");
      ctx->exit_code = -1;
      return true;
    }
    config->stop_at_set = true;
    return true;
  }
  const char* threads_prefix = "--compress-threads=";
  if (strncmp(arg, threads_prefix, strlen(threads_prefix)) == 0) {
    if (set_compression_threads_option(&config->compression_threads,
                                       arg + strlen(threads_prefix)) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--max-alloc=", 12) == 0 || strcmp(arg, "--max-alloc") == 0) {
    const char* value = strcmp(arg, "--max-alloc") == 0 ? "" : arg + 12;
    if (*value == '\0') {
      if (ctx->i + 1 >= ctx->argc) {
        log_message(LOG_LEVEL_ERROR, "missing argument for --max-alloc");
        ctx->exit_code = -1;
        return true;
      }
      value = ctx->argv[++ctx->i];
    }
    if (parse_size_arg(value, &config->max_alloc) != 0) {
      log_message(LOG_LEVEL_ERROR, "--max-alloc must be a positive size (B, K, M, G, T, P, or E)");
      ctx->exit_code = -1;
    }
    return true;
  }
  return false;
}

/* Options that map directly onto a Config field through OPTION_TABLE, plus the
 * derived implications those options trigger.  Returns true when an entry
 * matched. */
static bool cli_handle_table_option(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  const OptionEntry* entry = find_table_option(arg);
  const char* inline_value = NULL;
  if (!entry)
    entry = find_table_option_with_equals(arg, &inline_value);
  if (!entry)
    return false;
  const char* value = NULL;
  if (entry->kind != OPT_FLAG) {
    value = inline_value;
    if (!value && ctx->i + 1 < ctx->argc)
      value = ctx->argv[++ctx->i];
    if (!value) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", entry->name);
      ctx->exit_code = -1;
      return true;
    }
    if (strcmp(entry->name, "--compress-choice") == 0) {
      if (set_compression_choice(config, value) != 0) {
        ctx->exit_code = -1;
        return true;
      }
    } else {
      if (apply_table_option(config, entry, value) != 0) {
        ctx->exit_code = -1;
        return true;
      }
      if (strcmp(entry->name, "--compress-level") == 0 &&
          (config->compression_level < 1 || config->compression_level > 22)) {
        log_message(LOG_LEVEL_ERROR, "--compress-level must be between 1 and 22");
        ctx->exit_code = -1;
        return true;
      }
      if (entry->offset == offsetof(Config, chmod_spec)) {
        mode_t ignored;
        if (!chmod_apply(0, config->chmod_spec, &ignored)) {
          log_message(LOG_LEVEL_ERROR, "--chmod has invalid permission changes");
          ctx->exit_code = -1;
          return true;
        }
        config->use_metadata = true;
      }
    }
  } else if (apply_table_option(config, entry, NULL) != 0) {
    ctx->exit_code = -1;
    return true;
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
  if (entry->offset == offsetof(Config, preserve_xattrs) ||
      entry->offset == offsetof(Config, preserve_acls)) {
    config->use_metadata = true;
    config->use_xattrs = config->preserve_acls || config->preserve_xattrs;
  }
  if (entry->offset == offsetof(Config, fake_super))
    config->use_metadata = true;
  return true;
}

/* The inline "--chmod=SPEC" form (kept as its own handler because it bypasses
 * the table's OPT_STRING storage).  Returns true when the argument was
 * consumed. */
static bool cli_handle_inline_chmod(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (strncmp(arg, "--chmod=", 8) != 0)
    return false;
  if (set_string_option(&config->chmod_spec, arg + 8, "--chmod") != 0) {
    ctx->exit_code = -1;
    return true;
  }
  mode_t ignored;
  if (!chmod_apply(0, config->chmod_spec, &ignored)) {
    log_message(LOG_LEVEL_ERROR, "--chmod has invalid permission changes");
    ctx->exit_code = -1;
    return true;
  }
  config->use_metadata = true;
  return true;
}

/* Help/version and the short archive-style flags.  Returns true when the
 * argument was consumed. */
static bool cli_handle_meta_flags(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (opt_is(arg, "--help", NULL)) {
    print_usage();
    ctx->exit_code = 1;
    return true;
  }
  if (opt_is(arg, "-V", "--version")) {
    printf("fastsync version %s\n", PROTOCOL_VERSION);
    ctx->exit_code = 1;
    return true;
  }
  if (opt_is(arg, "-D", NULL)) {
    /* rsync -D == --devices --specials.  -D is otherwise unassigned in
       FastSync (verified: no collision), so it is free to imply both. */
    config->preserve_devices = true;
    config->preserve_specials = true;
    log_info_message(LOG_INFO_MISC, "Enabled preservation of device and special files (-D)");
    return true;
  }
  if (opt_is(arg, "-a", "--archive")) {
    /* Real rsync archive (-rlptgoD).  FastSync is always recursive and always
     * preserves hard-link/other transfer semantics per its own flags, so -a
     * implies links, full metadata (perms/times/group/owner as FastSync's
     * broad bundle), devices and specials.  Compression and multithreading
     * are NOT implied (they are no longer part of archive mode). */
    config->follow_symlinks = true;
    config->use_metadata = true;
    config->preserve_devices = true;
    config->preserve_specials = true;
    log_info_message(LOG_INFO_MISC,
                     "Enabled archive mode (-rlptgoD: links, metadata, devices, specials)");
    return true;
  }
  if (opt_is(arg, "-p", "--perms")) {
    /* rsync -p/--perms: preserve permission bits.  Folded into FastSync's
     * broad metadata bundle (mode/mtime travel together). */
    config->use_metadata = true;
    log_info_message(LOG_INFO_MISC, "Enabled permission preservation");
    return true;
  }
  return false;
}

/* SSH port and pattern/block-size options.  Returns true when the argument was
 * consumed. */
static bool cli_handle_ssh_and_pattern_options(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (opt_is(arg, "--ssh-port", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_positive_int_option(&config->ssh_port, ctx->argv[++ctx->i], "--ssh-port") != 0) {
      ctx->exit_code = -1;
      return true;
    }
    if (config->ssh_port > 65535) {
      log_message(LOG_LEVEL_ERROR, "SSH port must be 1-65535");
      ctx->exit_code = -1;
    }
    return true;
  }
  if (strncmp(arg, "--ssh-port=", 11) == 0) {
    if (set_positive_int_option(&config->ssh_port, arg + 11, "--ssh-port") != 0) {
      ctx->exit_code = -1;
      return true;
    }
    if (config->ssh_port > 65535) {
      log_message(LOG_LEVEL_ERROR, "SSH port must be 1-65535");
      ctx->exit_code = -1;
    }
    return true;
  }
  if (opt_is(arg, "--exclude", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (config_add_pattern(&config->exclude_patterns, &config->exclude_count, ctx->argv[++ctx->i],
                           "--exclude") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--include", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (config_add_pattern(&config->include_patterns, &config->include_count, ctx->argv[++ctx->i],
                           "--include") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--delta-block=", 14) == 0) {
    if (set_delta_block_size(config, arg + 14) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--block-size=", 13) == 0) {
    if (set_delta_block_size(config, arg + 13) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--delta-block", "--block-size")) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_delta_block_size(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--delta-max", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    unsigned long long val;
    if (parse_ull_arg(ctx->argv[++ctx->i], &val, "--delta-max") != 0) {
      ctx->exit_code = -1;
      return true;
    }
    if (val >= DELTA_MIN_FILE_SIZE)
      config->delta_max_file_size = val;
    else
      log_message(LOG_LEVEL_WARNING, "--delta-max value %llu too small, using default", val);
    return true;
  }
  return false;
}

/* Transfer-behavior flags that only toggle a Config field (plus their info
 * log lines).  Returns true when the argument was consumed. */
static bool cli_handle_transfer_flags(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (opt_is(arg, "-z", "--compress")) {
    config->use_compression =
        !config->compress_choice || strcmp(config->compress_choice, "zstd") == 0;
    log_info_message(LOG_INFO_MISC, "Enabled Compression");
    if (ctx->i + 1 < ctx->argc) {
      char* end_ptr;
      long level = strtol(ctx->argv[ctx->i + 1], &end_ptr, 10);
      if (*end_ptr == '\0') {
        if (level < 1 || level > 22) {
          log_message(LOG_LEVEL_ERROR, "compression level must be 1-22");
          ctx->exit_code = -1;
          return true;
        }
        config->compression_level = (int)level;
        log_info_message(LOG_INFO_MISC, "Set Compression level to %ld", level);
        ctx->i++;
      }
    }
    return true;
  }
  if (opt_is(arg, "--preserve", NULL)) {
    config->use_metadata = true;
    log_info_message(LOG_INFO_MISC, "Enabled metadata preservation");
    return true;
  }
  if (opt_is(arg, "-E", "--executability")) {
    config->use_metadata = true;
    config->use_executability = true;
    log_info_message(LOG_INFO_MISC, "Enabled executable permission preservation");
    return true;
  }
  if (opt_is(arg, "--sendfile", NULL)) {
    config->use_sendfile = true;
    log_info_message(LOG_INFO_MISC, "Enabled sendfile");
    return true;
  }
  if (opt_is(arg, "-j", "--threads")) {
    config->use_multithreading = true;
    log_info_message(LOG_INFO_MISC, "Enabled Multithreading");
    return true;
  }
  if (opt_is(arg, "--chunk-serialization", NULL)) {
    config->use_chunk_serialization = true;
    log_info_message(LOG_INFO_MISC, "Enabled Chunk Serialization");
    return true;
  }
  return false;
}

/* Network/IO options: --server-port, --bwlimit, --chunk-size, --log-file and
 * --stderr.  Returns true when the argument was consumed. */
static bool cli_handle_io_options(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (opt_is(arg, "--server-port", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (!parse_positive_int(ctx->argv[++ctx->i], &config->server_port)) {
      char* escaped = output_escape(ctx->argv[ctx->i], false);
      log_message(LOG_LEVEL_ERROR, "invalid --server-port value: %s",
                  escaped ? escaped : "<allocation failed>");
      free(escaped);
      ctx->exit_code = -1;
      return true;
    }
    if (config->server_port > 65535) {
      log_message(LOG_LEVEL_ERROR, "server port must be 1-65535");
      ctx->exit_code = -1;
    }
    return true;
  }
  if (opt_is(arg, "--bwlimit", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    unsigned long long kbps;
    if (parse_ull_arg(ctx->argv[++ctx->i], &kbps, "--bwlimit") != 0) {
      ctx->exit_code = -1;
      return true;
    }
    if (kbps == 0) {
      log_message(LOG_LEVEL_ERROR, "--bwlimit must be a positive integer");
      ctx->exit_code = -1;
      return true;
    }
    if (kbps > ULLONG_MAX / 1024) {
      log_message(LOG_LEVEL_ERROR, "--bwlimit value too large");
      ctx->exit_code = -1;
      return true;
    }
    io_set_bwlimit(kbps * 1024);
    log_info_message(LOG_INFO_MISC, "Set bandwidth limit to %llu KB/s", kbps);
    return true;
  }
  if (opt_is(arg, "--chunk-size", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    unsigned long long val;
    if (parse_ull_arg(ctx->argv[++ctx->i], &val, "--chunk-size") != 0) {
      ctx->exit_code = -1;
      return true;
    }
    if (val == 0) {
      log_message(LOG_LEVEL_ERROR, "--chunk-size must be a positive integer");
      ctx->exit_code = -1;
      return true;
    }
    config->chunk_size = val;
    return true;
  }
  if (opt_is(arg, "--log-file", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (config->log_file) {
      /* Detach the logger before closing: log I/O may be in flight and must
         never touch a freed FILE*. */
      log_set_file(NULL);
      fclose(config->log_file);
      config->log_file = NULL;
    }
    FILE* lf = fopen(ctx->argv[++ctx->i], "a");
    if (!lf) {
      char* escaped = output_escape(ctx->argv[ctx->i], false);
      log_message(LOG_LEVEL_ERROR, "could not open log file '%s': %s",
                  escaped ? escaped : "<allocation failed>", strerror(errno));
      free(escaped);
      ctx->exit_code = -1;
      return true;
    }
    config->log_file = lf;
    log_set_file(lf);
    return true;
  }
  if (strncmp(arg, "--stderr=", 9) == 0) {
    if (set_stderr_mode(arg + 9) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--stderr", NULL)) {
    if (ctx->i + 1 >= ctx->argc || set_stderr_mode(ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  return false;
}

/* Filter / files-from options.  Returns true when the argument was consumed. */
static bool cli_handle_filter_options(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (opt_is(arg, "--exclude-from", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (read_patterns_from_file(ctx->argv[++ctx->i], &config->exclude_patterns,
                                &config->exclude_count) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--include-from", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (read_patterns_from_file(ctx->argv[++ctx->i], &config->include_patterns,
                                &config->include_count) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--filter=", 9) == 0) {
    if (config_add_filter(config, arg + 9) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "-f=", 3) == 0) {
    if (config_add_filter(config, arg + 3) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--filter", "-f")) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (config_add_filter(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--files-from=", 13) == 0) {
    if (set_string_option(&config->files_from, arg + 13, "--files-from") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--files-from", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_string_option(&config->files_from, ctx->argv[++ctx->i], "--files-from") != 0)
      ctx->exit_code = -1;
    return true;
  }
  return false;
}

/* Logging/verbosity options: -v/--verbose, -q/--quiet, --debug, --info and
 * --skip-compress.  Returns true when the argument was consumed. */
static bool cli_handle_logging_options(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (opt_is(arg, "-v", "--verbose")) {
    ctx->verbose = true;
    set_log_level(LOG_LEVEL_DEBUG);
    return true;
  }
  if (opt_is(arg, "-q", "--quiet")) {
    config->quiet = true;
    return true;
  }
  if (strncmp(arg, "--debug=", 8) == 0) {
    int debug_ret = parse_debug_flags(arg + 8, config);
    if (debug_ret != 0)
      ctx->exit_code = debug_ret;
    return true;
  }
  if (opt_is(arg, "--debug", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      ctx->exit_code = parse_debug_flags(NULL, config);
      return true;
    }
    int debug_ret = parse_debug_flags(ctx->argv[++ctx->i], config);
    if (debug_ret != 0)
      ctx->exit_code = debug_ret;
    return true;
  }
  if (strncmp(arg, "--info=", 7) == 0) {
    if (parse_info_flags(arg + 7, config) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--info", NULL)) {
    if (ctx->i + 1 >= ctx->argc || parse_info_flags(ctx->argv[++ctx->i], config) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--skip-compress=", 16) == 0) {
    if (parse_skip_compress(config, arg + 16) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--skip-compress", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (parse_skip_compress(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  return false;
}

/* Checksum/socket options: --compress-threads, --checksum-choice, --cc,
 * --checksum-seed and --sockopts.  Returns true when the argument was
 * consumed. */
static bool cli_handle_checksum_options(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (opt_is(arg, "--compress-threads", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_compression_threads_option(&config->compression_threads, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--checksum-choice", "--cc")) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_checksum_choice(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--checksum-choice=", 18) == 0) {
    if (set_checksum_choice(config, arg + 18) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--cc=", 5) == 0) {
    if (set_checksum_choice(config, arg + 5) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--checksum-seed=", 16) == 0) {
    if (set_checksum_seed(config, arg + 16) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--checksum-seed", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for --checksum-seed");
      ctx->exit_code = -1;
      return true;
    }
    if (set_checksum_seed(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--sockopts=", 11) == 0) {
    if (set_sockopts_option(config, arg + 11) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--sockopts", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for --sockopts");
      ctx->exit_code = -1;
      return true;
    }
    if (set_sockopts_option(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  return false;
}

/* Remote-option, basis-directory and identity-mapping options.  Returns true
 * when the argument was consumed. */
static bool cli_handle_remote_basis_options(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (strncmp(arg, "--remote-option=", 16) == 0) {
    if (config_add_remote_option(config, arg + 16, "--remote-option") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "-M=", 3) == 0) {
    if (config_add_remote_option(config, arg + 3, "-M") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--remote-option", "-M")) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for --remote-option");
      ctx->exit_code = -1;
      return true;
    }
    if (config_add_remote_option(config, ctx->argv[++ctx->i], "--remote-option") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--compare-dest=", 15) == 0) {
    if (set_basis_dest_option(config, BASIS_DEST_COMPARE, arg + 15, "--compare-dest") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--compare-dest", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_basis_dest_option(config, BASIS_DEST_COMPARE, ctx->argv[++ctx->i], "--compare-dest") !=
        0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--copy-dest=", 12) == 0) {
    if (set_basis_dest_option(config, BASIS_DEST_COPY, arg + 12, "--copy-dest") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--copy-dest", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_basis_dest_option(config, BASIS_DEST_COPY, ctx->argv[++ctx->i], "--copy-dest") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--link-dest=", 12) == 0) {
    if (set_basis_dest_option(config, BASIS_DEST_LINK, arg + 12, "--link-dest") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--link-dest", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_basis_dest_option(config, BASIS_DEST_LINK, ctx->argv[++ctx->i], "--link-dest") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--usermap=", 10) == 0) {
    if (identity_parse_map(config, arg + 10, false) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    config->use_metadata = true;
    return true;
  }
  if (opt_is(arg, "--usermap", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (identity_parse_map(config, ctx->argv[++ctx->i], false) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    config->use_metadata = true;
    return true;
  }
  if (strncmp(arg, "--groupmap=", 11) == 0) {
    if (identity_parse_map(config, arg + 11, true) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    config->use_metadata = true;
    return true;
  }
  if (opt_is(arg, "--groupmap", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (identity_parse_map(config, ctx->argv[++ctx->i], true) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    config->use_metadata = true;
    return true;
  }
  if (strncmp(arg, "--chown=", 8) == 0) {
    if (identity_parse_chown(config, arg + 8) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    config->use_metadata = true;
    return true;
  }
  if (opt_is(arg, "--chown", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (identity_parse_chown(config, ctx->argv[++ctx->i]) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    config->use_metadata = true;
    return true;
  }
  if (strncmp(arg, "--copy-as=", 10) == 0) {
    if (identity_parse_copy_as(config, arg + 10) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--copy-as", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (identity_parse_copy_as(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  return false;
}

/* --outbuf.  Returns true when the argument was consumed. */
static bool cli_handle_outbuf_option(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (strncmp(arg, "--outbuf=", 9) == 0) {
    if (set_outbuf_option(config, arg + 9) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--outbuf", NULL)) {
    if (ctx->i + 1 >= ctx->argc || set_outbuf_option(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  return false;
}

/* Post-parse lowering: derive implied options over the final parsed config and
 * load --files-from once every argument has been seen.  Returns 0 on success,
 * -1 on error. */
static int cli_finalize_config(Config* config, bool verbose, bool no_delta, bool no_incremental) {
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
  /* Recompute the derived xattr flag from the FINAL preserve flags (after any
   * --no-xattrs/--no-acls negation) so the sender's wire gate always matches
   * the flags the receiver will recompute from the received config. */
  config->use_xattrs = config->preserve_acls || config->preserve_xattrs;
  return 0;
}

/* Parse CLI arguments into config. Returns 0 on success, -1 on error, 1 for help/clean-exit. */
int parse_args(Config* config, int argc, char* argv[], int* positional_args,
               int* positional_count) {
  protocol_set_8_bit_output(config->eight_bit_output);

  if (cli_apply_output_controls(config, argc, argv) != 0)
    return -1;

  CliParseCtx ctx = {
      .config = config,
      .argc = argc,
      .argv = argv,
      .i = 1,
      .exit_code = 0,
      .verbose = false,
      .no_delta = false,
      .no_incremental = false,
  };

  for (ctx.i = 1; ctx.i < argc; ctx.i++) {
    ctx.exit_code = 0;
    bool handled = cli_handle_pre_negation(&ctx) || cli_handle_range_time_options(&ctx) ||
                   cli_handle_table_option(&ctx) || cli_handle_inline_chmod(&ctx) ||
                   cli_handle_meta_flags(&ctx) || cli_handle_ssh_and_pattern_options(&ctx) ||
                   cli_handle_transfer_flags(&ctx) || cli_handle_io_options(&ctx) ||
                   cli_handle_filter_options(&ctx) || cli_handle_logging_options(&ctx) ||
                   cli_handle_checksum_options(&ctx) || cli_handle_remote_basis_options(&ctx) ||
                   cli_handle_outbuf_option(&ctx);
    if (handled) {
      if (ctx.exit_code != 0)
        return ctx.exit_code;
      continue;
    }

    if (argv[ctx.i][0] == '-') {
      char* escaped = output_escape(argv[ctx.i], false);
      fprintf(stderr, "Unknown option: %s\n", escaped ? escaped : "<allocation failed>");
      free(escaped);
      print_usage();
      return -1;
    }
    if (*positional_count < 2)
      positional_args[(*positional_count)++] = ctx.i;
    else {
      char* escaped = output_escape(argv[ctx.i], false);
      fprintf(stderr, "Unexpected argument: %s\n", escaped ? escaped : "<allocation failed>");
      free(escaped);
      print_usage();
      return -1;
    }
  }

  return cli_finalize_config(config, ctx.verbose, ctx.no_delta, ctx.no_incremental);
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
/* Daemon auth (A7, protocol 2.19.0): read --password-file and keep the
 * username plus the LITERAL password (client-only, never serialized).  Runs
 * once the destination form is known: the credentials only make sense for a
 * daemon (host::module/path) destination, so a --password-file without one is a
 * hard error here rather than a silently-ignored flag.  The password is handed
 * to the SCRAM challenge/response in config_send and burned by
 * config_burn_auth/config_delete at teardown.  Returns 0 on success, -1 on
 * error (the reason is logged; the password is never logged). */
static int load_daemon_credentials(Config* config) {
  if (!config->password_file)
    return 0;
  if (!config->module || config->module[0] == '\0') {
    log_message(LOG_LEVEL_ERROR,
                "--password-file requires a daemon destination (host::module/path)");
    return -1;
  }
  char err[512];
  char* user = NULL;
  char* password = NULL;
  if (credentials_read_secret_file(config->password_file, &user, &password, err, sizeof(err)) !=
      0) {
    log_message(LOG_LEVEL_ERROR, "%s", err);
    return -1;
  }

  config_burn_auth(config);
  config->auth_user = user;
  config->auth_password = password;
  log_info_message(LOG_INFO_MISC, "Loaded daemon credentials for user '%s'", config->auth_user);
  return 0;
}

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
  } else if (positional_count == 1) {
    if (config->read_batch) {
      /* --read-batch=<file> <dest>: the single positional is the destination
         (there is no source). */
      free(config->receive_root_directory);
      config->receive_root_directory = str_dup(argv[positional_args[0]]);
      if (!config->receive_root_directory) {
        log_message(LOG_LEVEL_ERROR, "memory allocation failed");
        exit_code = 1;
        goto cleanup;
      }
      config->save_to_disk = true;
    } else if (config->only_write_batch) {
      /* --only-write-batch=<file> <source>: the single positional is the
         source (there is no destination). */
      free(config->send_directory);
      config->send_directory = str_dup(argv[positional_args[0]]);
      if (!config->send_directory) {
        log_message(LOG_LEVEL_ERROR, "memory allocation failed");
        exit_code = 1;
        goto cleanup;
      }
    } else {
      log_message(LOG_LEVEL_ERROR, "missing destination argument");
      print_usage();
      exit_code = 1;
      goto cleanup;
    }
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

  /* Resolve the destination's transport form after the source/destination are
   * final (positional, --dest-dir, or the FASTSYNC_DEST_DIR env fallback):
   * host::module[/path] selects the daemon TCP transport, host:path the SSH
   * transport, anything else stays local TCP.  An invalid daemon destination
   * already logged its reason and is a hard error here. */
  if (config_parse_transport_dest(config) < 0) {
    exit_code = 1;
    goto cleanup;
  }

  /* Daemon auth: read --password-file (if any) into the wire credentials now
   * that the destination's module is known. */
  if (load_daemon_credentials(config) != 0) {
    exit_code = 1;
    goto cleanup;
  }

  if (!validate_config(config)) {
    exit_code = 1;
    goto cleanup;
  }

  /* --iconv: install the sender-side local->wire conversion before any path is
     scanned or serialized (the scanner and the chunk/data path read windows are
     all driven from this process, so one global initialization covers every
     send site). */
  if (!charset_wire_init_sender(config->iconv_spec)) {
    log_message(LOG_LEVEL_ERROR,
                "--iconv has an invalid CONVERT_SPEC or an unsupported charset name");
    exit_code = 1;
    goto cleanup;
  }

  /* Apply the requested --outbuf style now that the mode is parsed. */
  apply_output_buffering(config);

  /* --open-noatime is a sender-side policy: install it for every source read
     (scan + data path) without touching the receiver. */
  file_set_open_noatime(config->open_noatime);

  /* Initialize TLS if needed */
  if (config->use_tls)
    tls_global_init();

  tcp_set_timeouts(config->timeout, config->contimeout);

  /* Phase 6 residual-batch driver modes.  --read-batch / --only-write-batch are
     purely local (apply a batch file, or emit one from a scan): neither connects
     to nor transfers to a server.  --write-batch runs the normal live transfer
     AND then emits the batch FILE from a separate deterministic scan pass.  It
     drives the single-threaded transfer so the config outlives the run for that
     second pass (main retains ownership of the config; every send path
     borrows it). */
  if (config->read_batch) {
    exit_code = apply_batch_to_dest(config, config->read_batch, config->receive_root_directory);
    goto cleanup;
  }
  if (config->only_write_batch) {
    exit_code = write_batch_from_source(config, config->only_write_batch);
    goto cleanup;
  }

  /* Execute transfer */
  if (config->write_batch) {
    exit_code = send_files(config);
    if (exit_code == 0 && write_batch_from_source(config, config->write_batch) != 0) {
      log_message(LOG_LEVEL_ERROR, "live transfer succeeded but batch emission failed");
      exit_code = 1;
    }
  } else if (config->use_multithreading) {
    exit_code = send_files_multithreaded(&config);
  } else {
    exit_code = send_files(config);
  }

cleanup:
  charset_wire_free();
  if (config) {
    config_delete(config);
  }
  return exit_code;
}
#endif /* FASTSYNC_TEST_BUILD */
