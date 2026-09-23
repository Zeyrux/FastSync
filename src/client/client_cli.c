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
#include "scanner.h"
#include "stop_condition.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include "usage.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Async-signal-safe abort flag set by the SIGINT/SIGTERM handler.  Exposed via
 * client_send.h so the send loops can poll it.  Defined here (not in
 * client_send.c) so the unit-test binary, which compiles this file but not
 * client_send.c, still links the symbol. */
volatile sig_atomic_t client_abort_requested = 0;

/* Only armed while a network transfer is in flight.  Outside that window the
 * handler restores the default disposition and re-raises, so purely local modes
 * (--list-only/--dry-run/--read-batch/--only-write-batch and the batch-emission
 * pass) keep terminating on Ctrl-C/SIGTERM instead of silently swallowing it. */
volatile sig_atomic_t client_abort_armed = 0;

void client_set_abort_armed(bool armed) {
  client_abort_armed = armed ? 1 : 0;
}

bool client_abort_pending(void) {
  return client_abort_requested != 0;
}

#ifndef FASTSYNC_TEST_BUILD
/* SIG_DFL disposition used by the handler's "not armed" fallback.  It is built
 * once at load time so the handler can restore the default action with
 * sigaction(2) -- which is async-signal-safe -- instead of signal(3), which is
 * not.  The zero-initialized sa_mask is the empty set. */
static const struct sigaction client_default_action = {
    .sa_handler = SIG_DFL,
    .sa_flags = 0,
};

/* Signal handler: perform NO work beyond storing the flag.  Logging, protocol
 * I/O and the STATUS_ABORT frame are all done later on the normal send path,
 * which is not async-signal-safe.  When no transfer is armed, restore the
 * default disposition (async-signal-safe sigaction) and re-raise so local-only
 * modes remain interruptible.  The handler deliberately stays installed while a
 * transfer is armed -- rather than using SA_RESETHAND -- so a second Ctrl-C
 * during the graceful abort keeps setting the flag instead of hard-killing the
 * process mid-cleanup. */
static void client_signal_handler(int signo) {
  if (!client_abort_armed) {
    sigaction(signo, &client_default_action, NULL);
    raise(signo);
    return;
  }
  client_abort_requested = 1;
}
#endif

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

/* Append a --chmod clause list to the accumulated spec with a comma.  rsync
 * 3.2.4+ makes repeated --chmod options cumulative, so they must not replace
 * the previous ones.  Returns 0 on success, -1 on failure. */
static int append_chmod_spec(char** dest, const char* value) {
  if (!*dest)
    return set_string_option(dest, value, "--chmod");
  size_t old_len = strlen(*dest);
  size_t add_len = strlen(value);
  char* merged = malloc(old_len + add_len + 2);
  if (!merged) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for --chmod");
    return -1;
  }
  memcpy(merged, *dest, old_len);
  merged[old_len] = ',';
  memcpy(merged + old_len + 1, value, add_len + 1);
  free(*dest);
  *dest = merged;
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

/* Set and validate the compression algorithm selected by the client.  rsync
 * 3.4.1 can be built with zstd, none, lz4, zlibx, zlib and auto; all of those
 * names are accepted and mapped to a real codec here.  "auto" resolves through
 * FastSync's compiled-in preference order (rsync 3.4.1's list).  An unknown
 * name is a hard error with rsync's exit code 4, never a silent no-op. */
static int set_compression_choice(Config* config, const char* value) {
  if (!value) {
    config->cli.cli_exit_code = 4;
    return -1;
  }
  int algo;
  if (strcasecmp(value, "auto") == 0) {
    algo = compression_choice_resolve();
    if (algo < 0) {
      log_message(LOG_LEVEL_ERROR, "RSYNC_COMPRESS_LIST names no supported compression algorithm");
      config->cli.cli_exit_code = 4;
      return -1;
    }
  } else {
    algo = compression_algo_from_name(value);
  }
  if (algo < 0) {
    log_message(LOG_LEVEL_ERROR,
                "--compress-choice '%s' is not a supported algorithm; FastSync supports zstd, "
                "lz4, zlib, zlibx, none or auto",
                value);
    config->cli.cli_exit_code = 4;
    return -1;
  }
  const char* canonical = compression_algo_name((CompressionAlgo)algo);
  if (set_string_option(&config->compress_choice, canonical, "--compress-choice") != 0)
    return -1;
  config->compression_algo = algo;
  config->use_compression = (algo != (int)COMPRESSION_ALGO_NONE);
  return 0;
}

/* Store one algorithm name into *out.  Returns 0 for a valid name, 1 for
 * "auto" (caller resolves it), -1 for an unknown/too-long name. */
static int resolve_checksum_name(const char* name, size_t len, int* out) {
  char buf[64];
  if (len == 0 || len >= sizeof(buf))
    return -1;
  memcpy(buf, name, len);
  buf[len] = '\0';
  if (strcasecmp(buf, "auto") == 0)
    return 1;
  int algo = checksum_algo_from_name(buf);
  if (algo < 0)
    return -1;
  *out = algo;
  return 0;
}

/* Validate and store the --checksum-choice/--cc algorithm.  rsync 3.4.1 accepts
 * a single name (used for both the transfer and pre-transfer checksums) or the
 * two-name "TRANSFER,PRE-TRANSFER" form (only one comma is significant).  The
 * pre-transfer half is FastSync's whole-file digest; the transfer half is
 * validated for parity and, when "none", forces --whole-file like rsync.  An
 * unknown name (including an empty half or a second comma) is exit 4.  "auto"
 * resolves to FastSync's negotiated default (xxh128). */
static int set_checksum_choice(Config* config, const char* value) {
  if (!value) {
    config->cli.cli_exit_code = 4;
    return -1;
  }
  const char* comma = strchr(value, ',');
  const char* name1 = value;
  size_t len1 = comma ? (size_t)(comma - value) : strlen(value);
  const char* name2 = comma ? comma + 1 : NULL;
  size_t len2 = name2 ? strlen(name2) : 0;

  int transfer = -1;
  int pre = -1;
  int rc1 = resolve_checksum_name(name1, len1, &transfer);
  int rc2 = name2 ? resolve_checksum_name(name2, len2, &pre) : 1;
  if (rc1 < 0 || rc2 < 0) {
    log_message(LOG_LEVEL_ERROR,
                "--checksum-choice '%s' is invalid; FastSync supports xxh64 (or xxhash), xxh128, "
                "xxh3, md5, md4, sha1, none or auto, optionally as 'transfer,pre-transfer'",
                value);
    config->cli.cli_exit_code = 4;
    return -1;
  }
  int negotiated = -1;
  if (rc1 == 1 || rc2 == 1) {
    negotiated = checksum_choice_resolve();
    if (negotiated < 0) {
      log_message(LOG_LEVEL_ERROR, "RSYNC_CHECKSUM_LIST names no supported checksum algorithm");
      config->cli.cli_exit_code = 4;
      return -1;
    }
  }
  if (rc1 == 1)
    transfer = negotiated;
  if (!name2)
    pre = transfer;
  else if (rc2 == 1)
    pre = negotiated;

  config->checksum_algo = pre;
  config->cli.checksum_transfer_algo = transfer;
  config->cli.checksum_choice_set = true;
  /* rsync: "none" for the transfer checksum forces --whole-file. */
  if (transfer == (int)CHECKSUM_ALGO_NONE)
    config->whole_file = true;
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

/* --threads=N: enable the -m pipeline and size its parallel scanner pool.
 * Rejects a non-positive, non-numeric or oversized value up front. */
static int set_scanner_threads_option(Config* config, const char* value) {
  int threads;
  if (!parse_positive_int(value, &threads)) {
    log_message(LOG_LEVEL_ERROR, "--threads must be a positive integer");
    return -1;
  }
  if (threads > MAX_SCANNER_THREADS) {
    log_message(LOG_LEVEL_ERROR, "--threads must be between 1 and %d", MAX_SCANNER_THREADS);
    return -1;
  }
  config->use_multithreading = true;
  config->scanner_threads = threads;
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

/* Parse a signed integer, clamping every negative value to -1.  rsync's
   --max-delete treats a negative argument (the deprecated -1 spelling) as "no
   client limit", so -2/-5 must behave identically rather than being rejected. */
static int set_signed_clamped_int_option(int* dest, const char* value, const char* option_name) {
  if (!value || *value == '\0') {
    log_message(LOG_LEVEL_ERROR, "%s must be an integer", option_name);
    return -1;
  }
  char* endptr;
  errno = 0;
  long parsed = strtol(value, &endptr, 10);
  if (errno != 0 || *endptr != '\0' || parsed < INT_MIN || parsed > INT_MAX) {
    log_message(LOG_LEVEL_ERROR, "%s must be an integer", option_name);
    return -1;
  }
  *dest = parsed < 0 ? -1 : (int)parsed;
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
 * A relative path is interpreted on the receiver below the destination root; an
 * absolute path is used verbatim on the receiver (matching rsync), still subject
 * to the receiver's authorized-root confinement. Either way the path must be
 * non-empty and traversal-free (no ".."). Returns 0 on success, -1 on error. */
static int set_basis_dest_option(Config* config, BasisDestType type, const char* value,
                                 const char* option_name) {
  if (!value || !value[0]) {
    log_message(LOG_LEVEL_ERROR, "missing argument for %s", option_name);
    return -1;
  }
  if (config_basis_append(config, type, value) != 0) {
    log_message(LOG_LEVEL_ERROR,
                "%s requires a non-empty directory name with no '..' component "
                "(relative paths resolve below the destination root; absolute paths are used "
                "verbatim)",
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
  else if (strcmp(value, "client") == 0 || strcmp(value, "c") == 0)
    log_set_stderr_mode(LOG_STDERR_CLIENT);
  else {
    log_message(LOG_LEVEL_ERROR, "--stderr must be errors, all, or client");
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

static int read_patterns_from_file(const char* filepath, char*** patterns, int* count,
                                   Config* config, char sign, const char* optname);

/* Split one --debug/--info item into its category name and an optional rsync
 * verbosity level suffix (e.g. "io2", "all4", "none0").  The output `name` is
 * NUL-terminated and `level` is >= 0 (0 silences the item).  Returns false for
 * an empty token or a token that is all digits. */
static bool split_flag_level(const char* token, char* name, size_t name_size, int* level) {
  size_t len = strlen(token);
  if (len == 0 || name_size == 0)
    return false;
  size_t end = len;
  while (end > 0 && token[end - 1] >= '0' && token[end - 1] <= '9')
    end--;
  if (end == 0)
    return false; /* all digits: not a category name */
  size_t name_len = end < name_size - 1 ? end : name_size - 1;
  for (size_t i = 0; i < name_len; i++) {
    char c = token[i];
    name[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
  }
  name[name_len] = '\0';
  int lvl = 1;
  if (end < len) {
    lvl = 0;
    for (size_t i = end; i < len; i++) {
      int digit = token[i] - '0';
      if (lvl > (1000 - digit) / 10)
        return false;
      lvl = lvl * 10 + digit;
    }
  }
  *level = lvl;
  return true;
}

/* rsync --debug/--info categories that FastSync accepts for CLI parity but has
 * no output wired to (yet).  They must parse successfully so a valid rsync
 * invocation is not rejected up front; only categories with a FastSync
 * counterpart set a log flag.  `pack`/`util` are FastSync-specific (packed
 * metadata / general utility logging).  `syms`, `hl`, and `owner` are aliases
 * of rsync's `symsafe`, `hlink`, and `own`. */
static bool is_accepted_debug_category(const char* name) {
  static const char* const categories[] = {
      "acl",  "backup", "bind",  "chdir", "cmd",  "connect", "dup",   "exit", "fuzzy",
      "genr", "hl",     "hlink", "iconv", "nstr", "own",     "owner", "time",
  };
  for (size_t i = 0; i < sizeof(categories) / sizeof(categories[0]); i++) {
    if (strcmp(name, categories[i]) == 0)
      return true;
  }
  return false;
}

static bool is_accepted_info_category(const char* name) {
  static const char* const categories[] = {
      "backup",
      "syms",
      "symsafe",
  };
  for (size_t i = 0; i < sizeof(categories) / sizeof(categories[0]); i++) {
    if (strcmp(name, categories[i]) == 0)
      return true;
  }
  return false;
}

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
    char name[32];
    int level = 1;
    if (!split_flag_level(token, name, sizeof(name), &level)) {
      log_message(LOG_LEVEL_ERROR, "unsupported --debug flag: %s", token);
      free(flags);
      return -1;
    }
    if (strcmp(name, "help") == 0) {
      print_debug_usage();
      free(flags);
      return 1;
    } else if (strcmp(name, "all") == 0) {
      parsed = level == 0 ? 0 : LOG_DEBUG_ALL;
      continue;
    } else if (strcmp(name, "none") == 0) {
      parsed = 0;
      continue;
    } else if (strcmp(name, "io") == 0) {
      flag = LOG_DEBUG_IO;
    } else if (strcmp(name, "proto") == 0) {
      flag = LOG_DEBUG_PROTO;
    } else if (strcmp(name, "pack") == 0) {
      flag = LOG_DEBUG_PACK;
    } else if (strcmp(name, "util") == 0) {
      flag = LOG_DEBUG_UTIL;
    } else if (strcmp(name, "flist") == 0) {
      flag = LOG_DEBUG_FLIST;
    } else if (strcmp(name, "del") == 0) {
      flag = LOG_DEBUG_DEL;
    } else if (strcmp(name, "hash") == 0 || strcmp(name, "deltasum") == 0) {
      flag = LOG_DEBUG_HASH;
    } else if (strcmp(name, "recv") == 0) {
      flag = LOG_DEBUG_RECV;
    } else if (strcmp(name, "filter") == 0) {
      flag = LOG_DEBUG_FILTER;
    } else if (strcmp(name, "send") == 0) {
      flag = LOG_DEBUG_SEND;
    } else if (is_accepted_debug_category(name)) {
      continue;
    } else {
      log_message(LOG_LEVEL_ERROR, "unsupported --debug flag: %s", token);
      free(flags);
      return -1;
    }
    if (level == 0)
      parsed &= ~flag;
    else
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
    char name[32];
    int level = 1;
    if (!split_flag_level(token, name, sizeof(name), &level)) {
      log_message(LOG_LEVEL_ERROR, "unsupported --info flag: %s", token);
      free(flags);
      return -1;
    }
    if (strcmp(name, "all") == 0) {
      parsed = level == 0 ? 0 : LOG_INFO_ALL;
      continue;
    }
    if (strcmp(name, "none") == 0) {
      parsed = 0;
      continue;
    }
    if (strcmp(name, "help") == 0) {
      print_info_usage();
      free(flags);
      return 1;
    }
    if (strcmp(name, "copy") == 0)
      flag = LOG_INFO_COPY;
    else if (strcmp(name, "name") == 0) {
      /* name level 2 adds rsync's "is uptodate" lines. */
      if (level == 0)
        parsed &= ~(uint32_t)(LOG_INFO_NAME | LOG_INFO_NAME_UPTODATE);
      else {
        parsed |= LOG_INFO_NAME;
        if (level >= 2)
          parsed |= LOG_INFO_NAME_UPTODATE;
        else
          parsed &= ~(uint32_t)LOG_INFO_NAME_UPTODATE;
      }
      continue;
    } else if (strcmp(name, "misc") == 0)
      flag = LOG_INFO_MISC;
    else if (strcmp(name, "skip") == 0)
      flag = LOG_INFO_SKIP;
    else if (strcmp(name, "stats") == 0) {
      flag = LOG_INFO_STATS;
      /* `--info=stats` requests the same transfer-statistics block as
         `--stats`; `--info=stats0` turns it back off. */
      config->stats = level > 0;
    } else if (strcmp(name, "del") == 0)
      flag = LOG_INFO_DEL;
    else if (strcmp(name, "remove") == 0)
      flag = LOG_INFO_REMOVE;
    else if (strcmp(name, "flist") == 0)
      flag = LOG_INFO_FLIST;
    else if (strcmp(name, "nonreg") == 0)
      flag = LOG_INFO_NONREG;
    else if (strcmp(name, "mount") == 0)
      flag = LOG_INFO_MOUNT;
    else if (strcmp(name, "progress") == 0)
      flag = LOG_INFO_PROGRESS;
    else if (is_accepted_info_category(name))
      continue;
    else {
      log_message(LOG_LEVEL_ERROR, "unsupported --info flag: %s", token);
      free(flags);
      return -1;
    }
    if (level == 0)
      parsed &= ~flag;
    else
      parsed |= flag;
  }
  free(flags);
  config->info_level = (int)parsed;
  set_log_info_flags(parsed);
  return 0;
}

/* Parse a string as an unsigned long long. Returns 0 on success, -1 on error.
 * A leading '-'/'+' (or whitespace) is rejected outright: strtoull would
 * otherwise silently wrap a negative value to a huge unsigned one. */
static int parse_ull_arg(const char* val, unsigned long long* out, const char* optname) {
  if (!val || val[0] < '0' || val[0] > '9') {
    log_message(LOG_LEVEL_ERROR, "%s must be a non-negative integer", optname);
    return -1;
  }
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
  char err[256];
  /* Validate through the full list parser so clear/merge/dir-merge and the rule
     modifiers are accepted (and a merge file is readable) at parse time. */
  FilterParseOptions opts = {.delete_excluded = config->delete_excluded,
                             .cvs_exclude = config->cvs_exclude};
  FilterRuleList* probe = filter_rule_list_create();
  if (!probe) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for --filter");
    return -1;
  }
  bool ok = filter_rule_list_parse_append(probe, rule, &opts, NULL, err, sizeof(err));
  filter_rule_list_free(probe);
  if (!ok) {
    char* escaped = output_escape(rule, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "invalid --filter rule '%s': %s",
                escaped ? escaped : "<allocation failed>", err);
    free(escaped);
    return -1;
  }
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

/* Compile one --exclude/--include pattern into the SAME ordered filter rule
 * list used by --filter/-f: `--exclude P` becomes the rule "- P" and
 * `--include P` becomes "+ P", appended in command-line order.  This is what
 * makes rsync's first-match-wins semantics hold across a mixed sequence such as
 * `--include='*.txt' --exclude='*'`.  Returns 0 on success, -1 on error. */
static int config_add_selection_rule(Config* config, char sign, const char* pattern,
                                     const char* optname) {
  size_t len = strlen(pattern);
  char* rule = malloc(len + 3);
  if (!rule) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for %s", optname);
    return -1;
  }
  rule[0] = sign;
  rule[1] = ' ';
  memcpy(rule + 2, pattern, len + 1);
  int rc = config_add_filter(config, rule);
  free(rule);
  return rc;
}

static int parse_skip_compress(Config* config, const char* value) {
  char* list = str_dup(value);
  if (!list)
    return -1;
  config->skip_compress_set = true;
  /* rsync documents the LIST as slash-separated; accept that along with the
   * historical comma-separated spelling.  A leading dot is optional (rsync's
   * suffixes have none, FastSync historically used them). */
  for (char* token = strtok(list, ",/"); token; token = strtok(NULL, ",/")) {
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
  /* A signed integer whose negative values are clamped to -1 (rsync's
     "no limit" spelling for --max-delete). */
  OPT_SIGNED_INT,
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

/* Sentinel offset for --no-preserve, the rsync drop-in negation of the whole
 * preservation bundle: it clears all four per-attribute flags and records the
 * explicit metadata opt-out instead of clearing a single Config field. */
#define NEGATABLE_PRESERVE_BUNDLE ((size_t) - 1)

/* Options that map directly onto a Config field with no side effects.
 *
 * NOTE: these CLI tables are intentionally NOT generated from the wire-field
 * X-macro table in config.h.  The two sets only overlap partially: the CLI
 * surface also carries client-only fields that never cross the wire (rsh,
 * outbuf, remote-option, batch paths, trust-sender, ...) and needs flag/alias/
 * negation semantics that the wire table does not model.  Keeping them
 * hand-maintained is deliberate; the shared contract is enforced at the wire
 * boundary by config.[ch] and the golden test. */
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
    {"--backup", "-b", OPT_FLAG, offsetof(Config, backup)},
    {"--stats", NULL, OPT_FLAG, offsetof(Config, stats)},
    {"--human-readable", "-h", OPT_FLAG, offsetof(Config, human_readable)},
    {"--partial", NULL, OPT_FLAG, offsetof(Config, partial)},
    {"--secluded-args", "-s", OPT_NOOP, 0},
    /* rsync's pre-3.2.6 name for --secluded-args (--protect-args) is accepted
     * as the same secure-argv no-op. */
    {"--protect-args", NULL, OPT_NOOP, 0},
    /* rsync -r/--recursive: FastSync is always recursive, so this is a
     * faithful no-op (accepted silently, never consumes an argument). */
    {"--recursive", "-r", OPT_NOOP, 0},
    /* rsync's incremental-recursion scan-mode switch.  FastSync always performs
     * a single full recursive scan, so both spellings are accepted as no-ops:
     * the destination is identical whichever mode the caller requests.
     * --no-inc-recursive is handled before the generic --no-* negation branch
     * (see cli_handle_pre_negation) but is registered here for discoverability. */
    {"--inc-recursive", NULL, OPT_NOOP, 0},
    {"--no-inc-recursive", NULL, OPT_NOOP, 0},
    {"--update", "-u", OPT_FLAG, offsetof(Config, update)},
    /* rsync's --old-args: accepted for CLI compatibility as a documented no-op
     * (the remote server path is always safely quoted; see usage.c).  It is
     * recognized but stores no Config field. */
    {"--old-args", NULL, OPT_NOOP, 0},
    {"--rsh", "-e", OPT_STRING, offsetof(Config, rsh_command)},
    {"--blocking-io", NULL, OPT_FLAG, offsetof(Config, blocking_io)},
    {"--links", "-l", OPT_FLAG, offsetof(Config, follow_symlinks)},
    {"--copy-links", "-L", OPT_FLAG, offsetof(Config, copy_links)},
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
    /* rsync's man-page alias for --existing (--ignore-non-existing). */
    {"--ignore-non-existing", NULL, OPT_FLAG, offsetof(Config, existing)},
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
    /* FastSync-only long spelling of the late whole-tree commit, which selects
       the same timing as rsync's --delete-after in FastSync (the whole-tree
       keep-set manifest is committed only after the entire transfer succeeded).
       Plain --delete now defaults to delete-during, so this restores the old
       FastSync behavior; it maps onto the same delete_after wire field. */
    {"--delete-commit", NULL, OPT_FLAG, offsetof(Config, delete_after)},
    {"--delete-excluded", NULL, OPT_FLAG, offsetof(Config, delete_excluded)},
    {"--max-delete", NULL, OPT_SIGNED_INT, offsetof(Config, max_delete)},
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

    {"--timeout", NULL, OPT_NONNEG_INT, offsetof(Config, timeout)},
    {"--contimeout", NULL, OPT_NONNEG_INT, offsetof(Config, contimeout)},
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
    /* FastSync-only (not an rsync option): require a basis-hit's content to
     * match the source by whole-file digest instead of trusting rsync's
     * size+mtime quick-check.  Long-only; crosses the wire so the receiver
     * performs the extra read/hash. */
    {"--verify-basis", NULL, OPT_FLAG, offsetof(Config, verify_basis)},
};

/* Only boolean options with no required argument are safe to negate. */
static const NegatableOption NEGATABLE_OPTIONS[] = {
    {"dry-run", "n", offsetof(Config, dry_run)},
    {"delete", NULL, offsetof(Config, use_delete)},
    {"incremental", NULL, offsetof(Config, use_incremental)},
    {"delta", NULL, offsetof(Config, use_delta)},
    {"whole-file", "W", offsetof(Config, whole_file)},
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
    {"preserve", NULL, NEGATABLE_PRESERVE_BUNDLE},
    {"perms", "p", offsetof(Config, preserve_perms)},
    {"times", "t", offsetof(Config, preserve_times)},
    {"owner", "o", offsetof(Config, preserve_owner)},
    {"group", "g", offsetof(Config, preserve_group)},
    {"sendfile", NULL, offsetof(Config, use_sendfile)},
    {"chunk-serialization", NULL, offsetof(Config, use_chunk_serialization)},
    {"xattrs", "X", offsetof(Config, preserve_xattrs)},
    {"acls", "A", offsetof(Config, preserve_acls)},
    {"fake-super", NULL, offsetof(Config, fake_super)},
    {"verify-basis", NULL, offsetof(Config, verify_basis)},
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
          entry->kind == OPT_NONNEG_INT || entry->kind == OPT_ULL ||
          entry->kind == OPT_SIGNED_INT) {
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
  if (entry->offset == NEGATABLE_PRESERVE_BUNDLE) {
    config->preserve_perms = false;
    config->preserve_times = false;
    config->preserve_owner = false;
    config->preserve_group = false;
    config->cli.metadata_explicitly_disabled = true;
    /* --no-preserve is an explicit opt-out of the whole bundle: record it so
     * the --incremental/--delta auto-preserve in cli_finalize_config does not
     * silently re-enable perms/times. */
    config->cli.preserve_perms_explicit_off = true;
    config->cli.preserve_times_explicit_off = true;
    return 0;
  }
  *(bool*)((char*)config + entry->offset) = false;
  /* Track an explicit per-attribute negation so --incremental/--delta can
   * auto-preserve the OTHER attribute without undoing this one.  A later
   * -p/-t sets the attribute directly; this flag only gates the implication. */
  if (entry->offset == offsetof(Config, preserve_perms))
    config->cli.preserve_perms_explicit_off = true;
  else if (entry->offset == offsetof(Config, preserve_times))
    config->cli.preserve_times_explicit_off = true;
  return 0;
}

/* rsync's --iconv accepted extra spellings beyond explicit charset pairs:
 * "." selects the locale's default charset for both directions, and "-" (or
 * --no-iconv) disables conversion entirely.  Normalize both here so the rest
 * of the pipeline only ever sees a real charset spec or NULL. */
static int set_iconv_option(char** field, const char* value) {
  if (value && strcmp(value, "-") == 0) {
    free(*field);
    *field = NULL;
    return 0;
  }
  if (value && strcmp(value, ".") == 0) {
    setlocale(LC_ALL, "");
    const char* codeset = nl_langinfo(CODESET);
    if (!codeset || codeset[0] == '\0')
      codeset = "UTF-8";
    return set_string_option(field, codeset, "--iconv");
  }
  return set_string_option(field, value, "--iconv");
}

static int apply_table_option(Config* config, const OptionEntry* entry, const char* value) {
  if (entry->kind == OPT_NOOP)
    return 0;
  void* field = (char*)config + entry->offset;
  switch (entry->kind) {
  case OPT_FLAG:
    /* -x/--one-file-system is repeatable in rsync: `-xx` increments the level so
       the scanner drops mount-point directories instead of recreating them
       empty.  Everything else is a plain boolean. */
    if (entry->offset == offsetof(Config, one_file_system))
      (*(int*)field)++;
    else
      *(bool*)field = true;
    return 0;
  case OPT_NOOP:
    return 0;
  case OPT_STRING:
    if (entry->offset == offsetof(Config, chmod_spec))
      return append_chmod_spec((char**)field, value);
    if (entry->offset == offsetof(Config, iconv_spec))
      return set_iconv_option((char**)field, value);
    return set_string_option((char**)field, value, entry->name);
  case OPT_POS_INT:
    return set_positive_int_option((int*)field, value, entry->name);
  case OPT_NONNEG_INT:
    return set_nonneg_int_option((int*)field, value, entry->name);
  case OPT_SIGNED_INT:
    return set_signed_clamped_int_option((int*)field, value, entry->name);
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
 * irrelevant.  Returns 0 on success, a positive code for a help request
 * (parse_args returns it verbatim), or -1 on error. */
static int cli_apply_output_controls(Config* config, int argc, char* argv[]) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
      set_log_level(LOG_LEVEL_DEBUG);
    } else if (strncmp(argv[i], "--info=", 7) == 0) {
      int ret = parse_info_flags(argv[i] + 7, config);
      if (ret != 0)
        return ret;
    } else if (strcmp(argv[i], "--info") == 0) {
      if (i + 1 >= argc)
        return -1;
      int ret = parse_info_flags(argv[++i], config);
      if (ret != 0)
        return ret;
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
  /* "--no-iconv" is a real rsync option name that turns charset conversion off
   * (the negation of the argument-taking --iconv), so it is handled before the
   * generic --no-* negation branch. */
  if (strcmp(arg, "--no-iconv") == 0) {
    free(config->iconv_spec);
    config->iconv_spec = NULL;
    return true;
  }
  /* "--no-msgs2stderr" is the deprecated spelling of --stderr=client (rsync
   * 3.4.1); the client-message channel now exists, so it maps to `client`. */
  if (strcmp(arg, "--no-msgs2stderr") == 0)
    return set_stderr_mode("client") == 0;
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
  /* rsync's --no-timeout / --no-contimeout explicit spellings clear the
   * corresponding (integer) deadline; handled before the generic --no-* branch
   * because the negation table only models boolean fields. */
  if (strcmp(arg, "--no-timeout") == 0) {
    config->timeout = 0;
    return true;
  }
  if (strcmp(arg, "--no-contimeout") == 0) {
    config->contimeout = 0;
    return true;
  }
  if (strncmp(arg, "--no-", strlen("--no-")) == 0) {
    if (strcmp(arg, "--no-delta") == 0)
      ctx->no_delta = true;
    else if (strcmp(arg, "--no-incremental") == 0)
      ctx->no_incremental = true;
    /* Real rsync option names that merely start with "--no-" and are inert
     * no-ops (e.g. --no-inc-recursive) are registered as OPT_NOOP entries;
     * accept them before the generic negation table would reject the name. */
    const OptionEntry* noop = find_table_option(arg);
    if (noop && noop->kind == OPT_NOOP)
      return true;
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
      log_message(LOG_LEVEL_ERROR, "--stop-at must be a date/time such as 2000-12-31T23:59, 12-31, "
                                   "14:00, :59, HH:MM[:SS] or now+N[smhd]");
      ctx->exit_code = -1;
      return true;
    }
    config->cli.stop_at_set = true;
    return true;
  }
  if (strcmp(arg, "--stop-at") == 0) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for --stop-at");
      ctx->exit_code = -1;
      return true;
    }
    if (!stop_parse_at_time(ctx->argv[++ctx->i], time(NULL), &config->stop_at)) {
      log_message(LOG_LEVEL_ERROR, "--stop-at must be a date/time such as 2000-12-31T23:59, 12-31, "
                                   "14:00, :59, HH:MM[:SS] or now+N[smhd]");
      ctx->exit_code = -1;
      return true;
    }
    config->cli.stop_at_set = true;
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
    /* rsync: --max-alloc=0 means "no alloc limit" (it maps to SIZE_MAX).  A
     * size with an optional binary suffix is also accepted. */
    if (parse_size_arg_allow_zero(value, &config->max_alloc, true) != 0) {
      log_message(LOG_LEVEL_ERROR, "--max-alloc must be a size (0 = no limit; B, K, M, G, T, P, E "
                                   "suffixes allowed)");
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
  if (entry->kind != OPT_FLAG && entry->kind != OPT_NOOP) {
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
      if (entry->offset == offsetof(Config, compression_level))
        config->cli.compression_level_set = true;
      if (entry->offset == offsetof(Config, chmod_spec)) {
        mode_t ignored;
        if (!chmod_apply(0, config->chmod_spec, &ignored)) {
          log_message(LOG_LEVEL_ERROR, "--chmod has invalid permission changes");
          ctx->exit_code = -1;
          return true;
        }
      }
      /* Remember that --server-host was explicitly given (the field itself
         defaults to 127.0.0.1, so a value check cannot distinguish it).  Used
         by --dry-run to route an explicit remote target to the server. */
      if (entry->offset == offsetof(Config, server_host))
        config->cli.server_host_set = true;
    }
  } else if (apply_table_option(config, entry, NULL) != 0) {
    ctx->exit_code = -1;
    return true;
  }
  if (entry->offset == offsetof(Config, eight_bit_output))
    protocol_set_8_bit_output(true);
  /* -F is repeatable: rsync's single -F transfers .rsync-filter files, a
     repeated -FF excludes them.  Count the occurrences so the scanner can
     distinguish the two. */
  if (entry->offset == offsetof(Config, per_dir_filter) && config->per_dir_filter_count < INT_MAX)
    config->per_dir_filter_count++;
  /* A delete-timing flag selects when --delete removes extras, so it
     implies --delete exactly like the rsync options do.  --delete-commit (the
     FastSync-only late-commit spelling) is mapped onto delete_after and so is
     covered here too. */
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
  /* -A/--acls implies permission preservation as well as the xattr channel;
     -X/--xattrs preserves only the extended attributes.  Either sets the
     derived xattr transport bit so the sender emits the per-file xattr block. */
  if (entry->offset == offsetof(Config, preserve_xattrs) ||
      entry->offset == offsetof(Config, preserve_acls)) {
    config->use_xattrs = config->preserve_acls || config->preserve_xattrs;
    if (entry->offset == offsetof(Config, preserve_acls))
      config->preserve_perms = true;
  }
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
  if (append_chmod_spec(&config->chmod_spec, arg + 8) != 0) {
    ctx->exit_code = -1;
    return true;
  }
  mode_t ignored;
  if (!chmod_apply(0, config->chmod_spec, &ignored)) {
    log_message(LOG_LEVEL_ERROR, "--chmod has invalid permission changes");
    ctx->exit_code = -1;
    return true;
  }
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
    /* FastSync archive mode (-rlptgoD).  FastSync is always recursive and
     * always preserves hard-link/other transfer semantics per its own flags, so
     * -a implies links plus the four per-attribute preservation flags
     * (perms/times/owner/group), devices and specials.  Compression and
     * multithreading are NOT implied (they are no longer part of archive
     * mode). */
    config->follow_symlinks = true;
    config->preserve_perms = true;
    config->preserve_times = true;
    config->preserve_owner = true;
    config->preserve_group = true;
    config->preserve_devices = true;
    config->preserve_specials = true;
    log_info_message(LOG_INFO_MISC,
                     "Enabled archive mode (-rlptgoD: links, perms, times, owner, group, "
                     "devices, specials)");
    return true;
  }
  if (opt_is(arg, "-p", "--perms")) {
    config->preserve_perms = true;
    log_info_message(LOG_INFO_MISC, "Enabled permission preservation");
    return true;
  }
  if (opt_is(arg, "-t", "--times")) {
    config->preserve_times = true;
    log_info_message(LOG_INFO_MISC, "Enabled time preservation");
    return true;
  }
  if (opt_is(arg, "-o", "--owner")) {
    config->preserve_owner = true;
    log_info_message(LOG_INFO_MISC, "Enabled owner preservation");
    return true;
  }
  if (opt_is(arg, "-g", "--group")) {
    config->preserve_group = true;
    log_info_message(LOG_INFO_MISC, "Enabled group preservation");
    return true;
  }
  return false;
}

/* Apply a --delta-max value.  Values below the minimum warn and keep the
 * default; values above the maximum are a hard error.  Returns 0 on success,
 * -1 on error. */
static int set_delta_max_option(Config* config, const char* value) {
  unsigned long long val;
  if (parse_ull_arg(value, &val, "--delta-max") != 0)
    return -1;
  if (val >= DELTA_MIN_FILE_SIZE && val <= DELTA_MAX_FILE_SIZE) {
    config->delta_max_file_size = val;
    return 0;
  }
  if (val < DELTA_MIN_FILE_SIZE) {
    log_message(LOG_LEVEL_WARNING, "--delta-max value %llu too small, using default", val);
    return 0;
  }
  log_message(LOG_LEVEL_ERROR, "--delta-max must not exceed %llu bytes",
              (unsigned long long)DELTA_MAX_FILE_SIZE);
  return -1;
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
  if (strncmp(arg, "--exclude=", 10) == 0) {
    if (config_add_pattern(&config->exclude_patterns, &config->exclude_count, arg + 10,
                           "--exclude") != 0 ||
        config_add_selection_rule(config, '-', arg + 10, "--exclude") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--exclude", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (config_add_pattern(&config->exclude_patterns, &config->exclude_count, ctx->argv[++ctx->i],
                           "--exclude") != 0 ||
        config_add_selection_rule(config, '-', ctx->argv[ctx->i], "--exclude") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--include=", 10) == 0) {
    if (config_add_pattern(&config->include_patterns, &config->include_count, arg + 10,
                           "--include") != 0 ||
        config_add_selection_rule(config, '+', arg + 10, "--include") != 0)
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
                           "--include") != 0 ||
        config_add_selection_rule(config, '+', ctx->argv[ctx->i], "--include") != 0)
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
  if (strcmp(arg, "--delta-block") == 0 || strcmp(arg, "--block-size") == 0 ||
      strcmp(arg, "-B") == 0) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_delta_block_size(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--delta-max=", 12) == 0) {
    if (set_delta_max_option(config, arg + 12) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--delta-max", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_delta_max_option(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
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
        !config->compress_choice || strcmp(config->compress_choice, "none") != 0;
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
        config->cli.compression_level_set = true;
        log_info_message(LOG_INFO_MISC, "Set Compression level to %ld", level);
        ctx->i++;
      }
    }
    return true;
  }
  if (opt_is(arg, "--preserve", NULL)) {
    config->preserve_perms = true;
    config->preserve_times = true;
    log_info_message(LOG_INFO_MISC, "Enabled metadata preservation");
    return true;
  }
  if (opt_is(arg, "-E", "--executability")) {
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
    /* Bare -j/--threads: enable the pipeline with the scanner's built-in
       worker default (scanner_threads stays 0). */
    config->use_multithreading = true;
    log_info_message(LOG_INFO_MISC, "Enabled Multithreading");
    return true;
  }
  if (strncmp(arg, "--threads=", 10) == 0) {
    if (set_scanner_threads_option(config, arg + 10) != 0) {
      ctx->exit_code = -1;
    } else {
      log_info_message(LOG_INFO_MISC, "Enabled Multithreading with %d scanner threads",
                       config->scanner_threads);
    }
    return true;
  }
  if (opt_is(arg, "--chunk-serialization", NULL)) {
    config->use_chunk_serialization = true;
    log_info_message(LOG_INFO_MISC, "Enabled Chunk Serialization");
    return true;
  }
  return false;
}

/* Parse and validate a TCP server port (--server-port, or its rsync-friendly
 * alias --port).  Returns 0 on success, -1 (with a message) on a malformed or
 * out-of-range value. */
static int set_server_port_option(Config* config, const char* value, const char* option_name) {
  int port;
  if (!parse_positive_int(value, &port)) {
    char* escaped = output_escape(value, false);
    log_message(LOG_LEVEL_ERROR, "invalid %s value: %s", option_name,
                escaped ? escaped : "<allocation failed>");
    free(escaped);
    return -1;
  }
  if (port > 65535) {
    log_message(LOG_LEVEL_ERROR, "server port must be 1-65535");
    return -1;
  }
  config->server_port = port;
  config->cli.server_port_set = true;
  return 0;
}

/* Open (create/append) a --log-file target and install it in the logger.
 * Refuses a symlinked target and never leaks the descriptor across exec: an
 * attacker who can plant a symlink in the working directory must not be able to
 * redirect (or truncate) an arbitrary file.  The log is created with owner-only
 * permissions.  Returns 0 on success, -1 on error (already logged). */
static int set_log_file_option(Config* config, const char* log_path) {
  if (config->log_file) {
    /* Detach the logger before closing: log I/O may be in flight and must
       never touch a freed FILE*. */
    log_set_file(NULL);
    fclose(config->log_file);
    config->log_file = NULL;
  }
  int log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
  FILE* lf = log_fd >= 0 ? fdopen(log_fd, "a") : NULL;
  if (!lf) {
    int open_errno = errno;
    if (log_fd >= 0)
      close(log_fd);
    char* escaped = output_escape(log_path, false);
    log_message(LOG_LEVEL_ERROR, "could not open log file '%s': %s",
                escaped ? escaped : "<allocation failed>", strerror(open_errno));
    free(escaped);
    return -1;
  }
  config->log_file = lf;
  log_set_file(lf);
  return 0;
}

/* Faithful port of rsync 3.4.1's `parse_size_arg(bwlimit_arg, 'K', "bwlimit",
 * 512, -1, True)`: a default KiB suffix, binary (1024) multipliers unless a
 * `b`/`B` decimal suffix or explicit `iB` is given, an optional decimal
 * fraction, the P/T/G/M/K suffixes, and the special rules that a value of 0
 * means "no limit" while any other value below 512 bytes is rejected.  The
 * parsed byte count is then quantized to whole KiB exactly like rsync's
 * `bwlimit = (size + 512) / 1024`.  Returns 0 on success, -1 on a parse error. */
static int parse_bwlimit_value(const char* value, unsigned long long* bytes_per_sec_out) {
  if (!value || !bytes_per_sec_out)
    return -1;
  const char* arg = value;
  int reps;
  long long mult;
  while (*arg >= '0' && *arg <= '9')
    arg++;
  if (*arg != '\0' && (*arg == '.' || *arg == localeconv()->decimal_point[0]))
    for (arg++; *arg >= '0' && *arg <= '9'; arg++) {
    }

  char suffix = *arg && *arg != '+' && *arg != '-' ? *arg++ : 'K';
  switch (suffix) {
  case 'b':
  case 'B':
    reps = 0;
    break;
  case 'k':
  case 'K':
    reps = 1;
    break;
  case 'm':
  case 'M':
    reps = 2;
    break;
  case 'g':
  case 'G':
    reps = 3;
    break;
  case 't':
  case 'T':
    reps = 4;
    break;
  case 'p':
  case 'P':
    reps = 5;
    break;
  default:
    log_message(LOG_LEVEL_ERROR, "--bwlimit=%s is invalid", value);
    return -1;
  }
  if (*arg == 'b' || *arg == 'B') {
    mult = 1000;
    arg++;
  } else if (*arg == '\0' || *arg == '+' || *arg == '-') {
    mult = 1024;
  } else if ((arg[0] == 'i' || arg[0] == 'I') && (arg[1] == 'b' || arg[1] == 'B')) {
    mult = 1024;
    arg += 2;
  } else {
    log_message(LOG_LEVEL_ERROR, "--bwlimit=%s is invalid", value);
    return -1;
  }

  long long base = 1;
  for (int i = 0; i < reps; i++) {
    if (base > LLONG_MAX / mult) {
      log_message(LOG_LEVEL_ERROR, "--bwlimit=%s is too large", value);
      return -1;
    }
    base *= mult;
  }
  /* rsync multiplies the numeric prefix (atof) by mult^reps in a signed
   * ssize_t, which is undefined on overflow.  Scale in double and range-check
   * before converting, so a huge value is rejected as "too large" (where
   * rsync's overflow happens to land on a negative result) without invoking
   * signed-overflow UB. */
  double scaled = (double)base * strtod(value, NULL);
  /* (double)LLONG_MAX rounds up to 2^63, which is itself out of range for the
   * cast, so reject at >= that bound; LLONG_MIN == -2^63 is exactly
   * representable and thus castable, so the lower bound stays strict. */
  if (!isfinite(scaled) || scaled >= (double)LLONG_MAX || scaled < (double)LLONG_MIN) {
    log_message(LOG_LEVEL_ERROR, "--bwlimit=%s is too large", value);
    return -1;
  }
  long long size = (long long)scaled;
  if ((*arg == '+' || *arg == '-') && arg[1] == '1' && arg != value) {
    /* The only form accepted here is "+1"/"-1" (a longer number leaves a
       trailing byte and is rejected below), so apply the delta directly and
       guard the one overflow direction. */
    if (*arg == '+') {
      if (size == LLONG_MAX) {
        log_message(LOG_LEVEL_ERROR, "--bwlimit=%s is too large", value);
        return -1;
      }
      size += 1;
    } else {
      size -= 1;
    }
    arg += 2;
  }
  if (*arg != '\0' || size < 0) {
    log_message(LOG_LEVEL_ERROR, "--bwlimit=%s is %s", value, size < 0 ? "too large" : "invalid");
    return -1;
  }
  if (size != 0 && size < 512) {
    log_message(LOG_LEVEL_ERROR, "--bwlimit=%s is too small (min: 512 or 0 for unlimited)", value);
    return -1;
  }
  long long kib = size == 0 ? 0 : (size + 512) / 1024;
  if (kib > (long long)(ULLONG_MAX / 1024)) {
    log_message(LOG_LEVEL_ERROR, "--bwlimit=%s is too large", value);
    return -1;
  }
  *bytes_per_sec_out = (unsigned long long)kib * 1024;
  return 0;
}

/* Apply a --bwlimit value using rsync 3.4.1's units/semantics.  Returns 0 on
 * success, -1 on error. */
static int set_bwlimit_option(const char* value) {
  unsigned long long bytes_per_sec;
  if (parse_bwlimit_value(value, &bytes_per_sec) != 0)
    return -1;
  io_set_bwlimit(bytes_per_sec);
  log_info_message(LOG_INFO_MISC, "Set bandwidth limit to %llu KB/s", bytes_per_sec / 1024);
  return 0;
}

/* Apply a --chunk-size value.  Returns 0 on success, -1 on error. */
static int set_chunk_size_option(Config* config, const char* value) {
  unsigned long long val;
  if (parse_ull_arg(value, &val, "--chunk-size") != 0)
    return -1;
  if (val == 0) {
    log_message(LOG_LEVEL_ERROR, "--chunk-size must be a positive integer");
    return -1;
  }
  if (val > MAX_CHUNK_SIZE) {
    log_message(LOG_LEVEL_ERROR, "--chunk-size must be between 1 and %llu",
                (unsigned long long)MAX_CHUNK_SIZE);
    return -1;
  }
  config->chunk_size = val;
  return 0;
}

/* Network/IO options: --server-port/--port, --bwlimit, --chunk-size, --log-file
 * and --stderr.  Returns true when the argument was consumed. */
static bool cli_handle_io_options(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (opt_is(arg, "--server-port", "--port")) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_server_port_option(config, ctx->argv[++ctx->i], arg) != 0)
      ctx->exit_code = -1;
    return true;
  }
  /* rsync users commonly write --port=NNNN; --server-port=NNNN is accepted too
   * so both spellings behave identically. */
  if (strncmp(arg, "--server-port=", 14) == 0 || strncmp(arg, "--port=", 7) == 0) {
    const char* option_name = strncmp(arg, "--server-port=", 14) == 0 ? "--server-port" : "--port";
    const char* value = arg + (strncmp(arg, "--server-port=", 14) == 0 ? 14 : 7);
    if (set_server_port_option(config, value, option_name) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--bwlimit=", 10) == 0) {
    if (set_bwlimit_option(arg + 10) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--bwlimit", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_bwlimit_option(ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--chunk-size=", 13) == 0) {
    if (set_chunk_size_option(config, arg + 13) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--chunk-size", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_chunk_size_option(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--log-file=", 11) == 0) {
    if (set_log_file_option(config, arg + 11) != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--log-file", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (set_log_file_option(config, ctx->argv[++ctx->i]) != 0)
      ctx->exit_code = -1;
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
  /* rsync's deprecated spelling of --stderr=all. */
  if (opt_is(arg, "--msgs2stderr", NULL)) {
    if (set_stderr_mode("all") != 0)
      ctx->exit_code = -1;
    return true;
  }
  return false;
}

/* Filter / files-from options.  Returns true when the argument was consumed. */
static bool cli_handle_filter_options(CliParseCtx* ctx) {
  Config* config = ctx->config;
  const char* arg = ctx->argv[ctx->i];
  if (strncmp(arg, "--exclude-from=", 15) == 0) {
    if (read_patterns_from_file(arg + 15, &config->exclude_patterns, &config->exclude_count, config,
                                '-', "--exclude-from") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (opt_is(arg, "--exclude-from", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (read_patterns_from_file(ctx->argv[++ctx->i], &config->exclude_patterns,
                                &config->exclude_count, config, '-', "--exclude-from") != 0)
      ctx->exit_code = -1;
    return true;
  }
  if (strncmp(arg, "--include-from=", 15) == 0) {
    if (read_patterns_from_file(arg + 15, &config->include_patterns, &config->include_count, config,
                                '+', "--include-from") != 0)
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
                                &config->include_count, config, '+', "--include-from") != 0)
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
    int info_ret = parse_info_flags(arg + 7, config);
    if (info_ret != 0)
      ctx->exit_code = info_ret;
    return true;
  }
  if (opt_is(arg, "--info", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      ctx->exit_code = -1;
      return true;
    }
    int info_ret = parse_info_flags(ctx->argv[++ctx->i], config);
    if (info_ret != 0)
      ctx->exit_code = info_ret;
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

/* Determine whether a --chown spec sets the owner and/or group side, honoring
 * the same escape-aware splitting as identity_parse_chown(): a `\:` is a literal
 * colon, not a field separator. */
static void chown_spec_sides(const char* value, bool* has_owner, bool* has_group) {
  *has_owner = false;
  *has_group = false;
  if (!value)
    return;
  bool split = false;
  for (const char* p = value; *p; p++) {
    if (*p == '\\' && p[1] == ':') {
      p++;
      continue;
    }
    if (*p == ':') {
      split = true;
      continue;
    }
    if (split)
      *has_group = true;
    else
      *has_owner = true;
  }
}

/* rsync refuses to mix --chown with --usermap/--groupmap on the SAME side
 * ("--usermap conflicts with prior --chown").  `chown_value` is non-NULL only
 * for the --chown option itself.  Returns true and records a parse error when
 * the new option conflicts with one already seen. */
static bool mapping_option_conflicts(CliParseCtx* ctx, const char* optname, bool is_group,
                                     const char* chown_value) {
  const Config* config = ctx->config;
  if (chown_value) {
    bool has_owner;
    bool has_group;
    chown_spec_sides(chown_value, &has_owner, &has_group);
    if (has_owner && config->usermap_count > 0) {
      log_message(LOG_LEVEL_ERROR, "%s conflicts with prior --usermap", optname);
      ctx->exit_code = -1;
      return true;
    }
    if (has_group && config->groupmap_count > 0) {
      log_message(LOG_LEVEL_ERROR, "%s conflicts with prior --groupmap", optname);
      ctx->exit_code = -1;
      return true;
    }
    return false;
  }
  if (!is_group && config->chown_uid_set) {
    log_message(LOG_LEVEL_ERROR, "%s conflicts with prior --chown", optname);
    ctx->exit_code = -1;
    return true;
  }
  if (is_group && config->chown_gid_set) {
    log_message(LOG_LEVEL_ERROR, "%s conflicts with prior --chown", optname);
    ctx->exit_code = -1;
    return true;
  }
  return false;
}

static bool usermap_conflicts_with_chown(CliParseCtx* ctx, const char* optname, bool is_group) {
  return mapping_option_conflicts(ctx, optname, is_group, NULL);
}

static bool chown_conflicts_with_map(CliParseCtx* ctx, const char* optname, const char* value) {
  return mapping_option_conflicts(ctx, optname, false, value);
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
    if (usermap_conflicts_with_chown(ctx, "--usermap", false))
      return true;
    if (identity_parse_map(config, arg + 10, false) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    config->preserve_owner = true;
    return true;
  }
  if (opt_is(arg, "--usermap", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (usermap_conflicts_with_chown(ctx, "--usermap", false))
      return true;
    if (identity_parse_map(config, ctx->argv[++ctx->i], false) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    config->preserve_owner = true;
    return true;
  }
  if (strncmp(arg, "--groupmap=", 11) == 0) {
    if (usermap_conflicts_with_chown(ctx, "--groupmap", true))
      return true;
    if (identity_parse_map(config, arg + 11, true) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    config->preserve_group = true;
    return true;
  }
  if (opt_is(arg, "--groupmap", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (usermap_conflicts_with_chown(ctx, "--groupmap", true))
      return true;
    if (identity_parse_map(config, ctx->argv[++ctx->i], true) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    config->preserve_group = true;
    return true;
  }
  if (strncmp(arg, "--chown=", 8) == 0) {
    if (chown_conflicts_with_map(ctx, "--chown", arg + 8))
      return true;
    if (identity_parse_chown(config, arg + 8) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    if (config->chown_uid_set)
      config->preserve_owner = true;
    if (config->chown_gid_set)
      config->preserve_group = true;
    return true;
  }
  if (opt_is(arg, "--chown", NULL)) {
    if (ctx->i + 1 >= ctx->argc) {
      log_message(LOG_LEVEL_ERROR, "missing argument for %s", arg);
      ctx->exit_code = -1;
      return true;
    }
    if (chown_conflicts_with_map(ctx, "--chown", ctx->argv[ctx->i + 1]))
      return true;
    if (identity_parse_chown(config, ctx->argv[++ctx->i]) != 0) {
      ctx->exit_code = -1;
      return true;
    }
    if (config->chown_uid_set)
      config->preserve_owner = true;
    if (config->chown_gid_set)
      config->preserve_group = true;
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
  /* An explicit --debug=FLAGS enables the debug log level by itself (rsync
     behaviour); -v enables every other INFO-level message. */
  bool debug_enabled = verbose || config->debug_level != 0;
  set_log_level(config->quiet ? LOG_LEVEL_ERROR
                              : (debug_enabled ? LOG_LEVEL_DEBUG : LOG_LEVEL_WARNING));
  /* rsync's plain --delete defaults to delete-during (--del): each directory's
     extras are removed as that directory is processed, so space is freed
     progressively and a tight destination never has to hold the whole old+new
     tree at once.  The late whole-tree commit FastSync historically used is
     still selected explicitly by --delete-after or by the FastSync-only long
     spelling --delete-commit (an exact alias for --delete-after).  Resolve the
     default on the client, before validation and before the config crosses the
     wire, so exactly one timing flag is ever set; an explicit timing (including
     --delete-commit) always wins. */
  if (config->use_delete && !config->delete_before && !config->delete_during &&
      !config->delete_delay && !config->delete_after)
    config->delete_during = true;
  /* rsync parity: --partial-dir=DIR chooses where an interrupted transfer's
     partial file is kept, so it implies --partial.  rsync applies the
     implication after option parsing, so it wins over an explicit --no-partial
     regardless of the order the two options appear in (verified on rsync
     3.4.1).  --inplace is the exception: the destination file is written in
     place with no partial/temp staging, so the partial machinery is bypassed
     and the implication is skipped to leave --inplace behavior untouched. */
  if (config->partial_dir && !config->inplace)
    config->partial = true;
  if (config->compress_choice) {
    int algo = compression_algo_from_name(config->compress_choice);
    if (algo >= 0) {
      config->compression_algo = algo;
      config->use_compression = (algo != (int)COMPRESSION_ALGO_NONE);
    }
  }
  /* A bare -z (no --compress-choice) resolves like rsync's "auto": the
   * RSYNC_COMPRESS_LIST preference list first, then the compiled-in order.  A
   * list that names no supported codec is rsync's failed negotiation (exit 4). */
  if (config->use_compression && !config->compress_choice) {
    int resolved = compression_choice_resolve();
    if (resolved < 0) {
      log_message(LOG_LEVEL_ERROR, "RSYNC_COMPRESS_LIST names no supported compression algorithm");
      config->cli.cli_exit_code = 4;
      return -1;
    }
    config->compression_algo = resolved;
    if (resolved == (int)COMPRESSION_ALGO_NONE)
      config->use_compression = false;
  }
  /* Apply rsync's per-codec compression level: an explicit --compress-level is
   * clamped to the codec's range, otherwise the codec's own default is used. */
  if (config->use_compression) {
    CompressionAlgo algo = (CompressionAlgo)config->compression_algo;
    config->compression_level = config->cli.compression_level_set
                                    ? compression_clamp_level(algo, config->compression_level)
                                    : compression_default_level(algo);
    log_debug_message(LOG_DEBUG_UTIL, "Client compression: %s (level %d)",
                      compression_algo_name(algo), config->compression_level);
  }
  /* The negotiated checksum is always resolved (rsync negotiates one for the
   * delta strong sum even without --checksum): RSYNC_CHECKSUM_LIST first, then
   * the compiled-in order.  An explicit --checksum-choice already set it. */
  if (!config->cli.checksum_choice_set) {
    int resolved = checksum_choice_resolve();
    if (resolved < 0) {
      log_message(LOG_LEVEL_ERROR, "RSYNC_CHECKSUM_LIST names no supported checksum algorithm");
      config->cli.cli_exit_code = 4;
      return -1;
    }
    config->checksum_algo = resolved;
    config->cli.checksum_transfer_algo = resolved;
  }
  /* rsync parity: "none" as the pre-transfer checksum cannot be combined with
   * --checksum (exit 4).  The check runs here because --checksum may appear on
   * either side of --checksum-choice. */
  if (config->checksum && config->checksum_algo == (int)CHECKSUM_ALGO_NONE) {
    log_message(LOG_LEVEL_ERROR, "Invalid checksum-choice for --checksum: none");
    config->cli.cli_exit_code = 4;
    return -1;
  }

  /* rsync randomizes the checksum seed for every transfer when the user did not
   * supply one (a seed of 0, including an explicit --checksum-seed=0), using
   * time(NULL) ^ (getpid() << 6), and transmits it so both ends agree.  Mirror
   * that: the wire config carries the value, so the receiver uses the exact
   * seed this sender hashed with.  A non-zero --checksum-seed is honored
   * verbatim (deterministic). */
  if (config->checksum_seed == 0)
    config->checksum_seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 6);

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

  /* The "unchanged" decision for --compare-dest/--copy-dest/--link-dest must
   * be made on the receiver against the basis directories, which requires the
   * per-file STATUS_CHECK handshake: basis-dir options therefore imply
   * --incremental (and, via the derived bit below, metadata) on the sender. */
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

  /* -c/--checksum switches the per-file quick-check from size+mtime to a
   * content digest; FastSync expresses that comparison through the incremental
   * handshake, so -c implies --incremental.  rsync's -c does NOT imply -t (the
   * digest alone decides), so the incremental auto-preserve below must not be
   * triggered by a checksum-only implication: capture the explicitly requested
   * incremental/delta state first. */
  bool preserve_implied = config->use_incremental || config->use_delta;
  if (config->checksum)
    config->use_incremental = true;

  /* --incremental/--delta historically auto-enabled the metadata path, which
   * applied mode+mtime (README: "--incremental Auto-enables --preserve").
   * Restore that behavior by turning on the two attributes unless the user
   * explicitly negated them (--no-perms/--no-times/--no-preserve).  This runs
   * BEFORE the derived use_metadata bit so the transport frame is still sent
   * for the incremental/delta handshake even when both attributes were negated
   * via --no-preserve (cli.metadata_explicitly_disabled handles that opt-out). */
  if (preserve_implied && !config->cli.metadata_explicitly_disabled) {
    if (!config->cli.preserve_perms_explicit_off)
      config->preserve_perms = true;
    if (!config->cli.preserve_times_explicit_off)
      config->preserve_times = true;
  }

  /* --ignore-existing is a receiver-side existence policy: the receiver must
   * answer "skip" BEFORE the sender transmits any payload, which only the
   * per-file STATUS_CHECK handshake provides.  Imply --incremental here (after
   * the auto-preserve capture above, so a bare --ignore-existing does not gain
   * -p/-t, which rsync likewise does not imply) so an existing destination is
   * skipped on the wire instead of being streamed and discarded. */
  if (config->ignore_existing)
    config->use_incremental = true;

  /* Derive the transport bit from the FINAL parsed flags.  Every
   * preservation/ownership option that needs the metadata frame (per-attribute
   * perms/times/owner/group, atimes/crtimes, executability, xattrs/acls,
   * fake-super, devices/specials, chmod, identity maps/chown/copy-as, and the
   * incremental/delta handshake unless --no-preserve explicitly disabled it) is
   * centralized in config_derived_use_metadata(). */
  config->use_metadata = config_derived_use_metadata(config);
  /* Recompute the derived xattr flag from the FINAL preserve flags (after any
   * --no-xattrs/--no-acls negation) so the sender's wire gate always matches
   * the flags the receiver will recompute from the received config. */
  config->use_xattrs = config->preserve_acls || config->preserve_xattrs;
  /* Output parity: -i/--itemize-changes, --out-format and --log-file-format
   * need the pre-transfer destination snapshot (new vs modified and which
   * attributes differ), so ask the receiver to report it on every per-file
   * check.  This is a wire field. */
  bool progress_active =
      !config->quiet && (config->show_progress || (config->info_level & LOG_INFO_PROGRESS) != 0);
  config->report_dest_info = config->itemize_changes || config->out_format != NULL ||
                             (config->log_file != NULL && config->log_file_format != NULL) ||
                             progress_active;
  /* Wire-stats parity: --stats, --progress/-P, an --out-format token that needs
   * a wire counter (%b/%c), or a dry-run --delete need the receiver's
   * end-of-transfer STATUS_STATS report.  This is a wire field (protocol
   * 2.25.0). */
  bool format_needs_wire = false;
  if (config->out_format != NULL) {
    for (const char* p = config->out_format; *p != '\0'; p++) {
      if (p[0] == '%' && (p[1] == 'b' || p[1] == 'c')) {
        format_needs_wire = true;
        break;
      }
    }
  }
  /* --info=del on a real --delete run asks the receiver to report the paths it
     actually removed; the report rides the STATUS_STATS path list, so the wire
     stats frame must be negotiated too.  --debug=del needs the same paths, so
     it opts into the existing report (no new wire field). */
  config->report_deletes =
      config->use_delete && !config->dry_run &&
      ((config->info_level & LOG_INFO_DEL) != 0 || config->itemize_changes ||
       config->out_format != NULL || (config->debug_level & LOG_DEBUG_DEL) != 0);
  config->report_stats = config->stats || config->show_progress ||
                         (config->info_level & LOG_INFO_PROGRESS) || format_needs_wire ||
                         config->report_deletes || (config->dry_run && config->use_delete);
  return 0;
}

/* True for the rsync short options that take a value: the remainder of the
 * cluster is the value (attached form), or the next argv entry when the option
 * is written alone. */
static bool short_takes_value(char c) {
  return c == 'e' || c == 'B' || c == 'M' || c == 'f' || c == 'T' || c == '@';
}

/* True when the long option consumes the following argv entry as its value
 * (i.e. a value-taking option written without an inline "=").  The cluster
 * expander consults this so a value that happens to start with '-' (e.g.
 * --filter "- *.tmp") is copied verbatim instead of being mistaken for a
 * short-option cluster. */
static bool cli_long_takes_separate_value(const char* arg) {
  if (strchr(arg, '='))
    return false;
  const OptionEntry* entry = find_table_option(arg);
  if (entry)
    return entry->kind == OPT_STRING || entry->kind == OPT_POS_INT ||
           entry->kind == OPT_NONNEG_INT || entry->kind == OPT_ULL || entry->kind == OPT_SIGNED_INT;
  static const char* const extra[] = {
      "--ssh-port",        "--exclude",      "--include",       "--exclude-from",
      "--include-from",    "--files-from",   "--filter",        "--delta-block",
      "--block-size",      "--delta-max",    "--server-port",   "--port",
      "--bwlimit",         "--chunk-size",   "--log-file",      "--stderr",
      "--stop-after",      "--stop-at",      "--max-alloc",     "--compress-threads",
      "--checksum-choice", "--cc",           "--checksum-seed", "--sockopts",
      "--remote-option",   "--compare-dest", "--copy-dest",     "--link-dest",
      "--usermap",         "--groupmap",     "--chown",         "--copy-as",
      "--outbuf",          "--debug",        "--info",          "--skip-compress",
  };
  for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]); i++)
    if (strcmp(arg, extra[i]) == 0)
      return true;
  return false;
}

/* Expand rsync-style short-option clusters into one option per token before
 * parsing: -av -> -a -v, -rlpt -> -r -l -p -t, -B1048576 -> -B 1048576 and
 * -essh -> -e ssh.  A value-taking short consumes the remainder of its token
 * (an optional leading '=' is dropped) as its value; otherwise a value-taking
 * option written alone takes the next argv entry, which is therefore copied
 * verbatim.  Every expanded token is a copy; *out_orig maps each expanded
 * token back to its source argv index so the positional-argument indices
 * returned to main() stay valid for the caller's original argv.  Returns 0 on
 * success, -1 on allocation failure. */
static int expand_short_clusters(int argc, char* argv[], char*** out_argv, int** out_orig,
                                 int* out_argc) {
  size_t cap = 1;
  for (int i = 0; i < argc; i++)
    cap += strlen(argv[i]) + 2;
  char** exp = calloc(cap, sizeof(char*));
  int* orig = calloc(cap, sizeof(int));
  if (!exp || !orig) {
    free(exp);
    free(orig);
    return -1;
  }
  int n = 0;
  bool expect_value = false;
  for (int i = 0; i < argc; i++) {
    const char* tok = argv[i];
    if (i == 0 || expect_value || tok[0] != '-' || tok[1] == '\0') {
      exp[n] = str_dup(tok);
      if (!exp[n])
        goto oom;
      orig[n] = i;
      n++;
      expect_value = false;
      continue;
    }
    if (tok[1] == '-') {
      exp[n] = str_dup(tok);
      if (!exp[n])
        goto oom;
      orig[n] = i;
      n++;
      expect_value = cli_long_takes_separate_value(tok);
      continue;
    }
    size_t len = strlen(tok);
    for (size_t j = 1; j < len; j++) {
      char flag[3] = {'-', tok[j], '\0'};
      exp[n] = str_dup(flag);
      if (!exp[n])
        goto oom;
      orig[n] = i;
      n++;
      if (short_takes_value(tok[j])) {
        const char* value = tok + j + 1;
        if (*value == '=')
          value++;
        if (*value != '\0') {
          exp[n] = str_dup(value);
          if (!exp[n])
            goto oom;
          orig[n] = i;
          n++;
        } else {
          expect_value = true;
        }
        break;
      }
    }
  }
  *out_argv = exp;
  *out_orig = orig;
  *out_argc = n;
  return 0;
oom:
  for (int k = 0; k < n; k++)
    free(exp[k]);
  free(exp);
  free(orig);
  return -1;
}

static void free_expanded_args(char** exp, int exp_argc) {
  for (int i = 0; i < exp_argc; i++)
    free(exp[i]);
  free(exp);
}

/* Parse CLI arguments into config. Returns 0 on success, -1 on error, 1 for help/clean-exit. */
int parse_args(Config* config, int argc, char* argv[], int* positional_args,
               int* positional_count) {
  protocol_set_8_bit_output(config->eight_bit_output);

  char** exp_argv = NULL;
  int* exp_orig = NULL;
  int exp_argc = 0;
  if (expand_short_clusters(argc, argv, &exp_argv, &exp_orig, &exp_argc) != 0) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed parsing arguments");
    return -1;
  }

  int result = -1;
  /* rsync treats a lone -h as a help request (it only means human-readable
   * when combined with a source/destination or other options). */
  if (exp_argc == 2 && strcmp(exp_argv[1], "-h") == 0) {
    print_usage();
    result = 1;
    goto done;
  }
  int output_ret = cli_apply_output_controls(config, exp_argc, exp_argv);
  if (output_ret != 0) {
    result = output_ret;
    goto done;
  }

  CliParseCtx ctx = {
      .config = config,
      .argc = exp_argc,
      .argv = exp_argv,
      .i = 1,
      .exit_code = 0,
      .verbose = false,
      .no_delta = false,
      .no_incremental = false,
  };

  for (ctx.i = 1; ctx.i < exp_argc; ctx.i++) {
    ctx.exit_code = 0;
    bool handled = cli_handle_pre_negation(&ctx) || cli_handle_range_time_options(&ctx) ||
                   cli_handle_table_option(&ctx) || cli_handle_inline_chmod(&ctx) ||
                   cli_handle_meta_flags(&ctx) || cli_handle_ssh_and_pattern_options(&ctx) ||
                   cli_handle_transfer_flags(&ctx) || cli_handle_io_options(&ctx) ||
                   cli_handle_filter_options(&ctx) || cli_handle_logging_options(&ctx) ||
                   cli_handle_checksum_options(&ctx) || cli_handle_remote_basis_options(&ctx) ||
                   cli_handle_outbuf_option(&ctx);
    if (handled) {
      if (ctx.exit_code != 0) {
        result = ctx.exit_code;
        goto done;
      }
      continue;
    }

    if (ctx.argv[ctx.i][0] == '-') {
      char* escaped = output_escape(ctx.argv[ctx.i], false);
      fprintf(stderr, "Unknown option: %s (FastSync does not support this option)\n",
              escaped ? escaped : "<allocation failed>");
      free(escaped);
      print_usage();
      goto done;
    }
    if (*positional_count < 2)
      positional_args[(*positional_count)++] = exp_orig[ctx.i];
    else {
      char* escaped = output_escape(ctx.argv[ctx.i], false);
      fprintf(stderr, "Unexpected argument: %s\n", escaped ? escaped : "<allocation failed>");
      free(escaped);
      print_usage();
      goto done;
    }
  }

  result = cli_finalize_config(config, ctx.verbose, ctx.no_delta, ctx.no_incremental);
done:
  free_expanded_args(exp_argv, exp_argc);
  free(exp_orig);
  return result;
}

static int read_patterns_from_file(const char* filepath, char*** patterns, int* count,
                                   Config* config, char sign, const char* optname) {
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
  while (true) {
    ssize_t n = utils_getdelim_bounded(fp, &line, &line_size, '\n', UTILS_MAX_LINE_LEN);
    if (n < 0) {
      /* output_escape() may allocate (and clobber errno): capture the reader's
       * errno first so an over-long line is still reported as EFBIG. */
      int saved_errno = errno;
      char* escaped = output_escape(filepath, false);
      if (saved_errno == EFBIG) {
        log_message(LOG_LEVEL_ERROR, "pattern file '%s' has a line exceeding %d bytes",
                    escaped ? escaped : "<allocation failed>", (int)UTILS_MAX_LINE_LEN);
      } else {
        log_message(LOG_LEVEL_ERROR, "could not read pattern file '%s': %s",
                    escaped ? escaped : "<allocation failed>", strerror(saved_errno));
      }
      free(escaped);
      free(line);
      fclose(fp);
      return -1;
    }
    if (n == 0)
      break;
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
    if (config_add_pattern(patterns, count, p, "pattern file") != 0 ||
        config_add_selection_rule(config, sign, p, optname) != 0) {
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
  /* Capture the process umask now, while still single-threaded: the cached
   * value is what file_mode_base() uses, and reading it later would race with
   * receiver threads creating files. */
  file_umask_capture();
  /* The server may close a connection mid-stream (e.g. when it rejects an
     oversized delta).  Ignore SIGPIPE so that a broken TCP connection
     surfaces as a clean write error instead of killing the client. */
  signal(SIGPIPE, SIG_IGN);
  /* Ctrl-C / SIGTERM: set the abort flag so the send loops can send
   * STATUS_ABORT and let the receiver clean up, instead of dying abruptly.
   * No SA_RESTART so an in-flight poll()/read() is interrupted (EINTR), which
   * lets the keepalive/abort checks observe the flag promptly. */
  struct sigaction abort_action;
  memset(&abort_action, 0, sizeof(abort_action));
  abort_action.sa_handler = client_signal_handler;
  sigemptyset(&abort_action.sa_mask);
  abort_action.sa_flags = 0;
  sigaction(SIGINT, &abort_action, NULL);
  sigaction(SIGTERM, &abort_action, NULL);
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
      exit_code = config->cli.cli_exit_code ? config->cli.cli_exit_code : 1;
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

  /* Install the negotiated codec for this process before any transfer thread
   * is spawned; the compressed frames are self-describing, so the receiver's
   * decompressor does not need this, but the sender compressor does. */
  compression_set_algo((CompressionAlgo)config->compression_algo);

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
    exit_code = send_files_multithreaded(config);
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
