#include "config.h"
#include "charset.h"
#include "chmod.h"
#include "credentials.h"
#include "daemon_conf.h"
#include "delay_updates.h"
#include "delta.h"
#include "file_list.h"
#include "identity.h"
#include "log.h"
#include "protocol.h"
#include "utils.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <errno.h>

static void config_set_defaults(Config* config) {
  config->scanner_threads = 0;
  config->metadata_explicitly_disabled = false;
  config->preserve_perms_explicit_off = false;
  config->preserve_times_explicit_off = false;
  config->show_progress = false;
  config->compression_threads = 0;
  config->ssh_port = 22;
  config->transport = TRANSPORT_TCP;
  config->ssh_destination = NULL;
  config->auth_password = NULL;
  config->password_file = NULL;
  config->fastsync_server_path = NULL;
  config->exclude_patterns = NULL;
  config->exclude_count = 0;
  config->include_patterns = NULL;
  config->include_count = 0;
  config->max_size = 0;
  config->min_size = 0;
  config->whole_file = false;
  config->use_tls = false;
  config->tls_cert = NULL;
  config->tls_key = NULL;
  config->tls_ca = NULL;
  config->server_host = str_dup("127.0.0.1");
  config->server_port = 8080;
  config->server_port_set = false;
  config->server_host_set = false;
  /* rsync defaults: --timeout=0 (I/O timeouts disabled) and --contimeout=60.
   * A value of 0 disables the client's own deadline on both the socket layer
   * (tcp_set_timeouts) and the protocol layer
   * (protocol_session_set_io_timeout); a positive value sets it.  A server
   * session floors the deadline at SERVER_IO_TIMEOUT_SEC so 0 can never hold a
   * connection open forever. */
  config->timeout = 0;
  config->contimeout = 60;
  config->quiet = false;
  config->stats = false;
  config->max_depth = 0;
  config->log_file = NULL;
  config->copy_dirlinks = false;
  config->itemize_changes = false;
  config->out_format = NULL;
  config->log_file_format = NULL;
  config->info_level = 0;
  config->debug_level = 0;
  config->list_only = false;
  config->human_readable = false;
  config->ignore_errors = false;
  config->ignore_missing_args = false;
  config->checksum_transfer_algo = CHECKSUM_ALGO_DEFAULT;
  config->cli_exit_code = 0;
  config->compression_level_set = false;
  config->checksum_choice_set = false;
  config->filters = NULL;
  config->files_from = NULL;
  config->files_from_set = NULL;
  config->from0 = false;
  config->cvs_exclude = false;
  config->per_dir_filter = false;
  config->per_dir_filter_count = 0;
  config->one_file_system = false;
  config->no_implied_dirs = false;
  config->dirs = false;
  config->rsh_command = NULL;
  config->blocking_io = false;
  config->outbuf = OUTBUF_BLOCK;
  config->old_args = false;
  config->remote_options = NULL;
  config->remote_option_count = 0;
  config->address = NULL;
  config->ipv6 = false;
  config->ipv4 = false;
  config->sockopts = NULL;
  config->sockopt_count = 0;
  config->daemon = false;
  config->no_motd = false;
  config->delay_context = NULL;
  config->open_noatime = false;
  config->use_xattrs = false;
  config->trust_sender = false;
  config->stop_after_mins = 0;
  config->stop_at = 0;
  config->stop_at_set = false;
  config->write_batch = NULL;
  config->only_write_batch = NULL;
  config->read_batch = NULL;

  /* Serialized fields: defaults come from the CONFIG_WIRE_FIELDS table so the
   * member declaration, default and wire codec can never drift apart. */
#define CONFIG_DEFAULT_FIELD(name, ctype, def, kind) config->name = def;
  CONFIG_WIRE_FIELDS(CONFIG_DEFAULT_FIELD)
#undef CONFIG_DEFAULT_FIELD
}

static bool valid_wire_bool(int value) {
  return value == 0 || value == 1;
}

static bool receive_wire_bool(int fd, bool* value) {
  int wire_value;
  if (!receive_int(fd, &wire_value) || !valid_wire_bool(wire_value))
    return false;
  *value = wire_value != 0;
  return true;
}

/* Cumulative budget for the strings retained by one received Config (see
 * MAX_CONFIG_STRING_BYTES).  Config strings are received once per connection
 * before authentication and live for its whole lifetime, so the charge is never
 * released. */
typedef struct {
  unsigned long long used;
} ConfigStringBudget;

/* Charge `bytes` (the retained allocation: string body plus NUL) against the
 * aggregate config-string budget.  Returns false when the ceiling would be
 * exceeded, letting the caller reject the frame with a clear error instead of
 * retaining unbounded pre-auth memory. */
static bool config_string_budget_charge(ConfigStringBudget* budget, size_t bytes) {
  if ((unsigned long long)bytes > MAX_CONFIG_STRING_BYTES ||
      budget->used > MAX_CONFIG_STRING_BYTES - (unsigned long long)bytes) {
    log_message(LOG_LEVEL_ERROR, "Config string budget exceeded (%llu + %zu > %llu bytes)",
                budget->used, bytes, (unsigned long long)MAX_CONFIG_STRING_BYTES);
    return false;
  }
  budget->used += (unsigned long long)bytes;
  return true;
}

static char* config_receive_str(int fd, ConfigStringBudget* budget) {
  char* value = receive_str(fd);
  if (!value)
    return NULL;
  if (!config_string_budget_charge(budget, strlen(value) + 1)) {
    free(value);
    return NULL;
  }
  return value;
}

static char* config_receive_str_redacted(int fd, ConfigStringBudget* budget) {
  char* value = receive_str_redacted(fd);
  if (!value)
    return NULL;
  if (!config_string_budget_charge(budget, strlen(value) + 1)) {
    free(value);
    return NULL;
  }
  return value;
}

static bool validate_received_config(const Config* config) {
  /* Cross-field invariants live in one place (config_invariants_error) so the
     receiver enforces every combination the client relies on; a hostile peer
     can forge a frame that violates any clause of the shared predicate. */
  if (config_invariants_error(config) != NULL)
    return false;
  return valid_wire_bool(config->save_to_disk) && valid_wire_bool(config->use_multithreading) &&
         valid_wire_bool(config->use_chunk_serialization) &&
         valid_wire_bool(config->use_compression) && valid_wire_bool(config->use_metadata) &&
         valid_wire_bool(config->use_executability) && valid_wire_bool(config->use_sendfile) &&
         valid_wire_bool(config->use_delete) && valid_wire_bool(config->use_incremental) &&
         valid_wire_bool(config->size_only) && valid_wire_bool(config->ignore_times) &&
         valid_wire_bool(config->use_delta) && valid_wire_bool(config->backup) &&
         valid_wire_bool(config->fuzzy) && valid_wire_bool(config->remove_source_files) &&
         valid_wire_bool(config->follow_symlinks) && valid_wire_bool(config->copy_links) &&
         valid_wire_bool(config->safe_links) && valid_wire_bool(config->copy_unsafe_links) &&
         valid_wire_bool(config->preserve_hard_links) && valid_wire_bool(config->preserve_acls) &&
         valid_wire_bool(config->preserve_xattrs) && valid_wire_bool(config->preserve_devices) &&
         valid_wire_bool(config->preserve_sparse) && valid_wire_bool(config->preserve_specials) &&
         valid_wire_bool(config->copy_devices) && valid_wire_bool(config->write_devices) &&
         valid_wire_bool(config->ignore_existing) && valid_wire_bool(config->existing) &&
         valid_wire_bool(config->update) && valid_wire_bool(config->inplace) &&
         valid_wire_bool(config->append) && valid_wire_bool(config->use_fsync) &&
         valid_wire_bool(config->append_verify) && valid_wire_bool(config->delete_excluded) &&
         valid_wire_bool(config->force_delete) && valid_wire_bool(config->delete_missing_args) &&
         valid_wire_bool(config->delete_after) && valid_wire_bool(config->preallocate) &&
         valid_wire_bool(config->delete_delay) && valid_wire_bool(config->delete_during) &&
         valid_wire_bool(config->relative) && valid_wire_bool(config->prune_empty_dirs) &&
         valid_wire_bool(config->delay_updates) && valid_wire_bool(config->mkpath) &&
         valid_wire_bool(config->partial) && valid_wire_bool(config->delete_before) &&
         valid_wire_bool(config->checksum) && valid_wire_bool(config->eight_bit_output) &&
         valid_wire_bool(config->dry_run) && checksum_algo_valid(config->checksum_algo) &&
         compression_algo_valid(config->compression_algo) && identity_wire_valid(config) &&
         valid_wire_bool(config->preserve_atimes) && valid_wire_bool(config->preserve_crtimes) &&
         valid_wire_bool(config->omit_dir_times) && valid_wire_bool(config->omit_link_times) &&
         valid_wire_bool(config->preserve_perms) && valid_wire_bool(config->preserve_times) &&
         valid_wire_bool(config->preserve_owner) && valid_wire_bool(config->preserve_group) &&
         valid_wire_bool(config->munge_links) && valid_wire_bool(config->keep_dirlinks) &&
         valid_wire_bool(config->fake_super) && valid_wire_bool(config->report_dest_info) &&
         valid_wire_bool(config->report_stats) && valid_wire_bool(config->report_deletes) &&
         (!config->copy_as_set || (config->copy_as_uid >= 0 && config->copy_as_gid >= 0)) &&
         (!config->use_compression ||
          (config->compression_level >= 1 && config->compression_level <= 22)) &&
         config->chunk_size > 0 && config->chunk_size <= MAX_CHUNK_SIZE &&
         config->delta_block_size >= DELTA_BLOCK_SIZE_MIN &&
         config->delta_block_size <= DELTA_BLOCK_SIZE_MAX &&
         config->delta_max_file_size <= DELTA_MAX_FILE_SIZE && config->modify_window >= 0 &&
         config->max_delete >= -1 && config->max_alloc <= MAX_SERVER_ALLOC &&
         config->skip_compress_count >= 0 &&
         config->skip_compress_count <= MAX_SKIP_COMPRESS_SUFFIXES &&
         (!config->chmod_spec || !*config->chmod_spec ||
          chmod_apply(0, config->chmod_spec, &(mode_t){0})) &&
         config->super_mode >= SUPER_MODE_AUTO && config->super_mode <= SUPER_MODE_OFF;
}

Config* config_create(void) {
  Config* config = malloc(sizeof(Config));
  if (!config)
    return NULL;
  config_set_defaults(config);
  return config;
}

bool config_delete_timing_early(const Config* config) {
  if (!config)
    return false;
  return config->delete_before;
}

bool config_delete_timing_per_dir(const Config* config) {
  if (!config)
    return false;
  return config->delete_during || config->delete_delay;
}

/* A delete-timing flag is only meaningful together with --delete.  At most one
   of the four flags may be set; several simultaneous timings are a client bug
   and are rejected on both ends. */
bool config_has_valid_delete_timing(const Config* config) {
  if (!config)
    return false;
  if (!config->use_delete)
    return !config->delete_before && !config->delete_during && !config->delete_delay &&
           !config->delete_after;
  int timing_count = (config->delete_before ? 1 : 0) + (config->delete_during ? 1 : 0) +
                     (config->delete_delay ? 1 : 0) + (config->delete_after ? 1 : 0);
  return timing_count <= 1;
}

/* The cross-field invariants FastSync relies on, in one place.  Every message
 * here was previously duplicated (verbatim) in client_validation.c and/or
 * config.c; the client reports the returned string for UX and the server
 * enforces the same rules at its trust boundary.  Pure: no I/O, no logging.
 * The order is deliberate (most specific structural conflicts first). */
const char* config_invariants_error(const Config* config) {
  if (!config)
    return "Invalid configuration";
  if (config_has_basis(config) && config->use_chunk_serialization)
    return "--compare-dest/--copy-dest/--link-dest require per-file incremental checks and cannot "
           "be combined with -s (chunk serialization)";
  if (config->use_sendfile && (config->use_chunk_serialization || config->use_compression))
    return "-f/--sendfile cannot be combined with -c (compression) or -s (chunk serialization)";
  if (config->use_incremental && config->use_chunk_serialization)
    return "--incremental is not supported with -s (chunk serialization)";
  if (config->skip_compress_set && config->use_chunk_serialization)
    return "--skip-compress cannot be combined with -s (chunk serialization)";
  if (config->use_delta && !config->whole_file && !config->use_incremental)
    return "--delta requires --incremental";
  if (config->use_delta && !config->whole_file && config->use_chunk_serialization)
    return "--delta cannot be combined with -s (chunk serialization)";
  if (config->use_delta && !config->whole_file && config->use_sendfile)
    return "--delta cannot be combined with -f (sendfile)";
  /* --append / --append-verify resume a shorter existing destination by
     transmitting only the tail.  The resume needs the per-file STATUS_CHECK
     handshake (so the dest length is learned), which chunk serialization -s
     disables; whole-file is the opposite intent (send everything). */
  if ((config->append || config->append_verify) && config->use_chunk_serialization)
    return "--append/--append-verify require the per-file incremental check and cannot be "
           "combined with -s (chunk serialization)";
  if ((config->append || config->append_verify) && config->whole_file)
    return "--append/--append-verify are incompatible with --whole-file (which forces a full "
           "transfer)";
  /* -H transmits each later hard-link group member as a dedicated per-file
     STATUS_HARDLINK frame, which -s does not support; and a hard-links sibling
     carries no payload, so the tail-resume of --append is meaningless. */
  if (config->preserve_hard_links && config->use_chunk_serialization)
    return "--hard-links/-H cannot be combined with -s (chunk serialization)";
  /* -X/-A ride the per-file metadata frame; the chunk-serialization wire format
     does not carry the xattr block. */
  if ((config->preserve_xattrs || config->preserve_acls) && config->use_chunk_serialization)
    return "--xattrs/-X and --acls/-A cannot be combined with -s (chunk serialization)";
  if (config->preserve_hard_links && (config->append || config->append_verify))
    return "--hard-links/-H cannot be combined with --append/--append-verify";
  if (config->delay_updates && config->inplace)
    return "--delay-updates does not work with --inplace";
  if (config->delay_updates && delay_updates_staging_name_conflict(config->backup_dir))
    return "--backup-dir is reserved when --delay-updates is active (used for the internal "
           "staging directory)";
  if (!config_has_valid_delete_timing(config))
    return "--delete-before/--delete-during/--delete-delay/--delete-after select the delete "
           "timing; at most one may be given and each implies --delete";
  if (config->iconv_spec && !charset_spec_valid(config->iconv_spec))
    return "--iconv requires LOCAL[,REMOTE] charset names supported by iconv";
  if ((config->preserve_perms || config->preserve_times || config->preserve_owner ||
       config->preserve_group || config->preserve_atimes || config->preserve_crtimes ||
       config->use_executability) &&
      !config->use_metadata)
    return "a preservation attribute requires metadata transmission";
  if (config->copy_as_set && !config->use_metadata)
    return "--copy-as requires metadata preservation and cannot be combined with --no-preserve";
  return NULL;
}

bool config_derived_use_metadata(const Config* config) {
  if (!config)
    return false;
  if (config->preserve_perms || config->preserve_times || config->preserve_owner ||
      config->preserve_group || config->preserve_atimes || config->preserve_crtimes ||
      config->use_executability || config->preserve_xattrs || config->preserve_acls ||
      config->fake_super || config->preserve_devices || config->preserve_specials ||
      config->copy_devices || config->write_devices ||
      (config->chmod_spec && config->chmod_spec[0]) || config->copy_as_set ||
      config->chown_uid_set || config->chown_gid_set || config->usermap_count > 0 ||
      config->groupmap_count > 0 || config->update)
    return true;
  return (config->use_incremental || config->use_delta) && !config->metadata_explicitly_disabled;
}

bool config_has_basis(const Config* config) {
  return config && config->basis_count > 0;
}

/* A basis-dir path travels from the client to the receiver and is resolved
 * below the destination root when relative, or used verbatim when absolute
 * (matching rsync).  Either form must be non-empty, traversal-free (no "..")
 * and free of "." components: an escaping path would make the receiver read or
 * link files outside its authorized root.  An absolute path is still subject to
 * the receiver's root confinement at open time (file_open_secure_parent), so a
 * basis outside the authorized root is simply not found rather than an escape.
 *
 * Returns a malloc'd CANONICAL copy of an accepted path, or NULL when the path
 * is rejected.  Canonicalization collapses interior empty components ("a//b" ->
 * "a/b"), drops "." components and trailing "/"s, and preserves a leading '/'
 * for absolute paths, so validation, the delete walker prefix match and the
 * receiver's basis lookup all agree on one form.  The normalizer is the single
 * source of truth for both config_basis_path_valid and config_basis_append. */
static char* basis_path_normalize(const char* path) {
  if (!path || path[0] == '\0' || has_path_traversal(path))
    return NULL;
  bool absolute = path[0] == '/';
  if (!absolute && strcmp(path, ".") == 0)
    return NULL;
  if (absolute && strcmp(path, "/") == 0)
    return NULL;
  char* dup = str_dup(path);
  if (!dup)
    return NULL;
  size_t out_len = 0;
  char* out = malloc(strlen(path) + 2);
  if (!out) {
    free(dup);
    return NULL;
  }
  if (absolute)
    out[out_len++] = '/';
  char* saveptr = NULL;
  bool ok = true;
  for (char* part = strtok_r(dup, "/", &saveptr); part; part = strtok_r(NULL, "/", &saveptr)) {
    if (strcmp(part, "..") == 0) {
      ok = false;
      break;
    }
    if (strcmp(part, ".") == 0)
      continue;
    if (out_len > 0 && out[out_len - 1] != '/')
      out[out_len++] = '/';
    size_t len = strlen(part);
    memcpy(out + out_len, part, len);
    out_len += len;
  }
  free(dup);
  if (!ok || out_len == 0 || (absolute && out_len == 1)) {
    free(out);
    return NULL;
  }
  out[out_len] = '\0';
  return out;
}

bool config_basis_path_valid(const char* path) {
  char* normalized = basis_path_normalize(path);
  if (!normalized)
    return false;
  free(normalized);
  return true;
}

int config_basis_append(Config* config, BasisDestType type, const char* path) {
  if (!config ||
      (type != BASIS_DEST_COMPARE && type != BASIS_DEST_COPY && type != BASIS_DEST_LINK) ||
      config->basis_count >= MAX_BASIS_DIRS)
    return -1;
  char* normalized = basis_path_normalize(path);
  if (!normalized)
    return -1;
  BasisDest* grown = realloc(config->basis_dirs, (config->basis_count + 1) * sizeof(BasisDest));
  if (!grown) {
    free(normalized);
    return -1;
  }
  config->basis_dirs = grown;
  config->basis_dirs[config->basis_count].type = type;
  config->basis_dirs[config->basis_count].path = normalized;
  config->basis_count++;
  return 0;
}

/* Strict --sockopts allowlist: map an option NAME to its SockOptId, or -1 when
 * the name is not on the allowlist.  The list is intentionally closed so an
 * unknown option is an error, never a silent no-op. */
static int sockopt_id_from_name(const char* name) {
  if (strcmp(name, "TCP_NODELAY") == 0)
    return SOCKOPT_TCP_NODELAY;
  if (strcmp(name, "SO_KEEPALIVE") == 0)
    return SOCKOPT_SO_KEEPALIVE;
  if (strcmp(name, "SO_RCVBUF") == 0)
    return SOCKOPT_SO_RCVBUF;
  if (strcmp(name, "SO_SNDBUF") == 0)
    return SOCKOPT_SO_SNDBUF;
  if (strcmp(name, "SO_REUSEADDR") == 0)
    return SOCKOPT_SO_REUSEADDR;
  return -1;
}

static bool sockopt_is_boolean(SockOptId id) {
  return id == SOCKOPT_TCP_NODELAY || id == SOCKOPT_SO_KEEPALIVE || id == SOCKOPT_SO_REUSEADDR;
}

/* Parse one SockOptId's value.  Booleans accept only 0/1 (a numeric "on" is
 * rejected rather than coerced); buffer sizes accept any non-negative int.
 * Returns 0 on success, -1 on a bad value. */
static int sockopt_parse_value(SockOptId id, const char* value, int* out) {
  if (sockopt_is_boolean(id)) {
    if (strcmp(value, "0") == 0) {
      *out = 0;
      return 0;
    }
    if (strcmp(value, "1") == 0) {
      *out = 1;
      return 0;
    }
    return -1;
  }
  if (!value || *value == '\0')
    return -1;
  char* end;
  errno = 0;
  long v = strtol(value, &end, 10);
  if (errno != 0 || *end != '\0' || v < 0 || v > INT_MAX)
    return -1;
  *out = (int)v;
  return 0;
}

int config_sockopts_parse(const char* spec, SockOptEntry** out, int* out_count) {
  if (!spec || *spec == '\0' || !out || !out_count)
    return -1;
  char* copy = str_dup(spec);
  if (!copy)
    return -1;

  int count = 0;
  int capacity = 0;
  SockOptEntry* entries = NULL;
  char* saveptr = NULL;
  bool ok = true;
  for (const char* token = strtok_r(copy, ",", &saveptr); token != NULL;
       token = strtok_r(NULL, ",", &saveptr)) {
    if (*token == '\0') {
      ok = false; /* empty entry: a stray/trailing comma */
      break;
    }
    char* eq = strchr(token, '=');
    if (eq)
      *eq = '\0';
    int id = sockopt_id_from_name(token);
    if (id < 0) {
      ok = false; /* unknown option name */
      break;
    }
    int val;
    /* rsync's --sockopts are OPT=VAL; a value is required for every option, so
     * a bare option name (no '=') is rejected rather than coerced. */
    if (eq == NULL || eq[1] == '\0') {
      ok = false; /* missing '=' or missing value */
      break;
    }
    if (sockopt_parse_value((SockOptId)id, eq + 1, &val) != 0) {
      ok = false; /* bad value for an allowed option */
      break;
    }
    if (count == capacity) {
      int new_cap = capacity == 0 ? 4 : capacity * 2;
      SockOptEntry* grown = realloc(entries, (size_t)new_cap * sizeof(SockOptEntry));
      if (!grown) {
        ok = false;
        break;
      }
      entries = grown;
      capacity = new_cap;
    }
    entries[count].id = (SockOptId)id;
    entries[count].value = val;
    count++;
  }
  free(copy);
  if (!ok) {
    free(entries);
    return -1;
  }
  *out = entries;
  *out_count = count;
  return 0;
}

bool config_is_remote_dest(const char* s) {
  if (s == NULL)
    return false;
  const char* colon = strchr(s, ':');
  if (colon == NULL)
    return false;
  if (colon == s)
    return false;
  for (const char* p = s; p < colon; p++) {
    if (*p == '/')
      return false;
  }
  return true;
}

/* Daemon destination detection: rsync's host::module[/path] marker is a "::"
 * immediately after the host part (the first ':' is immediately followed by a
 * second ':'), with no '/' before it.  A single ':' (host:path) stays the SSH
 * form even when the path itself later contains colons, and a "[::1]"-style
 * bracketed IPv6 literal is not recognized as a daemon destination this wave
 * (its first "::" is inside the brackets). */
bool config_is_daemon_dest(const char* s) {
  if (s == NULL)
    return false;
  const char* colon = strchr(s, ':');
  if (colon == NULL || colon == s || colon[1] != ':')
    return false;
  for (const char* p = s; p < colon; p++) {
    if (*p == '/')
      return false;
  }
  return true;
}

/* Log an escaped message with an 8-bit-safe output policy and return -1 (the
 * caller-visible parse failure code). */
static int daemon_dest_parse_error(const char* message, const char* detail) {
  char* escaped = output_escape(detail ? detail : "", false);
  log_message(LOG_LEVEL_ERROR, "%s: %s", message, escaped ? escaped : "<allocation failed>");
  free(escaped);
  return -1;
}

int config_parse_daemon_dest(Config* config) {
  if (!config || !config->receive_root_directory)
    return 0;
  const char* dest = config->receive_root_directory;
  if (!config_is_daemon_dest(dest))
    return 0;

  const char* colon = strchr(dest, ':');
  /* user@host::module names a daemon auth user.  FastSync takes the username
   * from the --password-file (its first user:password line) so there is a
   * single source of truth; an @user that could contradict it is rejected
   * with a pointer to the supported form. */
  if (memchr(dest, '@', (size_t)(colon - dest)) != NULL)
    return daemon_dest_parse_error(
        "daemon destination user@host::module is not supported: supply the username with "
        "--password-file (first line: user:password)",
        dest);
  const char* host_start = dest;

  const char* module_and_path = colon + 2;
  if (*module_and_path == '\0')
    return daemon_dest_parse_error("daemon destination is missing its module name", dest);
  const char* slash = strchr(module_and_path, '/');
  size_t module_len = slash ? (size_t)(slash - module_and_path) : strlen(module_and_path);
  char* module = malloc(module_len + 1);
  if (!module)
    return daemon_dest_parse_error("out of memory parsing daemon destination", dest);
  memcpy(module, module_and_path, module_len);
  module[module_len] = '\0';
  if (!daemon_module_name_valid(module)) {
    free(module);
    return daemon_dest_parse_error(
        "invalid daemon module name (must be 1-200 chars of [A-Za-z0-9._-])", dest);
  }

  const char* path = slash ? slash + 1 : "";
  while (*path == '/')
    path++; /* normalize "mod//a" to "mod/a"; keeps path module-relative */
  if (has_path_traversal(path)) {
    free(module);
    return daemon_dest_parse_error("daemon destination path must not contain '..'", dest);
  }

  size_t host_len = (size_t)(colon - host_start);
  char* host = malloc(host_len + 1);
  if (!host) {
    free(module);
    return daemon_dest_parse_error("out of memory parsing daemon destination", dest);
  }
  memcpy(host, host_start, host_len);
  host[host_len] = '\0';
  if (*host == '\0') {
    free(host);
    free(module);
    return daemon_dest_parse_error("daemon destination has no host", dest);
  }

  char* path_dup = str_dup(path);
  if (!path_dup) {
    free(host);
    free(module);
    return daemon_dest_parse_error("out of memory parsing daemon destination", dest);
  }

  free(config->server_host);
  config->server_host = host;
  free(config->module);
  config->module = module;
  free(config->receive_root_directory);
  config->receive_root_directory = path_dup;
  config->transport = TRANSPORT_TCP;
  return 1;
}

int config_parse_transport_dest(Config* config) {
  if (!config || !config->receive_root_directory)
    return 0;
  /* Daemon (host::module[/path]) first: the single-colon SSH parser would
   * otherwise mis-split the double colon.  Returns 1 (parsed as daemon), 0
   * (not daemon syntax -> try SSH below), or -1 (invalid daemon destination,
   * already logged). */
  int daemon_ret = config_parse_daemon_dest(config);
  if (daemon_ret != 0)
    return daemon_ret;
  /* 0 for a local destination (nothing parsed) or a valid SSH destination;
   * -1 (already logged) for an injection-shaped user@host. */
  return config_parse_ssh_dest(config);
}

int config_parse_ssh_dest(Config* config) {
  if (!config || !config->receive_root_directory)
    return 0;
  if (!config_is_remote_dest(config->receive_root_directory))
    return 0;
  const char* dest = config->receive_root_directory;
  const char* colon = strchr(dest, ':');
  /* The user@host token is passed to ssh in option position, so a user or host
   * beginning with '-' would be consumed by ssh as an option (argument
   * injection: e.g. "-oProxyCommand=...").  An empty host is likewise not a
   * valid destination.  Validate before any wire/argv construction. */
  const char* at = memchr(dest, '@', (size_t)(colon - dest));
  const char* host = at ? at + 1 : dest;
  size_t host_len = (size_t)(colon - host);
  size_t user_len = at ? (size_t)(at - dest) : 0;
  if (host_len == 0 || host[0] == '-' || (user_len > 0 && dest[0] == '-'))
    return daemon_dest_parse_error("invalid remote destination user@host (must not be empty or "
                                   "start with '-')",
                                   dest);
  config->transport = TRANSPORT_SSH;
  config->ssh_destination = str_dup(dest);
  char* path = str_dup(colon + 1);
  free(config->receive_root_directory);
  config->receive_root_directory = path;
  return 0;
}

void config_burn_auth(Config* config) {
  if (!config)
    return;
  if (config->auth_password) {
    credentials_burn(config->auth_password, strlen(config->auth_password));
    free(config->auth_password);
    config->auth_password = NULL;
  }
  if (config->auth_user) {
    free(config->auth_user);
    config->auth_user = NULL;
  }
}

void config_delete(Config* config) {
  if (config == NULL)
    return;
  if (config->log_file) {
    /* The logging subsystem borrows this FILE*; detach it before closing so a
     * concurrent log call can never touch the freed handle. */
    log_set_file(NULL);
    fclose(config->log_file);
    config->log_file = NULL;
  }
  free(config->version);
  free(config->send_directory);
  free(config->receive_root_directory);
  free(config->ssh_destination);
  free(config->module);
  config_burn_auth(config);
  free(config->password_file);
  free(config->iconv_spec);
  free(config->write_batch);
  free(config->only_write_batch);
  free(config->read_batch);
  free(config->fastsync_server_path);
  for (int i = 0; i < config->exclude_count; i++)
    free(config->exclude_patterns[i]);
  free(config->exclude_patterns);
  for (int i = 0; i < config->include_count; i++)
    free(config->include_patterns[i]);
  free(config->include_patterns);
  free(config->tls_cert);
  free(config->tls_key);
  free(config->tls_ca);
  free(config->backup_dir);
  free(config->server_host);
  free(config->out_format);
  free(config->log_file_format);
  free(config->files_from);
  file_list_destroy((FileListSet*)config->files_from_set);
  free(config->rsh_command);
  free(config->temp_dir);
  if (config->remote_options) {
    for (int i = 0; i < config->remote_option_count; i++)
      free(config->remote_options[i]);
    free(config->remote_options);
  }
  config->remote_options = NULL;
  config->remote_option_count = 0;
  if (config->basis_dirs) {
    for (int i = 0; i < config->basis_count; i++) {
      free(config->basis_dirs[i].path);
      config->basis_dirs[i].path = NULL;
    }
    free(config->basis_dirs);
  }
  config->basis_dirs = NULL;
  config->basis_count = 0;
  free(config->partial_dir);
  free(config->suffix);
  free(config->address);
  free(config->sockopts);
  free(config->compress_choice);
  free(config->chmod_spec);
  if (config->skip_compress_suffixes) {
    for (int i = 0; i < config->skip_compress_count; i++)
      free(config->skip_compress_suffixes[i]);
    free(config->skip_compress_suffixes);
  }
  if (config->usermap) {
    for (int i = 0; i < config->usermap_count; i++)
      free(config->usermap[i].to_name);
    free(config->usermap);
  }
  config->usermap = NULL;
  config->usermap_count = 0;
  if (config->groupmap) {
    for (int i = 0; i < config->groupmap_count; i++)
      free(config->groupmap[i].to_name);
    free(config->groupmap);
  }
  config->groupmap = NULL;
  config->groupmap_count = 0;
  if (config->filters) {
    array_list_delete(config->filters);
  }
  filter_rule_list_free(config->protect_rules);
  config->protect_rules = NULL;
  /* A --delay-updates staging tree is transient receiver state: remove any
     leftovers on every exit path (success already emptied it). */
  if (config->delay_context)
    delay_updates_cleanup(config->delay_context);
  delay_updates_context_destroy(config->delay_context);
  config->delay_context = NULL;
  free(config);
}

/* ---------------------------------------------------------------------------
 * Wire codec helpers.
 *
 * The CONFIG_WIRE_*_FIELDS tables in config.h drive the send/receive
 * sequences below.  Each field's KIND names a CONFIG_SEND_<KIND> /
 * CONFIG_RECV_<KIND> macro (defined after the helpers) that expands to the
 * exact primitive call the previous hand-written code used, so the byte
 * stream is unchanged.  Fields whose per-field logic is not a plain scalar
 * (bounded enums, redacted auth, repeated count+array blocks) delegate to a
 * dedicated helper here.
 * ------------------------------------------------------------------------- */

/* --max-alloc: raw 64-bit value, clamped server-side and installed as the
 * session allocation ceiling.  A received 0 is rsync's "no alloc limit"; on the
 * receive path it is mapped to the server ceiling so a client can never disable
 * it (client-side 0 remains unlimited).  Any value above the ceiling is clamped
 * to it. */
static bool config_receive_max_alloc(int fd, unsigned long long* value) {
  if (!receive_n_data(fd, value, sizeof(*value)))
    return false;
  if (*value == 0 || *value > MAX_SERVER_ALLOC)
    *value = MAX_SERVER_ALLOC;
  protocol_session_set_max_alloc(NULL, *value);
  return true;
}

/* Optional string: the sender serializes an unset (NULL) string as "", so the
 * receiver canonicalizes the empty wire value back to NULL to preserve
 * NULL-vs-empty semantics. */
static bool config_receive_optional_str(int fd, ConfigStringBudget* budget, char** out) {
  char* value = config_receive_str(fd, budget);
  if (!value)
    return false;
  if (*value == '\0') {
    free(value);
    *out = NULL;
    return true;
  }
  *out = value;
  return true;
}

/* Daemon module name (Wave A, protocol 2.15.0): an unset module is "" (-> NULL
 * on receive).  A hostile over-long/invalid name is rejected with an explicit
 * STATUS_ERROR rather than logged and accepted. */
static bool config_receive_module(int fd, Config* c, ConfigStringBudget* budget) {
  char* module = config_receive_str(fd, budget);
  if (!module)
    return false;
  if (*module != '\0' && !daemon_module_name_valid(module)) {
    log_message(LOG_LEVEL_WARNING, "Daemon client sent an invalid or over-long module name");
    send_error_detail(fd, "invalid or over-long daemon module name");
    free(module);
    return false;
  }
  if (*module != '\0') {
    c->module = module;
  } else {
    free(module);
  }
  return true;
}

/* Daemon auth username (A7 remediation, protocol 2.19.0): a presence int is
 * followed, when set, by ONLY the redacted username; the password is never
 * serialized. */
static bool config_receive_auth_user(int fd, Config* c, ConfigStringBudget* budget) {
  int present;
  if (!receive_int(fd, &present) || !valid_wire_bool(present))
    return false;
  if (!present)
    return true;
  char* user = config_receive_str_redacted(fd, budget);
  if (!user)
    return false;
  if (!credentials_username_valid(user)) {
    free(user);
    log_message(LOG_LEVEL_WARNING, "Daemon client sent malformed auth credentials");
    return false;
  }
  c->auth_user = user;
  return true;
}

static bool config_send_auth_user(int fd, const Config* c) {
  bool present = c->auth_user != NULL && c->auth_user[0] != '\0';
  if (!send_int(fd, present ? 1 : 0))
    return false;
  if (!present)
    return true;
  /* Redacted send: the username must never reach a --verbose debug log. */
  return send_str_redacted(fd, c->auth_user);
}

static bool config_receive_checksum_algo(int fd, int* value) {
  int algo;
  if (!receive_int(fd, &algo) || !checksum_algo_valid(algo))
    return false;
  *value = algo;
  return true;
}

static bool config_receive_compression_algo(int fd, int* value) {
  int algo;
  if (!receive_int(fd, &algo) || !compression_algo_valid(algo))
    return false;
  *value = algo;
  return true;
}

static bool config_receive_super_mode(int fd, SuperMode* value) {
  int mode;
  if (!receive_int(fd, &mode) || mode < SUPER_MODE_AUTO || mode > SUPER_MODE_OFF)
    return false;
  *value = (SuperMode)mode;
  return true;
}

/* chown override ids: IDENTITY_MATCH_ANY (-1) is the lowest legal value. */
static bool config_receive_identity_id(int fd, int32_t* value) {
  int v;
  if (!receive_int(fd, &v) || v < IDENTITY_MATCH_ANY)
    return false;
  *value = v;
  return true;
}

/* Read a peer-controlled count into a LOCAL, validate the range, and only then
 * publish it through `*value`.  Writing through `*value` before validating
 * leaves the Config holding an over-cap count (e.g. 999999999) whose backing
 * array is still NULL; the receive error path then runs config_delete(), which
 * walks the array and dereferences NULL.  Leaving `*value` untouched on failure
 * also keeps the failed Config in a coherent, safely-deletable state. */
static bool config_receive_skip_count(int fd, int* value) {
  int v;
  if (!receive_int(fd, &v) || v < 0 || v > MAX_SKIP_COMPRESS_SUFFIXES)
    return false;
  *value = v;
  return true;
}

static bool config_receive_basis_count(int fd, int* value) {
  int v;
  if (!receive_int(fd, &v) || v < 0 || v > MAX_BASIS_DIRS)
    return false;
  *value = v;
  return true;
}

static bool config_receive_idmap_count(int fd, int* value) {
  int v;
  if (!receive_int(fd, &v) || v < 0 || v > MAX_IDENTITY_MAP)
    return false;
  *value = v;
  return true;
}

static bool config_receive_copy_as_presence(int fd, bool* value) {
  int present;
  if (!receive_int(fd, &present) || !valid_wire_bool(present))
    return false;
  *value = present != 0;
  return true;
}

/* --copy-as ids are forced onto the ownership path, so a hostile peer must not
 * smuggle a negative sentinel. */
static bool config_receive_copy_as_id(int fd, int32_t* value) {
  int v;
  if (!receive_int(fd, &v) || v < 0)
    return false;
  *value = v;
  return true;
}

static bool send_skip_compress_suffixes(int fd, const Config* c) {
  for (int i = 0; i < c->skip_compress_count; i++) {
    if (!send_str(fd, c->skip_compress_suffixes[i]))
      return false;
  }
  return true;
}

static bool receive_skip_compress_suffixes(int fd, Config* c, ConfigStringBudget* budget) {
  if (c->skip_compress_count <= 0)
    return true;
  c->skip_compress_suffixes = calloc((size_t)c->skip_compress_count, sizeof(char*));
  if (!c->skip_compress_suffixes)
    return false;
  for (int i = 0; i < c->skip_compress_count; i++) {
    c->skip_compress_suffixes[i] = config_receive_str(fd, budget);
    if (!c->skip_compress_suffixes[i])
      return false;
  }
  return true;
}

static bool send_basis_entries(int fd, const Config* c) {
  for (int i = 0; i < c->basis_count; i++) {
    if (!send_int(fd, (int)c->basis_dirs[i].type) ||
        !send_str(fd, c->basis_dirs[i].path ? c->basis_dirs[i].path : ""))
      return false;
  }
  return true;
}

static bool receive_basis_entries(int fd, Config* c, ConfigStringBudget* budget) {
  /* The count was read by the preceding INT_BASISCOUNT entry; config_basis_append
   * rebuilds basis_count as it validates and canonicalizes each path. */
  int count = c->basis_count;
  c->basis_count = 0;
  for (int i = 0; i < count; i++) {
    int type;
    if (!receive_int(fd, &type) || type <= BASIS_DEST_NONE || type > BASIS_DEST_LINK)
      return false;
    char* path = config_receive_str(fd, budget);
    if (!path)
      return false;
    bool ok = config_basis_append(c, (BasisDestType)type, path) == 0;
    free(path);
    if (!ok)
      return false;
  }
  return true;
}

/* Receiver-side delete-protection rules (protocol 2.28.0).  The sender compiles
 * its command-line selection rules exactly as the scanner does and streams the
 * result as one bounded, self-describing block (count + per-rule records); the
 * receiver reconstructs a FilterRuleList for the --delete extras walk.  owner
 * and pattern are charged through the shared ConfigStringBudget and the block
 * additionally enforces MAX_FILTER_RULES / MAX_FILTER_BYTES. */
static bool send_protect_entries(int fd, const Config* c) {
  int count = c->filters ? c->filters->size : 0;
  const char** texts = NULL;
  if (count > 0) {
    texts = malloc((size_t)count * sizeof(char*));
    if (!texts)
      return false;
    for (int i = 0; i < count; i++)
      texts[i] = (const char*)c->filters->items[i];
  }
  char err[160];
  FilterRuleList* rules =
      filter_base_build(texts, count, c->cvs_exclude, c->delete_excluded, err, sizeof(err));
  free(texts);
  if (!rules) {
    log_message(LOG_LEVEL_ERROR, "invalid filter rule: %s", err);
    return false;
  }
  bool ok = send_int(fd, rules->count);
  for (int i = 0; ok && i < rules->count; i++) {
    const FilterRule* r = rules->items[i];
    /* Mirror the receiver's limit so the peer never receives a rule it will
       reject as a protocol error. */
    if (r->pattern && strlen(r->pattern) > MAX_PROTECT_PATTERN_LEN) {
      log_message(LOG_LEVEL_ERROR, "filter pattern exceeds %d bytes", MAX_PROTECT_PATTERN_LEN);
      filter_rule_list_free(rules);
      return false;
    }
    ok = send_int(fd, (int)r->action) && send_int(fd, (int)r->sides) &&
         send_int(fd, r->anchored ? 1 : 0) && send_int(fd, r->dir_only ? 1 : 0) &&
         send_int(fd, r->negate ? 1 : 0) && send_str(fd, r->owner ? r->owner : "") &&
         send_str(fd, r->pattern ? r->pattern : "");
  }
  filter_rule_list_free(rules);
  return ok;
}

static bool receive_protect_entries(int fd, Config* c, ConfigStringBudget* budget) {
  int count;
  if (!receive_int(fd, &count))
    return false;
  if (count < 0 || count > MAX_FILTER_RULES)
    return false;
  if (count == 0)
    return true;
  FilterRuleList* list = filter_rule_list_create();
  if (!list)
    return false;
  size_t pattern_bytes = 0;
  for (int i = 0; i < count; i++) {
    int action;
    int sides;
    bool anchored;
    bool dir_only;
    bool negate;
    if (!receive_int(fd, &action) ||
        (action != FILTER_ACTION_EXCLUDE && action != FILTER_ACTION_INCLUDE) ||
        !receive_int(fd, &sides) || sides < (int)FILTER_SIDE_SENDER ||
        sides > (int)(FILTER_SIDE_SENDER | FILTER_SIDE_RECEIVER) ||
        !receive_wire_bool(fd, &anchored) || !receive_wire_bool(fd, &dir_only) ||
        !receive_wire_bool(fd, &negate))
      goto fail;
    char* owner = config_receive_str(fd, budget);
    if (!owner)
      goto fail;
    char* pattern = config_receive_str(fd, budget);
    if (!pattern || pattern[0] == '\0') {
      free(owner);
      free(pattern);
      goto fail;
    }
    /* A pattern too long to be evaluated by glob_match against a PATH_MAX path
       would silently fail to match and leave a protect rule inert (fail-open:
       the entry is then deleted).  Reject it up front as a protocol error
       rather than accept a rule that can never shield anything. */
    if (strlen(pattern) > MAX_PROTECT_PATTERN_LEN) {
      free(owner);
      free(pattern);
      goto fail;
    }
    size_t bytes = strlen(owner) + strlen(pattern);
    if (bytes > MAX_FILTER_BYTES - pattern_bytes) {
      free(owner);
      free(pattern);
      goto fail;
    }
    pattern_bytes += bytes;
    FilterRule* rule = calloc(1, sizeof(FilterRule));
    if (!rule) {
      free(owner);
      free(pattern);
      goto fail;
    }
    rule->action = (FilterAction)action;
    rule->sides = (unsigned)sides;
    rule->anchored = anchored;
    rule->dir_only = dir_only;
    rule->negate = negate;
    rule->owner = owner;
    rule->pattern = pattern;
    if (!filter_rule_list_add(list, rule)) {
      filter_rule_free(rule);
      goto fail;
    }
  }
  c->protect_rules = list;
  return true;
fail:
  filter_rule_list_free(list);
  return false;
}

static bool send_identity_entries(int fd, const IdentityMap* map, int count) {
  for (int i = 0; i < count; i++) {
    if (!send_int(fd, map[i].from) || !send_int(fd, map[i].from_hi) || !send_int(fd, map[i].to) ||
        !send_str(fd, map[i].to_name ? map[i].to_name : ""))
      return false;
  }
  return true;
}

static bool receive_identity_entries(int fd, ConfigStringBudget* budget, int count,
                                     IdentityMap** out) {
  if (count <= 0)
    return true;
  IdentityMap* map = calloc((size_t)count, sizeof(IdentityMap));
  if (!map)
    return false;
  for (int i = 0; i < count; i++) {
    if (!receive_int(fd, &map[i].from) || !receive_int(fd, &map[i].from_hi) ||
        !receive_int(fd, &map[i].to))
      goto fail;
    char* name = config_receive_str(fd, budget);
    if (!name)
      goto fail;
    if (name[0] == '\0') {
      free(name);
      map[i].to_name = NULL;
    } else {
      map[i].to_name = name;
    }
  }
  *out = map;
  return true;
fail:
  for (int i = 0; i < count; i++)
    free(map[i].to_name);
  free(map);
  return false;
}

/* ---------------------------------------------------------------------------
 * KIND dispatch.  A table entry X(member, ctype, def, KIND) expands to
 * CONFIG_SEND_<KIND>(member) in a sender and CONFIG_RECV_<KIND>(member) in a
 * receiver.  Send macros are bool expressions; receive macros are bool
 * expressions too (strings allocate through `budget`).
 * ------------------------------------------------------------------------- */
#define CONFIG_SEND_BOOL(name) send_int(fd, c->name)
#define CONFIG_RECV_BOOL(name) receive_wire_bool(fd, &c->name)

#define CONFIG_SEND_INT(name) send_int(fd, c->name)
#define CONFIG_RECV_INT(name) receive_int(fd, &c->name)

#define CONFIG_SEND_RAW(name) send_n_data(fd, &c->name, sizeof(c->name))
#define CONFIG_RECV_RAW(name) receive_n_data(fd, &c->name, sizeof(c->name))

#define CONFIG_SEND_BOOL_8BIT(name)                                                                \
  (send_int(fd, c->name) && (protocol_set_8_bit_output(c->name), true))
#define CONFIG_RECV_BOOL_8BIT(name)                                                                \
  (receive_wire_bool(fd, &c->name) && (protocol_set_8_bit_output(c->name), true))

#define CONFIG_SEND_RAW_MAXALLOC(name) send_n_data(fd, &c->name, sizeof(c->name))
#define CONFIG_RECV_RAW_MAXALLOC(name) config_receive_max_alloc(fd, &c->name)

/* --delta is sent as (use_delta && !whole_file); whole_file never crosses the
 * wire, so the receiver observes the effective bit. */
#define CONFIG_SEND_DERIVED_DELTA(name) send_int(fd, c->name && !c->whole_file)
#define CONFIG_RECV_DERIVED_DELTA(name) receive_wire_bool(fd, &c->name)

#define CONFIG_SEND_STR(name) send_str(fd, c->name)
#define CONFIG_RECV_STR(name) ((c->name = config_receive_str(fd, budget)) != NULL)

#define CONFIG_SEND_STR_OPT(name) send_str(fd, c->name ? c->name : "")
#define CONFIG_RECV_STR_OPT(name) config_receive_optional_str(fd, budget, &c->name)

#define CONFIG_SEND_STR_KEEP(name) send_str(fd, c->name ? c->name : "")
#define CONFIG_RECV_STR_KEEP(name) ((c->name = config_receive_str(fd, budget)) != NULL)

#define CONFIG_SEND_STR_MODULE(name) send_str(fd, c->name ? c->name : "")
#define CONFIG_RECV_STR_MODULE(name) config_receive_module(fd, c, budget)

#define CONFIG_SEND_STR_REDACTED_AUTH(name) config_send_auth_user(fd, c)
#define CONFIG_RECV_STR_REDACTED_AUTH(name) config_receive_auth_user(fd, c, budget)

#define CONFIG_SEND_INT_CHECKSUM_ALGO(name) send_int(fd, c->name)
#define CONFIG_RECV_INT_CHECKSUM_ALGO(name) config_receive_checksum_algo(fd, &c->name)

#define CONFIG_SEND_INT_COMPRESSION_ALGO(name) send_int(fd, c->name)
#define CONFIG_RECV_INT_COMPRESSION_ALGO(name) config_receive_compression_algo(fd, &c->name)

#define CONFIG_SEND_SUPERMODE(name) send_int(fd, (int)c->name)
#define CONFIG_RECV_SUPERMODE(name) config_receive_super_mode(fd, &c->name)

#define CONFIG_SEND_INT_IDENTITY(name) send_int(fd, c->name)
#define CONFIG_RECV_INT_IDENTITY(name) config_receive_identity_id(fd, &c->name)

#define CONFIG_SEND_INT_SKIPCOUNT(name) send_int(fd, c->name)
#define CONFIG_RECV_INT_SKIPCOUNT(name) config_receive_skip_count(fd, &c->name)

#define CONFIG_SEND_INT_BASISCOUNT(name) send_int(fd, c->name)
#define CONFIG_RECV_INT_BASISCOUNT(name) config_receive_basis_count(fd, &c->name)

#define CONFIG_SEND_INT_IDMAPCOUNT(name) send_int(fd, c->name)
#define CONFIG_RECV_INT_IDMAPCOUNT(name) config_receive_idmap_count(fd, &c->name)

/* use_xattrs is derived receiver-side from the xattr/acl preservation flags
 * that crossed the wire in the file-options block. */
#define CONFIG_SEND_BOOL_XATTR_DERIVE(name) send_int(fd, c->name)
#define CONFIG_RECV_BOOL_XATTR_DERIVE(name)                                                        \
  (receive_wire_bool(fd, &c->name) &&                                                              \
   (c->use_xattrs = (c->preserve_acls || c->preserve_xattrs), true))

#define CONFIG_SEND_COPY_AS_PRESENCE(name) send_int(fd, c->name ? 1 : 0)
#define CONFIG_RECV_COPY_AS_PRESENCE(name) config_receive_copy_as_presence(fd, &c->name)

/* The uid/gid follow the presence int only when --copy-as is set. */
#define CONFIG_SEND_COPY_AS_ID(name) (!c->copy_as_set || send_int(fd, c->name))
#define CONFIG_RECV_COPY_AS_ID(name) (!c->copy_as_set || config_receive_copy_as_id(fd, &c->name))

#define CONFIG_SEND_BLOCK_SKIP_SUFFIXES(name) send_skip_compress_suffixes(fd, c)
#define CONFIG_RECV_BLOCK_SKIP_SUFFIXES(name) receive_skip_compress_suffixes(fd, c, budget)

#define CONFIG_SEND_BLOCK_BASIS(name) send_basis_entries(fd, c)
#define CONFIG_RECV_BLOCK_BASIS(name) receive_basis_entries(fd, c, budget)

#define CONFIG_SEND_BLOCK_IDMAP(name) send_identity_entries(fd, c->name, c->name##_count)
#define CONFIG_RECV_BLOCK_IDMAP(name)                                                              \
  receive_identity_entries(fd, budget, c->name##_count, &c->name)

#define CONFIG_SEND_BLOCK_PROTECT_RULES(name) send_protect_entries(fd, c)
#define CONFIG_RECV_BLOCK_PROTECT_RULES(name) receive_protect_entries(fd, c, budget)

/* One table entry, applied in sequence.  XSEND/XRECV are statement macros so
 * consecutive entries read as a plain sequence of assignments. */
#define XSEND(name, ctype, def, kind) ok = ok && (CONFIG_SEND_##kind(name));
#define XRECV(name, ctype, def, kind) ok = ok && (CONFIG_RECV_##kind(name));

#define CONFIG_DEFINE_SEND(fn, fields)                                                             \
  static bool fn(int fd, const Config* c) {                                                        \
    bool ok = true;                                                                                \
    fields(XSEND) return ok;                                                                       \
  }

#define CONFIG_DEFINE_RECV(fn, fields)                                                             \
  static bool fn(int fd, Config* c, ConfigStringBudget* budget) {                                  \
    (void)budget;                                                                                  \
    bool ok = true;                                                                                \
    fields(XRECV) return ok;                                                                       \
  }

CONFIG_DEFINE_SEND(send_core_fields, CONFIG_WIRE_CORE_FIELDS)
CONFIG_DEFINE_SEND(send_delta_fields, CONFIG_WIRE_DELTA_FIELDS)
CONFIG_DEFINE_SEND(send_file_options, CONFIG_WIRE_FILE_OPTIONS_FIELDS)
CONFIG_DEFINE_SEND(send_selection_options, CONFIG_WIRE_SELECTION_FIELDS)
CONFIG_DEFINE_SEND(send_resume_options, CONFIG_WIRE_RESUME_FIELDS)
CONFIG_DEFINE_SEND(send_basis_options, CONFIG_WIRE_BASIS_FIELDS)
CONFIG_DEFINE_SEND(send_fuzzy_option, CONFIG_WIRE_FUZZY_FIELDS)
CONFIG_DEFINE_SEND(send_checksum_options, CONFIG_WIRE_CHECKSUM_FIELDS)
CONFIG_DEFINE_SEND(send_identity_options, CONFIG_WIRE_IDENTITY_FIELDS)
CONFIG_DEFINE_SEND(send_metadata_times_options, CONFIG_WIRE_METADATA_TIMES_FIELDS)
CONFIG_DEFINE_SEND(send_symlink_trust_options, CONFIG_WIRE_SYMLINK_TRUST_FIELDS)
CONFIG_DEFINE_SEND(send_phase4_xattr_options, CONFIG_WIRE_XATTR_FIELDS)
CONFIG_DEFINE_SEND(send_daemon_module, CONFIG_WIRE_MODULE_FIELDS)
CONFIG_DEFINE_SEND(send_daemon_auth, CONFIG_WIRE_DAEMON_AUTH_FIELDS)
CONFIG_DEFINE_SEND(send_iconv_spec, CONFIG_WIRE_ICONV_FIELDS)
CONFIG_DEFINE_SEND(send_privilege_options, CONFIG_WIRE_PRIVILEGE_FIELDS)
CONFIG_DEFINE_SEND(send_copy_as_options, CONFIG_WIRE_COPY_AS_FIELDS)
CONFIG_DEFINE_SEND(send_output_options, CONFIG_WIRE_OUTPUT_FIELDS)
CONFIG_DEFINE_SEND(send_codec_options, CONFIG_WIRE_CODEC_FIELDS)
CONFIG_DEFINE_SEND(send_protect_options, CONFIG_WIRE_PROTECT_FIELDS)

CONFIG_DEFINE_RECV(receive_core_fields, CONFIG_WIRE_CORE_FIELDS)
CONFIG_DEFINE_RECV(receive_delta_fields, CONFIG_WIRE_DELTA_FIELDS)
CONFIG_DEFINE_RECV(receive_file_options, CONFIG_WIRE_FILE_OPTIONS_FIELDS)
CONFIG_DEFINE_RECV(receive_selection_options, CONFIG_WIRE_SELECTION_FIELDS)
CONFIG_DEFINE_RECV(receive_resume_options, CONFIG_WIRE_RESUME_FIELDS)
CONFIG_DEFINE_RECV(receive_basis_options, CONFIG_WIRE_BASIS_FIELDS)
CONFIG_DEFINE_RECV(receive_fuzzy_option, CONFIG_WIRE_FUZZY_FIELDS)
CONFIG_DEFINE_RECV(receive_checksum_options, CONFIG_WIRE_CHECKSUM_FIELDS)
CONFIG_DEFINE_RECV(receive_identity_options, CONFIG_WIRE_IDENTITY_FIELDS)
CONFIG_DEFINE_RECV(receive_metadata_times_options, CONFIG_WIRE_METADATA_TIMES_FIELDS)
CONFIG_DEFINE_RECV(receive_symlink_trust_options, CONFIG_WIRE_SYMLINK_TRUST_FIELDS)
CONFIG_DEFINE_RECV(receive_phase4_xattr_options, CONFIG_WIRE_XATTR_FIELDS)
CONFIG_DEFINE_RECV(receive_daemon_module, CONFIG_WIRE_MODULE_FIELDS)
CONFIG_DEFINE_RECV(receive_daemon_auth, CONFIG_WIRE_DAEMON_AUTH_FIELDS)
CONFIG_DEFINE_RECV(receive_iconv_spec, CONFIG_WIRE_ICONV_FIELDS)
CONFIG_DEFINE_RECV(receive_privilege_options, CONFIG_WIRE_PRIVILEGE_FIELDS)
CONFIG_DEFINE_RECV(receive_copy_as_options, CONFIG_WIRE_COPY_AS_FIELDS)
CONFIG_DEFINE_RECV(receive_output_options, CONFIG_WIRE_OUTPUT_FIELDS)
CONFIG_DEFINE_RECV(receive_codec_options, CONFIG_WIRE_CODEC_FIELDS)
CONFIG_DEFINE_RECV(receive_protect_options, CONFIG_WIRE_PROTECT_FIELDS)

#undef XSEND
#undef XRECV

/* Client half of the SCRAM challenge/response (A7 remediation).  Called by
 * config_send after the config frame is written and the server answered
 * STATUS_AUTH_CHALLENGE.  The plaintext password lives only in
 * config->auth_password and every derived buffer is wiped on the way out. */
static bool client_auth_exchange(int fd, const Config* c) {
  if (!c->auth_user || !c->auth_password)
    return false;
  int iters = 0;
  if (!receive_int(fd, &iters))
    return false;
  if (iters < (int)CREDENTIAL_MIN_ITERS || iters > (int)CREDENTIAL_MAX_ITERS) {
    log_message(LOG_LEVEL_ERROR, "Daemon sent an out-of-range auth iteration count");
    return false;
  }
  char* salt_b64 = receive_str(fd);
  char* snonce_b64 = receive_str(fd);
  uint8_t salt[CREDENTIAL_SALT_LEN];
  uint8_t snonce[CREDENTIAL_NONCE_LEN];
  uint8_t cnonce[CREDENTIAL_NONCE_LEN];
  size_t salt_len = 0;
  size_t snonce_len = 0;
  bool ok = salt_b64 && snonce_b64 &&
            credentials_b64_decode(salt_b64, salt, sizeof(salt), &salt_len) &&
            salt_len == CREDENTIAL_SALT_LEN &&
            credentials_b64_decode(snonce_b64, snonce, sizeof(snonce), &snonce_len) &&
            snonce_len == CREDENTIAL_NONCE_LEN && credentials_random_bytes(cnonce, sizeof(cnonce));
  credentials_burn(salt_b64, salt_b64 ? strlen(salt_b64) : 0);
  credentials_burn(snonce_b64, snonce_b64 ? strlen(snonce_b64) : 0);
  free(salt_b64);
  free(snonce_b64);
  if (!ok) {
    log_message(LOG_LEVEL_ERROR, "Daemon sent a malformed auth challenge");
    return false;
  }
  uint8_t client_key[CREDENTIAL_KEY_LEN];
  uint8_t stored_key[CREDENTIAL_KEY_LEN];
  uint8_t server_key[CREDENTIAL_KEY_LEN];
  uint8_t auth_msg[CREDENTIAL_AUTH_MESSAGE_MAX];
  size_t msg_len = 0;
  uint8_t proof[CREDENTIAL_KEY_LEN];
  uint8_t expected_sig[CREDENTIAL_KEY_LEN];
  ok = credentials_compute_keys(c->auth_password, salt, (uint32_t)iters, client_key, stored_key,
                                server_key) &&
       credentials_build_auth_message(c->auth_user, snonce, cnonce, auth_msg, sizeof(auth_msg),
                                      &msg_len) &&
       credentials_client_proof(client_key, stored_key, server_key, auth_msg, msg_len, proof,
                                expected_sig);
  char cnonce_b64[45];
  char proof_b64[45];
  if (ok)
    ok = credentials_b64_encode(cnonce, sizeof(cnonce), cnonce_b64, sizeof(cnonce_b64)) &&
         credentials_b64_encode(proof, sizeof(proof), proof_b64, sizeof(proof_b64));
  if (!ok) {
    log_message(LOG_LEVEL_ERROR, "Failed to compute the daemon auth response");
  } else {
    ok = send_status(fd, STATUS_AUTH_RESPONSE) && send_str_redacted(fd, cnonce_b64) &&
         send_str_redacted(fd, proof_b64);
  }
  if (ok) {
    Status status = STATUS_ERROR;
    char* sig_b64 = NULL;
    uint8_t sig[CREDENTIAL_KEY_LEN];
    size_t sig_len = 0;
    ok = receive_status(fd, &status) && status == STATUS_AUTH_OK &&
         (sig_b64 = receive_str_redacted(fd)) != NULL &&
         credentials_b64_decode(sig_b64, sig, sizeof(sig), &sig_len) &&
         sig_len == CREDENTIAL_KEY_LEN &&
         credentials_secure_equal((const char*)sig, (const char*)expected_sig, CREDENTIAL_KEY_LEN);
    if (!ok)
      log_message(LOG_LEVEL_ERROR, "Daemon authentication failed");
    credentials_burn(sig_b64, sig_b64 ? strlen(sig_b64) : 0);
    credentials_burn((char*)sig, sizeof(sig));
    free(sig_b64);
  }
  credentials_burn((char*)client_key, sizeof(client_key));
  credentials_burn((char*)stored_key, sizeof(stored_key));
  credentials_burn((char*)server_key, sizeof(server_key));
  credentials_burn((char*)auth_msg, sizeof(auth_msg));
  credentials_burn((char*)proof, sizeof(proof));
  credentials_burn((char*)expected_sig, sizeof(expected_sig));
  credentials_burn((char*)salt, sizeof(salt));
  credentials_burn((char*)snonce, sizeof(snonce));
  credentials_burn((char*)cnonce, sizeof(cnonce));
  credentials_burn(cnonce_b64, sizeof(cnonce_b64));
  credentials_burn(proof_b64, sizeof(proof_b64));
  return ok;
}

/* The --iconv, --super/--no-super and --copy-as segment functions are
 * generated above from CONFIG_WIRE_ICONV_FIELDS, CONFIG_WIRE_PRIVILEGE_FIELDS
 * and CONFIG_WIRE_COPY_AS_FIELDS. */

bool config_send_wire_block(int file_descriptor, const Config* config) {
  protocol_session_set_max_alloc(NULL, config->max_alloc);
  /* The version is the frame header: the receiver validates it before parsing
   * any other field (see config_receive_with_validate), so it is not part of
   * the generated segment sequence.  It is still declared once, in
   * CONFIG_WIRE_HEADER_FIELDS. */
  return send_str(file_descriptor, config->version) && send_core_fields(file_descriptor, config) &&
         send_delta_fields(file_descriptor, config) && send_file_options(file_descriptor, config) &&
         send_selection_options(file_descriptor, config) &&
         send_resume_options(file_descriptor, config) &&
         send_basis_options(file_descriptor, config) &&
         send_fuzzy_option(file_descriptor, config) &&
         send_checksum_options(file_descriptor, config) &&
         send_identity_options(file_descriptor, config) &&
         send_metadata_times_options(file_descriptor, config) &&
         send_symlink_trust_options(file_descriptor, config) &&
         send_phase4_xattr_options(file_descriptor, config) &&
         send_daemon_module(file_descriptor, config) && send_daemon_auth(file_descriptor, config) &&
         send_iconv_spec(file_descriptor, config) &&
         send_privilege_options(file_descriptor, config) &&
         send_copy_as_options(file_descriptor, config) &&
         send_output_options(file_descriptor, config) &&
         send_codec_options(file_descriptor, config) &&
         send_protect_options(file_descriptor, config);
}

bool config_send(int file_descriptor, const Config* config) {
  if (!config_send_wire_block(file_descriptor, config))
    return false;
  Status status;
  if (!receive_status(file_descriptor, &status))
    return false;
  if (status == STATUS_AUTH_CHALLENGE) {
    /* Daemon auth (protocol 2.19.0): run the SCRAM exchange, then wait for the
     * ordinary STATUS_OK the server sends once authentication succeeded. */
    if (!client_auth_exchange(file_descriptor, config))
      return false;
    if (!receive_status(file_descriptor, &status))
      return false;
  }
  if (status != STATUS_OK) {
    const char* detail = protocol_last_error();
    if (detail && detail[0] != '\0') {
      /* The detail is peer-controlled: escape it before logging. */
      char* escaped = output_escape(detail, log_get_8_bit_output());
      log_message(LOG_LEVEL_ERROR, "Error transmitting config: %s",
                  escaped ? escaped : "<allocation failed>");
      free(escaped);
    } else {
      log_message(LOG_LEVEL_ERROR, "Error transmitting config");
    }
    return false;
  }
  return true;
}

Config* config_receive_with_validate(int file_descriptor, ConfigValidateFunc validate,
                                     void* context) {
  Config* config = config_create();
  if (!config)
    return NULL;
  ConfigStringBudget budget = {0};
  free(config->version);
  config->version = config_receive_str(file_descriptor, &budget);
  if (!config->version)
    goto error;
  if (strcmp(config->version, PROTOCOL_VERSION) != 0) {
    char* escaped_version = output_escape(config->version, false);
    log_message(LOG_LEVEL_ERROR, "Protocol version mismatch: client=%s, server=%s",
                escaped_version ? escaped_version : "<allocation failed>", PROTOCOL_VERSION);
    char detail[160];
    snprintf(detail, sizeof(detail), "protocol version mismatch (client=%s, server=%s)",
             escaped_version ? escaped_version : "<allocation failed>", PROTOCOL_VERSION);
    send_error_detail(file_descriptor, detail);
    free(escaped_version);
    goto error;
  }
  if (!receive_core_fields(file_descriptor, config, &budget) ||
      !receive_delta_fields(file_descriptor, config, &budget) ||
      !receive_file_options(file_descriptor, config, &budget) ||
      !receive_selection_options(file_descriptor, config, &budget) ||
      !receive_resume_options(file_descriptor, config, &budget) ||
      !receive_basis_options(file_descriptor, config, &budget) ||
      !receive_fuzzy_option(file_descriptor, config, &budget) ||
      !receive_checksum_options(file_descriptor, config, &budget) ||
      !receive_identity_options(file_descriptor, config, &budget) ||
      !receive_metadata_times_options(file_descriptor, config, &budget) ||
      !receive_symlink_trust_options(file_descriptor, config, &budget) ||
      !receive_phase4_xattr_options(file_descriptor, config, &budget) ||
      !receive_daemon_module(file_descriptor, config, &budget) ||
      !receive_daemon_auth(file_descriptor, config, &budget) ||
      !receive_iconv_spec(file_descriptor, config, &budget) ||
      !receive_privilege_options(file_descriptor, config, &budget) ||
      !receive_copy_as_options(file_descriptor, config, &budget) ||
      !receive_output_options(file_descriptor, config, &budget) ||
      !receive_codec_options(file_descriptor, config, &budget) ||
      !receive_protect_options(file_descriptor, config, &budget))
    goto error;
  /* Validate/normalize the negotiated codec.  compress_choice is the human
   * spelling (NULL or "" when -z was not given); compression_algo is the
   * concrete codec id the sender used.  They must agree, and "auto" is
   * canonicalized to FastSync's negotiated default so the stored spelling is
   * always concrete (a hostile/older client may still send "auto"). */
  if (config->compress_choice && config->compress_choice[0] != '\0') {
    int choice_algo = compression_algo_from_name(config->compress_choice);
    if (choice_algo < 0 && strcasecmp(config->compress_choice, "auto") != 0) {
      char* escaped_choice = output_escape(config->compress_choice, config->eight_bit_output);
      log_message(LOG_LEVEL_ERROR, "Unsupported compression choice: %s",
                  escaped_choice ? escaped_choice : "<allocation failed>");
      char detail[160];
      snprintf(detail, sizeof(detail), "unsupported compression choice: %s",
               escaped_choice ? escaped_choice : "<allocation failed>");
      send_error_detail(file_descriptor, detail);
      free(escaped_choice);
      goto error;
    }
    if (choice_algo < 0)
      choice_algo = (int)compression_negotiate_default();
    if (strcasecmp(config->compress_choice, "auto") == 0 ||
        choice_algo == (int)COMPRESSION_ALGO_NONE) {
      const char* canonical = compression_algo_name((CompressionAlgo)choice_algo);
      char* dup = str_dup(canonical);
      if (!dup)
        goto error;
      free(config->compress_choice);
      config->compress_choice = dup;
    }
    if (config->compression_algo != choice_algo) {
      log_message(LOG_LEVEL_ERROR, "Compression choice '%s' does not match codec id %d",
                  config->compress_choice, config->compression_algo);
      send_error_detail(file_descriptor, "compression choice/codec mismatch");
      goto error;
    }
  }
  /* The concrete codec must exist only when compression is on.  A client that
   * left -z off has no codec in effect, but the field keeps whatever id it
   * carried (the receiver never dispatches on it without use_compression), so
   * the wire value round-trips untouched. */
  if (config->use_compression && config->compression_algo == (int)COMPRESSION_ALGO_NONE) {
    log_message(LOG_LEVEL_ERROR, "Compression requested with the 'none' codec");
    send_error_detail(file_descriptor, "compression requested with the none codec");
    goto error;
  }
  /* rsync: "none" as the pre-transfer checksum is invalid with --checksum. */
  if (config->checksum && config->checksum_algo == (int)CHECKSUM_ALGO_NONE) {
    log_message(LOG_LEVEL_ERROR, "Invalid checksum-choice for --checksum: none");
    send_error_detail(file_descriptor, "checksum-choice 'none' cannot be used with --checksum");
    goto error;
  }
  if (!validate_received_config(config)) {
    log_message(LOG_LEVEL_ERROR, "Invalid configuration received from client");
    send_error_detail(file_descriptor, "invalid configuration received from client");
    goto error;
  }
  if (validate) {
    const char* rejection = validate(config, context);
    if (rejection != NULL) {
      /* Daemon module gate (unknown module / read-only module / auth-required
       * module): refuse BEFORE the STATUS_OK so the client aborts at the
       * config handshake and no file data is ever exchanged.  The auth
       * handshake already sent STATUS_AUTH_FAILED when it failed, signalled by
       * the CONFIG_VALIDATE_ALREADY_TERMINATED sentinel, so no second status is
       * written. */
      if (rejection != CONFIG_VALIDATE_ALREADY_TERMINATED) {
        log_message(LOG_LEVEL_ERROR, "%s", rejection);
        send_error_detail(file_descriptor, rejection);
      }
      goto error;
    }
  }
  if (!send_status(file_descriptor, STATUS_OK))
    goto error;
  return config;

error:
  config_delete(config);
  return NULL;
}

Config* config_receive(int file_descriptor) {
  return config_receive_with_validate(file_descriptor, NULL, NULL);
}
