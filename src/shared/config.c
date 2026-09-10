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
#include <limits.h>
#include <errno.h>

static void config_set_defaults(Config* config) {
  config->version = str_dup(PROTOCOL_VERSION);
  config->send_directory = NULL;
  config->receive_root_directory = NULL;
  config->save_to_disk = false;
  config->use_multithreading = false;
  config->use_chunk_serialization = false;
  config->use_compression = false;
  config->use_metadata = false;
  config->use_executability = false;
  config->metadata_explicitly_disabled = false;
  config->show_progress = false;
  config->dry_run = false;
  config->remove_source_files = false;
  config->use_delete = false;
  config->compression_level = 5;
  config->compression_threads = 0;
  config->use_sendfile = false;
  config->chunk_size = DEFAULT_CHUNK_SIZE;
  config->ssh_port = 22;
  config->transport = TRANSPORT_TCP;
  config->ssh_destination = NULL;
  config->module = NULL;
  config->auth_user = NULL;
  config->auth_password_hash = NULL;
  config->password_file = NULL;
  config->iconv_spec = NULL;
  config->fastsync_server_path = NULL;
  config->exclude_patterns = NULL;
  config->exclude_count = 0;
  config->include_patterns = NULL;
  config->include_count = 0;
  config->max_size = 0;
  config->min_size = 0;
  config->max_alloc = DEFAULT_MAX_ALLOC;
  config->use_incremental = false;
  config->ignore_times = false;
  config->size_only = false;
  config->use_delta = false;
  config->whole_file = false;
  config->fuzzy = false;
  config->modify_window = 0;
  config->delta_block_size = DELTA_BLOCK_SIZE_DEFAULT;
  config->delta_max_file_size = DELTA_MAX_FILE_SIZE;
  config->use_tls = false;
  config->tls_cert = NULL;
  config->tls_key = NULL;
  config->tls_ca = NULL;
  config->server_host = str_dup("127.0.0.1");
  config->server_port = 8080;
  config->timeout = 30;
  config->contimeout = 10;
  config->quiet = false;
  config->backup = false;
  config->backup_dir = NULL;
  config->stats = false;
  config->max_depth = 0;
  config->log_file = NULL;
  config->queue_size = 100;
  config->follow_symlinks = false;
  config->partial = false;
  config->copy_links = false;
  config->safe_links = false;
  config->copy_unsafe_links = false;
  config->copy_dirlinks = false;
  config->munge_links = false;
  config->keep_dirlinks = false;
  config->preserve_hard_links = false;
  config->preserve_acls = false;
  config->preserve_xattrs = false;
  config->preserve_devices = false;
  config->preserve_sparse = false;
  config->preserve_specials = false;
  config->copy_devices = false;
  config->write_devices = false;
  config->itemize_changes = false;
  config->out_format = NULL;
  config->log_file_format = NULL;
  config->info_level = 0;
  config->debug_level = 0;
  config->list_only = false;
  config->human_readable = false;
  config->eight_bit_output = false;
  config->existing = false;
  config->ignore_existing = false;
  config->update = false;
  config->inplace = false;
  config->delay_updates = false;
  config->use_fsync = false;
  config->append = false;
  config->append_verify = false;
  config->preallocate = false;
  config->delete_excluded = false;
  config->delete_after = false;
  config->max_delete = -1;
  config->ignore_errors = false;
  config->force_delete = false;
  config->ignore_missing_args = false;
  config->delete_missing_args = false;
  config->filters = NULL;
  config->files_from = NULL;
  config->files_from_set = NULL;
  config->from0 = false;
  config->cvs_exclude = false;
  config->per_dir_filter = false;
  config->prune_empty_dirs = false;
  config->one_file_system = false;
  config->relative = false;
  config->no_implied_dirs = false;
  config->dirs = false;
  config->mkpath = false;
  config->rsh_command = NULL;
  config->blocking_io = false;
  config->outbuf = OUTBUF_BLOCK;
  config->old_args = false;
  config->temp_dir = NULL;
  config->remote_options = NULL;
  config->remote_option_count = 0;
  config->basis_dirs = NULL;
  config->basis_count = 0;
  config->partial_dir = NULL;
  config->suffix = NULL;
  config->delete_before = false;
  config->delete_during = false;
  config->delete_delay = false;
  config->address = NULL;
  config->bind_address = NULL;
  config->ipv6 = false;
  config->ipv4 = false;
  config->sockopts = NULL;
  config->sockopt_count = 0;
  config->daemon = false;
  config->daemon_config = NULL;
  config->server_mode = false;
  config->no_motd = false;
  config->checksum = false;
  config->checksum_algo = CHECKSUM_ALGO_XXH64;
  config->checksum_seed = 0;
  config->compress_choice = NULL;
  config->chmod_spec = NULL;
  config->skip_compress_suffixes = NULL;
  config->skip_compress_count = 0;
  config->skip_compress_set = false;
  config->numeric_ids = false;
  config->chown_uid_set = false;
  config->chown_uid = 0;
  config->chown_gid_set = false;
  config->chown_gid = 0;
  config->usermap = NULL;
  config->usermap_count = 0;
  config->groupmap = NULL;
  config->groupmap_count = 0;
  config->delay_context = NULL;
  config->preserve_atimes = false;
  config->preserve_crtimes = false;
  config->omit_dir_times = false;
  config->omit_link_times = false;
  config->open_noatime = false;
  config->use_xattrs = false;
  config->fake_super = false;
  config->trust_sender = false;
  config->stop_after_mins = 0;
  config->stop_at = 0;
  config->stop_at_set = false;
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

static bool validate_received_config(const Config* config) {
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
         !(config->delay_updates && config->inplace) &&
         !(config->delay_updates && delay_updates_staging_name_conflict(config->backup_dir)) &&
         valid_wire_bool(config->partial) && valid_wire_bool(config->delete_before) &&
         valid_wire_bool(config->checksum) && valid_wire_bool(config->eight_bit_output) &&
         checksum_algo_valid(config->checksum_algo) && config_has_valid_delete_timing(config) &&
         identity_wire_valid(config) &&
         !(config->skip_compress_set && config->use_chunk_serialization) &&
         /* --append / --append-verify tail resume needs the per-file check,
            which chunk serialization -s disables: reject on the receiver too
            so a -s sender cannot negotiate an inert append mode. */
         !((config->append || config->append_verify) && config->use_chunk_serialization) &&
         !(config->preserve_hard_links && config->use_chunk_serialization) &&
         !(config->preserve_hard_links && (config->append || config->append_verify)) &&
         /* The xattr block rides the per-file streaming frame, which -s drops. */
         !((config->preserve_xattrs || config->preserve_acls) && config->use_chunk_serialization) &&
         valid_wire_bool(config->preserve_atimes) && valid_wire_bool(config->preserve_crtimes) &&
         valid_wire_bool(config->omit_dir_times) && valid_wire_bool(config->omit_link_times) &&
         valid_wire_bool(config->munge_links) && valid_wire_bool(config->keep_dirlinks) &&
         valid_wire_bool(config->fake_super) &&
         (!config->use_compression ||
          (config->compression_level >= 1 && config->compression_level <= 22)) &&
         config->chunk_size > 0 && config->chunk_size <= MAX_CHUNK_SIZE &&
         config->delta_block_size >= DELTA_BLOCK_SIZE_MIN &&
         config->delta_block_size <= DELTA_BLOCK_SIZE_MAX &&
         config->delta_max_file_size <= DELTA_MAX_FILE_SIZE && config->modify_window >= 0 &&
         config->max_delete >= -1 && config->skip_compress_count >= 0 &&
         config->skip_compress_count <= 10000 && config->max_alloc > 0 &&
         (!config->chmod_spec || !*config->chmod_spec ||
          chmod_apply(0, config->chmod_spec, &(mode_t){0})) &&
         /* The received --iconv CONVERT_SPEC is untrusted input that drives
            the receiver's path decoding: reject a malformed spec or an
            unsupported charset name so the run is refused up front instead of
            every received file name failing mid-transfer.  A NULL spec (iconv
            disabled) is always accepted. */
         (!config->iconv_spec || charset_spec_valid(config->iconv_spec));
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
  return config->delete_before || config->delete_during;
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

bool config_has_basis(const Config* config) {
  return config && config->basis_count > 0;
}

/* A basis-dir path travels from the client to the receiver and is resolved
 * below the destination root, so it must be a non-empty relative path with no
 * "." or ".." component and no traversal: an absolute or escaping path would
 * make the receiver read or link files outside its authorized root.
 *
 * Returns a malloc'd CANONICAL copy of an accepted path, or NULL when the path
 * is rejected.  Canonicalization collapses interior empty components ("a//b" ->
 * "a/b"), drops "." components and trailing "/"s, so validation, the delete
 * walker prefix match and the receiver's basis lookup all agree on one form.
 * The normalizer is the single source of truth for both config_basis_path_valid
 * and config_basis_append. */
static char* basis_path_normalize(const char* path) {
  if (!path || path[0] == '\0' || path[0] == '/' || has_path_traversal(path))
    return NULL;
  if (strcmp(path, ".") == 0)
    return NULL;
  char* dup = str_dup(path);
  if (!dup)
    return NULL;
  size_t out_len = 0;
  char* out = malloc(strlen(path) + 1);
  if (!out) {
    free(dup);
    return NULL;
  }
  char* saveptr = NULL;
  bool ok = true;
  for (char* part = strtok_r(dup, "/", &saveptr); part; part = strtok_r(NULL, "/", &saveptr)) {
    if (strcmp(part, "..") == 0) {
      ok = false;
      break;
    }
    if (strcmp(part, ".") == 0)
      continue;
    if (out_len > 0)
      out[out_len++] = '/';
    size_t len = strlen(part);
    memcpy(out + out_len, part, len);
    out_len += len;
  }
  free(dup);
  if (!ok || out_len == 0) {
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
  config_parse_ssh_dest(config);
  return 0;
}

void config_parse_ssh_dest(Config* config) {
  if (!config_is_remote_dest(config->receive_root_directory))
    return;
  config->transport = TRANSPORT_SSH;
  config->ssh_destination = str_dup(config->receive_root_directory);
  const char* colon = strchr(config->receive_root_directory, ':');
  char* path = str_dup(colon + 1);
  free(config->receive_root_directory);
  config->receive_root_directory = path;
}

void config_delete(Config* config) {
  if (config == NULL)
    return;
  if (config->log_file) {
    fclose(config->log_file);
    config->log_file = NULL;
  }
  free(config->version);
  free(config->send_directory);
  free(config->receive_root_directory);
  free(config->ssh_destination);
  free(config->module);
  free(config->auth_user);
  free(config->auth_password_hash);
  free(config->password_file);
  free(config->iconv_spec);
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
  for (int i = 0; i < config->basis_count; i++) {
    free(config->basis_dirs[i].path);
    config->basis_dirs[i].path = NULL;
  }
  free(config->basis_dirs);
  config->basis_dirs = NULL;
  config->basis_count = 0;
  free(config->partial_dir);
  free(config->suffix);
  free(config->address);
  free(config->bind_address);
  free(config->sockopts);
  free(config->daemon_config);
  free(config->compress_choice);
  free(config->chmod_spec);
  if (config->skip_compress_suffixes) {
    for (int i = 0; i < config->skip_compress_count; i++)
      free(config->skip_compress_suffixes[i]);
    free(config->skip_compress_suffixes);
  }
  free(config->usermap);
  config->usermap = NULL;
  config->usermap_count = 0;
  free(config->groupmap);
  config->groupmap = NULL;
  config->groupmap_count = 0;
  if (config->filters) {
    array_list_delete(config->filters);
  }
  /* A --delay-updates staging tree is transient receiver state: remove any
     leftovers on every exit path (success already emptied it). */
  if (config->delay_context)
    delay_updates_cleanup(config->delay_context);
  delay_updates_context_destroy(config->delay_context);
  config->delay_context = NULL;
  free(config);
}

/* Each helper is deliberately ordered to match the wire format. Keep the
 * helper call order in config_send and config_receive unchanged when adding
 * fields. */
static bool send_core_fields(int fd, const Config* c) {
  if (!send_str(fd, c->version) || !send_int(fd, c->eight_bit_output))
    return false;
  protocol_set_8_bit_output(c->eight_bit_output);
  if (!send_n_data(fd, &c->max_alloc, sizeof(c->max_alloc)))
    return false;
  return send_str(fd, c->send_directory) && send_str(fd, c->receive_root_directory) &&
         send_int(fd, c->save_to_disk) && send_int(fd, c->use_multithreading) &&
         send_int(fd, c->use_chunk_serialization) && send_int(fd, c->use_compression) &&
         send_int(fd, c->use_metadata) && send_int(fd, c->use_executability) &&
         send_int(fd, c->compression_level) &&
         send_n_data(fd, &c->chunk_size, sizeof(c->chunk_size)) && send_int(fd, c->use_sendfile);
}

static bool send_delta_fields(int fd, const Config* c) {
  return send_int(fd, c->use_delete) && send_int(fd, c->use_incremental) &&
         send_int(fd, c->size_only) && send_int(fd, c->ignore_times) &&
         send_int(fd, c->use_delta && !c->whole_file) &&
         send_n_data(fd, &c->delta_block_size, sizeof(c->delta_block_size)) &&
         send_n_data(fd, &c->delta_max_file_size, sizeof(unsigned long long));
}

static bool send_file_options(int fd, const Config* c) {
  /* Device/special preservation flags cross the wire so the receiver knows a
   * special/device entry must be recreated.  Trailing fields; protocol 2.13.0. */
  return send_int(fd, c->backup) && send_str(fd, c->backup_dir ? c->backup_dir : "") &&
         send_int(fd, c->remove_source_files) && send_int(fd, c->follow_symlinks) &&
         send_int(fd, c->copy_links) && send_int(fd, c->safe_links) &&
         send_int(fd, c->copy_unsafe_links) && send_int(fd, c->preserve_hard_links) &&
         send_int(fd, c->preserve_acls) && send_int(fd, c->preserve_xattrs) &&
         send_int(fd, c->preserve_devices) && send_int(fd, c->preserve_sparse) &&
         send_int(fd, c->preserve_specials) && send_int(fd, c->copy_devices) &&
         send_int(fd, c->write_devices);
}

static bool send_selection_options(int fd, const Config* c) {
  return send_int(fd, c->ignore_existing) && send_int(fd, c->existing) && send_int(fd, c->update) &&
         send_int(fd, c->inplace) && send_int(fd, c->delay_updates) && send_int(fd, c->append) &&
         send_int(fd, c->use_fsync) && send_int(fd, c->append_verify) &&
         send_int(fd, c->delete_excluded) && send_int(fd, c->force_delete) &&
         send_int(fd, c->delete_missing_args) && send_int(fd, c->delete_after) &&
         send_int(fd, c->preallocate) && send_n_data(fd, &c->max_delete, sizeof(c->max_delete)) &&
         send_int(fd, c->relative) && send_int(fd, c->prune_empty_dirs) &&
         send_int(fd, c->mkpath) && send_int(fd, c->delete_during) && send_int(fd, c->delete_delay);
}

static bool send_skip_compress_options(int fd, const Config* c) {
  if (!send_int(fd, c->skip_compress_set) || !send_int(fd, c->skip_compress_count))
    return false;
  for (int i = 0; i < c->skip_compress_count; i++) {
    if (!send_str(fd, c->skip_compress_suffixes[i]))
      return false;
  }
  return true;
}

static bool send_resume_options(int fd, const Config* c) {
  return send_str(fd, c->temp_dir ? c->temp_dir : "") && send_int(fd, c->partial) &&
         send_str(fd, c->partial_dir ? c->partial_dir : "") &&
         send_str(fd, c->suffix ? c->suffix : "") && send_int(fd, c->delete_before) &&
         send_int(fd, c->checksum) && send_int(fd, c->modify_window) &&
         send_str(fd, c->compress_choice ? c->compress_choice : "") &&
         send_str(fd, c->chmod_spec ? c->chmod_spec : "") && send_skip_compress_options(fd, c);
}

static bool send_basis_options(int fd, const Config* c) {
  if (!send_int(fd, c->basis_count))
    return false;
  for (int i = 0; i < c->basis_count; i++) {
    if (!send_int(fd, (int)c->basis_dirs[i].type) ||
        !send_str(fd, c->basis_dirs[i].path ? c->basis_dirs[i].path : ""))
      return false;
  }
  return true;
}

/* -y/--fuzzy (receiver-side similar-file basis selection).  Trailing field on
 * the config frame; protocol 2.9.0. */
static bool send_fuzzy_option(int fd, const Config* c) {
  return send_int(fd, c->fuzzy);
}

/* --checksum-choice/--cc + --checksum-seed.  The algorithm id and seed travel
 * with the config so the receiver hashes the on-disk old file with the same
 * parameters the sender used for its digest (see checksum.h).  Trailing fields
 * on the config frame; protocol 2.10.0. */
static bool send_checksum_options(int fd, const Config* c) {
  return send_int(fd, c->checksum_algo) &&
         send_n_data(fd, &c->checksum_seed, sizeof(c->checksum_seed));
}

static bool receive_core_fields(int fd, Config* c) {
  int value;
  if (!receive_wire_bool(fd, &c->eight_bit_output))
    return false;
  protocol_set_8_bit_output(c->eight_bit_output);
  if (!receive_n_data(fd, &c->max_alloc, sizeof(c->max_alloc)) || c->max_alloc == 0)
    return false;
  if (c->max_alloc > MAX_SERVER_ALLOC)
    c->max_alloc = MAX_SERVER_ALLOC;
  protocol_session_set_max_alloc(NULL, c->max_alloc);
  c->send_directory = receive_str(fd);
  c->receive_root_directory = receive_str(fd);
  if (!c->send_directory || !c->receive_root_directory)
    return false;
  if (!receive_wire_bool(fd, &c->save_to_disk) || !receive_wire_bool(fd, &c->use_multithreading) ||
      !receive_wire_bool(fd, &c->use_chunk_serialization) ||
      !receive_wire_bool(fd, &c->use_compression) || !receive_wire_bool(fd, &c->use_metadata) ||
      !receive_wire_bool(fd, &c->use_executability))
    return false;
  if (!receive_int(fd, &value))
    return false;
  c->compression_level = value;
  if (!receive_n_data(fd, &c->chunk_size, sizeof(c->chunk_size)))
    return false;
  if (!receive_wire_bool(fd, &c->use_sendfile))
    return false;
  return true;
}

static bool receive_delta_fields(int fd, Config* c) {
  if (!receive_wire_bool(fd, &c->use_delete))
    return false;
  if (!receive_wire_bool(fd, &c->use_incremental))
    return false;
  if (!receive_wire_bool(fd, &c->size_only))
    return false;
  if (!receive_wire_bool(fd, &c->ignore_times))
    return false;
  if (!receive_wire_bool(fd, &c->use_delta))
    return false;
  return receive_n_data(fd, &c->delta_block_size, sizeof(c->delta_block_size)) &&
         receive_n_data(fd, &c->delta_max_file_size, sizeof(unsigned long long));
}

static bool receive_file_options(int fd, Config* c) {
  if (!receive_wire_bool(fd, &c->backup))
    return false;
  char* backup_dir = receive_str(fd);
  if (!backup_dir)
    return false;
  if (*backup_dir != '\0') {
    c->backup_dir = backup_dir;
  } else {
    /* The sender serializes an unset (NULL) string as "", so canonicalize the
       empty wire value back to NULL to preserve NULL-vs-empty semantics. */
    free(backup_dir);
  }
  if (!receive_wire_bool(fd, &c->remove_source_files))
    return false;
  bool* flags[] = {&c->follow_symlinks,   &c->copy_links,          &c->safe_links,
                   &c->copy_unsafe_links, &c->preserve_hard_links, &c->preserve_acls,
                   &c->preserve_xattrs,   &c->preserve_devices,    &c->preserve_sparse,
                   &c->preserve_specials, &c->copy_devices,        &c->write_devices};
  for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    if (!receive_wire_bool(fd, flags[i]))
      return false;
  }
  return true;
}

static bool receive_selection_options(int fd, Config* c) {
  bool* flags[] = {&c->ignore_existing,
                   &c->existing,
                   &c->update,
                   &c->inplace,
                   &c->delay_updates,
                   &c->append,
                   &c->use_fsync,
                   &c->append_verify,
                   &c->delete_excluded,
                   &c->force_delete,
                   &c->delete_missing_args,
                   &c->delete_after,
                   &c->preallocate};
  for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    if (!receive_wire_bool(fd, flags[i]))
      return false;
  }
  if (!receive_n_data(fd, &c->max_delete, sizeof(c->max_delete)))
    return false;
  if (!receive_wire_bool(fd, &c->relative))
    return false;
  if (!receive_wire_bool(fd, &c->prune_empty_dirs))
    return false;
  if (!receive_wire_bool(fd, &c->mkpath))
    return false;
  if (!receive_wire_bool(fd, &c->delete_during))
    return false;
  return receive_wire_bool(fd, &c->delete_delay);
}

static bool receive_resume_options(int fd, Config* c) {
  char* temp_dir = receive_str(fd);
  if (!temp_dir)
    return false;
  if (*temp_dir != '\0') {
    c->temp_dir = temp_dir;
  } else {
    free(temp_dir);
  }
  if (!receive_wire_bool(fd, &c->partial))
    return false;
  /* These options have NULL client defaults, so the sender transmits an empty
     string for "unset".  Canonicalize the empty wire value back to NULL so
     receivers observe exactly what the client configured (plain --backup, for
     example, must not look like --backup-dir ""). */
  char* partial_dir = receive_str(fd);
  if (!partial_dir)
    return false;
  if (*partial_dir != '\0') {
    c->partial_dir = partial_dir;
  } else {
    free(partial_dir);
  }
  char* suffix = receive_str(fd);
  if (!suffix)
    return false;
  if (*suffix != '\0') {
    c->suffix = suffix;
  } else {
    free(suffix);
  }
  if (!receive_wire_bool(fd, &c->delete_before))
    return false;
  if (!receive_wire_bool(fd, &c->checksum))
    return false;
  if (!receive_n_data(fd, &c->modify_window, sizeof(c->modify_window)))
    return false;
  c->compress_choice = receive_str(fd);
  if (!c->compress_choice)
    return false;
  c->chmod_spec = receive_str(fd);
  if (!c->chmod_spec || !receive_wire_bool(fd, &c->skip_compress_set) ||
      !receive_int(fd, &c->skip_compress_count) || c->skip_compress_count < 0 ||
      c->skip_compress_count > 10000)
    return false;
  if (c->skip_compress_count > 0) {
    c->skip_compress_suffixes = calloc((size_t)c->skip_compress_count, sizeof(char*));
    if (!c->skip_compress_suffixes)
      return false;
    for (int i = 0; i < c->skip_compress_count; i++) {
      c->skip_compress_suffixes[i] = receive_str(fd);
      if (!c->skip_compress_suffixes[i])
        return false;
    }
  }
  return true;
}

static bool receive_basis_options(int fd, Config* c) {
  int count;
  if (!receive_int(fd, &count))
    return false;
  if (count < 0 || count > MAX_BASIS_DIRS)
    return false;
  for (int i = 0; i < count; i++) {
    int type;
    if (!receive_int(fd, &type) || type <= BASIS_DEST_NONE || type > BASIS_DEST_LINK)
      return false;
    char* path = receive_str(fd);
    if (!path)
      return false;
    /* config_basis_append validates and canonicalizes the path; a rejected
       path (absolute / traversal / empty) drops the whole connection. */
    bool ok = config_basis_append(c, (BasisDestType)type, path) == 0;
    free(path);
    if (!ok)
      return false;
  }
  return true;
}

static bool receive_fuzzy_option(int fd, Config* c) {
  return receive_wire_bool(fd, &c->fuzzy);
}

static bool receive_checksum_options(int fd, Config* c) {
  int algo;
  if (!receive_int(fd, &algo) || !checksum_algo_valid(algo))
    return false;
  c->checksum_algo = algo;
  return receive_n_data(fd, &c->checksum_seed, sizeof(c->checksum_seed));
}

/* --numeric-ids / --usermap / --groupmap / --chown (identity mapping).  The
 * receiver needs these to apply the ownership the client requested, so they
 * cross the config frame.  Trailing fields; protocol 2.11.0. */
static bool send_identity_map(int fd, const IdentityMap* map, int count) {
  if (!send_int(fd, count))
    return false;
  for (int i = 0; i < count; i++) {
    if (!send_int(fd, map[i].from) || !send_int(fd, map[i].to))
      return false;
  }
  return true;
}

static bool send_identity_options(int fd, const Config* c) {
  return send_int(fd, c->numeric_ids) && send_int(fd, c->chown_uid_set) &&
         send_int(fd, c->chown_uid) && send_int(fd, c->chown_gid_set) &&
         send_int(fd, c->chown_gid) && send_identity_map(fd, c->usermap, c->usermap_count) &&
         send_identity_map(fd, c->groupmap, c->groupmap_count);
}

static bool receive_identity_map(int fd, int* pcount, IdentityMap** pmap) {
  int count;
  if (!receive_int(fd, &count) || count < 0 || count > MAX_IDENTITY_MAP)
    return false;
  if (count > 0) {
    IdentityMap* map = calloc((size_t)count, sizeof(IdentityMap));
    if (!map)
      return false;
    for (int i = 0; i < count; i++) {
      if (!receive_int(fd, &map[i].from) || !receive_int(fd, &map[i].to)) {
        free(map);
        return false;
      }
    }
    *pmap = map;
  }
  *pcount = count;
  return true;
}

static bool receive_identity_options(int fd, Config* c) {
  int numeric_ids;
  if (!receive_int(fd, &numeric_ids) || !valid_wire_bool(numeric_ids))
    return false;
  c->numeric_ids = numeric_ids != 0;
  if (!receive_wire_bool(fd, &c->chown_uid_set) || !receive_int(fd, &c->chown_uid) ||
      !receive_wire_bool(fd, &c->chown_gid_set) || !receive_int(fd, &c->chown_gid))
    return false;
  if (c->chown_uid < IDENTITY_MATCH_ANY || c->chown_gid < IDENTITY_MATCH_ANY)
    return false;
  return receive_identity_map(fd, &c->usermap_count, &c->usermap) &&
         receive_identity_map(fd, &c->groupmap_count, &c->groupmap);
}

/* -U/--atimes, -N/--crtimes (affect both sender capture and receiver apply)
 * and -O/--omit-dir-times, -J/--omit-link-times (receiver-side prefs) all cross
 * the wire so the receiver knows what to apply / suppress.  --open-noatime is
 * client-only (it only governs the sender's source reads) and is never
 * serialized.  Trailing fields; protocol 2.12.0. */
static bool send_metadata_times_options(int fd, const Config* c) {
  return send_int(fd, c->preserve_atimes) && send_int(fd, c->preserve_crtimes) &&
         send_int(fd, c->omit_dir_times) && send_int(fd, c->omit_link_times);
}

static bool receive_metadata_times_options(int fd, Config* c) {
  return receive_wire_bool(fd, &c->preserve_atimes) &&
         receive_wire_bool(fd, &c->preserve_crtimes) && receive_wire_bool(fd, &c->omit_dir_times) &&
         receive_wire_bool(fd, &c->omit_link_times);
}

/* Phase 4 symlink-trust: --munge-links and -K/--keep-dirlinks.  Both CROSS the
 * wire (the receiver unmunges symlink targets and, with -K, follows an in-root
 * destination symlink-to-directory).  -k/--copy-dirlinks is sender-only and is
 * never serialized.  Trailing fields; protocol 2.13.0. */
static bool send_symlink_trust_options(int fd, const Config* c) {
  return send_int(fd, c->munge_links) && send_int(fd, c->keep_dirlinks);
}

static bool receive_symlink_trust_options(int fd, Config* c) {
  return receive_wire_bool(fd, &c->munge_links) && receive_wire_bool(fd, &c->keep_dirlinks);
}

/* -X/--xattrs, -A/--acls, --fake-super (Phase-4).  The receiver learns
 * preserve_xattrs/preserve_acls from the earlier file-options block and
 * recomputes the derived use_xattrs there; only --fake-super (receiver-side
 * behavior) needs an extra wire bit.  Trailing field; protocol 2.13.0. */
static bool send_phase4_xattr_options(int fd, const Config* c) {
  return send_int(fd, c->fake_super);
}

static bool receive_phase4_xattr_options(int fd, Config* c) {
  if (!receive_wire_bool(fd, &c->fake_super))
    return false;
  c->use_xattrs = c->preserve_acls || c->preserve_xattrs;
  return true;
}

/* Daemon module selection (Wave A, protocol 2.15.0).  Trailing string on the
 * config frame, sent after the Phase-4 xattr block and before the ack.  The
 * client composes it from a host::module/path destination; an unset module is
 * serialized as "" and canonicalized back to NULL on receive so the two never
 * look different to a peer. */
static bool send_daemon_module(int fd, const Config* c) {
  return send_str(fd, c->module ? c->module : "");
}

static bool receive_daemon_module(int fd, Config* c) {
  char* module = receive_str(fd);
  if (!module)
    return false;
  /* Guard against a hostile client flooding the log with an over-long module
   * name: only an empty string (module-less) or a valid module name
   * (bounded by DAEMON_MAX_MODULE_NAME) is accepted.  This is an input
   * guard, not a wire-format change. */
  if (*module != '\0' && !daemon_module_name_valid(module)) {
    log_message(LOG_LEVEL_WARNING, "Daemon client sent an invalid or over-long module name");
    free(module);
    send_status(fd, STATUS_ERROR);
    return false;
  }
  if (*module != '\0') {
    c->module = module;
  } else {
    free(module);
  }
  return true;
}

/* Daemon password credentials (Wave B, within protocol 2.15.0 -- see the
 * PROTOCOL_VERSION note in config.h: this rides the Wave A trailing-string
 * area, symmetric sender+receiver in every 2.15.0 build, so it is not a frame
 * layout that needs its own bump).  A single presence int is followed, when
 * set, by the username and the SHA-256 hex digest of the password.  The
 * literal password never crosses the wire. */
static bool send_daemon_auth(int fd, const Config* c) {
  bool present = c->auth_user != NULL && c->auth_password_hash != NULL && c->auth_user[0] != '\0' &&
                 c->auth_password_hash[0] != '\0';
  if (!send_int(fd, present ? 1 : 0))
    return false;
  if (!present)
    return true;
  /* Redacted send: the username and hard-wired digest must never reach a
   * --verbose debug log (they are replayable), while normal protocol strings
   * keep their debug trace. */
  return send_str_redacted(fd, c->auth_user) && send_str_redacted(fd, c->auth_password_hash);
}

static bool receive_daemon_auth(int fd, Config* c) {
  int present;
  if (!receive_int(fd, &present) || !valid_wire_bool(present))
    return false;
  if (!present)
    return true;
  /* Redacted receive: never log the incoming username/digest bodies. */
  char* user = receive_str_redacted(fd);
  char* hash = receive_str_redacted(fd);
  if (!user || !hash) {
    free(user);
    free(hash);
    return false;
  }
  size_t user_len = strlen(user);
  bool valid = user_len > 0 && user_len <= CREDENTIAL_MAX_USER_LEN && credentials_hash_valid(hash);
  if (!valid) {
    free(user);
    free(hash);
    log_message(LOG_LEVEL_WARNING, "Daemon client sent malformed auth credentials");
    return false;
  }
  c->auth_user = user;
  c->auth_password_hash = hash;
  return true;
}

/* --iconv CONVERT_SPEC (protocol 2.16.0).  Trailing string on the config frame,
 * sent after the Wave A/B daemon-auth block and before the ack, so the
 * receiver knows the wire charset before the first file name arrives.  The full
 * spec travels (LOCAL,REMOTE) and each end derives its own LOCAL and the wire
 * (REMOTE) charset symmetrically; an unset spec is serialized as "" and
 * canonicalized back to NULL on receive. */
static bool send_iconv_spec(int fd, const Config* c) {
  return send_str(fd, c->iconv_spec ? c->iconv_spec : "");
}

static bool receive_iconv_spec(int fd, Config* c) {
  char* spec = receive_str(fd);
  if (!spec)
    return false;
  if (*spec == '\0') {
    free(spec);
    c->iconv_spec = NULL;
    return true;
  }
  c->iconv_spec = spec;
  return true;
}

bool config_send(int file_descriptor, const Config* config) {
  protocol_session_set_max_alloc(NULL, config->max_alloc);
  if (!send_core_fields(file_descriptor, config) || !send_delta_fields(file_descriptor, config) ||
      !send_file_options(file_descriptor, config) ||
      !send_selection_options(file_descriptor, config) ||
      !send_resume_options(file_descriptor, config) ||
      !send_basis_options(file_descriptor, config) || !send_fuzzy_option(file_descriptor, config) ||
      !send_checksum_options(file_descriptor, config) ||
      !send_identity_options(file_descriptor, config) ||
      !send_metadata_times_options(file_descriptor, config) ||
      !send_symlink_trust_options(file_descriptor, config) ||
      !send_phase4_xattr_options(file_descriptor, config) ||
      !send_daemon_module(file_descriptor, config) || !send_daemon_auth(file_descriptor, config) ||
      !send_iconv_spec(file_descriptor, config))
    return false;
  Status status;
  if (!receive_status(file_descriptor, &status))
    return false;
  if (status != STATUS_OK) {
    log_message(LOG_LEVEL_ERROR, "Error transmitting config");
    return false;
  }
  return true;
}

Config* config_receive_with_validate(int file_descriptor, ConfigValidateFunc validate,
                                     void* context) {
  Config* config = config_create();
  if (!config)
    return NULL;
  free(config->version);
  config->version = receive_str(file_descriptor);
  if (!config->version)
    goto error;
  if (strcmp(config->version, PROTOCOL_VERSION) != 0) {
    char* escaped_version = output_escape(config->version, false);
    fprintf(stderr, "Protocol version mismatch: client=%s, server=%s\n",
            escaped_version ? escaped_version : "<allocation failed>", PROTOCOL_VERSION);
    free(escaped_version);
    send_status(file_descriptor, STATUS_ERROR);
    goto error;
  }
  if (!receive_core_fields(file_descriptor, config) ||
      !receive_delta_fields(file_descriptor, config) ||
      !receive_file_options(file_descriptor, config) ||
      !receive_selection_options(file_descriptor, config) ||
      !receive_resume_options(file_descriptor, config) ||
      !receive_basis_options(file_descriptor, config) ||
      !receive_fuzzy_option(file_descriptor, config) ||
      !receive_checksum_options(file_descriptor, config) ||
      !receive_identity_options(file_descriptor, config) ||
      !receive_metadata_times_options(file_descriptor, config) ||
      !receive_symlink_trust_options(file_descriptor, config) ||
      !receive_phase4_xattr_options(file_descriptor, config) ||
      !receive_daemon_module(file_descriptor, config) ||
      !receive_daemon_auth(file_descriptor, config) || !receive_iconv_spec(file_descriptor, config))
    goto error;
  if (config->compress_choice[0] != '\0' && strcmp(config->compress_choice, "zstd") != 0 &&
      strcmp(config->compress_choice, "none") != 0) {
    char* escaped_choice = output_escape(config->compress_choice, config->eight_bit_output);
    fprintf(stderr, "Unsupported compression choice: %s\n",
            escaped_choice ? escaped_choice : "<allocation failed>");
    free(escaped_choice);
    send_status(file_descriptor, STATUS_ERROR);
    goto error;
  }
  if (!validate_received_config(config)) {
    fprintf(stderr, "Invalid configuration received from client\n");
    send_status(file_descriptor, STATUS_ERROR);
    goto error;
  }
  if (validate) {
    const char* rejection = validate(config, context);
    if (rejection != NULL) {
      /* Daemon module gate (unknown module / read-only module / auth-required
       * module): refuse BEFORE the STATUS_OK so the client aborts at the
       * config handshake and no file data is ever exchanged. */
      fprintf(stderr, "%s\n", rejection);
      send_status(file_descriptor, STATUS_ERROR);
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
