#include "daemon_conf.h"
#include "credentials.h"
#include "utils.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

#define set_error utils_set_error

/* Trim leading and trailing ASCII space/tab in place; returns the new start. */
static char* trim_ws(char* s) {
  while (*s == ' ' || *s == '\t')
    s++;
  size_t len = strlen(s);
  while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t'))
    s[--len] = '\0';
  return s;
}

/* Case-insensitive equality of a parsed key against a canonical key name. */
static bool key_equals(const char* key, const char* canonical) {
  return strcasecmp(key, canonical) == 0;
}

static bool parse_bool_value(const char* value, bool* out) {
  if (strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
    *out = true;
    return true;
  }
  if (strcasecmp(value, "no") == 0 || strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
    *out = false;
    return true;
  }
  return false;
}

/* Parse an IPv4/IPv6 CIDR "addr/prefix" into `bytes`/`*family`.  Returns false
 * for a malformed address, a missing/oversized prefix, or a prefix that does
 * not fit the address family. */
static bool parse_cidr(const char* cidr, int* prefix_out, uint8_t* bytes, int* family_out) {
  const char* slash = strchr(cidr, '/');
  if (!slash)
    return false;
  size_t addr_len = (size_t)(slash - cidr);
  if (addr_len == 0 || addr_len >= INET6_ADDRSTRLEN)
    return false;
  char addr[INET6_ADDRSTRLEN];
  memcpy(addr, cidr, addr_len);
  addr[addr_len] = '\0';
  char* end = NULL;
  long prefix = strtol(slash + 1, &end, 10);
  if (end == slash + 1 || *end != '\0')
    return false;
  struct in_addr v4;
  struct in6_addr v6;
  if (inet_pton(AF_INET, addr, &v4) == 1) {
    if (prefix < 0 || prefix > 32)
      return false;
    memcpy(bytes, &v4, sizeof(v4));
    *prefix_out = (int)prefix;
    *family_out = AF_INET;
    return true;
  }
  if (inet_pton(AF_INET6, addr, &v6) == 1) {
    if (prefix < 0 || prefix > 128)
      return false;
    memcpy(bytes, &v6, sizeof(v6));
    *prefix_out = (int)prefix;
    *family_out = AF_INET6;
    return true;
  }
  return false;
}

/* A host pattern is valid when it is `*`, a valid IPv4/IPv6 literal, or a valid
 * CIDR.  Peer addresses reaching the matcher are always numeric, so hostname
 * globs are rejected at parse time: accepting one would create a deny rule that
 * silently never matches (fail-open). */
static bool host_pattern_valid(const char* pattern) {
  if (!pattern || *pattern == '\0')
    return false;
  if (strcmp(pattern, "*") == 0)
    return true;
  if (strchr(pattern, '/')) {
    uint8_t bytes[16];
    int prefix;
    int family;
    return parse_cidr(pattern, &prefix, bytes, &family);
  }
  struct in_addr v4;
  struct in6_addr v6;
  return inet_pton(AF_INET, pattern, &v4) == 1 || inet_pton(AF_INET6, pattern, &v6) == 1;
}

/* Append every comma- and/or whitespace-separated host pattern in `value` to
 * the heap-owned list (or replace the list when `replace` is set, which --dparam
 * uses so an override can narrow access rather than only widen it).  Returns
 * false (err filled) on an invalid pattern or an allocation failure. */
static bool store_host_list(char*** list, int* count, const char* value, const char* key,
                            const char* module_name, bool replace, char* err, size_t err_size) {
  if (replace) {
    for (int i = 0; i < *count; i++)
      free((*list)[i]);
    free(*list);
    *list = NULL;
    *count = 0;
  }
  char* copy = str_dup(value);
  if (!copy) {
    if (module_name)
      set_error(err, err_size, "out of memory parsing '%s' for module '%s'", key, module_name);
    else
      set_error(err, err_size, "out of memory parsing '%s'", key);
    return false;
  }
  char* save = NULL;
  int added = 0;
  for (char* token = strtok_r(copy, ", \t", &save); token; token = strtok_r(NULL, ", \t", &save)) {
    if (!host_pattern_valid(token)) {
      if (module_name)
        set_error(err, err_size, "module '%s': invalid host pattern '%s' in '%s'", module_name,
                  token, key);
      else
        set_error(err, err_size, "invalid host pattern '%s' in '%s'", token, key);
      free(copy);
      return false;
    }
    char** grown = realloc(*list, (size_t)(*count + 1) * sizeof(char*));
    if (!grown) {
      if (module_name)
        set_error(err, err_size, "out of memory parsing '%s' for module '%s'", key, module_name);
      else
        set_error(err, err_size, "out of memory parsing '%s'", key);
      free(copy);
      return false;
    }
    *list = grown;
    char* dup = str_dup(token);
    if (!dup) {
      if (module_name)
        set_error(err, err_size, "out of memory parsing '%s' for module '%s'", key, module_name);
      else
        set_error(err, err_size, "out of memory parsing '%s'", key);
      free(copy);
      return false;
    }
    (*list)[(*count)++] = dup;
    added++;
  }
  free(copy);
  /* A present key with an empty (or separator-only) value would otherwise
   * install a zero-length list, i.e. no ACL at all: a strict-parse config must
   * never silently turn a restrictive directive into "allow everyone". */
  if (added == 0) {
    if (module_name)
      set_error(err, err_size, "module '%s': '%s' must list at least one host pattern", module_name,
                key);
    else
      set_error(err, err_size, "'%s' must list at least one host pattern", key);
    return false;
  }
  return true;
}

/* Parse a `max connections` value: a positive integer (0/negative/garbage are
 * rejected because they would silently disable the cap or admit nothing). */
static bool store_max_connections(int* slot, const char* value, const char* module_name, char* err,
                                  size_t err_size) {
  char* end = NULL;
  errno = 0;
  long n = strtol(value, &end, 10);
  if (*value == '\0' || errno != 0 || *end != '\0' || n <= 0 || n > INT_MAX) {
    if (module_name)
      set_error(err, err_size,
                "module '%s': invalid 'max connections' '%s' (must be a positive "
                "integer)",
                module_name, value);
    else
      set_error(err, err_size, "invalid 'max connections' '%s' (must be a positive integer)",
                value);
    return false;
  }
  *slot = (int)n;
  return true;
}

/* Parse a non-negative concurrency cap where 0 means unlimited/disabled
 * (per-module `max connections`, `max connections per host`,
 * `auth lockout threshold`).  Negative/garbage/oversized values are rejected. */
static bool store_optional_cap(int* slot, const char* value, int max_value, const char* key,
                               const char* module_name, char* err, size_t err_size) {
  char* end = NULL;
  errno = 0;
  long n = strtol(value, &end, 10);
  if (*value == '\0' || errno != 0 || *end != '\0' || n < 0 || n > max_value) {
    if (module_name)
      set_error(err, err_size, "module '%s': invalid '%s' '%s' (must be 0-%d)", module_name, key,
                value, max_value);
    else
      set_error(err, err_size, "invalid '%s' '%s' (must be 0-%d)", key, value, max_value);
    return false;
  }
  *slot = (int)n;
  return true;
}

/* Parse an `auth failure delay` value: 0 (disabled) through the configured cap. */
static bool store_auth_failure_delay(int* slot, const char* value, char* err, size_t err_size) {
  char* end = NULL;
  errno = 0;
  long n = strtol(value, &end, 10);
  if (*value == '\0' || errno != 0 || *end != '\0' || n < 0 ||
      n > DAEMON_CONF_MAX_AUTH_FAILURE_DELAY_MS) {
    set_error(err, err_size, "invalid 'auth failure delay' '%s' (must be 0-%d milliseconds)", value,
              DAEMON_CONF_MAX_AUTH_FAILURE_DELAY_MS);
    return false;
  }
  *slot = (int)n;
  return true;
}

bool daemon_module_name_valid(const char* name) {
  if (!name || *name == '\0')
    return false;
  size_t len = strlen(name);
  if (len > DAEMON_MAX_MODULE_NAME)
    return false;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)name[i];
    bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    if (!alnum && c != '.' && c != '_' && c != '-')
      return false;
  }
  return true;
}

DaemonConf* daemon_conf_create(void) {
  DaemonConf* conf = calloc(1, sizeof(DaemonConf));
  if (!conf)
    return NULL;
  conf->global.port = DAEMON_CONF_DEFAULT_PORT;
  conf->global.max_connections = DAEMON_CONF_DEFAULT_MAX_CONNECTIONS;
  conf->global.auth_failure_delay_ms = DAEMON_CONF_DEFAULT_AUTH_FAILURE_DELAY_MS;
  conf->global.max_connections_per_host = DAEMON_CONF_DEFAULT_MAX_CONNECTIONS_PER_HOST;
  conf->global.auth_lockout_threshold = DAEMON_CONF_DEFAULT_AUTH_LOCKOUT_THRESHOLD;
  conf->global.auth_lockout_duration_sec = DAEMON_CONF_DEFAULT_AUTH_LOCKOUT_DURATION_SEC;
  return conf;
}

/* Free a heap-owned pattern list of `count` entries. */
static void free_string_list(char** list, int count) {
  for (int i = 0; i < count; i++)
    free(list[i]);
  free(list);
}

void daemon_conf_free(DaemonConf* conf) {
  if (!conf)
    return;
  free(conf->global.motd_file);
  free(conf->global.address);
  free_string_list(conf->global.hosts_allow, conf->global.hosts_allow_count);
  free_string_list(conf->global.hosts_deny, conf->global.hosts_deny_count);
  for (int i = 0; i < conf->module_count; i++) {
    DaemonModule* m = &conf->modules[i];
    free(m->name);
    free(m->path);
    for (int j = 0; j < m->auth_user_count; j++)
      free(m->auth_users[j]);
    free(m->auth_users);
    free_string_list(m->hosts_allow, m->hosts_allow_count);
    free_string_list(m->hosts_deny, m->hosts_deny_count);
  }
  free(conf->modules);
  free(conf);
}

const DaemonModule* daemon_conf_find_module(const DaemonConf* conf, const char* name) {
  if (!conf || !name)
    return NULL;
  for (int i = 0; i < conf->module_count; i++) {
    if (strcmp(conf->modules[i].name, name) == 0)
      return &conf->modules[i];
  }
  return NULL;
}

/* Replace *slot with a str_dup of value; returns false on allocation failure. */
static bool store_string(char** slot, const char* value) {
  char* dup = str_dup(value);
  if (!dup)
    return false;
  free(*slot);
  *slot = dup;
  return true;
}

static bool store_port(int* slot, const char* value, char* err, size_t err_size) {
  char* end;
  errno = 0;
  long p = strtol(value, &end, 10);
  if (errno != 0 || *end != '\0' || *value == '\0' || p <= 0 || p > 65535) {
    set_error(err, err_size, "invalid port '%s' (must be 1-65535)", value);
    return false;
  }
  *slot = (int)p;
  return true;
}

/* Apply a global scalar key/value.  Keys are case-insensitive.  Returns false
 * (err filled) on an unknown key or an invalid value. */
static bool apply_global_key(DaemonConf* conf, char* key, const char* value, bool replace_hosts,
                             char* err, size_t err_size) {
  if (key_equals(key, "port"))
    return store_port(&conf->global.port, value, err, err_size);
  if (key_equals(key, "motd file")) {
    if (!store_string(&conf->global.motd_file, value)) {
      set_error(err, err_size, "out of memory parsing 'motd file'");
      return false;
    }
    return true;
  }
  if (key_equals(key, "address")) {
    if (!store_string(&conf->global.address, value)) {
      set_error(err, err_size, "out of memory parsing 'address'");
      return false;
    }
    return true;
  }
  if (key_equals(key, "max connections"))
    return store_max_connections(&conf->global.max_connections, value, NULL, err, err_size);
  if (key_equals(key, "max connections per host"))
    return store_optional_cap(&conf->global.max_connections_per_host, value,
                              DAEMON_CONF_MAX_CONCURRENCY_LIMIT, "max connections per host", NULL,
                              err, err_size);
  if (key_equals(key, "auth failure delay"))
    return store_auth_failure_delay(&conf->global.auth_failure_delay_ms, value, err, err_size);
  if (key_equals(key, "auth lockout threshold"))
    return store_optional_cap(&conf->global.auth_lockout_threshold, value,
                              DAEMON_CONF_MAX_CONCURRENCY_LIMIT, "auth lockout threshold", NULL,
                              err, err_size);
  if (key_equals(key, "auth lockout duration"))
    return store_optional_cap(&conf->global.auth_lockout_duration_sec, value,
                              DAEMON_CONF_MAX_AUTH_LOCKOUT_DURATION_SEC, "auth lockout duration",
                              NULL, err, err_size);
  if (key_equals(key, "hosts allow"))
    return store_host_list(&conf->global.hosts_allow, &conf->global.hosts_allow_count, value,
                           "hosts allow", NULL, replace_hosts, err, err_size);
  if (key_equals(key, "hosts deny"))
    return store_host_list(&conf->global.hosts_deny, &conf->global.hosts_deny_count, value,
                           "hosts deny", NULL, replace_hosts, err, err_size);
  set_error(err, err_size, "unknown global key '%s'", key);
  return false;
}

/* Apply a module key/value to the currently-open module.  Returns false (err
 * filled) on an unknown module key or an invalid value. */
static bool apply_module_key(DaemonModule* module, char* key, char* value, char* err,
                             size_t err_size) {
  if (key_equals(key, "path")) {
    if (*value == '\0') {
      set_error(err, err_size, "module '%s': 'path' must not be empty", module->name);
      return false;
    }
    if (!store_string(&module->path, value)) {
      set_error(err, err_size, "out of memory parsing 'path' for module '%s'", module->name);
      return false;
    }
    return true;
  }
  if (key_equals(key, "read only")) {
    bool parsed;
    if (!parse_bool_value(value, &parsed)) {
      set_error(err, err_size,
                "module '%s': 'read only' must be yes/no (or true/false/1/0), got '%s'",
                module->name, value);
      return false;
    }
    module->read_only = parsed;
    return true;
  }
  if (key_equals(key, "client owner")) {
    bool parsed;
    if (!parse_bool_value(value, &parsed)) {
      set_error(err, err_size,
                "module '%s': 'client owner' must be yes/no (or true/false/1/0), got '%s'",
                module->name, value);
      return false;
    }
    module->client_owner = parsed;
    return true;
  }
  if (key_equals(key, "auth users")) {
    char* list = str_dup(value);
    if (!list) {
      set_error(err, err_size, "out of memory parsing 'auth users' for module '%s'", module->name);
      return false;
    }
    char* save = NULL;
    int added = 0;
    for (char* token = strtok_r(list, ",", &save); token; token = strtok_r(NULL, ",", &save)) {
      const char* user = trim_ws(token);
      if (*user == '\0')
        continue;
      if (!credentials_username_valid(user)) {
        set_error(err, err_size, "module '%s': invalid 'auth users' entry '%s'", module->name,
                  user);
        free(list);
        return false;
      }
      char** grown =
          realloc(module->auth_users, (size_t)(module->auth_user_count + 1) * sizeof(char*));
      if (!grown) {
        free(list);
        set_error(err, err_size, "out of memory parsing 'auth users' for module '%s'",
                  module->name);
        return false;
      }
      module->auth_users = grown;
      char* dup = str_dup(user);
      if (!dup) {
        free(list);
        set_error(err, err_size, "out of memory parsing 'auth users' for module '%s'",
                  module->name);
        return false;
      }
      module->auth_users[module->auth_user_count++] = dup;
      added++;
    }
    free(list);
    /* An empty/separator-only value must not silently disable authentication:
     * the key's presence is an explicit request for an allow-list. */
    if (added == 0) {
      set_error(err, err_size, "module '%s': 'auth users' must list at least one user",
                module->name);
      return false;
    }
    return true;
  }
  if (key_equals(key, "max connections"))
    return store_optional_cap(&module->max_connections, value, DAEMON_CONF_MAX_CONCURRENCY_LIMIT,
                              "max connections", module->name, err, err_size);
  if (key_equals(key, "hosts allow"))
    return store_host_list(&module->hosts_allow, &module->hosts_allow_count, value, "hosts allow",
                           module->name, false, err, err_size);
  if (key_equals(key, "hosts deny"))
    return store_host_list(&module->hosts_deny, &module->hosts_deny_count, value, "hosts deny",
                           module->name, false, err, err_size);
  set_error(err, err_size, "unknown key '%s' in module '%s'", key, module->name);
  return false;
}

static bool module_open_valid(const DaemonModule* module, char* err, size_t err_size) {
  if (module->path == NULL) {
    set_error(err, err_size, "module '%s' has no 'path'", module->name);
    return false;
  }
  return true;
}

/* Validate a [section] header line body (text between the brackets) and set
 * *name to the module name.  Returns false on a malformed header. */
static bool parse_section_name(char* body, const char** name_out, char* err, size_t err_size) {
  char* name = trim_ws(body);
  if (!daemon_module_name_valid(name)) {
    set_error(err, err_size, "invalid module name '%s' (must be 1-%d chars of [A-Za-z0-9._-])",
              name, DAEMON_MAX_MODULE_NAME);
    return false;
  }
  *name_out = name;
  return true;
}

/* Open (or switch to) a module section.  Closes any previously open module
 * (validating it has a path) and appends the new one. */
static int open_module(DaemonConf* conf, int* current_module, const char* name, char* err,
                       size_t err_size) {
  if (*current_module >= 0) {
    if (!module_open_valid(&conf->modules[*current_module], err, err_size))
      return -1;
  }
  if (daemon_conf_find_module(conf, name)) {
    set_error(err, err_size, "duplicate module '%s'", name);
    return -1;
  }
  if (conf->module_count >= DAEMON_CONF_MAX_MODULES) {
    set_error(err, err_size, "too many modules (limit %d); module '%s' rejected",
              DAEMON_CONF_MAX_MODULES, name);
    return -1;
  }
  DaemonModule* grown =
      realloc(conf->modules, (size_t)(conf->module_count + 1) * sizeof(DaemonModule));
  if (!grown) {
    set_error(err, err_size, "out of memory adding module '%s'", name);
    return -1;
  }
  conf->modules = grown;
  memset(&conf->modules[conf->module_count], 0, sizeof(DaemonModule));
  conf->modules[conf->module_count].name = str_dup(name);
  if (!conf->modules[conf->module_count].name) {
    set_error(err, err_size, "out of memory adding module '%s'", name);
    return -1;
  }
  conf->module_count++;
  *current_module = conf->module_count - 1;
  return 0;
}

/* Split a "key = value" line (value pointer returned in *value, pointing into
 * line).  Returns false when there is no '='. */
static bool split_key_value(char* line, char** key, char** value) {
  char* eq = strchr(line, '=');
  if (!eq)
    return false;
  *eq = '\0';
  *key = trim_ws(line);
  *value = trim_ws(eq + 1);
  return true;
}

/* Strip one layer of surrounding double quotes from a trimmed value.  A value
 * that starts with '"' but does not end with '"' is an error. */
static bool unquote_value(char* value, char* err, size_t err_size) {
  size_t len = strlen(value);
  if (len == 0 || value[0] != '"')
    return true;
  if (len < 2 || value[len - 1] != '"') {
    set_error(err, err_size, "unterminated quoted value");
    return false;
  }
  memmove(value, value + 1, len - 2);
  value[len - 2] = '\0';
  return true;
}

DaemonConf* daemon_conf_load(const char* path, char* err, size_t err_size) {
  if (err && err_size)
    err[0] = '\0';
  if (!path) {
    set_error(err, err_size, "no daemon config path");
    return NULL;
  }
  FILE* fp = fopen(path, "r");
  if (!fp) {
    set_error(err, err_size, "cannot open daemon config '%s': %s", path, strerror(errno));
    return NULL;
  }

  DaemonConf* conf = daemon_conf_create();
  if (!conf) {
    fclose(fp);
    set_error(err, err_size, "out of memory allocating daemon config");
    return NULL;
  }

  int current_module = -1;
  int line_no = 0;
  char line[DAEMON_CONF_MAX_LINE + 2];
  bool ok = true;

  while (ok && fgets(line, sizeof(line), fp)) {
    line_no++;
    size_t len = strlen(line);
    if (len == DAEMON_CONF_MAX_LINE + 1 && line[len - 1] != '\n') {
      /* The read stopped at the buffer edge without a newline and there is
       * more file to come: the line exceeds the bound. */
      if (!feof(fp)) {
        set_error(err, err_size, "line %d exceeds the %d-byte limit", line_no,
                  DAEMON_CONF_MAX_LINE);
        ok = false;
        break;
      }
    }
    if (len > 0 && line[len - 1] == '\n')
      line[--len] = '\0';
    if (len > 0 && line[len - 1] == '\r')
      line[--len] = '\0';

    char* cursor = line;
    while (*cursor == ' ' || *cursor == '\t')
      cursor++;
    if (*cursor == '\0' || *cursor == '#' || *cursor == ';')
      continue; /* blank or comment line */

    if (*cursor == '[') {
      char* close = strchr(cursor, ']');
      if (!close) {
        set_error(err, err_size, "line %d: unterminated module header", line_no);
        ok = false;
        break;
      }
      *close = '\0';
      char* trailing = close + 1;
      const char* rest = trim_ws(trailing);
      if (*rest != '\0') {
        set_error(err, err_size, "line %d: unexpected text after module header", line_no);
        ok = false;
        break;
      }
      const char* name = NULL;
      if (!parse_section_name(cursor + 1, &name, err, err_size)) {
        ok = false;
        break;
      }
      if (open_module(conf, &current_module, name, err, err_size) != 0) {
        ok = false;
        break;
      }
      continue;
    }

    char* key;
    char* value;
    if (!split_key_value(cursor, &key, &value)) {
      set_error(err, err_size, "line %d: expected 'key = value'", line_no);
      ok = false;
      break;
    }
    if (*key == '\0') {
      set_error(err, err_size, "line %d: empty key", line_no);
      ok = false;
      break;
    }
    if (!unquote_value(value, err, err_size)) {
      ok = false;
      break;
    }
    if (current_module >= 0) {
      if (!apply_module_key(&conf->modules[current_module], key, value, err, err_size)) {
        ok = false;
        break;
      }
    } else {
      if (!apply_global_key(conf, key, value, false, err, err_size)) {
        ok = false;
        break;
      }
    }
  }

  if (ok && ferror(fp)) {
    set_error(err, err_size, "error reading daemon config '%s': %s", path, strerror(errno));
    ok = false;
  }
  fclose(fp);

  if (ok && current_module >= 0 &&
      !module_open_valid(&conf->modules[current_module], err, err_size)) {
    ok = false;
  }
  if (!ok) {
    daemon_conf_free(conf);
    return NULL;
  }
  return conf;
}

int daemon_conf_apply_dparam(DaemonConf* conf, const char* assignment, char* err, size_t err_size) {
  if (err && err_size)
    err[0] = '\0';
  if (!conf || !assignment || *assignment == '\0') {
    set_error(err, err_size, "--dparam requires a KEY=VALUE override");
    return -1;
  }
  char* copy = str_dup(assignment);
  if (!copy) {
    set_error(err, err_size, "out of memory parsing --dparam");
    return -1;
  }
  char* eq = strchr(copy, '=');
  if (!eq) {
    free(copy);
    set_error(err, err_size, "--dparam '%s' has no '=' (expected KEY=VALUE)", assignment);
    return -1;
  }
  *eq = '\0';
  char* key = trim_ws(copy);
  const char* value = trim_ws(eq + 1);
  if (*key == '\0') {
    free(copy);
    set_error(err, err_size, "--dparam '%s' has an empty key", assignment);
    return -1;
  }
  if (*value == '\0') {
    free(copy);
    set_error(err, err_size, "--dparam '%s' has an empty value", assignment);
    return -1;
  }
  bool ok = apply_global_key(conf, key, value, true, err, err_size);
  free(copy);
  return ok ? 0 : -1;
}

/* Compare the first `prefix` bits of two 16-byte address buffers. */
static bool bit_prefix_match(const uint8_t* a, const uint8_t* b, int prefix) {
  int whole = prefix / 8;
  if (whole > 0 && memcmp(a, b, (size_t)whole) != 0)
    return false;
  int remainder = prefix % 8;
  if (remainder == 0)
    return true;
  uint8_t mask = (uint8_t)(0xffu << (8 - remainder));
  return (a[whole] & mask) == (b[whole] & mask);
}

/* Case-insensitive glob match used for hostname patterns.  Falls back to the
 * shared case-sensitive matcher when an operand is too long for the stack
 * buffers. */
static bool host_glob_match(const char* pattern, const char* str) {
  char pbuf[256];
  char sbuf[256];
  size_t plen = strlen(pattern);
  size_t slen = strlen(str);
  if (plen >= sizeof(pbuf) || slen >= sizeof(sbuf))
    return glob_match(pattern, str);
  for (size_t i = 0; i <= plen; i++)
    pbuf[i] = (char)tolower((unsigned char)pattern[i]);
  for (size_t i = 0; i <= slen; i++)
    sbuf[i] = (char)tolower((unsigned char)str[i]);
  return glob_match(pbuf, sbuf);
}

bool daemon_host_pattern_match(const char* pattern, const char* peer_ip) {
  if (!pattern || *pattern == '\0' || !peer_ip || *peer_ip == '\0')
    return false;
  if (strcmp(pattern, "*") == 0)
    return true;
  if (strchr(pattern, '/')) {
    uint8_t pattern_bytes[16];
    uint8_t peer_bytes[16];
    int prefix = 0;
    int family = AF_UNSPEC;
    if (!parse_cidr(pattern, &prefix, pattern_bytes, &family))
      return false;
    if (inet_pton(family, peer_ip, peer_bytes) != 1)
      return false;
    return bit_prefix_match(pattern_bytes, peer_bytes, prefix);
  }
  struct in_addr pattern_v4;
  struct in_addr peer_v4;
  if (inet_pton(AF_INET, pattern, &pattern_v4) == 1)
    return inet_pton(AF_INET, peer_ip, &peer_v4) == 1 && pattern_v4.s_addr == peer_v4.s_addr;
  struct in6_addr pattern_v6;
  struct in6_addr peer_v6;
  if (inet_pton(AF_INET6, pattern, &pattern_v6) == 1)
    return inet_pton(AF_INET6, peer_ip, &peer_v6) == 1 &&
           memcmp(&pattern_v6, &peer_v6, sizeof(pattern_v6)) == 0;
  /* Not a literal: a hostname/glob pattern. */
  return host_glob_match(pattern, peer_ip);
}

bool daemon_hosts_allowed(const char* peer_ip, char* const* allow, int allow_count,
                          char* const* deny, int deny_count) {
  if (!peer_ip)
    return false;
  for (int i = 0; i < deny_count; i++) {
    if (daemon_host_pattern_match(deny[i], peer_ip))
      return false;
  }
  if (allow_count > 0) {
    for (int i = 0; i < allow_count; i++) {
      if (daemon_host_pattern_match(allow[i], peer_ip))
        return true;
    }
    return false;
  }
  return true;
}

bool daemon_hosts_restricted(char* const* allow, int allow_count, char* const* deny,
                             int deny_count) {
  (void)allow;
  (void)deny;
  return allow_count > 0 || deny_count > 0;
}
