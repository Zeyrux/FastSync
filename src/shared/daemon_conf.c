#include "daemon_conf.h"
#include "utils.h"
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static void set_error(char* err, size_t err_size, const char* fmt, ...) {
  if (!err || err_size == 0)
    return;
  va_list args;
  va_start(args, fmt);
  vsnprintf(err, err_size, fmt, args);
  va_end(args);
}

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
  return conf;
}

void daemon_conf_free(DaemonConf* conf) {
  if (!conf)
    return;
  free(conf->global.motd_file);
  free(conf->global.address);
  for (int i = 0; i < conf->module_count; i++) {
    DaemonModule* m = &conf->modules[i];
    free(m->name);
    free(m->path);
    for (int j = 0; j < m->auth_user_count; j++)
      free(m->auth_users[j]);
    free(m->auth_users);
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
static bool apply_global_key(DaemonConf* conf, char* key, char* value, char* err, size_t err_size) {
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
  if (key_equals(key, "auth users")) {
    char* list = str_dup(value);
    if (!list) {
      set_error(err, err_size, "out of memory parsing 'auth users' for module '%s'", module->name);
      return false;
    }
    char* save = NULL;
    for (char* token = strtok_r(list, ",", &save); token; token = strtok_r(NULL, ",", &save)) {
      char* user = trim_ws(token);
      if (*user == '\0')
        continue;
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
    }
    free(list);
    return true;
  }
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
      char* rest = trim_ws(trailing);
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
      if (!apply_global_key(conf, key, value, err, err_size)) {
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
  char* value = trim_ws(eq + 1);
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
  bool ok = apply_global_key(conf, key, value, err, err_size);
  free(copy);
  return ok ? 0 : -1;
}
