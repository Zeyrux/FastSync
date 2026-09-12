#ifndef DAEMON_CONF_H
#define DAEMON_CONF_H

#include <stdbool.h>
#include <stddef.h>

/* FastSync-native daemon configuration (a FastSync analog of rsyncd.conf).
 *
 * This is the config the fastsync-server --daemon listener consumes.  It is
 * line-based with an implicit global section followed by zero or more
 * [module] sections.  The full grammar is documented in RSYNC_COMPAT.md
 * ("Daemon Mode") and summarized below; the parser lives entirely in
 * daemon_conf.c so it can be unit tested without any socket code.
 *
 * The parser is STRICT: an unknown key, a malformed line, a value that does
 * not parse, a module without a `path`, or a line longer than
 * DAEMON_CONF_MAX_LINE all fail the whole load with a clear, line-numbered
 * error instead of being silently ignored.  This keeps a typo from silently
 * changing what a module serves.
 */

/* A daemon module's configured root is used exactly like the standalone
 * server's --destination-root: the daemon confines every connection that
 * selects this module to this path (file_open_secure_parent /
 * has_path_traversal / path_is_within all keep the existing confinement, just
 * per-module).  There is never any client-chosen root: a module path always
 * stays confined.  A daemon also REFUSES a client --copy-as outright, because
 * there is no per-module opt-in for client-chosen ownership (unlike the
 * standalone/SSH server, which honors it for its single operator-authorized
 * root); the operator-level --no-super veto additionally forces super-user
 * activities off for every daemon connection.  See server_module_gate in
 * server.c and RSYNC_COMPAT.md.
 *
 * `auth_users` is honored by Wave B daemon authentication: a module that
 * declares auth users accepts a connection only when the presented username is
 * on this list AND verifies against the daemon's credential store
 * (--password-file / --early-input).  An auth-required module with no usable
 * store refuses (fail closed) rather than falling open; see server.c.  Auth is
 * never bypassed by ignoring the list. */
typedef struct DaemonModule {
  char* name;        /* module name, as the client requests it */
  char* path;        /* module root (daemon-side authorized root) */
  bool read_only;    /* `read only = yes/no`; default no */
  char** auth_users; /* `auth users = a,b`; Wave B credential list */
  int auth_user_count;
} DaemonModule;

/* Global (pre-module) scalar keys.  `motd file` is parsed and stored but has
 * no wire effect yet (MOTD display is Wave C). */
typedef struct DaemonConfGlobals {
  int port;        /* `port`, default DAEMON_CONF_DEFAULT_PORT (873) */
  char* motd_file; /* `motd file`, may be NULL */
  char* address;   /* `address` (optional bind address), may be NULL */
} DaemonConfGlobals;

typedef struct DaemonConf {
  DaemonConfGlobals global;
  DaemonModule* modules;
  int module_count;
} DaemonConf;

#define DAEMON_CONF_DEFAULT_PORT 873
/* Longest accepted config line (excluding the trailing newline).  Longer lines
 * are rejected rather than buffered unboundedly. */
#define DAEMON_CONF_MAX_LINE 4096
/* Upper bound on a module name.  Kept far below MAX_STRING_SIZE so a wire
 * module name can never exhaust anything by being long. */
#define DAEMON_MAX_MODULE_NAME 200

/* Allocate an empty daemon config with defaulted globals (port 873, no
 * modules, no motd/address).  Never fails for an allocation failure; callers
 * must still NULL-check. */
DaemonConf* daemon_conf_create(void);

/* Parse `path` into a freshly allocated DaemonConf.  Returns NULL on any error
 * and fills `err` (err_size bytes) with a clear, line-numbered message.  The
 * returned object is heap-owned; free it with daemon_conf_free. */
DaemonConf* daemon_conf_load(const char* path, char* err, size_t err_size);

void daemon_conf_free(DaemonConf* conf);

/* Case-sensitive exact module lookup by name.  Returns the module or NULL.
 * Module names are matched exactly (rsync semantics). */
const DaemonModule* daemon_conf_find_module(const DaemonConf* conf, const char* name);

/* Module-name syntax check: non-empty, at most DAEMON_MAX_MODULE_NAME chars,
 * and only [A-Za-z0-9._-].  Used by the config parser, the client's
 * host::module/path destination parser, and (implicitly) by the daemon lookup
 * (a name that fails this can never match a parsed module). */
bool daemon_module_name_valid(const char* name);

/* Parse one --dparam=KEY=VALUE (or "--dparam KEY=VALUE") override string and
 * apply it to the global scalars only.  Keys are case-insensitive and limited
 * to the global scalar keys defined by the grammar (port, motd file, address).
 * Returns 0 on success, -1 on error (err filled). */
int daemon_conf_apply_dparam(DaemonConf* conf, const char* assignment, char* err, size_t err_size);

#endif
