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
 * stays confined.  A daemon REFUSES every client-chosen ownership / super-user
 * request by default -- --numeric-ids, --chown, --usermap/--groupmap,
 * --fake-super, --copy-as and an explicit --super -- because there is no
 * per-module opt-in unless the operator adds one.  An operator opts a single
 * module in with `client owner = yes` (DaemonModule.client_owner), which allows
 * that client to choose ownership within that module's root (the standalone/SSH
 * server honors such requests for its single operator-authorized root).  The
 * operator-level --no-super veto additionally forces super-user activities off
 * for every daemon connection, even an opted-in module.  See server_module_gate
 * in server.c and RSYNC_COMPAT.md.
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
  bool client_owner; /* `client owner = yes/no`; default no.  Per-module opt-in
                        that lets this module's clients choose ownership
                        (--numeric-ids/--chown/--usermap/--groupmap/--fake-super/
                        --copy-as) and request explicit --super super-user
                        activities.  Without it the daemon refuses all of them. */
  char** auth_users; /* `auth users = a,b`; Wave B credential list */
  int auth_user_count;
  /* `max connections = N` (optional per-module cap).  0 means "not set"
   * (inherit the global cap).  Parsed, stored, and validated, but NOT enforced
   * per-module: connections are counted in the accept-loop parent before the
   * client's module is known, so only the global cap is enforced (see
   * transport_tcp.c and the Daemon Mode notes in RSYNC_COMPAT.md). */
  int max_connections;
  char** hosts_allow; /* `hosts allow = a,b`; host access allow patterns */
  int hosts_allow_count;
  char** hosts_deny; /* `hosts deny = a,b`; host access deny patterns */
  int hosts_deny_count;
} DaemonModule;

/* Global (pre-module) scalar keys.  `motd file` is parsed and stored but has
 * no wire effect yet (MOTD display is Wave C). */
typedef struct DaemonConfGlobals {
  int port;                  /* `port`, default DAEMON_CONF_DEFAULT_PORT (873) */
  char* motd_file;           /* `motd file`, may be NULL */
  char* address;             /* `address` (optional bind address), may be NULL */
  int max_connections;       /* `max connections`, default
                                DAEMON_CONF_DEFAULT_MAX_CONNECTIONS (100) */
  int auth_failure_delay_ms; /* `auth failure delay`, milliseconds; default
                                DAEMON_CONF_DEFAULT_AUTH_FAILURE_DELAY_MS */
  char** hosts_allow;        /* `hosts allow`; global host access allow patterns */
  int hosts_allow_count;
  char** hosts_deny; /* `hosts deny`; global host access deny patterns */
  int hosts_deny_count;
} DaemonConfGlobals;

typedef struct DaemonConf {
  DaemonConfGlobals global;
  DaemonModule* modules;
  int module_count;
} DaemonConf;

#define DAEMON_CONF_DEFAULT_PORT 873
/* Default global connection cap when `max connections` is absent.  Matches the
 * historical hardcoded listener value. */
#define DAEMON_CONF_DEFAULT_MAX_CONNECTIONS 100
/* Default `auth failure delay` in milliseconds (0 disables the throttle). */
#define DAEMON_CONF_DEFAULT_AUTH_FAILURE_DELAY_MS 500
/* Largest accepted `auth failure delay`, so a typo cannot pin a connection
 * child in nanosleep for an absurd time. */
/* Bounded well below the socket I/O timeout so a failed-auth child cannot hold
 * a connection slot for long enough to amplify connection-cap exhaustion. */
#define DAEMON_CONF_MAX_AUTH_FAILURE_DELAY_MS 5000
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
 * apply it to the global keys only.  Keys are case-insensitive and limited to
 * the global keys defined by the grammar (port, motd file, address,
 * max connections, auth failure delay, hosts allow, hosts deny).  Returns 0 on
 * success, -1 on error (err filled). */
int daemon_conf_apply_dparam(DaemonConf* conf, const char* assignment, char* err, size_t err_size);

/* Host access-control matching (pure; no I/O).  `daemon_host_pattern_match`
 * matches one configured pattern against a numeric peer IP string.  Supported
 * patterns: `*` (match anything), an IPv4/IPv6 literal, an IPv4/IPv6 CIDR
 * (`10.0.0.0/8`, `2001:db8::/32`), or a glob (`*.example.com`) evaluated with
 * the same matcher as file globs; a glob only matches a peer string of the
 * same shape, so a numeric peer never matches a hostname glob. */
bool daemon_host_pattern_match(const char* pattern, const char* peer_ip);

/* rsync-like combined decision over a deny list and an allow list: a matching
 * deny rejects (deny takes precedence); otherwise, when any allow entries
 * exist, a peer that matches none is rejected; with no allow entries every
 * peer not denied is accepted.  An empty/unset pair returns true. */
bool daemon_hosts_allowed(const char* peer_ip, char* const* allow, int allow_count,
                          char* const* deny, int deny_count);

/* True when at least one allow or deny pattern is configured (i.e. an
 * unprovable peer must fail closed rather than being treated as unrestricted). */
bool daemon_hosts_restricted(char* const* allow, int allow_count, char* const* deny,
                             int deny_count);

#endif
