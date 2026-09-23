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
 *
 * rsync compatibility: to reduce the divergence from rsync 3.4.1's rsyncd.conf
 * grammar, the parser also ACCEPTS the common rsync GLOBAL and MODULE keys.
 * Keys with a FastSync equivalent are mapped onto it (the native spellings are
 * unchanged; `read only` defaults to yes like rsync, and `write only = yes`
 * opts a module into writability).  Keys with no FastSync equivalent are
 * accepted and documented as inert (they load successfully but have no effect)
 * rather than failing the whole config; the accepted inert set is listed in
 * kRsyncInertGlobalKeys / kRsyncInertModuleKeys in daemon_conf.c and in
 * RSYNC_COMPAT.md.  Every inert key whose intent is access control is loudly
 * warned about at load time (kRsyncUnenforced*SecurityKeys) so an operator
 * migrating a hardened rsyncd.conf is never misled into believing the
 * restriction is enforced.  A key outside both the FastSync-native grammar and
 * the recognized rsync subset is still rejected as unknown. */

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
  char* name;              /* module name, as the client requests it */
  char* path;              /* module root (daemon-side authorized root) */
  bool read_only;          /* `read only = yes/no`; defaults to the global `read only`
                              default (rsync allows it in the global section), which is
                              itself default YES (rsync modules are read-only unless
                              `read only = no` / `write only = yes` opts in) */
  bool read_only_explicit; /* set when this module set its own `read only` or
                              `write only = yes`, so a later global default (from a
                              `--dparam read only=`) does not override it */
  bool client_owner;       /* `client owner = yes/no`; default no.  Per-module opt-in
                              that lets this module's clients choose ownership
                              (--numeric-ids/--chown/--usermap/--groupmap/--fake-super/
                              --copy-as) and request explicit --super super-user
                              activities.  Without it the daemon refuses all of them. */
  char** auth_users;       /* `auth users = a,b`; Wave B credential list */
  int auth_user_count;
  /* `max connections = N` (optional per-module cap).  0 means unlimited.  The
   * per-connection child records the selected module in the shared registry
   * (daemon_limits.c) once the config frame names it, so the cap is enforced
   * across all forked children; the parent reclaims the slot on SIGCHLD. */
  int max_connections;
  char** hosts_allow; /* `hosts allow = a,b`; host access allow patterns */
  int hosts_allow_count;
  char** hosts_deny; /* `hosts deny = a,b`; host access deny patterns */
  int hosts_deny_count;
} DaemonModule;

/* Global (pre-module) scalar keys.  `motd file` is parsed and stored but has
 * no wire effect yet (MOTD display is Wave C). */
typedef struct DaemonConfGlobals {
  int port;                      /* `port`, default DAEMON_CONF_DEFAULT_PORT (873) */
  char* motd_file;               /* `motd file`, may be NULL */
  char* address;                 /* `address` (optional bind address), may be NULL */
  bool read_only_default;        /* global `read only` default for modules defined
                                    after it (rsync allows the module key in the
                                    global section); default YES to match rsync's
                                    read-only modules */
  int max_connections;           /* `max connections`, default
                                    DAEMON_CONF_DEFAULT_MAX_CONNECTIONS (100) */
  int auth_failure_delay_ms;     /* `auth failure delay`, milliseconds; default
                                    DAEMON_CONF_DEFAULT_AUTH_FAILURE_DELAY_MS */
  int max_connections_per_host;  /* `max connections per host`, concurrent cap per
                                    source IP; default
                                    DAEMON_CONF_DEFAULT_MAX_CONNECTIONS_PER_HOST (0 =
                                    unlimited) */
  int auth_lockout_threshold;    /* `auth lockout threshold`, failed attempts from
                                    one source before lockout; default
                                    DAEMON_CONF_DEFAULT_AUTH_LOCKOUT_THRESHOLD (0
                                    disables) */
  int auth_lockout_duration_sec; /* `auth lockout duration`, seconds; default
                                    DAEMON_CONF_DEFAULT_AUTH_LOCKOUT_DURATION_SEC
                                    (0 disables) */
  char** hosts_allow;            /* `hosts allow`; global host access allow patterns */
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
/* Default `max connections per host` (0 = unlimited). */
#define DAEMON_CONF_DEFAULT_MAX_CONNECTIONS_PER_HOST 0
/* Default cross-process auth lockout: 10 failed attempts from one source lock
 * it out for 300 s (0 disables either knob). */
#define DAEMON_CONF_DEFAULT_AUTH_LOCKOUT_THRESHOLD 10
#define DAEMON_CONF_DEFAULT_AUTH_LOCKOUT_DURATION_SEC 300
/* Upper bound on a `max connections per host` or `auth lockout threshold`
 * value, so a typo cannot size the shared registry absurdly. */
#define DAEMON_CONF_MAX_CONCURRENCY_LIMIT 1000000
/* Upper bound on `auth lockout duration` (7 days). */
#define DAEMON_CONF_MAX_AUTH_LOCKOUT_DURATION_SEC 604800
/* Largest accepted `auth failure delay`, so a typo cannot pin a connection
 * child in nanosleep for an absurd time. */
/* Bounded well below the socket I/O timeout so a failed-auth child cannot hold
 * a connection slot for long enough to amplify connection-cap exhaustion. */
#define DAEMON_CONF_MAX_AUTH_FAILURE_DELAY_MS 5000
/* Upper bound on the number of [module] sections, so the shared registry's
 * per-module counter array stays fixed-size.  The parser rejects the next
 * section past this bound. */
#define DAEMON_CONF_MAX_MODULES 256
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
 * apply it to the global keys only.  Keys are case-insensitive and cover the
 * global keys defined by the grammar (port, motd file, address, read only,
 * max connections, max connections per host, auth failure delay,
 * auth lockout threshold, auth lockout duration, hosts allow, hosts deny) plus
 * the recognized inert rsync global keys and the compact rsync spellings
 * (`motdfile`, `pidfile`, `logfile`).  Applying `read only` sets the global
 * default and re-applies it to every module that did not set its own value.
 * Returns 0 on success, -1 on error (err filled). */
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
