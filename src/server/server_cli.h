#ifndef SERVER_CLI_H
#define SERVER_CLI_H

#include <stdbool.h>
#include <stddef.h>

/* Parsed fastsync-server command line.  All string members are borrowed
 * pointers into the original argv (valid for the life of the argv array the
 * caller passed to server_cli_parse); dparams points at the raw --dparam
 * argument strings.  No member owns heap memory. */
typedef struct ServerCliOptions {
  bool stdio_mode;              /* --stdio */
  bool daemon_mode;             /* --daemon */
  bool no_detach;               /* --no-detach */
  bool verbose;                 /* -v / --verbose */
  bool show_help;               /* --help */
  bool use_tls;                 /* --tls */
  const char* tls_cert;         /* --cert */
  const char* tls_key;          /* --key */
  const char* tls_ca;           /* --ca */
  const char* client_cn;        /* --client-cn */
  bool destination_root_set;    /* an explicit --destination-root was given */
  const char* destination_root; /* --destination-root value ("." if unset) */
  bool port_set;                /* an explicit -p was given */
  int port;                     /* -p value (default 8080 when unset) */
  const char* config_path;      /* --config value, or NULL */
  const char* password_file;    /* --password-file value, or NULL (daemon) */
  const char* early_input_file; /* --early-input value, or NULL (daemon) */
  const char** dparams;         /* raw --dparam override strings */
  int dparam_count;
  const char* bind_address;   /* --address */
  int bind_family;            /* AF_UNSPEC / AF_INET / AF_INET6 */
  bool allow_delete;          /* --allow-delete */
  bool trust_sender;          /* --trust-sender */
  bool allow_unauthenticated; /* --allow-unauthenticated */
  /* --no-super: operator veto forcing SUPER_MODE_OFF for every connection, so
   * the receiver never attempts super-user activities (ownership application,
   * device-node creation) even when running as root.  Applies to --stdio and
   * --daemon alike; also makes the server refuse any client --copy-as. */
  bool no_super; /* --no-super */
  /* --iconv=CONVERT_SPEC: the server's own LOCAL charset declaration.  The
   * client's full spec rides the wire config frame anyway; when the server is
   * started with its own --iconv, its LOCAL half overrides the local charset
   * the client assumed so the server converts received names to ITS charset.
   * Borrowed pointer into argv (never owns heap). */
  const char* iconv_spec; /* --iconv value, or NULL */
} ServerCliOptions;

/* Parse argc/argv into *opts.  Zero-initialize *opts before calling (or use
 * server_cli_options_default).  Returns:
 *   1  -- --help was requested (opts->show_help set; caller prints usage).
 *   0  -- parsed successfully.
 *  -1  -- invalid arguments (err is filled with the reason).
 */
void server_cli_options_default(ServerCliOptions* opts);
int server_cli_parse(int argc, char* argv[], ServerCliOptions* opts, char* err, size_t err_size);
/* Release the only heap the parsed options own (the dparams pointer array; the
 * strings it points at are borrowed from argv and are not freed).  Safe to
 * call on a zero-initialized/defaulted struct. */
void server_cli_options_free(ServerCliOptions* opts);
#endif
