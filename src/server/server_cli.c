#include "server_cli.h"
#include "charset.h"
#include "credentials.h"
#include "utils.h"
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static void set_error(char* err, size_t err_size, const char* fmt, ...) {
  if (!err || err_size == 0)
    return;
  va_list args;
  va_start(args, fmt);
  vsnprintf(err, err_size, fmt, args);
  va_end(args);
}

void server_cli_options_default(ServerCliOptions* opts) {
  if (!opts)
    return;
  memset(opts, 0, sizeof(*opts));
  opts->destination_root = ".";
  opts->port = 8080;
  opts->bind_family = AF_UNSPEC;
}

static bool arg_is(const char* arg, const char* name) {
  return strcmp(arg, name) == 0;
}

/* Match "--opt" against "--opt=value" / separate-value forms; on the "=" form
 * *value receives the inline value.  Returns true when the argument is the
 * named option in either form. */
static bool arg_has_value(const char* arg, const char* name, const char** value) {
  if (strcmp(arg, name) == 0)
    return true; /* separate form; caller takes the next argv slot */
  size_t name_len = strlen(name);
  if (strncmp(arg, name, name_len) == 0 && arg[name_len] == '=') {
    *value = arg + name_len + 1;
    return true;
  }
  return false;
}

static int parse_port_arg(const char* value, int* port, char* err, size_t err_size) {
  char* end;
  long p = strtol(value, &end, 10);
  if (*end != '\0' || p <= 0 || p > 65535) {
    char* escaped = output_escape(value, false);
    set_error(err, err_size, "invalid port '%s' (must be 1-65535)",
              escaped ? escaped : "<allocation failed>");
    free(escaped);
    return -1;
  }
  *port = (int)p;
  return 0;
}

int server_cli_parse(int argc, char* argv[], ServerCliOptions* opts, char* err, size_t err_size) {
  if (err && err_size)
    err[0] = '\0';
  server_cli_options_default(opts);

  for (int i = 1; i < argc; i++) {
    const char* inline_value = NULL;
    if (arg_is(argv[i], "--help")) {
      opts->show_help = true;
      return 1;
    } else if (arg_is(argv[i], "--stdio")) {
      opts->stdio_mode = true;
    } else if (arg_is(argv[i], "--daemon")) {
      opts->daemon_mode = true;
    } else if (arg_is(argv[i], "--no-detach")) {
      opts->no_detach = true;
    } else if (arg_is(argv[i], "-v") || arg_is(argv[i], "--verbose")) {
      opts->verbose = true;
    } else if (arg_is(argv[i], "--tls")) {
      opts->use_tls = true;
    } else if (arg_is(argv[i], "--cert")) {
      if (i + 1 >= argc) {
        set_error(err, err_size, "missing argument for --cert");
        return -1;
      }
      opts->tls_cert = argv[++i];
    } else if (arg_is(argv[i], "--key")) {
      if (i + 1 >= argc) {
        set_error(err, err_size, "missing argument for --key");
        return -1;
      }
      opts->tls_key = argv[++i];
    } else if (arg_is(argv[i], "--ca")) {
      if (i + 1 >= argc) {
        set_error(err, err_size, "missing argument for --ca");
        return -1;
      }
      opts->tls_ca = argv[++i];
    } else if (arg_is(argv[i], "--client-cn")) {
      if (i + 1 >= argc) {
        set_error(err, err_size, "missing argument for --client-cn");
        return -1;
      }
      opts->client_cn = argv[++i];
    } else if (arg_is(argv[i], "--destination-root")) {
      if (i + 1 >= argc) {
        set_error(err, err_size, "missing argument for --destination-root");
        return -1;
      }
      opts->destination_root = argv[++i];
      opts->destination_root_set = true;
    } else if (arg_has_value(argv[i], "--password-file", &inline_value)) {
      if (!inline_value) {
        if (i + 1 >= argc) {
          set_error(err, err_size, "missing argument for --password-file");
          return -1;
        }
        inline_value = argv[++i];
      }
      opts->password_file = inline_value;
    } else if (arg_has_value(argv[i], "--early-input", &inline_value)) {
      if (!inline_value) {
        if (i + 1 >= argc) {
          set_error(err, err_size, "missing argument for --early-input");
          return -1;
        }
        inline_value = argv[++i];
      }
      opts->early_input_file = inline_value;
    } else if (arg_has_value(argv[i], "--hash-credentials", &inline_value)) {
      if (!inline_value) {
        if (i + 1 >= argc) {
          set_error(err, err_size, "missing argument for --hash-credentials");
          return -1;
        }
        inline_value = argv[++i];
      }
      opts->hash_credentials_file = inline_value;
    } else if (arg_has_value(argv[i], "--iterations", &inline_value)) {
      if (!inline_value) {
        if (i + 1 >= argc) {
          set_error(err, err_size, "missing argument for --iterations");
          return -1;
        }
        inline_value = argv[++i];
      }
      char* end = NULL;
      long n = strtol(inline_value, &end, 10);
      if (!end || *end != '\0' || n < (long)CREDENTIAL_MIN_ITERS ||
          n > (long)CREDENTIAL_MAX_ITERS) {
        set_error(err, err_size, "--iterations must be in [%u,%u], got '%s'", CREDENTIAL_MIN_ITERS,
                  CREDENTIAL_MAX_ITERS, inline_value);
        return -1;
      }
      opts->hash_iterations = (uint32_t)n;
      opts->hash_iterations_set = true;
    } else if (arg_is(argv[i], "--address")) {
      if (i + 1 >= argc) {
        set_error(err, err_size, "missing argument for --address");
        return -1;
      }
      opts->bind_address = argv[++i];
    } else if (arg_is(argv[i], "-4") || arg_is(argv[i], "--ipv4")) {
      if (opts->bind_family == AF_INET6) {
        set_error(err, err_size, "--ipv4 and --ipv6 are mutually exclusive");
        return -1;
      }
      opts->bind_family = AF_INET;
    } else if (arg_is(argv[i], "-6") || arg_is(argv[i], "--ipv6")) {
      if (opts->bind_family == AF_INET) {
        set_error(err, err_size, "--ipv4 and --ipv6 are mutually exclusive");
        return -1;
      }
      opts->bind_family = AF_INET6;
    } else if (arg_is(argv[i], "--allow-delete")) {
      opts->allow_delete = true;
    } else if (arg_is(argv[i], "--trust-sender")) {
      opts->trust_sender = true;
    } else if (arg_is(argv[i], "--no-super")) {
      opts->no_super = true;
    } else if (arg_is(argv[i], "--allow-super")) {
      opts->allow_super = true;
    } else if (arg_is(argv[i], "--allow-unauthenticated")) {
      opts->allow_unauthenticated = true;
    } else if (arg_has_value(argv[i], "--iconv", &inline_value)) {
      if (!inline_value) {
        if (i + 1 >= argc) {
          set_error(err, err_size, "missing argument for --iconv");
          return -1;
        }
        inline_value = argv[++i];
      }
      opts->iconv_spec = inline_value;
    } else if (arg_is(argv[i], "-p")) {
      if (i + 1 >= argc) {
        set_error(err, err_size, "missing argument for -p");
        return -1;
      }
      opts->port_set = true;
      if (parse_port_arg(argv[++i], &opts->port, err, err_size) != 0)
        return -1;
    } else {
      if (arg_has_value(argv[i], "--config", &inline_value)) {
        if (!inline_value) {
          if (i + 1 >= argc) {
            set_error(err, err_size, "missing argument for --config");
            return -1;
          }
          inline_value = argv[++i];
        }
        opts->config_path = inline_value;
      } else if (arg_has_value(argv[i], "--dparam", &inline_value)) {
        if (!inline_value) {
          if (i + 1 >= argc) {
            set_error(err, err_size, "missing argument for --dparam");
            return -1;
          }
          inline_value = argv[++i];
        }
        const char** grown =
            realloc((char**)opts->dparams, (size_t)(opts->dparam_count + 1) * sizeof(const char*));
        if (!grown) {
          set_error(err, err_size, "out of memory parsing --dparam");
          return -1;
        }
        opts->dparams = grown;
        opts->dparams[opts->dparam_count++] = inline_value;
      } else if (argv[i][0] == '-') {
        char* escaped = output_escape(argv[i], false);
        set_error(err, err_size, "unknown option: %s", escaped ? escaped : "<allocation failed>");
        free(escaped);
        return -1;
      } else {
        set_error(err, err_size, "unexpected argument '%s'", argv[i]);
        return -1;
      }
    }
  }

  /* Cross-mode validation. */
  if (opts->stdio_mode && opts->daemon_mode) {
    set_error(err, err_size, "--stdio and --daemon are mutually exclusive");
    return -1;
  }
  if (opts->daemon_mode && opts->destination_root_set) {
    set_error(err, err_size,
              "--destination-root cannot be combined with --daemon (module paths "
              "replace it)");
    return -1;
  }
  if (!opts->daemon_mode &&
      (opts->config_path != NULL || opts->dparam_count > 0 || opts->no_detach ||
       opts->password_file != NULL || opts->early_input_file != NULL)) {
    set_error(err, err_size,
              "--config, --dparam, --no-detach, --password-file, and --early-input require "
              "--daemon");
    return -1;
  }
  if (opts->hash_credentials_file != NULL && (opts->daemon_mode || opts->stdio_mode)) {
    set_error(err, err_size, "--hash-credentials cannot be combined with --daemon or --stdio");
    return -1;
  }
  if (opts->allow_super && opts->no_super) {
    set_error(err, err_size, "--allow-super and --no-super are mutually exclusive");
    return -1;
  }
  if (opts->allow_super && opts->daemon_mode) {
    set_error(err, err_size,
              "--allow-super is for a locally-launched standalone TCP server; daemon modules opt "
              "in per module with 'client owner = yes'");
    return -1;
  }
  /* --stdio is the SSH transport: the remote server argv is composed by the
   * CLIENT (directly and via --remote-option), so a client could otherwise pass
   * --allow-super to a root --stdio receiver and defeat the C3 secure default.
   * Never honor it there; the super mode stays forced OFF.  An operator who
   * must keep the historical permissive behavior over SSH has to launch the
   * receiver through a forced command, not via client-composed argv. */
  if (opts->allow_super && opts->stdio_mode) {
    set_error(err, err_size,
              "--allow-super is not accepted with --stdio (the remote argv is client-composed; "
              "use a forced command if the default must hold)");
    return -1;
  }
  if (opts->hash_iterations_set && opts->hash_credentials_file == NULL) {
    set_error(err, err_size, "--iterations requires --hash-credentials");
    return -1;
  }
  /* --iconv: reject a malformed CONVERT_SPEC or an unsupported charset name at
     startup (a probe iconv_open is attempted). */
  if (opts->iconv_spec != NULL && !charset_spec_valid(opts->iconv_spec)) {
    set_error(err, err_size, "--iconv requires LOCAL[,REMOTE] charset names supported by iconv");
    return -1;
  }
  return 0;
}

void server_cli_options_free(ServerCliOptions* opts) {
  if (!opts)
    return;
  free((char**)opts->dparams);
  opts->dparams = NULL;
  opts->dparam_count = 0;
}
