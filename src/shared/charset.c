#include "charset.h"
#include "log.h"
#include "protocol.h"
#include "utils.h"
#include <errno.h>
#include <iconv.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  iconv_t cd;
} CharsetConversion;

static CharsetConversion* g_wire_conv;

/* Grow *buf to double capacity, freeing it on failure.  realloc preserves the
 * already-written prefix, so the caller only tracks its write offset. */
static bool grow_charset_buffer(char** buf, size_t* cap) {
  size_t new_cap = *cap * 2;
  if (new_cap <= *cap) {
    free(*buf);
    *buf = NULL;
    return false;
  }
  char* grown = realloc(*buf, new_cap);
  if (!grown) {
    free(*buf);
    *buf = NULL;
    return false;
  }
  *buf = grown;
  *cap = new_cap;
  return true;
}

int charset_spec_parse(const char* spec, char** local_out, char** remote_out) {
  if (local_out)
    *local_out = NULL;
  if (remote_out)
    *remote_out = NULL;
  if (!spec || spec[0] == '\0')
    return -1;
  char* dup = str_dup(spec);
  if (!dup)
    return -1;
  char* comma = strchr(dup, ',');
  if (comma) {
    if (comma == dup || comma[1] == '\0') {
      free(dup);
      return -1;
    }
    *comma = '\0';
    *local_out = str_dup(dup);
    *remote_out = str_dup(comma + 1);
    free(dup);
  } else {
    *local_out = str_dup(dup);
    *remote_out = str_dup(dup);
    free(dup);
  }
  if (!*local_out || !*remote_out) {
    free(*local_out);
    free(*remote_out);
    *local_out = NULL;
    *remote_out = NULL;
    return -1;
  }
  return 0;
}

void* charset_conversion_open(const char* from_charset, const char* to_charset) {
  if (!from_charset || !to_charset)
    return NULL;
  iconv_t cd = iconv_open(to_charset, from_charset);
  if (cd == (iconv_t)-1)
    return NULL;
  CharsetConversion* conv = malloc(sizeof(CharsetConversion));
  if (!conv) {
    iconv_close(cd);
    return NULL;
  }
  conv->cd = cd;
  return conv;
}

void charset_conversion_close(void* conversion) {
  if (!conversion)
    return;
  CharsetConversion* conv = (CharsetConversion*)conversion;
  iconv_close(conv->cd);
  free(conv);
}

bool charset_pair_valid(const char* local, const char* remote) {
  if (!local || !remote)
    return false;
  void* conv = charset_conversion_open(local, remote);
  if (!conv)
    return false;
  charset_conversion_close(conv);
  return true;
}

bool charset_spec_valid(const char* spec) {
  if (!spec)
    return true;
  char* local;
  char* remote;
  if (charset_spec_parse(spec, &local, &remote) != 0)
    return false;
  bool ok = charset_pair_valid(local, remote);
  free(local);
  free(remote);
  return ok;
}

char* charset_convert(const void* conversion, const char* in, int* err_out) {
  if (!conversion || !in)
    return NULL;
  const CharsetConversion* conv = (const CharsetConversion*)conversion;
  size_t in_len = strlen(in);
  size_t cap = in_len + 16;
  char* out = malloc(cap);
  if (!out)
    return NULL;
  size_t in_left = in_len;
  char* in_ptr = (char*)in;
  size_t out_used = 0;

  while (in_left > 0) {
    char* out_ptr = out + out_used;
    size_t out_left = cap - out_used;
    if (iconv(conv->cd, &in_ptr, &in_left, &out_ptr, &out_left) == (size_t)-1) {
      if (errno != E2BIG) {
        if (err_out)
          *err_out = errno;
        free(out);
        return NULL;
      }
      if (!grow_charset_buffer(&out, &cap))
        return NULL;
      continue;
    }
    out_used = (size_t)(out_ptr - out);
  }

  /* Flush any pending shift state (a no-op for the stateless single-byte and
     UTF charsets this feature targets, but keeps the descriptor clean). */
  for (;;) {
    char* out_ptr = out + out_used;
    size_t out_left = cap - out_used;
    if (iconv(conv->cd, NULL, NULL, &out_ptr, &out_left) == (size_t)-1) {
      if (errno != E2BIG) {
        if (err_out)
          *err_out = errno;
        free(out);
        return NULL;
      }
      if (!grow_charset_buffer(&out, &cap))
        return NULL;
      continue;
    }
    out_used = (size_t)(out_ptr - out);
    break;
  }

  out[out_used] = '\0';
  return out;
}

bool charset_wire_init_sender(const char* spec) {
  charset_wire_free();
  if (!spec)
    return true;
  char* local;
  char* remote;
  if (charset_spec_parse(spec, &local, &remote) != 0)
    return false;
  void* conv = charset_conversion_open(local, remote);
  free(local);
  free(remote);
  if (!conv)
    return false;
  g_wire_conv = (CharsetConversion*)conv;
  return true;
}

bool charset_wire_init_receiver(const char* spec, const char* server_spec) {
  charset_wire_free();
  if (!spec)
    return true;
  char* local;
  char* remote;
  if (charset_spec_parse(spec, &local, &remote) != 0)
    return false;
  /* The wire charset is the client spec's REMOTE half; the local charset is
   * the client spec's LOCAL half unless the server was itself started with
   * --iconv naming a different local charset (the server halves above never
   * travel, so the server's own flag is the only way its local charset can
   * differ from what the client assumed). */
  const char* wire = remote;
  const char* target_local = local;
  char* server_local = NULL;
  char* server_remote = NULL;
  if (server_spec) {
    if (charset_spec_parse(server_spec, &server_local, &server_remote) != 0) {
      free(local);
      free(remote);
      return false;
    }
    target_local = server_local;
  }
  void* conv = charset_conversion_open(wire, target_local);
  free(server_local);
  free(server_remote);
  free(local);
  free(remote);
  if (!conv)
    return false;
  g_wire_conv = (CharsetConversion*)conv;
  return true;
}

void charset_wire_free(void) {
  if (g_wire_conv) {
    charset_conversion_close(g_wire_conv);
    g_wire_conv = NULL;
  }
}

bool charset_wire_active(void) {
  return g_wire_conv != NULL;
}

char* charset_wire_apply(const char* path) {
  if (!g_wire_conv)
    return str_dup(path);
  return charset_convert(g_wire_conv, path, NULL);
}

static void charset_convert_failure_log(const char* path) {
  char* escaped = output_escape(path, false);
  log_message(LOG_LEVEL_ERROR, "--iconv: cannot convert file name '%s' to the target charset",
              escaped ? escaped : "<unprintable>");
  free(escaped);
}

bool send_wire_str(int file_descriptor, const char* local_path) {
  if (!g_wire_conv)
    return send_str(file_descriptor, local_path);
  char* wire = charset_wire_apply(local_path);
  if (!wire) {
    charset_convert_failure_log(local_path);
    return false;
  }
  bool ok = send_str(file_descriptor, wire);
  free(wire);
  return ok;
}

char* receive_wire_str(int file_descriptor) {
  char* raw = receive_str(file_descriptor);
  if (!raw)
    return NULL;
  if (!g_wire_conv)
    return raw;
  char* local = charset_convert(g_wire_conv, raw, NULL);
  if (!local) {
    charset_convert_failure_log(raw);
    free(raw);
    return NULL;
  }
  free(raw);
  return local;
}