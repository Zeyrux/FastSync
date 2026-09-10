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

/* Process-wide wire conversion descriptor (one direction per process: a client
 * only sends, a server only receives).  CONCURRENCY CONTRACT: iconv_t is not
 * guaranteed thread-safe, so every conversion MUST run on a single thread at a
 * time.  This holds today -- on the client the conversions run on the sender
 * thread (in the -m pipeline chunk_serialize/send happen on the sender thread
 * only), on the server on the receive-loop thread; the descriptor is
 * initialized on one thread before any transfer thread spawns and torn down
 * (charset_wire_free) only after all threads have joined.  Do not add a
 * concurrent conversion path (e.g. parallel chunk serialization) without
 * guarding access with a mutex. */
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

/* Throw away any pending shift state so a subsequent conversion starts clean.
 * The flush output is discarded; for the stateless single-byte/UTF charsets
 * this feature targets it is a no-op. */
static void charset_conversion_reset(const CharsetConversion* conv) {
  char scratch[64];
  char* sp = scratch;
  size_t sl = sizeof(scratch);
  (void)iconv(conv->cd, NULL, NULL, &sp, &sl);
}

int charset_spec_parse(const char* spec, char** local_out, char** remote_out) {
  if (!local_out || !remote_out)
    return -1;
  *local_out = NULL;
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

/* Probe a single conversion direction: the from/to charsets both open AND a
 * representative ASCII name converts to a byte string containing no embedded
 * NUL (so a target charset like UTF-16 that emits NUL bytes for ordinary ASCII
 * names is rejected up front -- such an output would be silently truncated by
 * the C-string wire helpers). */
static bool direction_probe_valid(const char* from, const char* to) {
  if (!from || !to)
    return false;
  void* conv = charset_conversion_open(from, to);
  if (!conv)
    return false;
  bool ok = true;
  char input = 'a';
  char* in_ptr = &input;
  size_t in_left = 1;
  char out_buf[64];
  char* out_ptr = out_buf;
  size_t out_left = sizeof(out_buf);
  if (iconv(((CharsetConversion*)conv)->cd, &in_ptr, &in_left, &out_ptr, &out_left) == (size_t)-1)
    ok = false;
  char flush_buf[64];
  char* flush_ptr = flush_buf;
  size_t flush_left = sizeof(flush_buf);
  if (ok &&
      iconv(((CharsetConversion*)conv)->cd, NULL, NULL, &flush_ptr, &flush_left) == (size_t)-1)
    ok = false;
  size_t produced = (size_t)(out_ptr - out_buf);
  if (ok && produced > 0 && memchr(out_buf, '\0', produced) != NULL)
    ok = false;
  charset_conversion_close(conv);
  return ok;
}

bool charset_pair_valid(const char* local, const char* remote) {
  /* Both ends convert in opposite directions with the same two charsets, so a
   * valid spec must open (and be NUL-free) in BOTH directions: the sender
   * opens local->remote, the receiver opens remote->local. */
  return direction_probe_valid(local, remote) && direction_probe_valid(remote, local);
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

bool charset_spec_valid_direction(const char* from_charset, const char* to_charset) {
  return direction_probe_valid(from_charset, to_charset);
}

/* The receiver's real conversion is wire(client REMOTE) -> server-local (the
 * server's own --iconv LOCAL half, or the client's LOCAL half when the server
 * has no --iconv).  A dedicated pre-ack check so an impossible direction is
 * rejected before the connection instead of refusing mid-transfer. */
bool charset_wire_receiver_spec_valid(const char* spec, const char* server_spec) {
  if (!spec)
    return true;
  char* local;
  char* remote;
  if (charset_spec_parse(spec, &local, &remote) != 0)
    return false;
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
  bool ok = charset_spec_valid_direction(wire, target_local);
  free(server_local);
  free(server_remote);
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
        charset_conversion_reset(conv);
        free(out);
        return NULL;
      }
      /* Output exhausted but input remains.  E2BIG does not roll the output
         pointer back: the bytes iconv already emitted before the failure must
         be preserved, so advance out_used before growing. */
      out_used = (size_t)(out_ptr - out);
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
        charset_conversion_reset(conv);
        free(out);
        return NULL;
      }
      out_used = (size_t)(out_ptr - out);
      if (!grow_charset_buffer(&out, &cap))
        return NULL;
      continue;
    }
    out_used = (size_t)(out_ptr - out);
    break;
  }

  /* A successful iconv call may legitimately consume the whole buffer (output
     exactly fills cap), leaving no room for the terminator: guarantee headroom
     before the final write. */
  if (out_used >= cap && !grow_charset_buffer(&out, &cap))
    return NULL;

  /* Defense in depth: a target charset that emits embedded NUL bytes would
     truncate at the first NUL in the C-string wire helpers; fail cleanly
     (validation already rejects such charsets up front). */
  if (memchr(out, '\0', out_used) != NULL) {
    if (err_out)
      *err_out = EILSEQ;
    charset_conversion_reset(conv);
    free(out);
    return NULL;
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