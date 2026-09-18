/*
 * Fuzz the delete-manifest parser: receive_manifest_entries(int fd).
 *
 * The parser reads three length-delimited sections (keeps, protected prefixes,
 * missing-args paths) from the connection.  Feeding raw bytes alone exercises
 * the "reject the first malformed count/string" fast paths, but because each
 * section is self-delimiting a single bad value hides every later section.
 *
 * To reach the protected-prefix and missing-args parsers (the paths that drive
 * actual destination deletion) we build one canonical, fully-valid manifest
 * with hand-written wire framing and then feed the receiver several shapes:
 *
 *   1. raw    : the raw fuzz bytes as the whole manifest.
 *   2. keeps  : the valid keep count only + the fuzz bytes, so the fuzzer
 *               drives the keep count and entries directly.
 *   3. prot   : the valid keeps section + the fuzz bytes, so the fuzzer drives
 *               the protected count and prefixes.
 *   4. missing: the valid keeps+protected sections + the fuzz bytes, so the
 *               fuzzer drives the trailing missing-args section, including the
 *               aggregate MAX_MANIFEST_BYTES budget.
 *
 * The wire encoding matches receive_int (native int) and receive_wire_str
 * (native size_t length prefix + body); no charset conversion is configured in
 * the fuzz process, so receive_wire_str is receive_str.
 */
#include "file_receive.h"
#include "protocol.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned char g_manifest[512];
static size_t g_len_after_count;     /* offset of the first keep entry */
static size_t g_len_after_keeps;     /* offset of the protected count */
static size_t g_len_after_protected; /* offset of the missing count */
static int g_manifest_ready;

static void append_int32(unsigned char* buf, size_t* off, int32_t value) {
  memcpy(buf + *off, &value, sizeof(value));
  *off += sizeof(value);
}

static void append_wire_str(unsigned char* buf, size_t* off, const char* s) {
  size_t n = strlen(s);
  memcpy(buf + *off, &n, sizeof(n));
  *off += sizeof(n);
  memcpy(buf + *off, s, n);
  *off += n;
}

static void build_canonical_manifest(void) {
  g_manifest_ready = 1;
  size_t off = 0;
  append_int32(g_manifest, &off, 2);
  g_len_after_count = off;
  append_wire_str(g_manifest, &off, "keep/a");
  append_wire_str(g_manifest, &off, "keep/b");
  g_len_after_keeps = off;
  append_int32(g_manifest, &off, 1);
  append_wire_str(g_manifest, &off, "excluded/prefix");
  g_len_after_protected = off;
  append_int32(g_manifest, &off, 1);
  append_wire_str(g_manifest, &off, "missing/path");
}

/* Best-effort non-blocking write: an oversized fuzz input is truncated rather
 * than stalling the harness. */
static void write_best_effort(int fd, const void* data, size_t size) {
  const unsigned char* p = data;
  size_t off = 0;
  while (off < size) {
    ssize_t n = write(fd, p + off, size - off);
    if (n > 0) {
      off += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR)
      continue;
    break;
  }
}

/* Build prefix ++ data as a stream and drive receive_manifest_entries over it.
 * The write half is shut down first so the parser always sees EOF instead of
 * blocking on a missing frame tail. */
static void receive_stream(const unsigned char* prefix, size_t prefix_len, const uint8_t* data,
                           size_t size) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    return;

  int flags = fcntl(sv[0], F_GETFL, 0);
  if (flags != -1)
    (void)fcntl(sv[0], F_SETFL, flags | O_NONBLOCK);

  if (prefix_len > 0)
    write_best_effort(sv[0], prefix, prefix_len);
  if (size > 0)
    write_best_effort(sv[0], data, size);
  shutdown(sv[0], SHUT_WR);

  DeleteManifest* manifest = receive_manifest_entries(sv[1]);
  delete_manifest_free(manifest);

  close(sv[0]);
  close(sv[1]);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!g_manifest_ready)
    build_canonical_manifest();

  /* Raw bytes as the whole manifest. */
  receive_stream(NULL, 0, data, size);

  /* Keep the valid framing so the fuzzer reaches each later section. */
  receive_stream(g_manifest, g_len_after_protected, data, size);
  receive_stream(g_manifest, g_len_after_keeps, data, size);
  receive_stream(g_manifest, g_len_after_count, data, size);

  return 0;
}
