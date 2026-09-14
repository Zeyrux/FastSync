/*
 * Fuzz the xattr wire block parser: xattr_receive(int fd, int* ok).
 *
 * The block is a count followed by that many (name_len, name, value_len, value)
 * records.  The receiver must reject an invalid count, an out-of-range or
 * negative name/value length, an embedded NUL or non-whitelisted namespace in
 * the name, an oversized value, and an aggregate payload beyond
 * XATTR_TOTAL_MAX -- all without over-allocating or leaking.
 *
 * Raw bytes mostly stop at the first invalid count/length, so we also build a
 * canonical, fully-valid two-entry block by hand and feed the receiver valid
 * prefixes of it followed by the fuzz bytes.  That drives the deep value-
 * parsing and per-entry namespace/budget checks with attacker-controlled input.
 */
#include "protocol.h"
#include "xattr.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned char g_block[512];
static size_t g_off_after_count;  /* start of entry 0 */
static size_t g_off_after_entry0; /* start of entry 1 */
static size_t g_off_value0;       /* start of the first value length */
static int g_block_ready;

static void append_int32(unsigned char* buf, size_t* off, int32_t value) {
  memcpy(buf + *off, &value, sizeof(value));
  *off += sizeof(value);
}

static void append_bytes(unsigned char* buf, size_t* off, const void* p, size_t n) {
  if (n > 0)
    memcpy(buf + *off, p, n);
  *off += n;
}

static void build_canonical_block(void) {
  g_block_ready = 1;
  size_t off = 0;
  append_int32(g_block, &off, 2);
  g_off_after_count = off;

  int32_t name0_len = (int32_t)strlen("user.foo");
  append_int32(g_block, &off, name0_len);
  append_bytes(g_block, &off, "user.foo", (size_t)name0_len);
  g_off_value0 = off;
  append_int32(g_block, &off, 3);
  append_bytes(g_block, &off, "bar", 3);

  g_off_after_entry0 = off;
  int32_t name1_len = (int32_t)strlen("user.empty");
  append_int32(g_block, &off, name1_len);
  append_bytes(g_block, &off, "user.empty", (size_t)name1_len);
  append_int32(g_block, &off, 0);
}

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

static void receive_stream(const unsigned char* prefix, size_t prefix_len, const uint8_t* data,
                           size_t size, bool preserve_acls) {
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

  int ok = 0;
  FileXattrList* list = xattr_receive(sv[1], &ok, preserve_acls);
  xattr_list_free(list);

  close(sv[0]);
  close(sv[1]);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!g_block_ready)
    build_canonical_block();

  /* Raw bytes as the whole block.  Exercise both the -X-only (no ACLs) and the
   * -A (ACL names accepted) receiver gates. */
  for (int acls = 0; acls < 2; acls++) {
    bool preserve_acls = acls != 0;
    receive_stream(NULL, 0, data, size, preserve_acls);

    /* Valid framing so the fuzzer mutates the entry list, the first value and
     * the second entry respectively instead of stopping at the count. */
    receive_stream(g_block, g_off_after_entry0, data, size, preserve_acls);
    receive_stream(g_block, g_off_value0, data, size, preserve_acls);
    receive_stream(g_block, g_off_after_count, data, size, preserve_acls);
  }

  return 0;
}
