/*
 * Fuzz the binary config-frame receive path: Config* config_receive(int fd).
 *
 * The frame is a length-prefixed stream of strings/ints/bools, so the receiver
 * stops at the first malformed field.  Feeding raw fuzz bytes alone therefore
 * almost never reaches the deep P8 trailing blocks (--super / --copy-as) or the
 * identity-map block, because every preceding wire bool must be exactly 0 or 1.
 *
 * To exercise those paths we first build one canonical, fully-valid frame with
 * the production sender and then feed the receiver four shapes:
 *
 *   1. raw     : the raw fuzz bytes as the whole frame (version gate included).
 *   2. general : the valid version-string prefix + the raw fuzz bytes, so the
 *                fuzzer can walk the early/core/selection blocks from arbitrary
 *                input while staying past the version gate.
 *   3. tail    : the valid frame up to its last P8_TAIL_BYTES (super_mode +
 *                copy-as presence/uid/gid) + the raw fuzz bytes, so the fuzzer
 *                directly mutates super_mode and the copy-as ids and truncates
 *                the tail at any byte.
 *   4. map     : the valid frame up to the --usermap count + the raw fuzz bytes,
 *                so the fuzzer directly drives the map count (huge/extreme) and
 *                the map entries.
 *
 * The canonical frame is captured by running config_send once, writing the
 * frame into a pipe whose read end is drained afterwards; the STATUS_OK ack is
 * pre-loaded into a second pipe so a single thread suffices.
 */
#include "config.h"
#include "credentials.h"
#include "protocol.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* super_mode (4) + copy-as presence (4) + uid (4) + gid (4) = the P8 tail. */
#define P8_TAIL_BYTES 16

/* Distinctive --usermap entry used to locate the map-count field in the
 * canonical frame without duplicating the wire layout here. */
#define MAP_FROM 0x11223344
#define MAP_TO 0x55667788

static unsigned char* g_frame;
static size_t g_frame_len;
static size_t g_version_len;       /* length of the leading version-string frame */
static size_t g_usermap_count_off; /* offset of the usermap count int, 0 = unknown */
static size_t g_auth_off;          /* offset of the auth presence int, 0 = unknown */
static bool g_auth_found;          /* whether g_auth_off is valid */
static bool g_frame_ready;

/* Read the canonical frame from the send peer.  The producer shuts down its
 * write half first, so a blocking read drains the frame and then sees EOF. */
static unsigned char* drain_frame(int fd, size_t* out_len) {
  size_t cap = 4096;
  size_t len = 0;
  unsigned char* buf = malloc(cap);
  if (!buf)
    return NULL;
  for (;;) {
    if (len == cap) {
      size_t grown = cap * 2;
      unsigned char* bigger = realloc(buf, grown);
      if (!bigger) {
        free(buf);
        return NULL;
      }
      buf = bigger;
      cap = grown;
    }
    ssize_t n = read(fd, buf + len, cap - len);
    if (n > 0) {
      len += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR)
      continue;
    break; /* 0 (EOF) or error */
  }
  *out_len = len;
  return buf;
}

/* Serialize a valid Config with the real sender.  The frame is written into a
 * pipe (64 KiB kernel buffer, far larger than one config frame) whose read end
 * is drained afterwards; the STATUS_OK ack is pre-loaded into a second pipe so
 * a single thread suffices (config_send writes the whole frame before it reads
 * the ack). */
static void build_canonical_frame(void) {
  g_frame_ready = true;

  Config* cfg = config_create();
  if (!cfg)
    return;
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");
  /* Force the shortened auth block (`[present][username]`) to be present so the
   * fuzzer can mutate it. */
  cfg->auth_user = str_dup("alice");
  cfg->auth_password = str_dup("alice-s3cret");
  /* Force the three P8 tail fields to be present (copy-as requires metadata). */
  cfg->copy_as_set = true;
  cfg->copy_as_uid = 0;
  cfg->copy_as_gid = 0;
  cfg->use_metadata = true;
  /* Force one usermap entry with a locatable sentinel. */
  cfg->usermap = malloc(sizeof(IdentityMap));
  if (cfg->usermap) {
    cfg->usermap_count = 1;
    cfg->usermap[0].from = MAP_FROM;
    cfg->usermap[0].from_hi = MAP_FROM;
    cfg->usermap[0].to = MAP_TO;
    cfg->usermap[0].to_name = NULL;
  }
  if (!cfg->send_directory || !cfg->receive_root_directory || !cfg->usermap) {
    config_delete(cfg);
    return;
  }

  int frame_pipe[2] = {-1, -1};
  int status_pipe[2] = {-1, -1};
  if (pipe(frame_pipe) != 0 || pipe(status_pipe) != 0)
    goto out;

  int ack = STATUS_OK;
  if (write(status_pipe[1], &ack, sizeof(ack)) != (ssize_t)sizeof(ack))
    goto out;

  io_set_fds(status_pipe[0], frame_pipe[1]);
  io_set_bwlimit(0);
  bool sent = config_send(frame_pipe[1], cfg);
  close(frame_pipe[1]);
  frame_pipe[1] = -1;
  close(status_pipe[0]);
  status_pipe[0] = -1;
  close(status_pipe[1]);
  status_pipe[1] = -1;

  if (sent)
    g_frame = drain_frame(frame_pipe[0], &g_frame_len);

out:
  if (frame_pipe[0] != -1)
    close(frame_pipe[0]);
  if (frame_pipe[1] != -1)
    close(frame_pipe[1]);
  if (status_pipe[0] != -1)
    close(status_pipe[0]);
  if (status_pipe[1] != -1)
    close(status_pipe[1]);
  config_delete(cfg);
  if (!g_frame || g_frame_len == 0) {
    free(g_frame);
    g_frame = NULL;
    g_frame_len = 0;
    return;
  }

  g_version_len = sizeof(size_t) + strlen(PROTOCOL_VERSION);
  if (g_version_len > g_frame_len)
    g_version_len = g_frame_len;

  /* Locate the usermap entry sentinel; its count int sits 4 bytes before it. */
  int32_t from = MAP_FROM;
  int32_t to = MAP_TO;
  unsigned char pattern[8];
  memcpy(pattern, &from, sizeof(from));
  memcpy(pattern + sizeof(from), &to, sizeof(to));
  if (g_frame_len >= sizeof(pattern)) {
    for (size_t i = 4; i + sizeof(pattern) <= g_frame_len; i++) {
      if (memcmp(g_frame + i, pattern, sizeof(pattern)) == 0) {
        g_usermap_count_off = i - sizeof(int32_t);
        break;
      }
    }
  }

  /* Locate the auth username string (a size_t length followed by its bytes);
   * the presence int sits one int before the length.  The username bytes cannot
   * start before sizeof(size_t)+sizeof(int) without the presence-int offset
   * underflowing, so begin the scan there. */
  const char* auth_name = "alice";
  size_t auth_name_len = strlen(auth_name);
  if (g_frame_len >= sizeof(size_t) + auth_name_len + sizeof(int)) {
    for (size_t i = sizeof(size_t) + sizeof(int); i + auth_name_len <= g_frame_len; i++) {
      if (memcmp(g_frame + i, auth_name, auth_name_len) != 0)
        continue;
      size_t found_len = 0;
      memcpy(&found_len, g_frame + i - sizeof(size_t), sizeof(size_t));
      if (found_len == auth_name_len) {
        g_auth_off = i - sizeof(size_t) - sizeof(int);
        g_auth_found = true;
        break;
      }
    }
  }
}

/* Fuzz the A7 auth crypto primitives directly: arbitrary bytes through the
 * base64 decoder, plus a self-consistent SCRAM property (a proof built from a
 * chosen client key must verify, while a tampered proof, a proof replayed
 * against a different nonce, and a not-found verifier must all be refused). */
static uint8_t pick_byte(const uint8_t* data, size_t size, size_t index) {
  return size ? data[index % size] : 0;
}

static void fuzz_credentials(const uint8_t* data, size_t size) {
  char b64[300];
  size_t n = size < sizeof(b64) - 1 ? size : sizeof(b64) - 1;
  memcpy(b64, data, n);
  b64[n] = '\0';
  uint8_t decoded[64];
  size_t decoded_len = 0;
  (void)credentials_b64_decode(b64, decoded, sizeof(decoded), &decoded_len);

  uint8_t client_key[CREDENTIAL_KEY_LEN];
  uint8_t stored_key[CREDENTIAL_KEY_LEN];
  uint8_t server_key[CREDENTIAL_KEY_LEN];
  uint8_t snonce[CREDENTIAL_NONCE_LEN];
  uint8_t cnonce[CREDENTIAL_NONCE_LEN];
  for (size_t i = 0; i < CREDENTIAL_KEY_LEN; i++) {
    client_key[i] = pick_byte(data, size, i);
    server_key[i] = pick_byte(data, size, i + CREDENTIAL_KEY_LEN);
  }
  for (size_t i = 0; i < CREDENTIAL_NONCE_LEN; i++) {
    snonce[i] = pick_byte(data, size, i + 2 * CREDENTIAL_KEY_LEN);
    cnonce[i] = pick_byte(data, size, i + 2 * CREDENTIAL_KEY_LEN + CREDENTIAL_NONCE_LEN);
  }
  unsigned int stored_len = 0;
  if (EVP_Digest(client_key, sizeof(client_key), stored_key, &stored_len, EVP_sha256(), NULL) !=
          1 ||
      stored_len != CREDENTIAL_KEY_LEN)
    return;
  uint8_t auth_msg[CREDENTIAL_AUTH_MESSAGE_MAX];
  size_t msg_len = 0;
  if (!credentials_build_auth_message("alice", snonce, cnonce, auth_msg, sizeof(auth_msg),
                                      &msg_len))
    return;
  uint8_t proof[CREDENTIAL_KEY_LEN];
  uint8_t server_sig[CREDENTIAL_KEY_LEN];
  if (!credentials_client_proof(client_key, stored_key, server_key, auth_msg, msg_len, proof,
                                server_sig))
    return;
  CredentialVerifier verifier;
  memset(&verifier, 0, sizeof(verifier));
  verifier.found = true;
  verifier.iters = CREDENTIAL_DEFAULT_ITERS;
  memcpy(verifier.stored_key, stored_key, CREDENTIAL_KEY_LEN);
  memcpy(verifier.server_key, server_key, CREDENTIAL_KEY_LEN);
  uint8_t out_sig[CREDENTIAL_KEY_LEN];
  if (!credentials_verify_response(&verifier, "alice", snonce, cnonce, proof, out_sig))
    abort();
  if (memcmp(out_sig, server_sig, CREDENTIAL_KEY_LEN) != 0)
    abort();
  uint8_t bad_proof[CREDENTIAL_KEY_LEN];
  memcpy(bad_proof, proof, CREDENTIAL_KEY_LEN);
  bad_proof[pick_byte(data, size, 0) % CREDENTIAL_KEY_LEN] ^= 0x01;
  if (credentials_verify_response(&verifier, "alice", snonce, cnonce, bad_proof, out_sig))
    abort();
  uint8_t other_cnonce[CREDENTIAL_NONCE_LEN];
  memcpy(other_cnonce, cnonce, CREDENTIAL_NONCE_LEN);
  other_cnonce[pick_byte(data, size, 1) % CREDENTIAL_NONCE_LEN] ^= 0x80;
  if (credentials_verify_response(&verifier, "alice", snonce, other_cnonce, proof, out_sig))
    abort();
  verifier.found = false;
  if (credentials_verify_response(&verifier, "alice", snonce, cnonce, proof, out_sig))
    abort();
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

/* Build prefix ++ data as a stream and drive config_receive over it. */
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
  /* Signal EOF without closing the read half, so the receiver's STATUS_ERROR
   * replies do not hit EPIPE. */
  shutdown(sv[0], SHUT_WR);

  io_set_fds(sv[1], sv[1]);
  io_set_bwlimit(0);
  Config* cfg = config_receive(sv[1]);
  config_delete(cfg);

  close(sv[0]);
  close(sv[1]);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  fuzz_credentials(data, size);

  if (!g_frame_ready)
    build_canonical_frame();

  /* Raw bytes as the whole frame (version gate and all). */
  receive_stream(NULL, 0, data, size);

  if (g_frame) {
    /* Keep the valid version prefix, fuzz everything after it. */
    receive_stream(g_frame, g_version_len, data, size);

    /* Keep the valid frame up to the shortened auth block, fuzz it. */
    if (g_auth_found)
      receive_stream(g_frame, g_auth_off, data, size);

    /* Keep the valid frame up to the P8 tail, fuzz super_mode + copy-as. */
    if (g_frame_len > P8_TAIL_BYTES)
      receive_stream(g_frame, g_frame_len - P8_TAIL_BYTES, data, size);

    /* Keep the valid frame up to the usermap count, fuzz the count + entries. */
    if (g_usermap_count_off > 0)
      receive_stream(g_frame, g_usermap_count_off, data, size);
  }
  return 0;
}
