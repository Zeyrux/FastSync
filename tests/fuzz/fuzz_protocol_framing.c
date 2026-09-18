/*
 * Fuzz the base protocol framing: receive_str / receive_data / receive_status
 * (plus the redacted string, the size-limited data and the timed-status
 * variants) fed arbitrary bytes over an in-memory socketpair.
 *
 * Every receive primitive reads a fixed-width header (a size_t string length,
 * an unsigned long long data length, an int status/int value) and then a body.
 * The fuzzer attacks:
 *   - oversized length headers (the MAX_STRING_SIZE / MAX_DATA_PAYLOAD_SIZE
 *     gates must reject before allocating),
 *   - truncated bodies (a declared body larger than the stream must fail
 *     cleanly at EOF, never read uninitialised memory or leak),
 *   - embedded NUL bytes in strings (must be refused),
 *   - out-of-range status enum values (status_to_string must stay in bounds).
 *
 * Each entry point gets its own socketpair because a single receive consumes a
 * variable number of bytes from the stream; reusing one would make the later
 * calls meaningless.  The write half is shut down first so a truncated frame
 * always terminates at EOF instead of blocking.
 */
#include "data.h"
#include "protocol.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* Create a socketpair pre-loaded with `data`, shut down the write half and
 * return the read end (which the receiver reads from).  `*write_end` is also
 * returned so the caller can close it. */
static int make_stream(const uint8_t* data, size_t size, int* write_end) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    *write_end = -1;
    return -1;
  }
  int flags = fcntl(sv[0], F_GETFL, 0);
  if (flags != -1)
    (void)fcntl(sv[0], F_SETFL, flags | O_NONBLOCK);
  if (size > 0)
    write_best_effort(sv[0], data, size);
  shutdown(sv[0], SHUT_WR);
  *write_end = sv[0];
  return sv[1];
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  int w;

  int rd = make_stream(data, size, &w);
  if (rd >= 0) {
    char* s = receive_str(rd);
    free(s);
    close(rd);
    close(w);
  }

  rd = make_stream(data, size, &w);
  if (rd >= 0) {
    char* s = receive_str_redacted(rd);
    free(s);
    close(rd);
    close(w);
  }

  /* Bounded so a crafted 256 MiB length header cannot make each iteration
     allocate the full MAX_DATA_PAYLOAD_SIZE under ASan; the framing logic is
     identical to receive_data(), which delegates to the limited variant. */
  rd = make_stream(data, size, &w);
  if (rd >= 0) {
    Data* d = receive_data_limited(rd, 1u << 20);
    data_destroy(d);
    close(rd);
    close(w);
  }

  /* The size-limited variant must reject anything beyond its explicit bound
   * before allocating the body buffer. */
  rd = make_stream(data, size, &w);
  if (rd >= 0) {
    Data* d = receive_data_limited(rd, 256);
    data_destroy(d);
    close(rd);
    close(w);
  }

  rd = make_stream(data, size, &w);
  if (rd >= 0) {
    Status status = STATUS_OK;
    (void)receive_status(rd, &status);
    close(rd);
    close(w);
  }

  rd = make_stream(data, size, &w);
  if (rd >= 0) {
    Status status = STATUS_OK;
    (void)receive_status_timed(rd, &status, 1);
    close(rd);
    close(w);
  }

  rd = make_stream(data, size, &w);
  if (rd >= 0) {
    int value = 0;
    (void)receive_int(rd, &value);
    close(rd);
    close(w);
  }

  return 0;
}
