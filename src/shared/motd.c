#include "motd.h"
#include "protocol.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* motd_read_file(const char* path) {
  if (!path || path[0] == '\0')
    return NULL;
  FILE* fp = fopen(path, "rb");
  if (!fp)
    return NULL;
  char* buffer = malloc(MOTD_MAX_BYTES + 1);
  if (!buffer) {
    fclose(fp);
    return NULL;
  }
  /* fread stops at the bound; a larger file is truncated rather than read
   * unbounded.  ferror distinguishes a truncated read from an I/O failure. */
  size_t total = fread(buffer, 1, MOTD_MAX_BYTES, fp);
  if (ferror(fp)) {
    free(buffer);
    fclose(fp);
    return NULL;
  }
  fclose(fp);
  buffer[total] = '\0';
  return buffer;
}

char* motd_render(const char* motd, bool eight_bit_output) {
  if (!motd)
    return NULL;
  size_t length = strlen(motd);
  if (length > (SIZE_MAX - 1) / 5)
    return NULL;
  char* rendered = malloc(length * 5 + 1);
  if (!rendered)
    return NULL;
  size_t out = 0;
  for (size_t i = 0; i < length; i++) {
    unsigned char byte = (unsigned char)motd[i];
    if (byte == '\n' || byte == '\t') {
      rendered[out++] = (char)byte;
    } else if ((byte >= 32 && byte <= 126) || (eight_bit_output && byte >= 128)) {
      rendered[out++] = (char)byte;
    } else {
      rendered[out++] = '\\';
      rendered[out++] = '#';
      rendered[out++] = (char)('0' + ((byte >> 6) & 7));
      rendered[out++] = (char)('0' + ((byte >> 3) & 7));
      rendered[out++] = (char)('0' + (byte & 7));
    }
  }
  rendered[out] = '\0';
  return rendered;
}

bool motd_send(int file_descriptor, const char* motd) {
  return send_str(file_descriptor, motd ? motd : "");
}

char* motd_receive(int file_descriptor) {
  char* motd = receive_str(file_descriptor);
  if (!motd)
    return NULL;
  /* Guard against a hostile/oversized peer: receive_str already bounded the
   * frame at MAX_STRING_SIZE and consumed it, so discarding an over-bound
   * body here keeps the stream framed while refusing to display it. */
  if (strlen(motd) > MOTD_MAX_BYTES) {
    free(motd);
    return NULL;
  }
  return motd;
}
