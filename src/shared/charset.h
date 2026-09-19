#ifndef CHARSET_H
#define CHARSET_H

#include <stdbool.h>
#include <stddef.h>

/* --iconv=CONVERT_SPEC file-name charset conversion (rsync compatibility).
 *
 * CONVERT_SPEC is "LOCAL[,REMOTE]": LOCAL is the charset of our own file
 * names, REMOTE is the charset of the remote side's file names and defaults
 * to LOCAL when the comma half is omitted.  The sender converts every local
 * path from LOCAL to REMOTE before it goes on the wire; the receiver converts
 * every received path back from REMOTE to LOCAL.  A NULL/disabled spec means
 * identity with zero overhead (the common path never consults iconv).
 *
 * All helpers are friendly to the strict cold path: the wire conversion state
 * is process-global (one direction per process -- a client only sends, a
 * server only receives) and is initialized once, before any path is
 * serialized, so conversion compiles to a single non-NULL check when disabled.
 */

/* Parse CONVERT_SPEC into malloc'd LOCAL and REMOTE charset names (caller
 * frees both).  REMOTE is a separate copy of LOCAL when no comma is present.
 * Returns 0 on success, -1 on a malformed spec (empty halves / missing value /
 * allocation failure); nothing is allocated on the -1 path.  Both output
 * pointers are REQUIRED (non-NULL). */
int charset_spec_parse(const char* spec, char** local_out, char** remote_out);

/* True when a CONVERT_SPEC is well-formed AND its charsets are usable for this
 * feature: each pair opens in a probe iconv_open in BOTH directions (a sender
 * converts local->remote, the receiver converts remote->local) and converting
 * a representative ASCII name emits no embedded NUL byte (a UTF-16-style NUL
 * emitter would be silently truncated by the C-string wire helpers).  A typo'd
 * charset name is therefore rejected at startup, not mid-run.  NULL (iconv
 * disabled) is always valid. */
bool charset_spec_valid(const char* spec);

/* Probe a concrete from->to conversion pair without keeping the descriptor:
 * both charsets open AND a representative ASCII name converts with no embedded
 * NUL.  Used for direction-specific validation (e.g. the receiver's exact
 * wire->local direction including a server-side charset override). */
bool charset_spec_valid_direction(const char* from_charset, const char* to_charset);
bool charset_pair_valid(const char* local, const char* remote);

/* One-shot conversion of a NUL-terminated input to a malloc'd NUL-terminated
 * result, or NULL on failure.  On failure *err_out (when non-NULL) receives
 * the iconv errno (EILSEQ/EINVAL = the input is not representable in the
 * target charset).  The caller must free the result. */
char* charset_convert(const void* conversion, const char* in, int* err_out);

/* Open a conversion descriptor for direction from_charset -> to_charset.
 * Returns NULL (errno = EINVAL) when a charset name is unsupported.  Freed
 * with charset_conversion_close. */
void* charset_conversion_open(const char* from_charset, const char* to_charset);
void charset_conversion_close(void* conversion);

/* Process-wide wire conversion.  charset_wire_init_sender (client side) opens
 * LOCAL->REMOTE; charset_wire_init_receiver (server side) opens
 * wire(REMOTE)->server-local.  server_spec is the server's own --iconv, whose
 * LOCAL half overrides the destination charset; NULL means the destination
 * charset is the client spec's REMOTE half (rsync's push semantics: the wire
 * bytes are written verbatim).  Both return false on an unsupported spec.
 * The state is freed with charset_wire_free. */
bool charset_wire_init_sender(const char* spec);
bool charset_wire_init_receiver(const char* spec, const char* server_spec);
void charset_wire_free(void);
bool charset_wire_active(void);

/* Pre-ack receiver-direction sanity (see charset_wire_init_receiver): true
 * when the exact wire->destination conversion the receiver will use (client
 * spec's REMOTE half into the server's own LOCAL half, or REMOTE->REMOTE when
 * the server has no --iconv) opens and produces NUL-free output. */
bool charset_wire_receiver_spec_valid(const char* spec, const char* server_spec);

/* Convert a path across the wire in the process direction.  Returns a malloc'd
 * string, or NULL when the name cannot be represented in the target charset. */
char* charset_wire_apply(const char* path);

/* Convenience wire string I/O: encode+send_str / receive_str+decode.  Both
 * return false/NULL (logging a clear --iconv error) on conversion failure, so
 * an unconvertible path FAILS the transfer cleanly instead of silently sending
 * a mangled name. */
bool send_wire_str(int file_descriptor, const char* local_path);
char* receive_wire_str(int file_descriptor);

#endif