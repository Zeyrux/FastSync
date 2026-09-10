#ifndef MOTD_H
#define MOTD_H

#include <stdbool.h>

/* Daemon Message-Of-The-Day (Wave C).
 *
 * The daemon listener (fastsync-server --daemon) may advertise a `motd file`
 * configured in its globals.  When a client connects with a host::module/path
 * destination and the module gate accepts the connection, the server sends the
 * MOTD as a single string frame BEFORE any transfer data (rsync sends its MOTD
 * as the first thing from the server at the start of a daemon connection).
 * The client reads that frame right after the config/status handshake and
 * displays it on stdout unless --no-motd was given.
 *
 * The MOTD is ordinary display text, never a secret, so it uses the normal
 * (non-redacted) string primitive.  The exchange is strictly server->client
 * and happens on the daemon listener path only; the --stdio SSH path has no
 * MOTD.
 *
 * No PROTOCOL_VERSION bump is involved: the frame is sent and read
 * symmetrically by every 2.15.0 daemon build (the strict same-version
 * handshake rejects any other version before the frame), so it cannot
 * desynchronize a peer. */

/* Upper bound on the MOTD bytes the server will read from disk and put on the
 * wire.  Kept far below MAX_STRING_SIZE (64 KB) so a huge/hostile motd file
 * can never produce an unbounded frame or allocation. */
#define MOTD_MAX_BYTES 4096

/* Read a daemon MOTD file, bounded to MOTD_MAX_BYTES.  Returns a malloc'd
 * NUL-terminated copy of the file content (bytes beyond the bound are
 * truncated) or NULL when path is NULL/empty, the file cannot be opened or
 * read, or allocation fails.  An absent or unreadable motd file is NOT an
 * error: the caller simply sends an empty MOTD frame and continues. */
char* motd_read_file(const char* path);

/* Render MOTD text for terminal display.  Newlines and tabs are preserved so
 * a multi-line motd still reads naturally, while every other non-printable /
 * control byte (ESC included) is escaped with FastSync's `\NNN` octal
 * convention, so a hostile server cannot inject terminal escape sequences
 * through the MOTD.  eight_bit_output keeps bytes >= 0x80 verbatim (matching
 * --8-bit-output).  Returns a malloc'd string or NULL on allocation failure. */
char* motd_render(const char* motd, bool eight_bit_output);

/* Send/receive the MOTD string frame.  These wrap the normal string
 * primitive: the MOTD is not a credential, so no redaction is used.  The
 * receiver additionally rejects an over-bound frame (> MOTD_MAX_BYTES) as a
 * hostile input guard; the frame itself is always fully consumed first, so the
 * stream stays framed. */
bool motd_send(int file_descriptor, const char* motd);
char* motd_receive(int file_descriptor);

#endif
