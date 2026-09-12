#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "data.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>

/* Maximum allowed string size for receive_str (64 KB) */
#define MAX_STRING_SIZE (64 * 1024)

/* Maximum uncompressed file payload accepted by the receiver's whole-file
 * paths.  A single whole file is charged against the per-connection memory
 * reservation (MAX_CONNECTION_MEMORY) and against the server allocation
 * ceiling (MAX_SERVER_ALLOC), so this mirrors those 256 MB bounds rather than
 * the older 64 MB chunk-era cap.  Chunk-serialized payloads keep their own
 * 64 MB cap (MAX_CHUNK_SIZE). */
#define MAX_RECEIVE_WHOLE_FILE_SIZE (256ULL * 1024 * 1024)

/* Maximum allowed data payload size for receive_data (whole-file bound) */
#define MAX_DATA_PAYLOAD_SIZE MAX_RECEIVE_WHOLE_FILE_SIZE

/* Maximum chunk size (64 MB) — prevents unbounded allocation from the wire */
#define MAX_CHUNK_SIZE (64ULL * 1024 * 1024)
#define MAX_MANIFEST_ENTRIES (1024 * 1024)
/* Aggregate bytes retained by one received deletion manifest. */
#define MAX_MANIFEST_BYTES (16ULL * 1024 * 1024)
#define DEFAULT_MAX_ALLOC (1ULL * 1024 * 1024 * 1024)
/* Server policy ceiling for a client-provided allocation limit. */
#define MAX_SERVER_ALLOC (256ULL * 1024 * 1024)
/* Bounded cumulative per-connection receive budget.  In-flight wire buffers,
   decompression buffers and queued (not yet written) file payloads for a
   connection must stay within this ceiling. */
#define MAX_CONNECTION_MEMORY (256ULL * 1024 * 1024)

typedef struct ssl_st SSL;

/*
 * Explicit owner of protocol I/O.  A session does not own the descriptors or
 * SSL object; it only describes the transport used by a transfer.  This makes
 * it safe to pass the transport to a worker without relying on inherited
 * thread-local state.
 */
typedef struct ProtocolSession {
  int read_fd;
  int write_fd;
  SSL* ssl;
  unsigned long long bwlimit;
  long long bw_tokens;
  long long bw_last_refill_sec;
  long bw_last_refill_nsec;
  atomic_ullong total_allocated_bytes;
  bool eight_bit_output;
  unsigned long long max_alloc;
} ProtocolSession;

typedef int Status;
enum NET_STATUS {
  STATUS_OK,
  STATUS_ERROR,
  STATUS_FINISHED,
  STATUS_NEXT,
  STATUS_CHUNK,
  STATUS_MANIFEST,
  STATUS_CHECK,
  STATUS_DELTA_SIGNATURE,
  STATUS_DELTA_DATA,
  STATUS_KEEPALIVE,
  STATUS_ABORT,
  STATUS_CHECK_BATCH,
  /* An explicit directory entry (--dirs): the sender transmits only the path;
   * the receiver creates the directory below the receive root. */
  STATUS_MKDIR,
  /* --append / --append-verify tail resume.  STATUS_APPEND is sent by the
   * receiver after a per-file STATUS_CHECK when the existing destination file
   * is SHORTER than the source and an append mode is negotiated: its payload is
   * the resume offset (the number of prefix bytes already present), after which
   * the sender answers either directly with STATUS_APPEND_DATA (plain --append,
   * prefix not verified) or, for --append-verify, first with STATUS_APPEND_SIG
   * carrying the xxHash64 of the source prefix; the receiver then replies
   * STATUS_APPEND_OK (prefix matched -> sender transmits the tail) or
   * STATUS_NEXT (prefix mismatch -> sender falls back to a full transfer).
   * STATUS_APPEND_DATA carries the tail bytes (compressed data frame). */
  STATUS_APPEND,
  STATUS_APPEND_SIG,
  STATUS_APPEND_OK,
  STATUS_APPEND_DATA,
  /* --hard-links/-H: a sibling (later member) of a source hard-link group.
   * The sender transmits only the path, the run-local link-group id, and the
   * first (data-carrying) member's destination-relative wire path; the receiver
   * creates this entry as a hard link to the first member's installed file
   * (falling back to a byte-identical copy if link() fails).  Protocol 2.12.0. */
  STATUS_HARDLINK,
  /* A symlink-type entry (-l/--links, -k/--copy-dirlinks' keep-as-symlink
   * branch).  The sender transmits the destination path, the (sender-munged,
   * if --munge-links) symlink target, and optional metadata; the receiver
   * creates a symlink to the unmunged target beneath the receive root (see
   * file_receive_symlink).  Protocol 2.13.0. */
  STATUS_SYMLINK,
  /* --devices / --specials (-D): a device or special node the sender wants
   * recreated (not written from content).  Payload: destination path, the
   * metadata frame (whose mode's S_IFMT bits carry the node kind), and two
   * int32 rdev major/minor fields.  The receiver validates the kind and rdev,
   * confines the node below the receive root, and recreates it (mknod/mkfifo),
   * privilege-gating the mknod.  Protocol 2.13.0. */
  STATUS_SPECIAL,
  /* Directory-time superstructure (P7 Wave D, protocol 2.17.0): one or more
   * trailing frames sent after all file data (and after the optional delete
   * manifest) carrying the source directories' captured metadata so the
   * receiver can apply directory mtimes/atimes AFTER all of a directory's
   * children have been written.  Payload per frame: an int count, then count
   * repetitions of (wire path string, metadata frame); an entry count larger
   * than MAX_MANIFEST_ENTRIES is split across repeated frames.  The receiver
   * defers the actual utimensat until its own delete/publish phase has
   * committed, then skips the whole set when -O/--omit-dir-times is set. */
  STATUS_DIR_TIMES,
  /* Daemon SCRAM-SHA-256 authentication (A7 remediation, protocol 2.19.0).
   * STATUS_AUTH_CHALLENGE: the server requires auth and is about to send the
   * iteration count, the base64 salt and the base64 server nonce.
   * STATUS_AUTH_RESPONSE: the client's reply, followed by the base64 client
   * nonce and the base64 ClientProof.  STATUS_AUTH_OK: the client proof
   * verified, followed by the base64 ServerSignature.  STATUS_AUTH_FAILED:
   * a single generic refusal (unknown user, off-list user, wrong proof,
   * missing/malformed credentials) after which the server closes without
   * writing any data. */
  STATUS_AUTH_CHALLENGE,
  STATUS_AUTH_RESPONSE,
  STATUS_AUTH_OK,
  STATUS_AUTH_FAILED
};

void io_set_fds(int read_fd, int write_fd);
void io_set_bwlimit(unsigned long long bytes_per_sec);
void io_set_ssl(SSL* ssl);
SSL* io_get_ssl(void);

void protocol_session_init(ProtocolSession* session, int read_fd, int write_fd);
/* Transitional bridge for helpers whose signatures still carry only an fd. */
void protocol_session_bind(ProtocolSession* session);
void protocol_session_unbind(void);
void protocol_session_set_ssl(ProtocolSession* session, SSL* ssl);
void protocol_session_set_bwlimit(ProtocolSession* session, unsigned long long bytes_per_sec);
void protocol_session_set_max_alloc(ProtocolSession* session, unsigned long long max_alloc);
void* protocol_alloc(size_t size);
void* protocol_realloc(void* ptr, size_t size);
void protocol_session_set_8_bit_output(ProtocolSession* session, bool enabled);
void protocol_set_8_bit_output(bool enabled);
bool protocol_send_n_data(ProtocolSession* session, const void* data, size_t data_size);
bool protocol_receive_n_data(ProtocolSession* session, void* data, size_t data_size);
bool protocol_send_str(ProtocolSession* session, const char* data);
char* protocol_receive_str(ProtocolSession* session);
/* Redacted string variants: identical wire framing to protocol_send_str /
 * protocol_receive_str, but the payload body is replaced by `<redacted>` in the
 * LOG_DEBUG_PROTO debug log.  Used for daemon auth material (the username and
 * the proof/signature fields) so a --verbose log can never capture a credential
 * that could be replayed. */
bool protocol_send_str_redacted(ProtocolSession* session, const char* data);
char* protocol_receive_str_redacted(ProtocolSession* session);
bool protocol_send_data(ProtocolSession* session, const Data* data);
Data* protocol_receive_data(ProtocolSession* session);
Data* protocol_receive_data_limited(ProtocolSession* session, unsigned long long maximum_size);
bool protocol_send_int(ProtocolSession* session, int data);
bool protocol_receive_int(ProtocolSession* session, int* data);
bool protocol_send_status(ProtocolSession* session, Status status);
bool protocol_receive_status(ProtocolSession* session, Status* status);
bool send_n_data(int file_descriptor, const void* data, size_t data_size);
bool receive_n_data(int file_descriptor, void* data, size_t data_size);

bool send_str(int file_descriptor, const char* data);
char* receive_str(int file_descriptor);
/* Redacted fd-level string variants (see protocol_send_str_redacted). */
bool send_str_redacted(int file_descriptor, const char* data);
char* receive_str_redacted(int file_descriptor);
bool send_data(int file_descriptor, const Data* data);
Data* receive_data(int file_descriptor);
Data* receive_data_limited(int file_descriptor, unsigned long long maximum_size);
bool send_int(int file_descriptor, int data);
bool receive_int(int file_descriptor, int* data);
bool send_status(int file_descriptor, Status status);
bool receive_status(int file_descriptor, Status* status);
/* receive_status with an explicit per-message deadline in seconds, instead of
   the default RECEIVE_TIMEOUT_SEC.  A reply that may legitimately take longer
   (e.g. the early-delete ACK after a large receiver-side deletion) must use
   this so the sender does not abort after the deletion already committed. */
bool receive_status_timed(int file_descriptor, Status* status, int timeout_sec);

#endif
