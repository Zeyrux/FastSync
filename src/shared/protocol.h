#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "data.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>

/* Maximum allowed string size for receive_str (64 KB) */
#define MAX_STRING_SIZE (64 * 1024)

/* Hard cap on the optional server->client rejection detail carried by
 * STATUS_ERROR_DETAIL (protocol 2.21.0).  A longer message is sliced to this
 * many bytes before it is sent, so a peer can never be made to retain more than
 * this for a rejection and the detail frame stays a small, fixed bound. */
#define MAX_ERROR_DETAIL_BYTES 4096

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
/* Server-owned floor for the per-message I/O deadline.  A client --timeout=0
   (rsync's default) disables the client's own deadlines, but a server session
   must never be held open forever by a silent peer (slow-loris), so the server
   floors the effective deadline at this value. */
#define SERVER_IO_TIMEOUT_SEC 60
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
  /* Per-session deadline (seconds) applied to every protocol send/receive by
   * protocol_send_n_data / protocol_receive_n_data.  The initialized default is
   * the built-in 60 s window; a value <= 0 disables the deadline (rsync's
   * --timeout=0).  Set from the negotiated Config->timeout so --timeout is
   * honored by the poll()-driven protocol I/O, not just the socket
   * SO_RCVTIMEO/SO_SNDTIMEO.  The server does not propagate a client 0 here: it
   * installs protocol_server_io_timeout_sec() so its sessions keep a floor. */
  int io_timeout_sec;
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
  STATUS_AUTH_FAILED,
  /* Optional server->client rejection detail (protocol 2.21.0).  When the
   * server refuses a transfer for a concrete reason it may send
   * STATUS_ERROR_DETAIL followed by a length-prefixed, bounded string instead
   * of a bare STATUS_ERROR.  receive_status() consumes the string and maps the
   * status back to STATUS_ERROR, so every pre-2.21 call site keeps working;
   * callers that want the human-readable reason consult protocol_last_error().
   * Appended immediately after STATUS_AUTH_FAILED so the existing wire values
   * never move. */
  STATUS_ERROR_DETAIL,
  /* Server-contacting --dry-run (protocol 2.21.0).  Sent by the receiver in
   * response to a per-file STATUS_CHECK when the wire config carries
   * dry_run=true and the file is NOT already up to date: it tells the sender
   * the file WOULD be transferred, and the sender must NOT transmit any data
   * (the receiver reads none in dry-run).  STATUS_OK keeps its meaning in this
   * path ("already up to date / nothing to do").  Appended after
   * STATUS_ERROR_DETAIL so no existing status is renumbered. */
  STATUS_DRY_RUN_TRANSFER,
  /* --max-delete budget exhausted (protocol 2.23.0).  Sent by the receiver as
   * the terminal success status INSTEAD of STATUS_OK when a --delete/
   * --delete-missing-args commit removed up to the --max-delete bound but had
   * to skip further extras.  The transfer itself succeeded and all file data is
   * stored; the sender maps this to rsync's exit code 25 ("the --max-delete
   * limit stopped deletions").  Appended after STATUS_DRY_RUN_TRANSFER so no
   * existing status is renumbered. */
  STATUS_DELETE_LIMIT,
  /* Destination-state report for output parity (protocol 2.23.0).  When the
   * wire config carries report_dest_info=true, the receiver answers every
   * per-file STATUS_CHECK request with STATUS_DEST_INFO FIRST, followed by a
   * fixed record describing the pre-transfer destination entry
   * (int32 has_old; uint64 size; int64 mtime; int64 mtime_nsec; uint32 mode;
   * int32 uid; int32 gid).  The ordinary STATUS_OK/STATUS_NEXT/... verdict
   * follows, so the sender can render rsync-accurate -i/--out-format columns
   * (new vs modified, and which of size/time/perms/owner/group differ) without
   * changing the transfer decision itself.  Appended after
   * STATUS_DELETE_LIMIT so no existing status is renumbered. */
  STATUS_DEST_INFO,
  /* Per-directory delete plan (protocol 2.24.0).  The sender of a
   * --delete-during/--delete-delay transfer streams one frame per source
   * directory in directory order instead of a single whole-tree keep-set
   * manifest.  The receiver applies the plan when it arrives
   * (--delete-during removes that directory's extras immediately) or records
   * the extras and applies them only after the whole transfer succeeded
   * (--delete-delay).  Payload: an int32 has_config flag (1 on the first plan
   * of the run, 0 afterwards); when set, the three global config sections
   * (protected-prefix count+paths, size-skipped count+paths, missing-args
   * count+paths); then an int32 apply flag (1 for a real plan, 0 for a
   * config-only carrier frame that must not walk a directory); then the
   * destination-relative directory path wire string
   * ("." for the receive root); then the child-directory count + names and the
   * child-file count + names that must be kept.  Appended after
   * STATUS_DEST_INFO so no existing status is renumbered. */
  STATUS_DELETE_PLAN,
  /* End-of-transfer receiver counter report (protocol 2.25.0).  When the wire
   * config carries report_stats=true, the receiver sends this status once,
   * immediately before its terminal success status, followed by a fixed stats
   * record (see format_stats_send/receive in format.h) and, when the run is a
   * --dry-run with --delete, the would-delete path list.  Appended after
   * STATUS_DELETE_PLAN so no existing status is renumbered. */
  STATUS_STATS
};

void io_set_fds(int read_fd, int write_fd);
void io_set_bwlimit(unsigned long long bytes_per_sec);
unsigned long long io_get_bwlimit(void);
void io_set_ssl(SSL* ssl);
SSL* io_get_ssl(void);

/* Process-wide wire byte counters.  protocol_send_n_data/protocol_receive_n_data
 * update them; the zero-copy sendfile path reports through
 * protocol_note_bytes_written.  Used by the client to render rsync's
 * --stats/--progress totals and the --out-format %b/%c tokens. */
unsigned long long protocol_bytes_written(void);
unsigned long long protocol_bytes_read(void);
void protocol_note_bytes_written(unsigned long long bytes);
/* Apply --bwlimit pacing to bytes written outside protocol_send_n_data (the
 * plaintext zero-copy sendfile fast path).  Resolves the bound/legacy session
 * exactly as send_n_data does and runs the same token-bucket throttle, so the
 * sendfile transport is paced identically to the buffered/TLS paths.  A no-op
 * when the effective session has no bandwidth limit. */
void protocol_throttle_bytes(size_t bytes);

void protocol_session_init(ProtocolSession* session, int read_fd, int write_fd);
/* Transitional bridge for helpers whose signatures still carry only an fd. */
void protocol_session_bind(ProtocolSession* session);
void protocol_session_unbind(void);
void protocol_session_set_ssl(ProtocolSession* session, SSL* ssl);
void protocol_session_set_bwlimit(ProtocolSession* session, unsigned long long bytes_per_sec);
void protocol_session_set_max_alloc(ProtocolSession* session, unsigned long long max_alloc);
/* Override the per-message send/receive deadline for this session.  The value
 * is stored verbatim: a positive value sets the deadline, `sec` <= 0 disables
 * it (rsync's --timeout=0).  An explicit long deadline (e.g. the delete-ack
 * wait) is applied per-call by protocol_receive_status_timed and is unaffected
 * by this setter. */
void protocol_session_set_io_timeout(ProtocolSession* session, int sec);
/* Effective per-message I/O deadline (seconds) for the currently-bound session.
 * Zero means the deadline is disabled (rsync's --timeout=0).  Used by the
 * plaintext sendfile path which bypasses the protocol send primitive. */
int protocol_get_io_timeout_sec(void);
/* The server-side effective deadline for a client-requested timeout: a positive
 * client value is honored, otherwise the SERVER_IO_TIMEOUT_SEC floor applies so
 * a silent peer can never hold a session open forever. */
int protocol_server_io_timeout_sec(int client_timeout);
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
Data* protocol_receive_data_limited(ProtocolSession* session, unsigned long long maximum_size);
bool protocol_send_int(ProtocolSession* session, int data);
bool protocol_receive_int(ProtocolSession* session, int* data);
bool protocol_send_status(ProtocolSession* session, Status status);
bool protocol_receive_status(ProtocolSession* session, Status* status);
/* As protocol_receive_status, but with an explicit per-message deadline
 * (seconds) instead of the session's configured io_timeout_sec. */
bool protocol_receive_status_timed(ProtocolSession* session, Status* status, int timeout_sec);
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
/* Send STATUS_ERROR_DETAIL followed by a bounded (<= MAX_ERROR_DETAIL_BYTES)
 * length-prefixed string.  Over-long messages are sliced and NULL is treated
 * as "".  Returns false if the status or the string could not be sent. */
bool send_error_detail(int file_descriptor, const char* message);
/* Human-readable reason captured from the most recent STATUS_ERROR_DETAIL
 * received on this thread, or "" when the last status was a bare STATUS_ERROR
 * (or no detail was seen).  Thread-local, and valid until the next non-keepalive
 * status read on the same thread; a later STATUS_KEEPALIVE does NOT clear it.
 * The detail body is bounded by MAX_ERROR_DETAIL_BYTES: an over-cap declared
 * length is drained and yields "" (so the stream never desyncs), while an
 * absurd length is a fatal framing error that fails the status read. */
const char* protocol_last_error(void);
/* Clear the thread-local last-error buffer. */
void protocol_clear_last_error(void);
/* receive_status with an explicit per-message deadline in seconds, instead of
   the default RECEIVE_TIMEOUT_SEC.  A reply that may legitimately take longer
   (e.g. the early-delete ACK after a large receiver-side deletion) must use
   this so the sender does not abort after the deletion already committed. */
bool receive_status_timed(int file_descriptor, Status* status, int timeout_sec);

/* Callback polled by protocol_receive_status_keepalive once per keepalive
   interval.  Return true to stop waiting (e.g. a SIGINT/SIGTERM abort flag was
   set).  Kept as a function pointer so the protocol layer does not depend on
   client signal state. */
typedef bool (*ProtocolWaitAbort)(void);

/* Like receive_status_timed, but while the peer is silent it emits
   STATUS_KEEPALIVE every keepalive_interval_sec (the receiver answers each with
   STATUS_KEEPALIVE, which this function consumes and skips) so a long
   server-side operation does not look like a dead connection.  The total wait
   is still bounded by timeout_sec; abort_check (may be NULL) is polled every
   interval and, when it returns true, ends the wait immediately with false.
   Runs entirely on the calling thread: the protocol send path is NOT safe for
   concurrent writers, so this must not be paired with a helper thread. */
bool receive_status_keepalive(int file_descriptor, Status* status, int timeout_sec,
                              int keepalive_interval_sec, ProtocolWaitAbort abort_check);
bool protocol_receive_status_keepalive(ProtocolSession* session, Status* status, int timeout_sec,
                                       int keepalive_interval_sec, ProtocolWaitAbort abort_check);

#endif
