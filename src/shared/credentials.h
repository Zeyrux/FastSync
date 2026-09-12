#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Daemon password authentication (A7 remediation, protocol 2.19.0).
 *
 * FastSync authenticates a daemon connection with a SCRAM-SHA-256-style
 * challenge/response handshake.  The daemon stores only a salted PBKDF2
 * verifier (never the password, and never a value that can be replayed as a
 * bearer credential): the client proves knowledge of the password against a
 * per-connection server nonce, and the server proves the same shared secret
 * back.  See credentials.c for the exact derivation.
 *
 * Server credential store format (--password-file and --early-input): one line
 * per entry,
 *   user:$fastsync$1$pbkdf2-sha256$<iters>$<salt_b64>$<stored_key_b64>$<server_key_b64>
 * with standard base64, a 16-byte salt and 32-byte keys, and iters in
 * [CREDENTIAL_MIN_ITERS, CREDENTIAL_MAX_ITERS].  Blank lines and lines whose
 * first non-space character is '#' or ';' are comments.  The parser is STRICT:
 * a malformed line fails the whole load so a typo can never silently change who
 * may log in.  A line holding the legacy (unsalted SHA-256 hex) secret is
 * hard-rejected with an actionable "legacy" error; there is no auto-upgrade.
 * Use `fastsync-server --hash-credentials` to generate new-format lines.
 *
 * Alongside the store, credentials_load maintains an exact-mode-0600
 * `<store_path>.dummykey` sidecar holding the store-wide random dummy key.  It
 * is auto-created on first load and MUST be preserved across restarts: it makes
 * the dummy challenge for an unknown user stable for the life of the store, so
 * a daemon restart cannot be used as a username-enumeration oracle.  A sidecar
 * that is not an exact-mode-0600 regular file of exactly 32 bytes fails the load
 * (fail closed); if it cannot be created (e.g. a read-only mount or a restrictive
 * umask the fchmod cannot repair) the daemon warns and uses a transient per-run
 * key instead.  NOTE: the sidecar requires EXACT 0600, whereas the store /
 * password files only reject group/other bits (a deliberate difference).
 *
 * Client --password-file format: the FIRST meaningful (non-comment, non-blank)
 * line is `user:password`, holding the literal password.  The client keeps it
 * only for the duration of the handshake and wipes it at teardown; the file
 * should be mode 0600 and readable only by its owner. */

/* Longest accepted credential-file line (excluding the trailing newline). */
#define CREDENTIAL_MAX_LINE 4096
/* Upper bound on a username in a credential file and on the wire.  Kept well
 * below MAX_STRING_SIZE so a wire username can never exhaust anything. */
#define CREDENTIAL_MAX_USER_LEN 256
/* Upper bound on a client-file password (before derivation). */
#define CREDENTIAL_MAX_PASSWORD_LEN 1024

/* SCRAM-SHA-256 parameters.  Salt and client nonce sizes are fixed by the
 * shared-auth-message framing; keys are always 32 bytes (SHA-256). */
#define CREDENTIAL_SALT_LEN 16
#define CREDENTIAL_NONCE_LEN 32
#define CREDENTIAL_KEY_LEN 32
#define CREDENTIAL_DEFAULT_ITERS 600000u
#define CREDENTIAL_MIN_ITERS 100000u
#define CREDENTIAL_MAX_ITERS 10000000u
/* Buffer size for the full AuthMessage (prefix + three length-prefixed fields).
 * Worst case: 16 + 4 + 256 + 4 + 32 + 4 + 32. */
#define CREDENTIAL_AUTH_MESSAGE_MAX                                                                \
  (16 + 4 + CREDENTIAL_MAX_USER_LEN + 4 + CREDENTIAL_NONCE_LEN + 4 + CREDENTIAL_NONCE_LEN)

typedef struct CredentialStore CredentialStore;

/* One resolved verifier.  `found` is false for an unknown user or a user not on
 * a module's auth list; the remaining fields then hold a deterministic dummy
 * salt (HMAC of the store-wide dummy key over the username), the store-wide
 * uniform iteration count (default for an empty store) and fixed dummy keys, so
 * the server can run the same challenge/response math with no enumeration or
 * timing oracle. */
typedef struct {
  uint8_t salt[CREDENTIAL_SALT_LEN];
  uint32_t iters;
  uint8_t stored_key[CREDENTIAL_KEY_LEN];
  uint8_t server_key[CREDENTIAL_KEY_LEN];
  bool found;
} CredentialVerifier;

/* Load the daemon credential store.
 *
 * password_file and early_input_file are both NULL-or-path, matching the
 * server's --password-file and --early-input options.  A file that cannot be
 * opened or that fails the strict grammar is a hard error (err filled, NULL
 * returned) -- the daemon fails CLOSED rather than serving an auth-required
 * module with a partial store.  Both files may be NULL, which yields an empty
 * store (every auth-required module then refuses connections).  Every entry in
 * the resulting store must agree on the iteration count; entries that disagree
 * (within one file or across the two layered sources) are rejected.  When both
 * are given, the --early-input file is layered over --password-file: a duplicate
 * username whose verifier matches is deduplicated; one whose verifier differs
 * is an error (the two sources disagree), never a silent pick.
 *
 * The returned store is heap-owned; free it with credentials_free. */
CredentialStore* credentials_load(const char* password_file, const char* early_input_file,
                                  char* err, size_t err_size);

/* Wipe every stored key/salt and free the store. */
void credentials_free(CredentialStore* store);

/* True when `user` is a single bounded token free of whitespace/control bytes
 * (the rule applied to store users, client-file users and the module list). */
bool credentials_username_valid(const char* user);

/* Standard base64.  encode writes NUL-terminated output to out (size out_sz).
 * decode writes the raw bytes to out (capacity out_sz) and stores the length;
 * the input must be a well-formed padded base64 string.  Both return false on
 * NULL arguments, a bad character/length, or insufficient output space. */
bool credentials_b64_encode(const uint8_t* in, size_t n, char* out, size_t out_sz);
bool credentials_b64_decode(const char* in, uint8_t* out, size_t out_sz, size_t* out_len);

/* Fill out[0..n) from the CSPRNG (RAND_bytes).  Returns false on failure. */
bool credentials_random_bytes(uint8_t* out, size_t n);

/* Resolve `user` against the store AND the module's auth-user list.  The list
 * scan is a constant-time full-length comparison with no early break.  On a
 * miss, *out is filled with a dummy verifier (a deterministic per-username salt
 * derived from the store's dummy key, the store-wide uniform iteration count,
 * fixed dummy keys, found=false).  Returns false on invalid arguments or an
 * HMAC/crypto primitive failure. */
bool credentials_get_verifier(const CredentialStore* store, const char* user,
                              const char* const* module_users, int n, CredentialVerifier* out);

/* Derive the SCRAM keys from a plaintext password:
 *   K = PBKDF2-HMAC-SHA256(password, salt, iters, 32)
 *   ClientKey = HMAC-SHA256(K, "Client Key"); StoredKey = SHA256(ClientKey)
 *   ServerKey = HMAC-SHA256(K, "Server Key")
 * Any of client_key/stored_key/server_key may be NULL when not needed.
 * `iters` must lie in [CREDENTIAL_MIN_ITERS, CREDENTIAL_MAX_ITERS]. */
bool credentials_compute_keys(const char* password, const uint8_t salt[CREDENTIAL_SALT_LEN],
                              uint32_t iters, uint8_t client_key[CREDENTIAL_KEY_LEN],
                              uint8_t stored_key[CREDENTIAL_KEY_LEN],
                              uint8_t server_key[CREDENTIAL_KEY_LEN]);

/* Serialize the shared AuthMessage:
 *   "FastSync-Auth-v1" || be32(len(user)) || user
 *                      || be32(32) || server_nonce
 *                      || be32(32) || client_nonce
 * out must hold at least CREDENTIAL_AUTH_MESSAGE_MAX bytes.  *out_len receives
 * the number of bytes written. */
bool credentials_build_auth_message(const char* user, const uint8_t* snonce, const uint8_t* cnonce,
                                    uint8_t* out, size_t out_sz, size_t* out_len);

/* Client side: ClientProof = ClientKey XOR HMAC(StoredKey, AuthMessage), and
 * the expected ServerSignature = HMAC(ServerKey, AuthMessage). */
bool credentials_client_proof(const uint8_t client_key[CREDENTIAL_KEY_LEN],
                              const uint8_t stored_key[CREDENTIAL_KEY_LEN],
                              const uint8_t server_key[CREDENTIAL_KEY_LEN], const uint8_t* auth_msg,
                              size_t msg_len, uint8_t proof[CREDENTIAL_KEY_LEN],
                              uint8_t server_sig[CREDENTIAL_KEY_LEN]);

/* Server side: recompute ClientSig' = HMAC(StoredKey, AuthMessage) and
 * ClientKey' = proof XOR ClientSig', then accept iff v->found AND
 * SHA256(ClientKey') equals StoredKey (constant-time over the 32-byte keys).
 * Always computes server_sig_out = HMAC(ServerKey, AuthMessage).  Returns the
 * accept decision. */
bool credentials_verify_response(const CredentialVerifier* v, const char* user,
                                 const uint8_t* snonce, const uint8_t* cnonce,
                                 const uint8_t proof[CREDENTIAL_KEY_LEN],
                                 uint8_t server_sig_out[CREDENTIAL_KEY_LEN]);

/* Derive a new-format store line for `user`/`password` and write it (without a
 * trailing newline) into out.  A random 16-byte salt is used.  On failure err is
 * filled.  Used by --hash-credentials and by tests. */
bool credentials_hash_store_line(const char* user, const char* password, uint32_t iters, char* out,
                                 size_t out_sz, char* err, size_t err_size);

/* Read `user:password` lines from `path` (the same no-group/other-bits check as
 * the other secret files) and write one new-format store line per entry to
 * `out`.
 * Blank/comment lines are skipped; a malformed line fails the whole run.
 * Returns 0 on success, -1 on error (err filled).  Used by
 * `--hash-credentials`. */
int credentials_hash_file(const char* path, uint32_t iters, FILE* out, char* err, size_t err_size);

/* Read the CLIENT-side secret file: the first meaningful line is
 * `user:password` (the literal password).  *user_out and *password_out are
 * freshly allocated on success (password is plaintext -- the caller derives the
 * proof and then burns/frees it); both are NULL on error.  Returns 0 on
 * success, -1 on failure (err filled: the path is named, never the credential
 * itself).  Only the line's trailing CR/LF are stripped: the password's bytes
 * are otherwise preserved exactly, so a password with leading/trailing
 * whitespace (after the ':') is kept usable.  The username is trimmed of
 * surrounding space/tabs. */
int credentials_read_secret_file(const char* path, char** user_out, char** password_out, char* err,
                                 size_t err_size);

/* Constant-time equality over exactly len bytes. */
bool credentials_secure_equal(const char* a, const char* b, size_t len);

/* Overwrite secret[0..len) with zeros (best-effort wipe). */
void credentials_burn(char* secret, size_t len);

/* Number of entries currently in the store (tests/introspection). */
int credentials_store_size(const CredentialStore* store);

/* Whether the store contains an entry for `user` (tests/introspection). */
bool credentials_store_has(const CredentialStore* store, const char* user);

#endif
