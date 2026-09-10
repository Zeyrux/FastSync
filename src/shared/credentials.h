#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#include <stdbool.h>
#include <stddef.h>

/* Daemon password authentication (Wave B).
 *
 * FastSync authenticates a daemon connection with a username plus a SHA-256
 * hex digest of that username's password.  The digest is what crosses the
 * wire: a challenge-less credential exchange, so the literal password is never
 * transmitted (and never stored on the daemon host).  A module that declares
 * `auth users` demands that the presented username is on its list AND that the
 * presented digest matches the credential store's entry for that username.
 * The digest comparison is constant-time; a module with `auth users` whose
 * store is missing/misconfigured fails CLOSED (never falls open).
 *
 * Credential store format (server --password-file and --early-input): one
 * `user:SHA256HEX` entry per line.  SHA256HEX is the lowercase hex SHA-256 of
 * the user's password -- the exact value a FastSync client transmits.  Blank
 * lines and lines whose first non-space character is '#' or ';' are comments.
 * The parser is STRICT: a malformed line (no ':', an empty/whitespace user, a
 * secret that is not 64 lowercase hex chars, a line longer than
 * CREDENTIAL_MAX_LINE) fails the whole load so a typo can never silently
 * change who may log in.
 *
 * Client --password-file format: the FIRST meaningful (non-comment, non-blank)
 * line is `user:password`, holding the literal password.  The client hashes it
 * and sends only the digest; the file should be mode 0600 and readable only by
 * its owner.
 */

/* Lowercase hex length of a SHA-256 digest (what travels on the wire and what
 * the server store holds). */
#define CREDENTIAL_HASH_HEX_LEN 64
/* Longest accepted credential-file line (excluding the trailing newline). */
#define CREDENTIAL_MAX_LINE 4096
/* Upper bound on a username in a credential file and on the wire.  Kept well
 * below MAX_STRING_SIZE so a wire username can never exhaust anything. */
#define CREDENTIAL_MAX_USER_LEN 256
/* Upper bound on a client-file password (before hashing). */
#define CREDENTIAL_MAX_PASSWORD_LEN 1024

typedef struct CredentialStore CredentialStore;

/* Load the daemon credential store.
 *
 * password_file and early_input_file are both NULL-or-path, matching the
 * server's --password-file and --early-input options.  A file that cannot be
 * opened or that fails the strict grammar is a hard error (err filled, NULL
 * returned) -- the daemon fails CLOSED rather than serving an auth-required
 * module with a partial store.  Both files may be NULL, which yields an empty
 * store (every auth-required module then refuses connections).  When both are
 * given, the --early-input file is layered over --password-file: a duplicate
 * username whose secret matches is deduplicated; one whose secret differs is
 * an error (the two sources disagree), never a silent pick.
 *
 * The returned store is heap-owned; free it with credentials_free. */
CredentialStore* credentials_load(const char* password_file, const char* early_input_file,
                                  char* err, size_t err_size);

void credentials_free(CredentialStore* store);

/* True when `hash_hex` is exactly CREDENTIAL_HASH_HEX_LEN lowercase hex digits
 * (the wire/store digest form).  Used to reject a malformed presented digest
 * before it reaches the comparison. */
bool credentials_hash_valid(const char* hash_hex);

/* Compute the lowercase hex SHA-256 of `password` into out_hex, which must
 * hold at least CREDENTIAL_HASH_HEX_LEN + 1 bytes.  Returns false on a NULL
 * password or a hashing failure.  The output is NUL-terminated. */
bool credentials_hash_password(const char* password, char* out_hex);

/* Read the CLIENT-side secret file: the first meaningful line is
 * `user:password` (the literal password).  *user_out and *password_out are
 * freshly allocated on success (password is plaintext -- the caller hashes it
 * and then burns/frees it); both are NULL on error.  Returns 0 on success, -1
 * on failure (err filled: the path is named, never the credential itself).
 * Only the line's trailing CR/LF are stripped: the password's bytes are
 * otherwise preserved exactly, so a password with leading/trailing whitespace
 * (after the ':') is kept usable.  The username is trimmed of surrounding
 * space/tabs. */
int credentials_read_secret_file(const char* path, char** user_out, char** password_out, char* err,
                                 size_t err_size);

/* Constant-time equality over exactly len bytes.  Returns true when the two
 * buffers match.  No early exit: the whole length is always scanned, so a
 * timing side-channel cannot reveal how many leading bytes matched. */
bool credentials_secure_equal(const char* a, const char* b, size_t len);

/* Overwrite secret[0..len) with zeros (best-effort wipe of a plaintext
 * password that is about to be freed). */
void credentials_burn(char* secret, size_t len);

/* Verify a presented (user, digest) against the store.  Returns true only when
 * the store holds an entry for `user` whose stored digest equals the presented
 * one.  A NULL store, NULL user/digest, unknown user and wrong digest all
 * return false.  The digest comparison runs over a fixed dummy whenever the
 * user is absent, and the username lookup is a single constant-time
 * full-length compare (no byte-wise early exit), so neither "unknown user" vs
 * "wrong password" nor a username prefix match can be distinguished by timing
 * (no user-enumeration oracle in the comparison path). */
bool credentials_verify(const CredentialStore* store, const char* user,
                        const char* presented_hash_hex);

/* The daemon's per-module auth decision, in one pure, unit-testable function.
 * `module_users`/`module_user_count` are the module's `auth users` list; a
 * module that declares auth users requires the presented user to be ON that
 * list AND to verify against the store.  Returns false (fail closed) when the
 * store is NULL, when no credential was presented, when the user is not on the
 * module's list, or when verification fails.  This is the single decision the
 * server_module_gate seam applies to an auth-required module.  Like
 * credentials_verify, username matches here use a constant-time full-length
 * compare rather than a byte-wise-short-circuiting strcmp. */
bool credentials_gate_allows(const CredentialStore* store, const char* const* module_users,
                             int module_user_count, const char* presented_user,
                             const char* presented_hash_hex);

/* Number of entries currently in the store (tests/introspection). */
int credentials_store_size(const CredentialStore* store);

/* Whether the store contains an entry for `user` (tests/introspection). */
bool credentials_store_has(const CredentialStore* store, const char* user);

#endif
