#include "credentials.h"
#include "log.h"
#include "utils.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* One store entry: a username and its salted PBKDF2 verifier.  The plaintext
 * password never appears here (and never on the daemon host); the verifier is
 * not replayable because the proof is bound to a per-connection nonce. */
typedef struct CredentialEntry {
  char* user;
  uint8_t salt[CREDENTIAL_SALT_LEN];
  uint32_t iters;
  uint8_t stored_key[CREDENTIAL_KEY_LEN];
  uint8_t server_key[CREDENTIAL_KEY_LEN];
} CredentialEntry;

struct CredentialStore {
  CredentialEntry* entries;
  int count;
  int capacity;
  /* Store-wide uniform PBKDF2 iteration count.  Every entry must agree on it
   * (the parser refuses a store whose entries disagree), so a miss can be
   * challenged with the same count as a hit and the count itself never leaks
   * membership.  Unused (0) for an empty store. */
  uint32_t iters;
  /* Store-wide secret loaded from (or created in) the exact-mode-0600
   * `<store_path>.dummykey` sidecar, so it also survives a daemon restart.  The
   * dummy salt handed out for an unknown/off-list user is
   * HMAC-SHA256(dummy_key, username)[:SALT_LEN], so repeated probes of the same
   * username always see an identical challenge while different usernames differ
   * -- with no fresh-random tell, and cross-restart stability hides the
   * restart-gated enumeration oracle. */
  uint8_t dummy_key[CREDENTIAL_KEY_LEN];
};

/* Exact marker prefix of the new store verifier field. */
#define CREDENTIAL_STORE_PREFIX "$fastsync$1$pbkdf2-sha256$"
#define CREDENTIAL_AUTH_PREFIX "FastSync-Auth-v1"
/* Exact-mode-0600 sidecar holding the persistent store-wide dummy key, placed
 * next to the credential store (`<store_path>.dummykey`). */
#define CREDENTIAL_DUMMY_KEY_SUFFIX ".dummykey"

/* Fixed dummy keys used when a user is unknown or off the module's list.  They
 * can never authenticate because acceptance additionally requires found=true. */
static const uint8_t k_dummy_stored_key[CREDENTIAL_KEY_LEN] = {0};
static const uint8_t k_dummy_server_key[CREDENTIAL_KEY_LEN] = {0};

static void set_error(char* err, size_t err_size, const char* fmt, ...) {
  if (!err || err_size == 0)
    return;
  va_list args;
  va_start(args, fmt);
  vsnprintf(err, err_size, fmt, args);
  va_end(args);
}

static bool is_comment_char(char c) {
  return c == '#' || c == ';';
}

/* Open a --password-file / --early-input after verifying the EXACT inode we
 * will read: it must be owned by the effective user and grant no group/other
 * permission bit (so 0600 and stricter modes such as 0400 are accepted),
 * mirroring the TLS private-key check.  This only rejects group/other bits,
 * deliberately unlike the dummy-key sidecar which requires EXACT mode 0600.  We
 * open by
 * path and then fstat the resulting fd (rather than stat()ing the path first
 * and reopening it), so the permission decision is made on the same inode that
 * is read and cannot be raced by swapping the path between check and open.
 * The path may be a process-substitution pipe (`<(...)` -> /dev/fd/N), so
 * regular files and FIFOs are accepted when the ownership/mode checks pass.
 *
 * Returns a FILE* the caller must fclose, or NULL with `err` filled. */
static FILE* secret_file_open(const char* path, char* err, size_t err_size) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    set_error(err, err_size, "cannot open secret file '%s': %s", path, strerror(errno));
    return NULL;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    set_error(err, err_size, "cannot stat secret file '%s': %s", path, strerror(errno));
    close(fd);
    return NULL;
  }
  bool is_readable_kind = S_ISREG(st.st_mode) || S_ISFIFO(st.st_mode);
  if (!is_readable_kind || st.st_uid != geteuid() || (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    set_error(err, err_size,
              "refusing to read secret file '%s': it must be owned by the current user and "
              "owner-only (0600), not accessible to group/other",
              path);
    close(fd);
    return NULL;
  }
  FILE* fp = fdopen(fd, "r");
  if (!fp) {
    set_error(err, err_size, "cannot read secret file '%s': %s", path, strerror(errno));
    close(fd);
    return NULL;
  }
  return fp;
}

/* Trim leading/trailing ASCII space and tab in place; returns the new start. */
static char* trim_space(char* s) {
  while (*s == ' ' || *s == '\t')
    s++;
  size_t len = strlen(s);
  while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t'))
    s[--len] = '\0';
  return s;
}

/* A username is a single token: non-empty, bounded, and free of whitespace and
 * control characters.  The same rule is applied to store users, client-file
 * users and the module `auth users` gate so an exact strcmp can never be
 * confused by invisible characters. */
static bool username_wellformed(const char* user) {
  if (!user || *user == '\0')
    return false;
  size_t len = strlen(user);
  if (len > CREDENTIAL_MAX_USER_LEN)
    return false;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)user[i];
    if (c <= 0x20 || c == 0x7f)
      return false;
  }
  return true;
}

bool credentials_username_valid(const char* user) {
  return username_wellformed(user);
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

/* True for the OLD `user:SHA256HEX` secret form: exactly 64 lowercase hex
 * digits.  Such a line is refused loudly (and never accepted) so an operator
 * cannot keep a replayable bearer digest in place after the protocol bump. */
static bool secret_is_legacy_hex(const char* s) {
  if (!s || strlen(s) != 64)
    return false;
  for (int i = 0; i < 64; i++) {
    if (hex_value(s[i]) < 0)
      return false;
  }
  return true;
}

bool credentials_b64_encode(const uint8_t* in, size_t n, char* out, size_t out_sz) {
  if (!in || !out)
    return false;
  if (n > (size_t)INT_MAX)
    return false;
  size_t encoded_len = 4 * ((n + 2) / 3);
  if (out_sz < encoded_len + 1)
    return false;
  int written = EVP_EncodeBlock((unsigned char*)out, in, (int)n);
  if (written < 0 || (size_t)written != encoded_len)
    return false;
  out[encoded_len] = '\0';
  return true;
}

bool credentials_b64_decode(const char* in, uint8_t* out, size_t out_sz, size_t* out_len) {
  if (!in || !out || !out_len)
    return false;
  size_t len = strlen(in);
  /* Every value we decode is short (a 32-byte key is 44 chars); refusing long
   * input keeps the scratch buffer fixed and bounds a hostile frame. */
  if (len == 0 || (len % 4) != 0 || len > 256)
    return false;
  size_t padded_len = (len / 4) * 3;
  size_t decoded_len = padded_len;
  if (in[len - 1] == '=')
    decoded_len--;
  if (len >= 2 && in[len - 2] == '=')
    decoded_len--;
  if (decoded_len > out_sz)
    return false;
  /* EVP_DecodeBlock writes the full (padded) quantum, so decode into a scratch
   * buffer sized for it and copy only the real bytes out.  The single `done`
   * path burns the scratch on failure as well as success, so no partial secret
   * survives an early return. */
  uint8_t scratch[192] = {0};
  bool ok = false;
  int n = EVP_DecodeBlock(scratch, (const unsigned char*)in, (int)len);
  if (n < 0 || (size_t)n != padded_len)
    goto done;
  memcpy(out, scratch, decoded_len);
  *out_len = decoded_len;
  ok = true;
done:
  credentials_burn((char*)scratch, sizeof(scratch));
  return ok;
}

bool credentials_random_bytes(uint8_t* out, size_t n) {
  if (!out || n == 0 || n > (size_t)INT_MAX)
    return false;
  return RAND_bytes(out, (int)n) == 1;
}

/* HMAC-SHA256 via the OpenSSL 3 EVP_MAC API (HMAC() is deprecated). */
static bool hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len,
                        uint8_t out[CREDENTIAL_KEY_LEN]) {
  EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (!mac)
    return false;
  EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);
  if (!ctx)
    return false;
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA256", 0);
  params[1] = OSSL_PARAM_construct_end();
  size_t out_len = 0;
  bool ok =
      EVP_MAC_init(ctx, key, key_len, params) == 1 && EVP_MAC_update(ctx, data, data_len) == 1 &&
      EVP_MAC_final(ctx, out, &out_len, CREDENTIAL_KEY_LEN) == 1 && out_len == CREDENTIAL_KEY_LEN;
  EVP_MAC_CTX_free(ctx);
  return ok;
}

static bool sha256(const uint8_t* data, size_t len, uint8_t out[CREDENTIAL_KEY_LEN]) {
  unsigned int out_len = 0;
  if (EVP_Digest(data, len, out, &out_len, EVP_sha256(), NULL) != 1)
    return false;
  return out_len == CREDENTIAL_KEY_LEN;
}

bool credentials_compute_keys(const char* password, const uint8_t salt[CREDENTIAL_SALT_LEN],
                              uint32_t iters, uint8_t client_key[CREDENTIAL_KEY_LEN],
                              uint8_t stored_key[CREDENTIAL_KEY_LEN],
                              uint8_t server_key[CREDENTIAL_KEY_LEN]) {
  if (!password || !salt)
    return false;
  /* Enforce the full [MIN,MAX] policy here so no caller can derive a verifier
   * with a work factor outside the validated store range. */
  if (iters < CREDENTIAL_MIN_ITERS || iters > CREDENTIAL_MAX_ITERS)
    return false;
  size_t password_len = strlen(password);
  if (password_len > CREDENTIAL_MAX_PASSWORD_LEN || password_len > (size_t)INT_MAX)
    return false;
  uint8_t k[CREDENTIAL_KEY_LEN];
  if (PKCS5_PBKDF2_HMAC(password, (int)password_len, salt, CREDENTIAL_SALT_LEN, (int)iters,
                        EVP_sha256(), CREDENTIAL_KEY_LEN, k) != 1) {
    credentials_burn((char*)k, sizeof(k));
    return false;
  }
  uint8_t derived_client[CREDENTIAL_KEY_LEN];
  uint8_t derived_server[CREDENTIAL_KEY_LEN];
  bool ok = hmac_sha256(k, sizeof(k), (const uint8_t*)"Client Key", 10, derived_client) &&
            hmac_sha256(k, sizeof(k), (const uint8_t*)"Server Key", 10, derived_server);
  if (ok && stored_key)
    ok = sha256(derived_client, sizeof(derived_client), stored_key);
  if (ok && client_key)
    memcpy(client_key, derived_client, CREDENTIAL_KEY_LEN);
  if (ok && server_key)
    memcpy(server_key, derived_server, CREDENTIAL_KEY_LEN);
  credentials_burn((char*)k, sizeof(k));
  credentials_burn((char*)derived_client, sizeof(derived_client));
  credentials_burn((char*)derived_server, sizeof(derived_server));
  return ok;
}

static void write_be32(uint8_t* out, uint32_t value) {
  out[0] = (uint8_t)(value >> 24);
  out[1] = (uint8_t)(value >> 16);
  out[2] = (uint8_t)(value >> 8);
  out[3] = (uint8_t)value;
}

bool credentials_build_auth_message(const char* user, const uint8_t* snonce, const uint8_t* cnonce,
                                    uint8_t* out, size_t out_sz, size_t* out_len) {
  if (!user || !snonce || !cnonce || !out || !out_len)
    return false;
  size_t user_len = strlen(user);
  if (user_len > CREDENTIAL_MAX_USER_LEN)
    return false;
  size_t total = 16 + 4 + user_len + 4 + CREDENTIAL_NONCE_LEN + 4 + CREDENTIAL_NONCE_LEN;
  if (out_sz < total)
    return false;
  size_t off = 0;
  memcpy(out + off, CREDENTIAL_AUTH_PREFIX, 16);
  off += 16;
  write_be32(out + off, (uint32_t)user_len);
  off += 4;
  memcpy(out + off, user, user_len);
  off += user_len;
  write_be32(out + off, CREDENTIAL_NONCE_LEN);
  off += 4;
  memcpy(out + off, snonce, CREDENTIAL_NONCE_LEN);
  off += CREDENTIAL_NONCE_LEN;
  write_be32(out + off, CREDENTIAL_NONCE_LEN);
  off += 4;
  memcpy(out + off, cnonce, CREDENTIAL_NONCE_LEN);
  off += CREDENTIAL_NONCE_LEN;
  *out_len = off;
  return true;
}

bool credentials_client_proof(const uint8_t client_key[CREDENTIAL_KEY_LEN],
                              const uint8_t stored_key[CREDENTIAL_KEY_LEN],
                              const uint8_t server_key[CREDENTIAL_KEY_LEN], const uint8_t* auth_msg,
                              size_t msg_len, uint8_t proof[CREDENTIAL_KEY_LEN],
                              uint8_t server_sig[CREDENTIAL_KEY_LEN]) {
  if (!client_key || !stored_key || !server_key || !auth_msg || !proof || !server_sig)
    return false;
  uint8_t client_sig[CREDENTIAL_KEY_LEN];
  bool ok = hmac_sha256(stored_key, CREDENTIAL_KEY_LEN, auth_msg, msg_len, client_sig);
  if (ok) {
    for (size_t i = 0; i < CREDENTIAL_KEY_LEN; i++)
      proof[i] = client_key[i] ^ client_sig[i];
    ok = hmac_sha256(server_key, CREDENTIAL_KEY_LEN, auth_msg, msg_len, server_sig);
  }
  credentials_burn((char*)client_sig, sizeof(client_sig));
  return ok;
}

bool credentials_verify_response(const CredentialVerifier* v, const char* user,
                                 const uint8_t* snonce, const uint8_t* cnonce,
                                 const uint8_t proof[CREDENTIAL_KEY_LEN],
                                 uint8_t server_sig_out[CREDENTIAL_KEY_LEN]) {
  if (!v || !user || !snonce || !cnonce || !proof || !server_sig_out)
    return false;
  uint8_t auth_msg[CREDENTIAL_AUTH_MESSAGE_MAX];
  size_t msg_len = 0;
  if (!credentials_build_auth_message(user, snonce, cnonce, auth_msg, sizeof(auth_msg), &msg_len))
    return false;
  uint8_t client_sig[CREDENTIAL_KEY_LEN];
  uint8_t client_key[CREDENTIAL_KEY_LEN];
  uint8_t recovered[CREDENTIAL_KEY_LEN];
  uint8_t server_sig[CREDENTIAL_KEY_LEN];
  bool computed = hmac_sha256(v->stored_key, CREDENTIAL_KEY_LEN, auth_msg, msg_len, client_sig);
  if (computed) {
    for (size_t i = 0; i < CREDENTIAL_KEY_LEN; i++)
      client_key[i] = proof[i] ^ client_sig[i];
    computed = sha256(client_key, CREDENTIAL_KEY_LEN, recovered);
  }
  if (computed)
    computed = hmac_sha256(v->server_key, CREDENTIAL_KEY_LEN, auth_msg, msg_len, server_sig);
  if (computed)
    memcpy(server_sig_out, server_sig, CREDENTIAL_KEY_LEN);
  /* Always run the constant-time key compare (even when `found` is false) and
   * fold the accept decision with bitwise AND so no short-circuit reveals
   * whether the user was found.  A tampered nonce changes the AuthMessage and
   * so the recovered key. */
  bool key_match = false;
  if (computed)
    key_match = credentials_secure_equal((const char*)recovered, (const char*)v->stored_key,
                                         CREDENTIAL_KEY_LEN);
  bool accept = computed & v->found & key_match;
  credentials_burn((char*)auth_msg, sizeof(auth_msg));
  credentials_burn((char*)client_sig, sizeof(client_sig));
  credentials_burn((char*)client_key, sizeof(client_key));
  credentials_burn((char*)recovered, sizeof(recovered));
  credentials_burn((char*)server_sig, sizeof(server_sig));
  return accept;
}

static bool entries_equal(const CredentialEntry* a, const CredentialEntry* b) {
  return a->iters == b->iters &&
         credentials_secure_equal((const char*)a->salt, (const char*)b->salt,
                                  CREDENTIAL_SALT_LEN) &&
         credentials_secure_equal((const char*)a->stored_key, (const char*)b->stored_key,
                                  CREDENTIAL_KEY_LEN) &&
         credentials_secure_equal((const char*)a->server_key, (const char*)b->server_key,
                                  CREDENTIAL_KEY_LEN);
}

static bool append_entry(CredentialStore* store, const char* user, const uint8_t* salt,
                         uint32_t iters, const uint8_t* stored_key, const uint8_t* server_key) {
  if (store->count == store->capacity) {
    int new_capacity = store->capacity == 0 ? 8 : store->capacity * 2;
    CredentialEntry* grown =
        realloc(store->entries, (size_t)new_capacity * sizeof(CredentialEntry));
    if (!grown)
      return false;
    store->entries = grown;
    store->capacity = new_capacity;
  }
  CredentialEntry* entry = &store->entries[store->count];
  memset(entry, 0, sizeof(*entry));
  entry->user = str_dup(user);
  if (!entry->user)
    return false;
  memcpy(entry->salt, salt, CREDENTIAL_SALT_LEN);
  entry->iters = iters;
  memcpy(entry->stored_key, stored_key, CREDENTIAL_KEY_LEN);
  memcpy(entry->server_key, server_key, CREDENTIAL_KEY_LEN);
  store->count++;
  return true;
}

static int find_user(const CredentialStore* store, const char* user) {
  for (int i = 0; i < store->count; i++) {
    if (strcmp(store->entries[i].user, user) == 0)
      return i;
  }
  return -1;
}

/* Parse the new `$fastsync$1$pbkdf2-sha256$...` verifier field in place. */
static bool parse_verifier_secret(char* secret, CredentialEntry* entry, const char* path,
                                  int line_no, const char* user, char* err, size_t err_size) {
  if (secret_is_legacy_hex(secret)) {
    set_error(err, err_size,
              "credential file '%s' line %d: legacy unsalted SHA-256 secret for user '%s' is not "
              "accepted (protocol 2.19.0 uses a salted PBKDF2 verifier); regenerate the store "
              "with --hash-credentials",
              path, line_no, user);
    return false;
  }
  const char* prefix = CREDENTIAL_STORE_PREFIX;
  size_t prefix_len = strlen(prefix);
  if (strncmp(secret, prefix, prefix_len) != 0) {
    set_error(err, err_size,
              "credential file '%s' line %d: expected a '%s...' verifier for user '%s' (regenerate "
              "a legacy line with --hash-credentials)",
              path, line_no, prefix, user);
    return false;
  }
  char* cursor = secret + prefix_len;
  const char* iters_str = cursor;
  char* sep = strchr(cursor, '$');
  if (!sep)
    goto malformed;
  *sep = '\0';
  const char* salt_str = sep + 1;
  sep = strchr(salt_str, '$');
  if (!sep)
    goto malformed;
  *sep = '\0';
  const char* stored_str = sep + 1;
  sep = strchr(stored_str, '$');
  if (!sep)
    goto malformed;
  *sep = '\0';
  const char* server_str = sep + 1;
  if (*iters_str == '\0' || *salt_str == '\0' || *stored_str == '\0' || *server_str == '\0')
    goto malformed;

  char* end = NULL;
  unsigned long parsed = strtoul(iters_str, &end, 10);
  if (!end || *end != '\0' || parsed < CREDENTIAL_MIN_ITERS || parsed > CREDENTIAL_MAX_ITERS)
    goto malformed;
  entry->iters = (uint32_t)parsed;

  size_t decoded = 0;
  if (!credentials_b64_decode(salt_str, entry->salt, CREDENTIAL_SALT_LEN, &decoded) ||
      decoded != CREDENTIAL_SALT_LEN)
    goto malformed;
  if (!credentials_b64_decode(stored_str, entry->stored_key, CREDENTIAL_KEY_LEN, &decoded) ||
      decoded != CREDENTIAL_KEY_LEN)
    goto malformed;
  if (!credentials_b64_decode(server_str, entry->server_key, CREDENTIAL_KEY_LEN, &decoded) ||
      decoded != CREDENTIAL_KEY_LEN)
    goto malformed;
  return true;

malformed:
  set_error(err, err_size,
            "credential file '%s' line %d: malformed verifier for user '%s' (expected "
            "'%s<iters>$<salt_b64>$<stored_key_b64>$<server_key_b64>')",
            path, line_no, user, prefix);
  return false;
}

/* Parse one credential store file into a fresh store.  Duplicate usernames
 * WITHIN one file are an error (ambiguous).  A NULL path yields an empty
 * store. */
static CredentialStore* load_store_file(const char* path, char* err, size_t err_size) {
  CredentialStore* store = calloc(1, sizeof(CredentialStore));
  if (!store) {
    set_error(err, err_size, "out of memory allocating credential store");
    return NULL;
  }
  if (!path)
    return store;

  FILE* fp = secret_file_open(path, err, err_size);
  if (!fp) {
    credentials_free(store);
    return NULL;
  }

  int line_no = 0;
  char line[CREDENTIAL_MAX_LINE + 2];
  bool ok = true;

  while (fgets(line, sizeof(line), fp)) {
    line_no++;
    size_t len = strlen(line);
    if (len == CREDENTIAL_MAX_LINE + 1 && line[len - 1] != '\n' && !feof(fp)) {
      set_error(err, err_size, "credential file '%s' line %d exceeds the %d-byte limit", path,
                line_no, CREDENTIAL_MAX_LINE);
      ok = false;
      break;
    }
    if (len > 0 && line[len - 1] == '\n')
      line[--len] = '\0';
    if (len > 0 && line[len - 1] == '\r')
      line[--len] = '\0';

    char* cursor = line;
    while (*cursor == ' ' || *cursor == '\t')
      cursor++;
    if (*cursor == '\0' || is_comment_char(*cursor))
      continue; /* blank or comment */

    char* colon = strchr(cursor, ':');
    if (!colon) {
      set_error(err, err_size,
                "credential file '%s' line %d: expected 'user:$fastsync$...' (no ':' found)", path,
                line_no);
      ok = false;
      break;
    }
    *colon = '\0';
    const char* user = trim_space(cursor);
    char* secret = trim_space(colon + 1);
    if (!username_wellformed(user)) {
      set_error(err, err_size,
                "credential file '%s' line %d: invalid username (must be 1-%d "
                "non-whitespace characters)",
                path, line_no, CREDENTIAL_MAX_USER_LEN);
      ok = false;
      break;
    }
    CredentialEntry parsed;
    memset(&parsed, 0, sizeof(parsed));
    if (!parse_verifier_secret(secret, &parsed, path, line_no, user, err, err_size)) {
      ok = false;
      break;
    }
    /* Every entry must agree on the iteration count, so a miss can be answered
     * with the store-wide count without leaking membership. */
    if (store->count == 0) {
      store->iters = parsed.iters;
    } else if (store->iters != parsed.iters) {
      set_error(err, err_size,
                "credential file '%s' line %d: iteration count %u disagrees with the store-wide %u "
                "(the store must be uniform)",
                path, line_no, parsed.iters, store->iters);
      ok = false;
      break;
    }
    if (find_user(store, user) >= 0) {
      set_error(err, err_size, "credential file '%s' line %d: duplicate entry for user '%.*s'",
                path, line_no, (int)strlen(user), user);
      ok = false;
      break;
    }
    if (!append_entry(store, user, parsed.salt, parsed.iters, parsed.stored_key,
                      parsed.server_key)) {
      set_error(err, err_size, "out of memory reading credential file '%s'", path);
      ok = false;
      break;
    }
  }

  if (ok && ferror(fp)) {
    set_error(err, err_size, "error reading credential file '%s': %s", path, strerror(errno));
    ok = false;
  }
  fclose(fp);
  credentials_burn(line, sizeof(line));
  if (!ok) {
    credentials_free(store);
    return NULL;
  }
  return store;
}

/* Validate and read an already-open `<store>.dummykey` sidecar.  Fails closed on
 * anything that is not an exact-mode-0600 regular file of exactly
 * CREDENTIAL_KEY_LEN bytes, so a loosened, swapped or truncated file can never
 * silently change the dummy challenge. */
static bool read_dummy_key_fd(int fd, const char* path, uint8_t out[CREDENTIAL_KEY_LEN], char* err,
                              size_t err_size) {
  struct stat st;
  if (fstat(fd, &st) != 0) {
    set_error(err, err_size, "cannot stat dummy key file '%s': %s", path, strerror(errno));
    return false;
  }
  if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 07777) != 0600 ||
      st.st_size != (off_t)CREDENTIAL_KEY_LEN) {
    set_error(err, err_size,
              "refusing to read dummy key file '%s': it must be an owned regular file with exact "
              "mode 0600 and exactly %d bytes",
              path, CREDENTIAL_KEY_LEN);
    return false;
  }
  size_t got = 0;
  while (got < CREDENTIAL_KEY_LEN) {
    ssize_t n = read(fd, out + got, CREDENTIAL_KEY_LEN - got);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      set_error(err, err_size, "cannot read dummy key file '%s': %s", path, strerror(errno));
      return false;
    }
    if (n == 0)
      break;
    got += (size_t)n;
  }
  if (got != CREDENTIAL_KEY_LEN) {
    set_error(err, err_size, "dummy key file '%s' is truncated", path);
    return false;
  }
  return true;
}

/* fsync the directory containing `path` (best effort).  After publishing the
 * sidecar with link(2), syncing the directory makes the new name durable so a
 * crash cannot leave a restart without the key it just started using. */
static void fsync_containing_dir(const char* path) {
  char* dir = str_dup(path);
  if (!dir)
    return;
  char* slash = strrchr(dir, '/');
  if (!slash) {
    free(dir);
    dir = str_dup(".");
    if (!dir)
      return;
  } else if (slash == dir) {
    slash[1] = '\0'; /* keep the leading '/' */
  } else {
    *slash = '\0';
  }
  int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  free(dir);
  if (dfd < 0)
    return;
  fsync(dfd);
  close(dfd);
}

/* Load the persistent dummy key for `store_path` from its `<store_path>.dummykey`
 * sidecar, creating it (exact mode 0600, 32 random bytes) if absent.  A NULL
 * store_path (empty store) yields a fresh ephemeral key.  Reading an existing
 * sidecar fails CLOSED on any validation error; only the CREATE path degrades
 * to an ephemeral key (with a warning) when the filesystem cannot hold the
 * sidecar (e.g. read-only mount), so a daemon still starts.
 *
 * Creation is ATOMIC: the key is written to a private same-directory temp file
 * and hard-linked into place, so a concurrent starter (or reader) never observes
 * a partial/zero sidecar that would fail the load closed.  Returns false only
 * when the CSPRNG itself fails (or a present-but-invalid sidecar is found). */
static bool load_or_create_dummy_key(const char* store_path, uint8_t out[CREDENTIAL_KEY_LEN],
                                     char* err, size_t err_size) {
  if (!store_path) {
    if (!credentials_random_bytes(out, CREDENTIAL_KEY_LEN)) {
      set_error(err, err_size, "failed to generate the credential store dummy key");
      return false;
    }
    return true;
  }

  size_t path_len = strlen(store_path);
  size_t suffix_len = sizeof(CREDENTIAL_DUMMY_KEY_SUFFIX); /* includes the NUL */
  if (path_len > SIZE_MAX - suffix_len) {
    set_error(err, err_size, "credential store path is too long to build a dummy key path");
    return false;
  }
  char* sidecar = malloc(path_len + suffix_len);
  if (!sidecar) {
    set_error(err, err_size, "out of memory building the dummy key path");
    return false;
  }
  int n = snprintf(sidecar, path_len + suffix_len, "%s%s", store_path, CREDENTIAL_DUMMY_KEY_SUFFIX);
  if (n < 0 || (size_t)n >= path_len + suffix_len) {
    set_error(err, err_size, "credential store path is too long to build a dummy key path");
    free(sidecar);
    return false;
  }

  /* Readers reject a planted symlink (O_NOFOLLOW) and never block on a planted
   * FIFO (O_NONBLOCK; fstat rejects the non-regular file before any data read).
   * Any open error other than ENOENT fails closed. */
  int fd = open(sidecar, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd >= 0) {
    bool ok = read_dummy_key_fd(fd, sidecar, out, err, err_size);
    close(fd);
    free(sidecar);
    return ok;
  }
  if (errno != ENOENT) {
    /* The sidecar exists but cannot be opened for reading (EACCES, or ELOOP
     * from a symlink): fail closed rather than substituting a different key. */
    set_error(err, err_size, "cannot open dummy key file '%s': %s", sidecar, strerror(errno));
    free(sidecar);
    return false;
  }

  /* Publish atomically: write a private same-directory temp file, fsync it,
   * then hard-link it into place.  A concurrent reader therefore only ever
   * sees a complete 32-byte sidecar (or none), never a partial/zero file.
   *
   * The temp name carries both the pid and a fresh random suffix, so it is not
   * predictable.  If the name nevertheless already exists (a SIGKILL/crash
   * leftover, pid reuse, or a planted file) the stale temp is removed and the
   * O_EXCL create is retried once, so it can never silently defeat persistence
   * for this pid. */
  uint8_t fresh[CREDENTIAL_KEY_LEN];
  if (!credentials_random_bytes(fresh, CREDENTIAL_KEY_LEN)) {
    set_error(err, err_size, "failed to generate the credential store dummy key");
    free(sidecar);
    return false;
  }

  uint8_t name_rand[8];
  if (!credentials_random_bytes(name_rand, sizeof(name_rand))) {
    set_error(err, err_size, "failed to generate the dummy key temp name");
    free(sidecar);
    credentials_burn((char*)fresh, sizeof(fresh));
    return false;
  }
  char name_hex[sizeof(name_rand) * 2 + 1];
  static const char hex_digits[] = "0123456789abcdef";
  for (size_t i = 0; i < sizeof(name_rand); i++) {
    name_hex[2 * i] = hex_digits[name_rand[i] >> 4];
    name_hex[2 * i + 1] = hex_digits[name_rand[i] & 0x0f];
  }
  name_hex[sizeof(name_hex) - 1] = '\0';

  char tmp_suffix[64];
  int pn = snprintf(tmp_suffix, sizeof(tmp_suffix), ".tmp.%ld.%s", (long)getpid(), name_hex);
  if (pn < 0 || (size_t)pn >= sizeof(tmp_suffix)) {
    set_error(err, err_size, "failed to build the dummy key temp path");
    free(sidecar);
    credentials_burn((char*)fresh, sizeof(fresh));
    return false;
  }
  size_t sidecar_len = (size_t)n;
  size_t tmp_len = sidecar_len + (size_t)pn;
  char* tmp = malloc(tmp_len + 1);
  if (!tmp) {
    set_error(err, err_size, "out of memory building the dummy key temp path");
    free(sidecar);
    credentials_burn((char*)fresh, sizeof(fresh));
    return false;
  }
  snprintf(tmp, tmp_len + 1, "%s%s", sidecar, tmp_suffix);

  /* Bounded create: at most one unlink+retry on EEXIST.  The retry keeps
   * O_EXCL, so only a stale name is reclaimed and a live peer's temp is never
   * truncated. */
  int create_errno = 0;
  for (int attempt = 0; attempt < 2; attempt++) {
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd >= 0)
      break;
    create_errno = errno;
    if (create_errno != EEXIST || attempt == 1)
      break;
    unlink(tmp);
  }
  /* umask can clear owner bits from the 0600 create mode while the reader
   * requires an exact 0600, so force the mode on the fd before publishing; a
   * failure here is treated like any other create failure (warning + ephemeral
   * key) so the published sidecar is always exactly 0600. */
  if (fd >= 0 && fchmod(fd, 0600) != 0) {
    create_errno = errno;
    close(fd);
    unlink(tmp);
    fd = -1;
  }
  if (fd < 0) {
    /* Creation failed (read-only filesystem, missing directory, fchmod, ...).
     * Warn and fall back to an ephemeral key: unknown-user challenges stay
     * deterministic within this daemon lifetime but will change on restart. */
    char* escaped = output_escape(tmp, log_get_8_bit_output());
    log_message(LOG_LEVEL_WARNING,
                "cannot create dummy key file %s: %s; using a transient dummy key so unknown-user "
                "challenges will change across restarts",
                escaped ? escaped : tmp, strerror(create_errno));
    free(escaped);
    memcpy(out, fresh, CREDENTIAL_KEY_LEN);
    free(tmp);
    free(sidecar);
    credentials_burn((char*)fresh, sizeof(fresh));
    return true;
  }

  size_t written = 0;
  bool write_ok = true;
  int write_errno = 0;
  while (written < CREDENTIAL_KEY_LEN) {
    ssize_t w = write(fd, fresh + written, CREDENTIAL_KEY_LEN - written);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      write_ok = false;
      write_errno = errno;
      break;
    }
    if (w == 0) {
      /* A zero-length write is not a system error; errno is stale here, so
       * report a clear short-write instead of a bogus strerror(errno). */
      write_ok = false;
      write_errno = 0;
      break;
    }
    written += (size_t)w;
  }
  if (write_ok && fsync(fd) != 0) {
    write_ok = false;
    write_errno = errno;
  }
  close(fd);
  if (!write_ok) {
    /* Do not leave a truncated temp file behind; fall back to an ephemeral key
     * instead of failing closed on the next restart. */
    unlink(tmp);
    char* escaped = output_escape(tmp, log_get_8_bit_output());
    const char* why = write_errno != 0 ? strerror(write_errno) : "short write";
    log_message(LOG_LEVEL_WARNING,
                "cannot write dummy key file %s: %s; using a transient dummy key so unknown-user "
                "challenges will change across restarts",
                escaped ? escaped : tmp, why);
    free(escaped);
    memcpy(out, fresh, CREDENTIAL_KEY_LEN);
    free(tmp);
    free(sidecar);
    credentials_burn((char*)fresh, sizeof(fresh));
    return true;
  }

  if (link(tmp, sidecar) != 0) {
    int link_errno = errno;
    if (link_errno == EEXIST) {
      /* A concurrent starter published first; adopt its key.  Read it back
       * through the same hardened path (no symlink, no block, exact mode). */
      int rfd = open(sidecar, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
      if (rfd < 0) {
        set_error(err, err_size, "cannot open dummy key file '%s': %s", sidecar, strerror(errno));
        unlink(tmp);
        free(tmp);
        free(sidecar);
        credentials_burn((char*)fresh, sizeof(fresh));
        return false;
      }
      bool ok = read_dummy_key_fd(rfd, sidecar, out, err, err_size);
      close(rfd);
      unlink(tmp);
      free(tmp);
      free(sidecar);
      credentials_burn((char*)fresh, sizeof(fresh));
      return ok;
    }
    /* Linking failed for another reason (e.g. no hard-link support on this
     * filesystem).  Warn and fall back to an ephemeral key. */
    unlink(tmp);
    char* escaped = output_escape(sidecar, log_get_8_bit_output());
    log_message(LOG_LEVEL_WARNING,
                "cannot publish dummy key file %s: %s; using a transient dummy key so unknown-user "
                "challenges will change across restarts",
                escaped ? escaped : sidecar, strerror(link_errno));
    free(escaped);
    memcpy(out, fresh, CREDENTIAL_KEY_LEN);
    free(tmp);
    free(sidecar);
    credentials_burn((char*)fresh, sizeof(fresh));
    return true;
  }

  /* Published: make the new directory entry durable, then drop the private
   * temp name (the sidecar keeps the inode alive). */
  fsync_containing_dir(sidecar);
  unlink(tmp);
  memcpy(out, fresh, CREDENTIAL_KEY_LEN);
  free(tmp);
  free(sidecar);
  credentials_burn((char*)fresh, sizeof(fresh));
  return true;
}

CredentialStore* credentials_load(const char* password_file, const char* early_input_file,
                                  char* err, size_t err_size) {
  if (err && err_size)
    err[0] = '\0';
  CredentialStore* store = load_store_file(password_file, err, err_size);
  if (!store)
    return NULL;
  /* Load (or create) the store-wide dummy key once for the final (possibly
   * merged) store.  It makes an unknown-user challenge deterministic AND
   * stable across daemon restarts, so a restart cannot be used as a
   * username-enumeration oracle.  It is persisted in an exact-mode-0600 sidecar
   * next to the credential store; a NULL store path (empty store) keeps it
   * ephemeral.  Fail the load if the CSPRNG is unavailable rather than
   * degrading the anti-enumeration property. */
  const char* store_path = password_file ? password_file : early_input_file;
  if (!load_or_create_dummy_key(store_path, store->dummy_key, err, err_size)) {
    credentials_free(store);
    return NULL;
  }
  if (!early_input_file)
    return store;

  CredentialStore* early = load_store_file(early_input_file, err, err_size);
  if (!early) {
    credentials_free(store);
    return NULL;
  }
  /* A layered store must stay uniform too. */
  if (store->count > 0 && early->count > 0 && store->iters != early->iters) {
    set_error(err, err_size,
              "credential file '%s' and early-input file '%s' disagree on the iteration count "
              "(%u vs %u); the store must be uniform",
              password_file, early_input_file, store->iters, early->iters);
    credentials_free(early);
    credentials_free(store);
    return NULL;
  }
  if (store->count == 0 && early->count > 0)
    store->iters = early->iters;
  /* Layer early input over the password file: an identical verifier dedupes, a
   * differing verifier for the same user is ambiguous and fails closed. */
  for (int i = 0; i < early->count; i++) {
    int existing = find_user(store, early->entries[i].user);
    if (existing >= 0) {
      if (!entries_equal(&store->entries[existing], &early->entries[i])) {
        set_error(err, err_size,
                  "credential file '%s' and early-input file '%s' disagree on the verifier for "
                  "user '%s'",
                  password_file, early_input_file, early->entries[i].user);
        credentials_free(early);
        credentials_free(store);
        return NULL;
      }
      continue; /* identical; nothing to merge */
    }
    if (!append_entry(store, early->entries[i].user, early->entries[i].salt,
                      early->entries[i].iters, early->entries[i].stored_key,
                      early->entries[i].server_key)) {
      set_error(err, err_size, "out of memory merging early-input credentials");
      credentials_free(early);
      credentials_free(store);
      return NULL;
    }
  }
  credentials_free(early);
  return store;
}

void credentials_free(CredentialStore* store) {
  if (!store)
    return;
  for (int i = 0; i < store->count; i++) {
    /* Wipe the derived keys before releasing the entry (A7-4). */
    credentials_burn((char*)store->entries[i].salt, CREDENTIAL_SALT_LEN);
    credentials_burn((char*)store->entries[i].stored_key, CREDENTIAL_KEY_LEN);
    credentials_burn((char*)store->entries[i].server_key, CREDENTIAL_KEY_LEN);
    free(store->entries[i].user);
  }
  /* The store-wide dummy key is secret (it shapes the miss challenge), so wipe
   * it before releasing the store. */
  credentials_burn((char*)store->dummy_key, sizeof(store->dummy_key));
  free(store->entries);
  free(store);
}

int credentials_store_size(const CredentialStore* store) {
  return store ? store->count : 0;
}

bool credentials_store_has(const CredentialStore* store, const char* user) {
  return store && find_user(store, user) >= 0;
}

bool credentials_secure_equal(const char* a, const char* b, size_t len) {
  unsigned char diff = 0;
  for (size_t i = 0; i < len; i++)
    diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
  return diff == 0;
}

/* Constant-time equality over two usernames.  Compares a fixed
 * CREDENTIAL_MAX_USER_LEN-byte window (padding with zeros past each string's
 * own length) and folds the length difference into the accumulator, so no byte
 * returns early.  This closes the byte-wise username-enumeration timing oracle
 * that a plain strcmp (which short-circuits on the first differing byte)
 * would otherwise expose.  Over-long inputs are refused (length differs), which
 * is a non-secret branch: usernames are bounded in every caller anyway. */
static bool username_secure_equal(const char* a, const char* b) {
  size_t alen = strlen(a);
  size_t blen = strlen(b);
  if (alen > CREDENTIAL_MAX_USER_LEN || blen > CREDENTIAL_MAX_USER_LEN)
    return false;
  size_t diff = alen ^ blen;
  for (size_t i = 0; i < CREDENTIAL_MAX_USER_LEN; i++) {
    unsigned char ac = i < alen ? (unsigned char)a[i] : 0u;
    unsigned char bc = i < blen ? (unsigned char)b[i] : 0u;
    diff |= (size_t)(ac ^ bc);
  }
  return diff == 0;
}

bool credentials_get_verifier(const CredentialStore* store, const char* user,
                              const char* const* module_users, int n, CredentialVerifier* out) {
  if (!out)
    return false;
  memset(out, 0, sizeof(*out));
  const char* uname = user ? user : "";
  /* The dummy verifier is shaped exactly like a hit: the store-wide uniform
   * iteration count (default for an empty store) and fixed dummy keys. */
  out->iters = (store && store->count > 0) ? store->iters : CREDENTIAL_DEFAULT_ITERS;
  memcpy(out->stored_key, k_dummy_stored_key, CREDENTIAL_KEY_LEN);
  memcpy(out->server_key, k_dummy_server_key, CREDENTIAL_KEY_LEN);
  out->found = false;
  /* Deterministic per-username dummy salt: HMAC-SHA256(dummy_key, username)
   * truncated to the salt length.  Two probes of the same unknown username see
   * an identical challenge; distinct usernames differ.  A NULL store (never
   * reached in production) falls back to the all-zero static key. */
  const uint8_t* dummy_key = store ? store->dummy_key : k_dummy_stored_key;
  uint8_t mac[CREDENTIAL_KEY_LEN];
  if (!hmac_sha256(dummy_key, CREDENTIAL_KEY_LEN, (const uint8_t*)uname, strlen(uname), mac)) {
    credentials_burn((char*)mac, sizeof(mac));
    return false;
  }
  memcpy(out->salt, mac, CREDENTIAL_SALT_LEN);
  credentials_burn((char*)mac, sizeof(mac));
  /* Module-list membership: constant-time full scan, no early break, so the
   * list is not a username-enumeration oracle. */
  bool on_list = false;
  for (int i = 0; i < n; i++) {
    const char* listed = (module_users && user) ? module_users[i] : NULL;
    on_list |= listed ? username_secure_equal(listed, user) : false;
  }
  /* Store lookup is an unconditional constant-time full scan, executed even for
   * an off-list user so a probe that is not on the module list still pays the
   * same O(store) cost as one that is; skipping it would reopen an off-list
   * timing channel.  The real verifier is selected only when the user is both
   * on the list and matched in the store. */
  const CredentialEntry* match = NULL;
  for (int i = 0; store && user && i < store->count; i++) {
    if (username_secure_equal(store->entries[i].user, user))
      match = &store->entries[i];
  }
  if (on_list && match) {
    memcpy(out->salt, match->salt, CREDENTIAL_SALT_LEN);
    out->iters = match->iters;
    memcpy(out->stored_key, match->stored_key, CREDENTIAL_KEY_LEN);
    memcpy(out->server_key, match->server_key, CREDENTIAL_KEY_LEN);
    out->found = true;
  }
  return true;
}

bool credentials_hash_store_line(const char* user, const char* password, uint32_t iters, char* out,
                                 size_t out_sz, char* err, size_t err_size) {
  if (err && err_size)
    err[0] = '\0';
  if (!username_wellformed(user)) {
    set_error(err, err_size, "invalid username (1-%d non-whitespace characters)",
              CREDENTIAL_MAX_USER_LEN);
    return false;
  }
  if (!password || !out || out_sz == 0) {
    set_error(err, err_size, "missing password or output buffer");
    return false;
  }
  if (strlen(password) > CREDENTIAL_MAX_PASSWORD_LEN) {
    set_error(err, err_size, "password exceeds %d characters", CREDENTIAL_MAX_PASSWORD_LEN);
    return false;
  }
  if (iters < CREDENTIAL_MIN_ITERS || iters > CREDENTIAL_MAX_ITERS) {
    set_error(err, err_size, "iterations %u out of range [%u,%u]", iters, CREDENTIAL_MIN_ITERS,
              CREDENTIAL_MAX_ITERS);
    return false;
  }
  uint8_t salt[CREDENTIAL_SALT_LEN];
  uint8_t client_key[CREDENTIAL_KEY_LEN];
  uint8_t stored_key[CREDENTIAL_KEY_LEN];
  uint8_t server_key[CREDENTIAL_KEY_LEN];
  char salt_b64[25];
  char stored_b64[45];
  char server_b64[45];
  bool ok =
      credentials_random_bytes(salt, sizeof(salt)) &&
      credentials_compute_keys(password, salt, iters, client_key, stored_key, server_key) &&
      credentials_b64_encode(salt, sizeof(salt), salt_b64, sizeof(salt_b64)) &&
      credentials_b64_encode(stored_key, sizeof(stored_key), stored_b64, sizeof(stored_b64)) &&
      credentials_b64_encode(server_key, sizeof(server_key), server_b64, sizeof(server_b64));
  int written = -1;
  if (ok) {
    written = snprintf(out, out_sz, "%s:%s%u$%s$%s$%s", user, CREDENTIAL_STORE_PREFIX, iters,
                       salt_b64, stored_b64, server_b64);
  }
  credentials_burn((char*)client_key, sizeof(client_key));
  credentials_burn((char*)stored_key, sizeof(stored_key));
  credentials_burn((char*)server_key, sizeof(server_key));
  credentials_burn((char*)salt, sizeof(salt));
  /* The base64 encodings of the salt/keys are secret material too (A7-4). */
  credentials_burn(salt_b64, sizeof(salt_b64));
  credentials_burn(stored_b64, sizeof(stored_b64));
  credentials_burn(server_b64, sizeof(server_b64));
  if (!ok) {
    credentials_burn(out, out_sz);
    return false;
  }
  if (written < 0 || (size_t)written >= out_sz) {
    set_error(err, err_size, "output buffer too small for the credential line");
    credentials_burn(out, out_sz);
    return false;
  }
  return true;
}

int credentials_hash_file(const char* path, uint32_t iters, FILE* out, char* err, size_t err_size) {
  if (err && err_size)
    err[0] = '\0';
  if (!path || !out) {
    set_error(err, err_size, "missing plaintext file or output stream");
    return -1;
  }
  if (iters < CREDENTIAL_MIN_ITERS || iters > CREDENTIAL_MAX_ITERS) {
    set_error(err, err_size, "iterations %u out of range [%u,%u]", iters, CREDENTIAL_MIN_ITERS,
              CREDENTIAL_MAX_ITERS);
    return -1;
  }
  FILE* fp = secret_file_open(path, err, err_size);
  if (!fp)
    return -1;
  int line_no = 0;
  int result = 0;
  char line[CREDENTIAL_MAX_LINE + 2];
  while (fgets(line, sizeof(line), fp)) {
    line_no++;
    size_t len = strlen(line);
    if (len == CREDENTIAL_MAX_LINE + 1 && line[len - 1] != '\n' && !feof(fp)) {
      set_error(err, err_size, "plaintext file '%s' line %d exceeds the %d-byte limit", path,
                line_no, CREDENTIAL_MAX_LINE);
      result = -1;
      break;
    }
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      line[--len] = '\0';
    char* cursor = line;
    while (*cursor == ' ' || *cursor == '\t')
      cursor++;
    if (*cursor == '\0' || is_comment_char(*cursor))
      continue;
    char* colon = strchr(cursor, ':');
    if (!colon) {
      set_error(err, err_size, "plaintext file '%s' line %d: expected 'user:password'", path,
                line_no);
      result = -1;
      break;
    }
    *colon = '\0';
    const char* user = trim_space(cursor);
    const char* password = colon + 1;
    if (!username_wellformed(user)) {
      set_error(err, err_size, "plaintext file '%s' line %d: invalid username", path, line_no);
      result = -1;
      break;
    }
    if (*password == '\0') {
      set_error(err, err_size, "plaintext file '%s' line %d: empty password", path, line_no);
      result = -1;
      break;
    }
    char store_line[CREDENTIAL_MAX_LINE];
    if (!credentials_hash_store_line(user, password, iters, store_line, sizeof(store_line), err,
                                     err_size)) {
      credentials_burn(store_line, sizeof(store_line));
      result = -1;
      break;
    }
    if (fprintf(out, "%s\n", store_line) < 0) {
      set_error(err, err_size, "cannot write hashed credentials: %s", strerror(errno));
      credentials_burn(store_line, sizeof(store_line));
      result = -1;
      break;
    }
    credentials_burn(store_line, sizeof(store_line));
  }
  if (result == 0 && ferror(fp)) {
    set_error(err, err_size, "error reading plaintext file '%s': %s", path, strerror(errno));
    result = -1;
  }
  credentials_burn(line, sizeof(line));
  fclose(fp);
  return result;
}

int credentials_read_secret_file(const char* path, char** user_out, char** password_out, char* err,
                                 size_t err_size) {
  if (user_out)
    *user_out = NULL;
  if (password_out)
    *password_out = NULL;
  if (err && err_size)
    err[0] = '\0';
  if (!path) {
    set_error(err, err_size, "no --password-file path");
    return -1;
  }
  FILE* fp = secret_file_open(path, err, err_size);
  if (!fp)
    return -1;

  int line_no = 0;
  char line[CREDENTIAL_MAX_LINE + 2];
  int result = -1;

  while (fgets(line, sizeof(line), fp)) {
    line_no++;
    size_t len = strlen(line);
    if (len == CREDENTIAL_MAX_LINE + 1 && line[len - 1] != '\n' && !feof(fp)) {
      set_error(err, err_size, "password file '%s' line %d exceeds the %d-byte limit", path,
                line_no, CREDENTIAL_MAX_LINE);
      goto done;
    }
    if (len > 0 && line[len - 1] == '\n')
      line[--len] = '\0';
    if (len > 0 && line[len - 1] == '\r')
      line[--len] = '\0';

    char* cursor = line;
    while (*cursor == ' ' || *cursor == '\t')
      cursor++;
    if (*cursor == '\0' || is_comment_char(*cursor))
      continue; /* skip blank/comment lines; the first real line is the secret */

    char* colon = strchr(cursor, ':');
    if (!colon) {
      set_error(err, err_size,
                "password file '%s' line %d: expected 'user:password' (no ':' found)", path,
                line_no);
      goto done;
    }
    *colon = '\0';
    const char* user = trim_space(cursor);
    /* Preserve the password's exact bytes: only the line's trailing CR/LF was
     * already stripped above.  Trimming leading/trailing space here would make
     * a password that legitimately begins or ends with whitespace unusable. */
    const char* password = colon + 1;
    if (!username_wellformed(user)) {
      set_error(err, err_size,
                "password file '%s' line %d: invalid username (must be 1-%d "
                "non-whitespace characters)",
                path, line_no, CREDENTIAL_MAX_USER_LEN);
      goto done;
    }
    if (*password == '\0') {
      set_error(err, err_size, "password file '%s' line %d: empty password", path, line_no);
      goto done;
    }
    if (strlen(password) > CREDENTIAL_MAX_PASSWORD_LEN) {
      set_error(err, err_size, "password file '%s' line %d: password exceeds %d characters", path,
                line_no, CREDENTIAL_MAX_PASSWORD_LEN);
      goto done;
    }
    char* user_dup = str_dup(user);
    char* password_dup = str_dup(password);
    if (!user_dup || !password_dup) {
      free(user_dup);
      free(password_dup);
      set_error(err, err_size, "out of memory reading password file '%s'", path);
      goto done;
    }
    if (user_out)
      *user_out = user_dup;
    else
      free(user_dup);
    if (password_out)
      *password_out = password_dup;
    else
      free(password_dup);
    result = 0;
    goto done;
  }

  if (ferror(fp)) {
    set_error(err, err_size, "error reading password file '%s': %s", path, strerror(errno));
    goto done;
  }
  /* Reached end of file with no meaningful line: the file is empty (or only
   * comments), which the client policy rejects. */
  set_error(err, err_size, "password file '%s' contains no 'user:password' line", path);

done:
  /* Wipe the stack line (which may hold the literal password) before return.
   * user/password were str_dup'd into their outputs on success, so the stack
   * copy is the only remaining plaintext. */
  credentials_burn(line, sizeof(line));
  fclose(fp);
  return result;
}

void credentials_burn(char* secret, size_t len) {
  if (!secret)
    return;
  volatile char* p = (volatile char*)secret;
  for (size_t i = 0; i < len; i++)
    p[i] = '\0';
}
