#include "credentials.h"
#include "utils.h"
#include <ctype.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One store entry: a username and its password's SHA-256 hex digest.  The
 * plaintext password never appears here (and never on the daemon host). */
typedef struct CredentialEntry {
  char* user;
  char* password_hex; /* CREDENTIAL_HASH_HEX_LEN lowercase hex chars */
} CredentialEntry;

struct CredentialStore {
  CredentialEntry* entries;
  int count;
  int capacity;
};

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

static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

bool credentials_hash_valid(const char* hash_hex) {
  if (!hash_hex)
    return false;
  for (int i = 0; i < CREDENTIAL_HASH_HEX_LEN; i++) {
    if (hex_value(hash_hex[i]) < 0)
      return false;
  }
  return hash_hex[CREDENTIAL_HASH_HEX_LEN] == '\0';
}

static bool append_entry(CredentialStore* store, const char* user, const char* password_hex) {
  if (store->count == store->capacity) {
    int new_capacity = store->capacity == 0 ? 8 : store->capacity * 2;
    CredentialEntry* grown =
        realloc(store->entries, (size_t)new_capacity * sizeof(CredentialEntry));
    if (!grown)
      return false;
    store->entries = grown;
    store->capacity = new_capacity;
  }
  store->entries[store->count].user = str_dup(user);
  store->entries[store->count].password_hex = str_dup(password_hex);
  if (!store->entries[store->count].user || !store->entries[store->count].password_hex) {
    free(store->entries[store->count].user);
    free(store->entries[store->count].password_hex);
    store->entries[store->count].user = NULL;
    store->entries[store->count].password_hex = NULL;
    return false;
  }
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

/* Parse one credential store file (user:SHA256HEX per line) into a fresh
 * store.  Duplicate usernames WITHIN one file are an error (ambiguous).  A
 * NULL path yields an empty store. */
static CredentialStore* load_store_file(const char* path, char* err, size_t err_size) {
  CredentialStore* store = calloc(1, sizeof(CredentialStore));
  if (!store) {
    set_error(err, err_size, "out of memory allocating credential store");
    return NULL;
  }
  if (!path)
    return store;

  FILE* fp = fopen(path, "r");
  if (!fp) {
    set_error(err, err_size, "cannot open credential file '%s': %s", path, strerror(errno));
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
                "credential file '%s' line %d: expected 'user:SHA256HEX' (no ':' found)", path,
                line_no);
      ok = false;
      break;
    }
    *colon = '\0';
    const char* user = trim_space(cursor);
    const char* secret = trim_space(colon + 1);
    if (!username_wellformed(user)) {
      set_error(err, err_size,
                "credential file '%s' line %d: invalid username (must be 1-%d "
                "non-whitespace characters)",
                path, line_no, CREDENTIAL_MAX_USER_LEN);
      ok = false;
      break;
    }
    if (!credentials_hash_valid(secret)) {
      set_error(err, err_size,
                "credential file '%s' line %d: secret for user '%s' must be %d "
                "lowercase hex characters (the SHA-256 of the password)",
                path, line_no, user, CREDENTIAL_HASH_HEX_LEN);
      ok = false;
      break;
    }
    if (find_user(store, user) >= 0) {
      set_error(err, err_size, "credential file '%s' line %d: duplicate entry for user '%.*s'",
                path, line_no, (int)strlen(user), user);
      ok = false;
      break;
    }
    if (!append_entry(store, user, secret)) {
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
  if (!ok) {
    credentials_free(store);
    return NULL;
  }
  return store;
}

CredentialStore* credentials_load(const char* password_file, const char* early_input_file,
                                  char* err, size_t err_size) {
  if (err && err_size)
    err[0] = '\0';
  CredentialStore* store = load_store_file(password_file, err, err_size);
  if (!store)
    return NULL;
  if (!early_input_file)
    return store;

  CredentialStore* early = load_store_file(early_input_file, err, err_size);
  if (!early) {
    credentials_free(store);
    return NULL;
  }
  /* Layer early input over the password file: same secret dedupes, a differing
   * secret for the same user is ambiguous and fails closed. */
  for (int i = 0; i < early->count; i++) {
    int existing = find_user(store, early->entries[i].user);
    if (existing >= 0) {
      if (strcmp(store->entries[existing].password_hex, early->entries[i].password_hex) != 0) {
        set_error(err, err_size,
                  "credential file '%s' and early-input file '%s' disagree on the secret for "
                  "user '%s'",
                  password_file, early_input_file, early->entries[i].user);
        credentials_free(early);
        credentials_free(store);
        return NULL;
      }
      continue; /* identical; nothing to merge */
    }
    if (!append_entry(store, early->entries[i].user, early->entries[i].password_hex)) {
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
    free(store->entries[i].user);
    free(store->entries[i].password_hex);
  }
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

bool credentials_hash_password(const char* password, char* out_hex) {
  if (!password || !out_hex)
    return false;
  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;
  if (EVP_Digest(password, strlen(password), digest, &digest_len, EVP_sha256(), NULL) != 1)
    return false;
  if (digest_len != 32)
    return false;
  static const char hex[] = "0123456789abcdef";
  for (unsigned int i = 0; i < digest_len; i++) {
    out_hex[2 * i] = hex[digest[i] >> 4];
    out_hex[2 * i + 1] = hex[digest[i] & 0x0f];
  }
  out_hex[2 * digest_len] = '\0';
  return true;
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
  FILE* fp = fopen(path, "r");
  if (!fp) {
    set_error(err, err_size, "cannot open password file '%s': %s", path, strerror(errno));
    return -1;
  }

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
    const char* password = trim_space(colon + 1);
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

/* Fixed 64-lowercase-hex dummy used for a constant-time digest comparison when
 * the presented user is unknown, so the verify path takes the same time for an
 * unknown user and a wrong password.  Value chosen arbitrarily; it can never
 * authenticate because a real store entry is preferred when it exists. */
static const char k_dummy_hash[CREDENTIAL_HASH_HEX_LEN + 1] =
    "0000000000000000000000000000000000000000000000000000000000000000";

bool credentials_verify(const CredentialStore* store, const char* user,
                        const char* presented_hash_hex) {
  if (!store || !user || !presented_hash_hex || !credentials_hash_valid(presented_hash_hex))
    return false;
  const char* stored = k_dummy_hash;
  for (int i = 0; i < store->count; i++) {
    if (strcmp(store->entries[i].user, user) == 0)
      stored = store->entries[i].password_hex;
  }
  return credentials_secure_equal(presented_hash_hex, stored, CREDENTIAL_HASH_HEX_LEN);
}

bool credentials_gate_allows(const CredentialStore* store, const char* const* module_users,
                             int module_user_count, const char* presented_user,
                             const char* presented_hash_hex) {
  if (!store || module_user_count < 0)
    return false; /* fail closed: an auth-required module without a store refuses */
  if (!presented_user || !presented_hash_hex)
    return false; /* no credentials presented */
  bool on_module_list = false;
  for (int i = 0; i < module_user_count; i++) {
    if (module_users[i] && strcmp(module_users[i], presented_user) == 0) {
      on_module_list = true;
      break;
    }
  }
  if (!on_module_list)
    return false;
  return credentials_verify(store, presented_user, presented_hash_hex);
}
