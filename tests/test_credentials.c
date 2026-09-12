#include "test_credentials.h"
#include "credentials.h"
#include "test_utils.h"
#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Known-answer vector, independently recomputed with Python
 * (hashlib.pbkdf2_hmac / hmac / hashlib.sha256). */
#define KAT_PASSWORD "alice-s3cret"
#define KAT_USER "alice"
#define KAT_ITERS 4096u
#define KAT_CLIENT_KEY "80f0e0af43e34e8aeec1738609c5d1eac8646601b4f244cef5a04a9f13563cf8"
#define KAT_STORED_KEY "5b3b489437085a11fe594ab99154da4cb4ebab4ae8c2edf51fbaa9277e9f9099"
#define KAT_SERVER_KEY "38f668736210bd4dbcb5193b9a514c5b1047174eff5f5a80ee4c2b1e8b2c76a1"
#define KAT_CLIENT_PROOF "c9b0d397b853176b842a751b9af327270ae0c5e286cb77d16e59fa42245270f6"
#define KAT_SERVER_SIG "93c0d94b9ee29798ffd42734a9becb2168bad1f69e492d2ccb042a43db13bffc"
#define KAT_SALT_B64 "AAECAwQFBgcICQoLDA0ODw=="
#define KAT_NAME_PREFIX "$fastsync$1$pbkdf2-sha256$"

static int g_file_counter = 0;

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static void unhex(const char* hex, uint8_t* out, size_t out_len) {
  for (size_t i = 0; i < out_len; i++)
    out[i] = (uint8_t)((hex_nibble(hex[2 * i]) << 4) | hex_nibble(hex[2 * i + 1]));
}

/* Fill deterministic nonces: out[i] = first + i. */
static void ramp(uint8_t* out, size_t len, uint8_t first) {
  for (size_t i = 0; i < len; i++)
    out[i] = (uint8_t)(first + i);
}

static char* make_tmp_file(const char* contents) {
  char path[256];
  snprintf(path, sizeof(path), "/tmp/fs_cred_test_%d_%d", (int)getpid(), g_file_counter++);
  FILE* fp = fopen(path, "w");
  if (!fp)
    return NULL;
  size_t n = strlen(contents);
  if (n > 0 && fwrite(contents, 1, n, fp) != n) {
    fclose(fp);
    unlink(path);
    return NULL;
  }
  fclose(fp);
  /* Credential/password files are owner-only; the reader rejects group/other
   * permission bits, so create temp files 0600 like the real ones. */
  chmod(path, 0600);
  return str_dup(path);
}

static void rm_temp(const char* path) {
  if (path)
    unlink(path);
}

/* Build a valid new-format line for user/password at iters. */
static bool make_store_line(const char* user, const char* password, uint32_t iters, char* out,
                            size_t out_sz) {
  char err[256];
  return credentials_hash_store_line(user, password, iters, out, out_sz, err, sizeof(err));
}

static void test_credentials_secure_equal() {
  EXPECT_TRUE(credentials_secure_equal("abc", "abc", 3));
  EXPECT_TRUE(credentials_secure_equal("", "", 0));
  EXPECT_FALSE(credentials_secure_equal("abc", "abd", 3));
  EXPECT_TRUE(credentials_secure_equal("abc", "ab", 2));
  EXPECT_FALSE(credentials_secure_equal("ab", "ac", 2));
}

static void test_credentials_b64() {
  uint8_t salt[CREDENTIAL_SALT_LEN];
  ramp(salt, sizeof(salt), 0x00);
  char encoded[25];
  EXPECT_TRUE(credentials_b64_encode(salt, sizeof(salt), encoded, sizeof(encoded)));
  EXPECT_EQ_STR(encoded, KAT_SALT_B64);

  uint8_t decoded[CREDENTIAL_SALT_LEN];
  size_t decoded_len = 0;
  EXPECT_TRUE(credentials_b64_decode(encoded, decoded, sizeof(decoded), &decoded_len));
  EXPECT_EQ_INT((int)decoded_len, CREDENTIAL_SALT_LEN);
  EXPECT_TRUE(memcmp(decoded, salt, sizeof(salt)) == 0);

  /* Malformed input is refused: bad length, bad alphabet, missing buffer. */
  EXPECT_FALSE(credentials_b64_decode("abc", decoded, sizeof(decoded), &decoded_len));
  EXPECT_FALSE(credentials_b64_decode("!!!!", decoded, sizeof(decoded), &decoded_len));
  EXPECT_FALSE(credentials_b64_decode("", decoded, sizeof(decoded), &decoded_len));
  EXPECT_FALSE(credentials_b64_decode(KAT_SALT_B64, decoded, 4, &decoded_len));
  EXPECT_FALSE(credentials_b64_decode(NULL, decoded, sizeof(decoded), &decoded_len));
  EXPECT_FALSE(credentials_b64_encode(NULL, 3, encoded, sizeof(encoded)));
  EXPECT_FALSE(credentials_b64_encode(salt, sizeof(salt), encoded, 3));
}

static void test_credentials_random_bytes() {
  uint8_t a[CREDENTIAL_NONCE_LEN];
  uint8_t b[CREDENTIAL_NONCE_LEN];
  EXPECT_TRUE(credentials_random_bytes(a, sizeof(a)));
  EXPECT_TRUE(credentials_random_bytes(b, sizeof(b)));
  EXPECT_TRUE(memcmp(a, b, sizeof(a)) != 0);
  EXPECT_FALSE(credentials_random_bytes(NULL, 4));
}

static void test_credentials_compute_keys_kat() {
  uint8_t salt[CREDENTIAL_SALT_LEN];
  ramp(salt, sizeof(salt), 0x00);
  uint8_t client_key[CREDENTIAL_KEY_LEN];
  uint8_t stored_key[CREDENTIAL_KEY_LEN];
  uint8_t server_key[CREDENTIAL_KEY_LEN];
  EXPECT_TRUE(
      credentials_compute_keys(KAT_PASSWORD, salt, KAT_ITERS, client_key, stored_key, server_key));
  uint8_t expect[CREDENTIAL_KEY_LEN];
  unhex(KAT_CLIENT_KEY, expect, sizeof(expect));
  EXPECT_TRUE(memcmp(client_key, expect, sizeof(expect)) == 0);
  unhex(KAT_STORED_KEY, expect, sizeof(expect));
  EXPECT_TRUE(memcmp(stored_key, expect, sizeof(expect)) == 0);
  unhex(KAT_SERVER_KEY, expect, sizeof(expect));
  EXPECT_TRUE(memcmp(server_key, expect, sizeof(expect)) == 0);
  EXPECT_FALSE(credentials_compute_keys(KAT_PASSWORD, salt, 0, client_key, stored_key, server_key));
  EXPECT_FALSE(credentials_compute_keys(NULL, salt, KAT_ITERS, client_key, stored_key, server_key));
}

static void test_credentials_auth_message_and_proof_kat() {
  uint8_t snonce[CREDENTIAL_NONCE_LEN];
  uint8_t cnonce[CREDENTIAL_NONCE_LEN];
  ramp(snonce, sizeof(snonce), 0xa0);
  ramp(cnonce, sizeof(cnonce), 0x10);

  uint8_t auth_msg[CREDENTIAL_AUTH_MESSAGE_MAX];
  size_t msg_len = 0;
  EXPECT_TRUE(credentials_build_auth_message(KAT_USER, snonce, cnonce, auth_msg, sizeof(auth_msg),
                                             &msg_len));
  const char* expect_msg =
      "4661737453796e632d417574682d763100000005616c69636500000020a0a1a2a3a4a5a6a7a8a9aaabac"
      "adaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf00000020101112131415161718191a1b1c1d1e1f2021"
      "22232425262728292a2b2c2d2e2f";
  uint8_t expect[CREDENTIAL_AUTH_MESSAGE_MAX];
  size_t expect_len = strlen(expect_msg) / 2;
  unhex(expect_msg, expect, expect_len);
  EXPECT_EQ_INT((int)msg_len, (int)expect_len);
  EXPECT_TRUE(memcmp(auth_msg, expect, expect_len) == 0);

  uint8_t client_key[CREDENTIAL_KEY_LEN];
  uint8_t stored_key[CREDENTIAL_KEY_LEN];
  uint8_t server_key[CREDENTIAL_KEY_LEN];
  unhex(KAT_CLIENT_KEY, client_key, sizeof(client_key));
  unhex(KAT_STORED_KEY, stored_key, sizeof(stored_key));
  unhex(KAT_SERVER_KEY, server_key, sizeof(server_key));
  uint8_t proof[CREDENTIAL_KEY_LEN];
  uint8_t server_sig[CREDENTIAL_KEY_LEN];
  EXPECT_TRUE(credentials_client_proof(client_key, stored_key, server_key, auth_msg, msg_len, proof,
                                       server_sig));
  unhex(KAT_CLIENT_PROOF, expect, sizeof(expect));
  EXPECT_TRUE(memcmp(proof, expect, CREDENTIAL_KEY_LEN) == 0);
  unhex(KAT_SERVER_SIG, expect, sizeof(expect));
  EXPECT_TRUE(memcmp(server_sig, expect, CREDENTIAL_KEY_LEN) == 0);
}

static CredentialVerifier kat_verifier(void) {
  CredentialVerifier v;
  memset(&v, 0, sizeof(v));
  ramp(v.salt, sizeof(v.salt), 0x00);
  v.iters = KAT_ITERS;
  unhex(KAT_STORED_KEY, v.stored_key, sizeof(v.stored_key));
  unhex(KAT_SERVER_KEY, v.server_key, sizeof(v.server_key));
  v.found = true;
  return v;
}

static void test_credentials_verify_response_kat() {
  CredentialVerifier v = kat_verifier();
  uint8_t snonce[CREDENTIAL_NONCE_LEN];
  uint8_t cnonce[CREDENTIAL_NONCE_LEN];
  ramp(snonce, sizeof(snonce), 0xa0);
  ramp(cnonce, sizeof(cnonce), 0x10);
  uint8_t proof[CREDENTIAL_KEY_LEN];
  uint8_t expect_sig[CREDENTIAL_KEY_LEN];
  unhex(KAT_CLIENT_PROOF, proof, sizeof(proof));
  unhex(KAT_SERVER_SIG, expect_sig, sizeof(expect_sig));

  uint8_t server_sig[CREDENTIAL_KEY_LEN];
  EXPECT_TRUE(credentials_verify_response(&v, KAT_USER, snonce, cnonce, proof, server_sig));
  EXPECT_TRUE(memcmp(server_sig, expect_sig, CREDENTIAL_KEY_LEN) == 0);

  /* Tampered proof refused. */
  uint8_t bad[CREDENTIAL_KEY_LEN];
  memcpy(bad, proof, sizeof(bad));
  bad[0] ^= 0x01;
  EXPECT_FALSE(credentials_verify_response(&v, KAT_USER, snonce, cnonce, bad, server_sig));

  /* Unit replay: the same proof bound to a different client nonce is refused. */
  uint8_t other[CREDENTIAL_NONCE_LEN];
  memcpy(other, cnonce, sizeof(other));
  other[0] ^= 0x01;
  EXPECT_FALSE(credentials_verify_response(&v, KAT_USER, snonce, other, proof, server_sig));
  /* Different server nonce too. */
  uint8_t other_server[CREDENTIAL_NONCE_LEN];
  memcpy(other_server, snonce, sizeof(other_server));
  other_server[0] ^= 0x01;
  EXPECT_FALSE(credentials_verify_response(&v, KAT_USER, other_server, cnonce, proof, server_sig));

  /* Wrong user changes the AuthMessage and fails. */
  EXPECT_FALSE(credentials_verify_response(&v, "bob", snonce, cnonce, proof, server_sig));

  /* found=false never accepts. */
  v.found = false;
  EXPECT_FALSE(credentials_verify_response(&v, KAT_USER, snonce, cnonce, proof, server_sig));

  /* NULL arguments fail closed. */
  v.found = true;
  EXPECT_FALSE(credentials_verify_response(NULL, KAT_USER, snonce, cnonce, proof, server_sig));
  EXPECT_FALSE(credentials_verify_response(&v, NULL, snonce, cnonce, proof, server_sig));
  EXPECT_FALSE(credentials_verify_response(&v, KAT_USER, NULL, cnonce, proof, server_sig));
  EXPECT_FALSE(credentials_verify_response(&v, KAT_USER, snonce, cnonce, NULL, server_sig));
}

static void test_credentials_username_valid() {
  EXPECT_TRUE(credentials_username_valid("alice"));
  EXPECT_TRUE(credentials_username_valid("a"));
  EXPECT_FALSE(credentials_username_valid(NULL));
  EXPECT_FALSE(credentials_username_valid(""));
  EXPECT_FALSE(credentials_username_valid("bad user"));
  EXPECT_FALSE(credentials_username_valid("tab\there"));
  EXPECT_FALSE(credentials_username_valid("nul\nhere"));
}

/* A generated line round-trips through the store parser and verifies with the
 * same password. */
static void test_credentials_hash_store_line_roundtrip() {
  char line[CREDENTIAL_MAX_LINE];
  EXPECT_TRUE(make_store_line("alice", KAT_PASSWORD, CREDENTIAL_MIN_ITERS, line, sizeof(line)));
  EXPECT_TRUE(strncmp(line, "alice:", 6) == 0);
  EXPECT_TRUE(strstr(line, KAT_NAME_PREFIX) != NULL);

  char* path = make_tmp_file(line);
  EXPECT_NOT_NULL(path);
  char err[512];
  CredentialStore* store = credentials_load(path, NULL, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 1);
  EXPECT_TRUE(credentials_store_has(store, "alice"));

  CredentialVerifier v;
  const char* module_users[] = {"alice"};
  EXPECT_TRUE(credentials_get_verifier(store, "alice", module_users, 1, &v));
  EXPECT_TRUE(v.found);
  EXPECT_EQ_INT((int)v.iters, (int)CREDENTIAL_MIN_ITERS);
  uint8_t client_key[CREDENTIAL_KEY_LEN];
  uint8_t stored_key[CREDENTIAL_KEY_LEN];
  uint8_t server_key[CREDENTIAL_KEY_LEN];
  EXPECT_TRUE(
      credentials_compute_keys(KAT_PASSWORD, v.salt, v.iters, client_key, stored_key, server_key));
  EXPECT_TRUE(memcmp(stored_key, v.stored_key, CREDENTIAL_KEY_LEN) == 0);
  EXPECT_TRUE(memcmp(server_key, v.server_key, CREDENTIAL_KEY_LEN) == 0);

  credentials_free(store);
  rm_temp(path);
  free(path);
}

static void test_credentials_store_parse_valid() {
  char line_alice[CREDENTIAL_MAX_LINE];
  char line_bob[CREDENTIAL_MAX_LINE];
  EXPECT_TRUE(
      make_store_line("alice", KAT_PASSWORD, CREDENTIAL_MIN_ITERS, line_alice, sizeof(line_alice)));
  EXPECT_TRUE(
      make_store_line("bob", "bob-s3cret", CREDENTIAL_MIN_ITERS, line_bob, sizeof(line_bob)));
  char contents[2 * CREDENTIAL_MAX_LINE + 64];
  snprintf(contents, sizeof(contents), "# server credential store\n; comment\n\n%s\n%s\n",
           line_alice, line_bob);
  char* path = make_tmp_file(contents);
  EXPECT_NOT_NULL(path);
  char err[512];
  CredentialStore* store = credentials_load(path, NULL, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 2);
  EXPECT_TRUE(credentials_store_has(store, "alice"));
  EXPECT_TRUE(credentials_store_has(store, "bob"));
  EXPECT_FALSE(credentials_store_has(store, "mallory"));

  /* Unknown user and off-list user both yield a not-found dummy. */
  const char* module_users[] = {"alice"};
  CredentialVerifier v;
  EXPECT_TRUE(credentials_get_verifier(store, "mallory", module_users, 1, &v));
  EXPECT_FALSE(v.found);
  EXPECT_TRUE(credentials_get_verifier(store, "bob", module_users, 1, &v));
  EXPECT_FALSE(v.found);
  EXPECT_TRUE(credentials_get_verifier(store, "alice", module_users, 1, &v));
  EXPECT_TRUE(v.found);
  /* The dummy keys are fixed (all zero) so they can never authenticate. */
  const uint8_t zero[CREDENTIAL_KEY_LEN] = {0};
  EXPECT_TRUE(credentials_get_verifier(store, "mallory", module_users, 1, &v));
  EXPECT_TRUE(memcmp(v.stored_key, zero, CREDENTIAL_KEY_LEN) == 0);
  EXPECT_TRUE(memcmp(v.server_key, zero, CREDENTIAL_KEY_LEN) == 0);
  /* Miss salt is fresh random on each call. */
  uint8_t salt_a[CREDENTIAL_SALT_LEN];
  uint8_t salt_b[CREDENTIAL_SALT_LEN];
  EXPECT_TRUE(credentials_get_verifier(store, "mallory", module_users, 1, &v));
  memcpy(salt_a, v.salt, sizeof(salt_a));
  EXPECT_TRUE(credentials_get_verifier(store, "mallory", module_users, 1, &v));
  memcpy(salt_b, v.salt, sizeof(salt_b));
  EXPECT_TRUE(memcmp(salt_a, salt_b, sizeof(salt_a)) != 0);

  credentials_free(store);
  rm_temp(path);
  free(path);
}

static void test_credentials_store_parse_rejects_malformed() {
  /* A valid salt (16 bytes -> 24 b64 chars) / keys (32 bytes -> 44 chars). */
  uint8_t sixteen[CREDENTIAL_SALT_LEN] = {0};
  uint8_t thirtytwo[CREDENTIAL_KEY_LEN] = {0};
  char salt_b64[25];
  char key_b64[45];
  credentials_b64_encode(sixteen, sizeof(sixteen), salt_b64, sizeof(salt_b64));
  credentials_b64_encode(thirtytwo, sizeof(thirtytwo), key_b64, sizeof(key_b64));

  char below_min[CREDENTIAL_MAX_LINE];
  char above_max[CREDENTIAL_MAX_LINE];
  char short_salt[CREDENTIAL_MAX_LINE];
  char short_key[CREDENTIAL_MAX_LINE];
  char empty_field[CREDENTIAL_MAX_LINE];
  snprintf(below_min, sizeof(below_min), "alice:$fastsync$1$pbkdf2-sha256$99$%s$%s$%s\n", salt_b64,
           key_b64, key_b64);
  snprintf(above_max, sizeof(above_max), "alice:$fastsync$1$pbkdf2-sha256$99999999$%s$%s$%s\n",
           salt_b64, key_b64, key_b64);
  snprintf(short_salt, sizeof(short_salt), "alice:$fastsync$1$pbkdf2-sha256$600000$AAAA$%s$%s\n",
           key_b64, key_b64);
  snprintf(short_key, sizeof(short_key), "alice:$fastsync$1$pbkdf2-sha256$600000$%s$AAAA$%s\n",
           salt_b64, key_b64);
  snprintf(empty_field, sizeof(empty_field), "alice:$fastsync$1$pbkdf2-sha256$600000$%s$%s$\n",
           salt_b64, key_b64);

  const char* cases[] = {
      "alice\n",
      ":anything\n",
      "alice:not-a-verifier\n",
      below_min,
      above_max,
      short_salt,
      short_key,
      empty_field,
      "ali "
      "ce:$fastsync$1$pbkdf2-sha256$600000$AAECAwQFBgcICQoLDA0ODw==$WztIlDcIWhH+"
      "WUq5kVTaTLTrq0rowu31H7qpJ36fkJk=$OPZoc2IQvU28tRk7mlFMWxBHF07/X1qA7kwrHossdqE=\n",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char* path = make_tmp_file(cases[i]);
    EXPECT_NOT_NULL(path);
    char err[512];
    const CredentialStore* store = credentials_load(path, NULL, err, sizeof(err));
    EXPECT_NULL(store);
    EXPECT_TRUE(err[0] != '\0');
    rm_temp(path);
    free(path);
  }
}

static void test_credentials_store_rejects_legacy_hex() {
  const char* secret = "9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3";
  char contents[CREDENTIAL_MAX_LINE];
  snprintf(contents, sizeof(contents), "alice:%s\n", secret);
  char* path = make_tmp_file(contents);
  EXPECT_NOT_NULL(path);
  char err[512];
  const CredentialStore* store = credentials_load(path, NULL, err, sizeof(err));
  EXPECT_NULL(store);
  EXPECT_TRUE(strstr(err, "legacy") != NULL);
  EXPECT_TRUE(strstr(err, "alice") != NULL);
  rm_temp(path);
  free(path);
}

static void test_credentials_store_duplicate_rejected() {
  char line[CREDENTIAL_MAX_LINE];
  EXPECT_TRUE(make_store_line("alice", KAT_PASSWORD, CREDENTIAL_MIN_ITERS, line, sizeof(line)));
  char contents[2 * CREDENTIAL_MAX_LINE + 8];
  snprintf(contents, sizeof(contents), "%s\n%s\n", line, line);
  char* path = make_tmp_file(contents);
  EXPECT_NOT_NULL(path);
  char err[512];
  EXPECT_NULL(credentials_load(path, NULL, err, sizeof(err)));
  EXPECT_TRUE(strstr(err, "duplicate") != NULL);
  rm_temp(path);
  free(path);
}

static void test_credentials_store_parse_missing_file() {
  char err[512];
  const CredentialStore* store =
      credentials_load("/nonexistent/cred-file-xyz", NULL, err, sizeof(err));
  EXPECT_NULL(store);
  EXPECT_TRUE(strstr(err, "cannot open") != NULL);
}

static void test_credentials_store_empty_and_null() {
  char err[512];
  CredentialStore* store = credentials_load(NULL, NULL, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 0);
  credentials_free(store);

  char* path = make_tmp_file("# nothing here\n; nor here\n");
  EXPECT_NOT_NULL(path);
  store = credentials_load(path, NULL, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 0);
  credentials_free(store);
  rm_temp(path);
  free(path);
}

static void test_credentials_store_overlong_line_rejected() {
  char big[CREDENTIAL_MAX_LINE + 80];
  int n = snprintf(big, sizeof(big), "alice:%s", KAT_NAME_PREFIX);
  memset(big + n, 'a', sizeof(big) - (size_t)n - 1);
  big[sizeof(big) - 2] = '\n';
  big[sizeof(big) - 1] = '\0';
  char* path = make_tmp_file(big);
  EXPECT_NOT_NULL(path);
  char err[512];
  const CredentialStore* store = credentials_load(path, NULL, err, sizeof(err));
  EXPECT_NULL(store);
  rm_temp(path);
  free(path);
}

static void test_credentials_early_input_merge() {
  char alice[CREDENTIAL_MAX_LINE];
  char bob[CREDENTIAL_MAX_LINE];
  EXPECT_TRUE(make_store_line("alice", KAT_PASSWORD, CREDENTIAL_MIN_ITERS, alice, sizeof(alice)));
  EXPECT_TRUE(make_store_line("bob", "bob-s3cret", CREDENTIAL_MIN_ITERS, bob, sizeof(bob)));
  char alice_file[CREDENTIAL_MAX_LINE + 2];
  char bob_file[CREDENTIAL_MAX_LINE + 2];
  char alice_other[CREDENTIAL_MAX_LINE];
  snprintf(alice_file, sizeof(alice_file), "%s\n", alice);
  snprintf(bob_file, sizeof(bob_file), "%s\n", bob);
  EXPECT_TRUE(make_store_line("alice", "different-s3cret", CREDENTIAL_MIN_ITERS, alice_other,
                              sizeof(alice_other)));

  char* pw = make_tmp_file(alice_file);
  char* early = make_tmp_file(bob_file);
  char* early_same = make_tmp_file(alice_file); /* byte-identical verifier dedupes */
  char* early_diff = make_tmp_file(alice_other);
  EXPECT_NOT_NULL(pw);
  EXPECT_NOT_NULL(early);
  EXPECT_NOT_NULL(early_same);
  EXPECT_NOT_NULL(early_diff);
  char err[512];

  /* A second file adds a new user. */
  CredentialStore* store = credentials_load(pw, early, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 2);
  EXPECT_TRUE(credentials_store_has(store, "alice"));
  EXPECT_TRUE(credentials_store_has(store, "bob"));
  credentials_free(store);

  /* The same user with the SAME verifier dedupes. */
  store = credentials_load(pw, early_same, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 1);
  credentials_free(store);

  /* The same user with a DIFFERENT verifier fails closed (ambiguous). */
  store = credentials_load(pw, early_diff, err, sizeof(err));
  EXPECT_NULL(store);
  EXPECT_TRUE(err[0] != '\0');

  rm_temp(pw);
  rm_temp(early);
  rm_temp(early_same);
  rm_temp(early_diff);
  free(pw);
  free(early);
  free(early_same);
  free(early_diff);
}

static void test_credentials_read_secret_file() {
  char err[512];
  char* user = NULL;
  char* password = NULL;

  char* path = make_tmp_file("# password file\n"
                             "\n"
                             "alice:correct horse battery staple\n"
                             "ignored:second line\n");
  EXPECT_NOT_NULL(path);
  EXPECT_EQ_INT(credentials_read_secret_file(path, &user, &password, err, sizeof(err)), 0);
  EXPECT_EQ_STR(user, "alice");
  EXPECT_EQ_STR(password, "correct horse battery staple");
  free(user);
  free(password);
  user = password = NULL;
  rm_temp(path);
  free(path);

  path = make_tmp_file("  bob  :  s3cret  \r\n");
  EXPECT_NOT_NULL(path);
  EXPECT_EQ_INT(credentials_read_secret_file(path, &user, &password, err, sizeof(err)), 0);
  EXPECT_EQ_STR(user, "bob");
  EXPECT_EQ_STR(password, "  s3cret  ");
  free(user);
  free(password);
  user = password = NULL;
  rm_temp(path);
  free(path);

  path = make_tmp_file("carol:   \n");
  EXPECT_NOT_NULL(path);
  EXPECT_EQ_INT(credentials_read_secret_file(path, &user, &password, err, sizeof(err)), 0);
  EXPECT_EQ_STR(user, "carol");
  EXPECT_EQ_STR(password, "   ");
  free(user);
  free(password);
  user = password = NULL;
  rm_temp(path);
  free(path);

  path = make_tmp_file("");
  EXPECT_NOT_NULL(path);
  EXPECT_EQ_INT(credentials_read_secret_file(path, &user, &password, err, sizeof(err)), -1);
  EXPECT_NULL(user);
  EXPECT_NULL(password);
  EXPECT_TRUE(strstr(err, "no 'user:password'") != NULL);
  rm_temp(path);
  free(path);
}

static void test_credentials_read_secret_file_bad() {
  char err[512];
  const char* cases[] = {
      "alicepassword\n",
      ":password\n",
      "alice:\n",
      "alice:\r\n",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char* path = make_tmp_file(cases[i]);
    EXPECT_NOT_NULL(path);
    char* user = (char*)1;
    char* password = (char*)1;
    EXPECT_EQ_INT(credentials_read_secret_file(path, &user, &password, err, sizeof(err)), -1);
    EXPECT_NULL(user);
    EXPECT_NULL(password);
    EXPECT_TRUE(err[0] != '\0');
    rm_temp(path);
    free(path);
  }

  char* missing = "/nonexistent/password-file-xyz";
  EXPECT_EQ_INT(credentials_read_secret_file(missing, NULL, NULL, err, sizeof(err)), -1);
}

static void test_credentials_hash_file() {
  char* plaintext = make_tmp_file("# comment\n\n alice :" KAT_PASSWORD "\nbob:bob-s3cret\n");
  EXPECT_NOT_NULL(plaintext);
  FILE* out = tmpfile();
  EXPECT_NOT_NULL(out);
  char err[512];
  EXPECT_EQ_INT(credentials_hash_file(plaintext, CREDENTIAL_MIN_ITERS, out, err, sizeof(err)), 0);
  rewind(out);

  char line1[CREDENTIAL_MAX_LINE];
  char line2[CREDENTIAL_MAX_LINE];
  EXPECT_NOT_NULL(fgets(line1, sizeof(line1), out));
  EXPECT_NOT_NULL(fgets(line2, sizeof(line2), out));
  EXPECT_NULL(fgets(err, sizeof(err), out)); /* exactly two entries */
  size_t n1 = strlen(line1);
  if (n1 > 0 && line1[n1 - 1] == '\n')
    line1[--n1] = '\0';
  size_t n2 = strlen(line2);
  if (n2 > 0 && line2[n2 - 1] == '\n')
    line2[--n2] = '\0';
  EXPECT_TRUE(strncmp(line1, "alice:", 6) == 0);
  EXPECT_TRUE(strncmp(line2, "bob:", 4) == 0);
  EXPECT_TRUE(strstr(line1, KAT_NAME_PREFIX) != NULL);
  fclose(out);

  /* The generated lines load as a valid store. */
  char contents[2 * CREDENTIAL_MAX_LINE + 8];
  snprintf(contents, sizeof(contents), "%s\n%s\n", line1, line2);
  char* store_path = make_tmp_file(contents);
  EXPECT_NOT_NULL(store_path);
  CredentialStore* store = credentials_load(store_path, NULL, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 2);
  credentials_free(store);
  rm_temp(store_path);
  free(store_path);
  rm_temp(plaintext);
  free(plaintext);

  /* An invalid iteration count is refused up front. */
  char* p2 = make_tmp_file("alice:pw\n");
  EXPECT_NOT_NULL(p2);
  FILE* out2 = tmpfile();
  EXPECT_NOT_NULL(out2);
  EXPECT_EQ_INT(credentials_hash_file(p2, 10, out2, err, sizeof(err)), -1);
  EXPECT_TRUE(err[0] != '\0');
  fclose(out2);
  rm_temp(p2);
  free(p2);
}

static void test_credentials_rejects_group_or_other_accessible() {
  char err[512];
  char line[CREDENTIAL_MAX_LINE];
  EXPECT_TRUE(make_store_line("alice", KAT_PASSWORD, CREDENTIAL_MIN_ITERS, line, sizeof(line)));
  char contents[CREDENTIAL_MAX_LINE + 2];
  snprintf(contents, sizeof(contents), "%s\n", line);
  char* path = make_tmp_file(contents);
  EXPECT_NOT_NULL(path);

  EXPECT_EQ_INT(chmod(path, 0600), 0);
  CredentialStore* store = credentials_load(path, NULL, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  credentials_free(store);

  EXPECT_EQ_INT(chmod(path, 0640), 0);
  EXPECT_NULL(credentials_load(path, NULL, err, sizeof(err)));
  EXPECT_TRUE(strstr(err, "owner-only") != NULL);
  EXPECT_EQ_INT(chmod(path, 0604), 0);
  EXPECT_NULL(credentials_load(path, NULL, err, sizeof(err)));

  EXPECT_EQ_INT(chmod(path, 0644), 0);
  char* user = NULL;
  char* password = NULL;
  EXPECT_EQ_INT(credentials_read_secret_file(path, &user, &password, err, sizeof(err)), -1);
  EXPECT_NULL(user);
  EXPECT_NULL(password);
  EXPECT_TRUE(strstr(err, "owner-only") != NULL);

  char* pw = make_tmp_file("bob:bob-s3cret\n");
  EXPECT_NOT_NULL(pw);
  EXPECT_EQ_INT(chmod(path, 0644), 0);
  EXPECT_NULL(credentials_load(pw, path, err, sizeof(err)));

  rm_temp(pw);
  rm_temp(path);
  free(pw);
  free(path);
}

static void test_credentials_burn() {
  char secret[32];
  memcpy(secret, "supersecretvalue", 17);
  credentials_burn(secret, 16);
  for (int i = 0; i < 16; i++)
    EXPECT_EQ_INT(secret[i], 0);
  credentials_burn(NULL, 0);
}

void test_credentials(void) {
  test_credentials_secure_equal();
  test_credentials_b64();
  test_credentials_random_bytes();
  test_credentials_compute_keys_kat();
  test_credentials_auth_message_and_proof_kat();
  test_credentials_verify_response_kat();
  test_credentials_username_valid();
  test_credentials_hash_store_line_roundtrip();
  test_credentials_store_parse_valid();
  test_credentials_store_parse_rejects_malformed();
  test_credentials_store_rejects_legacy_hex();
  test_credentials_store_duplicate_rejected();
  test_credentials_store_parse_missing_file();
  test_credentials_store_empty_and_null();
  test_credentials_store_overlong_line_rejected();
  test_credentials_early_input_merge();
  test_credentials_read_secret_file();
  test_credentials_read_secret_file_bad();
  test_credentials_hash_file();
  test_credentials_rejects_group_or_other_accessible();
  test_credentials_burn();
}
