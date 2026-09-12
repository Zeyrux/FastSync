#include "test_credentials.h"
#include "credentials.h"
#include "test_utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Known SHA-256 vectors pin the digest derivation to real SHA-256 so a change
 * in the hashing (or a wire/store format change) is observable. */
#define SHA256_EMPTY "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define SHA256_SECRET "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
#define SHA256_ALICE_PASS "9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3"

static int g_file_counter = 0;

/* Write `contents` to a uniquely-named temp file and return a malloc'd path
 * (the caller frees it; the file is removed at the end of the test process or
 * on request via rm_temp). */
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
  return strdup(path);
}

static void rm_temp(const char* path) {
  if (path)
    unlink(path);
}

static void test_credentials_hash_vectors() {
  char out[CREDENTIAL_HASH_HEX_LEN + 1];
  EXPECT_TRUE(credentials_hash_password("", out));
  EXPECT_EQ_STR(out, SHA256_EMPTY);
  EXPECT_TRUE(credentials_hash_password("secret", out));
  EXPECT_EQ_STR(out, SHA256_SECRET);
  EXPECT_TRUE(credentials_hash_password("alice-pass", out));
  EXPECT_EQ_STR(out, SHA256_ALICE_PASS);
  EXPECT_FALSE(credentials_hash_password(NULL, out));
  EXPECT_FALSE(credentials_hash_password("x", NULL));
}

static void test_credentials_hash_valid() {
  EXPECT_TRUE(credentials_hash_valid(SHA256_SECRET));
  EXPECT_FALSE(credentials_hash_valid(NULL));
  EXPECT_FALSE(credentials_hash_valid(""));
  /* Wrong length. */
  EXPECT_FALSE(credentials_hash_valid("abc"));
  EXPECT_FALSE(
      credentials_hash_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  EXPECT_FALSE(
      credentials_hash_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  /* Uppercase hex and non-hex are rejected. */
  EXPECT_FALSE(
      credentials_hash_valid("2BB80D537B1DA3E38BD30361AA855686BDE0EACD7162FEF6A25FE97BF527A25B"));
  EXPECT_FALSE(
      credentials_hash_valid("gbb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"));
}

static void test_credentials_secure_equal() {
  EXPECT_TRUE(credentials_secure_equal("abc", "abc", 3));
  EXPECT_TRUE(credentials_secure_equal("", "", 0));
  EXPECT_FALSE(credentials_secure_equal("abc", "abd", 3));
  EXPECT_TRUE(credentials_secure_equal("abc", "ab", 2));
  /* Same prefix, difference at the very last byte must still be detected. */
  EXPECT_FALSE(credentials_secure_equal(SHA256_SECRET, SHA256_ALICE_PASS, CREDENTIAL_HASH_HEX_LEN));
}

static void test_credentials_store_parse_valid() {
  char* path = make_tmp_file(
      "# server credential store\n"
      "; another comment style\n"
      "\n"
      "alice:9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3\n"
      "   bob   :   2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b   \n"
      "carol:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\n");
  EXPECT_NOT_NULL(path);
  char err[512];
  CredentialStore* store = credentials_load(path, NULL, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 3);
  EXPECT_TRUE(credentials_store_has(store, "alice"));
  EXPECT_TRUE(credentials_store_has(store, "bob"));
  EXPECT_TRUE(credentials_store_has(store, "carol"));
  EXPECT_FALSE(credentials_store_has(store, "mallory"));
  EXPECT_FALSE(credentials_store_has(store, "ALICE"));
  EXPECT_TRUE(credentials_verify(store, "alice", SHA256_ALICE_PASS));
  EXPECT_TRUE(credentials_verify(store, "bob", SHA256_SECRET));
  EXPECT_TRUE(credentials_verify(store, "carol", SHA256_EMPTY));
  EXPECT_FALSE(credentials_verify(store, "alice", SHA256_SECRET));
  EXPECT_FALSE(credentials_verify(store, "mallory", SHA256_ALICE_PASS));
  credentials_free(store);
  rm_temp(path);
  free(path);
}

static void test_credentials_store_parse_rejects_malformed() {
  const char* cases[] = {
      /* no colon */
      "alice\n",
      /* empty user */
      ":9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3\n",
      /* empty secret */
      "alice:\n",
      /* secret too short */
      "alice:8ce9c8b52c5\n",
      /* secret not hex */
      "alice:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n",
      /* uppercase hex rejected (strict) */
      "alice:2BB80D537B1DA3E38BD30361AA855686BDE0EACD7162FEF6A25FE97BF527A25B\n",
      /* whitespace inside the username */
      "ali ce:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\n",
      /* duplicate user within one file */
      "alice:9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3\n"
      "alice:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\n",
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

static void test_credentials_store_parse_missing_file() {
  char err[512];
  const CredentialStore* store =
      credentials_load("/nonexistent/cred-file-xyz", NULL, err, sizeof(err));
  EXPECT_NULL(store);
  EXPECT_TRUE(strstr(err, "cannot open") != NULL);
}

static void test_credentials_store_empty_and_null() {
  char err[512];
  /* A NULL path is a valid (empty) store: no module can authenticate, which is
   * the fail-closed state the startup check turns into a refusal to start. */
  CredentialStore* store = credentials_load(NULL, NULL, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 0);
  EXPECT_FALSE(credentials_verify(store, "alice", SHA256_ALICE_PASS));
  credentials_free(store);

  /* A blank/comment-only file is an empty store too (not an error). */
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
  /* A line longer than CREDENTIAL_MAX_LINE must be rejected.  Fill the buffer
   * fully so the line really is overlong, but keep both a trailing newline and
   * a NUL terminator at known indices: make_tmp_file does strlen(contents), so
   * an unterminated stack buffer would be an out-of-bounds read (ASan). */
  char big[CREDENTIAL_MAX_LINE + 80];
  int n = snprintf(big, sizeof(big), "alice:%s", SHA256_SECRET);
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
  char* pw =
      make_tmp_file("alice:9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3\n");
  EXPECT_NOT_NULL(pw);
  char err[512];

  /* A second file adds a new user. */
  char* early =
      make_tmp_file("bob:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\n");
  EXPECT_NOT_NULL(early);
  CredentialStore* store = credentials_load(pw, early, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 2);
  EXPECT_TRUE(credentials_verify(store, "alice", SHA256_ALICE_PASS));
  EXPECT_TRUE(credentials_verify(store, "bob", SHA256_SECRET));
  credentials_free(store);

  /* The same user with the SAME secret dedupes. */
  char* early_same =
      make_tmp_file("alice:9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3\n");
  EXPECT_NOT_NULL(early_same);
  store = credentials_load(pw, early_same, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  EXPECT_EQ_INT(credentials_store_size(store), 1);
  credentials_free(store);

  /* The same user with a DIFFERENT secret fails closed (ambiguous). */
  char* early_diff =
      make_tmp_file("alice:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\n");
  EXPECT_NOT_NULL(early_diff);
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

  /* Leading comments/blanks skipped; first real line wins. */
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

  /* CRLF is tolerated; the username is trimmed but the password's exact bytes
   * (edge spaces included) are preserved so a whitespace password stays usable. */
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

  /* A whitespace-only password (no characters) is still a real password and is
   * preserved exactly, not mistaken for an empty line. */
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

  /* Empty file / comment-only file rejected. */
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
      /* no colon */
      "alicepassword\n",
      /* empty user */
      ":password\n",
      /* empty password */
      "alice:\n",
      /* empty password after CR-only line ending */
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

static void test_credentials_gate_allows() {
  char* path =
      make_tmp_file("alice:9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3\n"
                    "bob:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\n");
  EXPECT_NOT_NULL(path);
  char err[512];
  CredentialStore* store = credentials_load(path, NULL, err, sizeof(err));
  EXPECT_NOT_NULL(store);

  const char* module_users[] = {"alice", "bob"};

  /* Matching user + digest passes. */
  EXPECT_TRUE(credentials_gate_allows(store, module_users, 2, "alice", SHA256_ALICE_PASS));
  EXPECT_TRUE(credentials_gate_allows(store, module_users, 2, "bob", SHA256_SECRET));
  /* Wrong digest for a listed user fails. */
  EXPECT_FALSE(credentials_gate_allows(store, module_users, 2, "alice", SHA256_SECRET));
  /* A store user that is not on the module's list fails. */
  EXPECT_FALSE(credentials_gate_allows(store, module_users, 2, "alice", SHA256_ALICE_PASS) &&
               credentials_gate_allows(store, module_users, 1, "bob", SHA256_SECRET));
  EXPECT_TRUE(credentials_gate_allows(store, module_users, 1, "alice", SHA256_ALICE_PASS));
  EXPECT_FALSE(credentials_gate_allows(store, module_users, 1, "bob", SHA256_SECRET));
  /* No credentials presented fails. */
  EXPECT_FALSE(credentials_gate_allows(store, module_users, 2, NULL, NULL));
  EXPECT_FALSE(credentials_gate_allows(store, module_users, 2, "alice", NULL));
  /* Unknown user fails. */
  EXPECT_FALSE(credentials_gate_allows(store, module_users, 2, "mallory", SHA256_ALICE_PASS));
  /* Fail closed: a NULL store refuses even with correct credentials. */
  EXPECT_FALSE(credentials_gate_allows(NULL, module_users, 2, "alice", SHA256_ALICE_PASS));
  /* An empty module list refuses everyone. */
  EXPECT_FALSE(credentials_gate_allows(store, NULL, 0, "alice", SHA256_ALICE_PASS));

  credentials_free(store);
  rm_temp(path);
  free(path);
}

static void test_credentials_rejects_group_or_other_accessible() {
  char err[512];
  char* path =
      make_tmp_file("alice:9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3\n");
  EXPECT_NOT_NULL(path);

  /* 0600 is accepted by the server store loader. */
  EXPECT_EQ_INT(chmod(path, 0600), 0);
  CredentialStore* store = credentials_load(path, NULL, err, sizeof(err));
  EXPECT_NOT_NULL(store);
  credentials_free(store);

  /* Group-readable and world-readable are both refused, with a clear error. */
  EXPECT_EQ_INT(chmod(path, 0640), 0);
  EXPECT_NULL(credentials_load(path, NULL, err, sizeof(err)));
  EXPECT_TRUE(strstr(err, "owner-only") != NULL);
  EXPECT_EQ_INT(chmod(path, 0604), 0);
  EXPECT_NULL(credentials_load(path, NULL, err, sizeof(err)));

  /* The client --password-file reader enforces the same rule. */
  EXPECT_EQ_INT(chmod(path, 0644), 0);
  char* user = NULL;
  char* password = NULL;
  EXPECT_EQ_INT(credentials_read_secret_file(path, &user, &password, err, sizeof(err)), -1);
  EXPECT_NULL(user);
  EXPECT_NULL(password);
  EXPECT_TRUE(strstr(err, "owner-only") != NULL);

  /* An --early-input file is checked too. */
  char* pw =
      make_tmp_file("bob:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\n");
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
  credentials_burn(NULL, 0); /* must not crash */
}

void test_credentials(void) {
  test_credentials_hash_vectors();
  test_credentials_hash_valid();
  test_credentials_secure_equal();
  test_credentials_store_parse_valid();
  test_credentials_store_parse_rejects_malformed();
  test_credentials_store_parse_missing_file();
  test_credentials_store_empty_and_null();
  test_credentials_store_overlong_line_rejected();
  test_credentials_early_input_merge();
  test_credentials_read_secret_file();
  test_credentials_read_secret_file_bad();
  test_credentials_rejects_group_or_other_accessible();
  test_credentials_gate_allows();
  test_credentials_burn();
}
