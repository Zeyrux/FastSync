#include "test_config.h"
#include "config.h"
#include "identity.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "test_utils.h"
#include "utils.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static Config* make_config(const char* version, const char* src, const char* dst, bool save,
                           bool mt, bool cs, bool comp, bool meta, int clevel, bool sf,
                           unsigned long long csize) {
  Config* cfg = config_create();
  if (!cfg)
    return NULL;
  free(cfg->version);
  cfg->version = str_dup(version);
  cfg->send_directory = str_dup(src);
  cfg->receive_root_directory = str_dup(dst);
  cfg->save_to_disk = save;
  cfg->use_multithreading = mt;
  cfg->use_chunk_serialization = cs;
  cfg->use_compression = comp;
  cfg->use_metadata = meta;
  cfg->compression_level = clevel;
  cfg->use_sendfile = sf;
  if (csize > 0)
    cfg->chunk_size = csize;
  return cfg;
}

static void test_config_lifecycle() {
  Config* cfg = make_config("1.0", "/src", "/dst", true, true, false, false, false, 1, false, 0);
  EXPECT_NOT_NULL(cfg);
  EXPECT_EQ_STR(cfg->version, "1.0");
  EXPECT_EQ_STR(cfg->send_directory, "/src");
  EXPECT_EQ_STR(cfg->receive_root_directory, "/dst");
  EXPECT_TRUE(cfg->save_to_disk);
  EXPECT_TRUE(cfg->use_multithreading);
  EXPECT_FALSE(cfg->use_chunk_serialization);
  EXPECT_FALSE(cfg->use_compression);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_TCP);
  EXPECT_NULL(cfg->ssh_destination);
  config_delete(cfg);
}

static void test_config_ssh_dest() {
  Config* cfg =
      make_config("1.0", "/src", "user@host:/dst", true, false, false, false, false, 1, false, 0);
  EXPECT_NOT_NULL(cfg);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_TCP);
  EXPECT_NULL(cfg->ssh_destination);
  EXPECT_EQ_STR(cfg->receive_root_directory, "user@host:/dst");

  config_parse_ssh_dest(cfg);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_SSH);
  EXPECT_EQ_STR(cfg->ssh_destination, "user@host:/dst");
  EXPECT_EQ_STR(cfg->receive_root_directory, "/dst");
  config_delete(cfg);
}

static void test_config_ssh_dest_local_path() {
  Config* cfg =
      make_config("1.0", "/src", "/local/path", true, false, false, false, false, 1, false, 0);
  config_parse_ssh_dest(cfg);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_TCP);
  EXPECT_NULL(cfg->ssh_destination);
  EXPECT_EQ_STR(cfg->receive_root_directory, "/local/path");
  config_delete(cfg);
}

static void test_config_ssh_dest_no_user() {
  Config* cfg =
      make_config("1.0", "/src", "host:/remote", true, false, false, false, false, 1, false, 0);
  config_parse_ssh_dest(cfg);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_SSH);
  EXPECT_EQ_STR(cfg->ssh_destination, "host:/remote");
  EXPECT_EQ_STR(cfg->receive_root_directory, "/remote");
  config_delete(cfg);
}

static void test_config_daemon_dest_parse() {
  Config* cfg = make_config("1.0", "/src", "dahost::files/sub/dir", true, false, false, false,
                            false, 1, false, 0);
  int ret = config_parse_daemon_dest(cfg);
  EXPECT_EQ_INT(ret, 1);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_TCP);
  EXPECT_EQ_STR(cfg->server_host, "dahost");
  EXPECT_EQ_STR(cfg->module, "files");
  EXPECT_EQ_STR(cfg->receive_root_directory, "sub/dir");
  config_delete(cfg);
}

static void test_config_daemon_dest_no_path() {
  Config* cfg =
      make_config("1.0", "/src", "dahost::files", true, false, false, false, false, 1, false, 0);
  int ret = config_parse_daemon_dest(cfg);
  EXPECT_EQ_INT(ret, 1);
  EXPECT_EQ_STR(cfg->server_host, "dahost");
  EXPECT_EQ_STR(cfg->module, "files");
  EXPECT_EQ_STR(cfg->receive_root_directory, "");
  config_delete(cfg);
}

static void test_config_daemon_dest_double_slash_normalized() {
  Config* cfg = make_config("1.0", "/src", "dahost::files//sub", true, false, false, false, false,
                            1, false, 0);
  int ret = config_parse_daemon_dest(cfg);
  EXPECT_EQ_INT(ret, 1);
  EXPECT_EQ_STR(cfg->module, "files");
  EXPECT_EQ_STR(cfg->receive_root_directory, "sub");
  config_delete(cfg);
}

static void test_config_daemon_dest_bad() {
  /* Missing module name after "::". */
  Config* cfg =
      make_config("1.0", "/src", "dahost::", true, false, false, false, false, 1, false, 0);
  EXPECT_EQ_INT(config_parse_daemon_dest(cfg), -1);
  config_delete(cfg);

  /* Invalid module name. */
  cfg =
      make_config("1.0", "/src", "dahost::bad name", true, false, false, false, false, 1, false, 0);
  EXPECT_EQ_INT(config_parse_daemon_dest(cfg), -1);
  config_delete(cfg);

  /* Traversal path rejected. */
  cfg = make_config("1.0", "/src", "dahost::mod/../../etc", true, false, false, false, false, 1,
                    false, 0);
  EXPECT_EQ_INT(config_parse_daemon_dest(cfg), -1);
  config_delete(cfg);

  /* user@host::module is not yet supported. */
  cfg =
      make_config("1.0", "/src", "user@dahost::mod", true, false, false, false, false, 1, false, 0);
  EXPECT_EQ_INT(config_parse_daemon_dest(cfg), -1);
  config_delete(cfg);

  /* A non-daemon destination is untouched (returns 0). */
  cfg = make_config("1.0", "/src", "plain:path", true, false, false, false, false, 1, false, 0);
  EXPECT_EQ_INT(config_parse_daemon_dest(cfg), 0);
  EXPECT_EQ_STR(cfg->receive_root_directory, "plain:path");
  config_delete(cfg);
}

static void test_config_transport_dest_daemon_beats_ssh() {
  /* host::module selects daemon TCP; host:path still selects SSH. */
  Config* cfg = make_config("1.0", "/src", "h::m/x", true, false, false, false, false, 1, false, 0);
  int ret = config_parse_transport_dest(cfg);
  EXPECT_EQ_INT(ret, 1);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_TCP);
  EXPECT_EQ_STR(cfg->module, "m");
  config_delete(cfg);

  cfg = make_config("1.0", "/src", "h:dst", true, false, false, false, false, 1, false, 0);
  ret = config_parse_transport_dest(cfg);
  EXPECT_EQ_INT(ret, 0);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_SSH);
  EXPECT_EQ_STR(cfg->receive_root_directory, "dst");
  config_delete(cfg);
}

static void test_config_is_daemon_dest() {
  EXPECT_TRUE(config_is_daemon_dest("host::mod"));
  EXPECT_TRUE(config_is_daemon_dest("host::mod/path"));
  EXPECT_FALSE(config_is_daemon_dest("host:path"));
  EXPECT_FALSE(config_is_daemon_dest("/local/path"));
  /* A colon inside the module-relative path does not change the detection. */
  EXPECT_TRUE(config_is_daemon_dest("host::mod/single:colon"));
  EXPECT_FALSE(config_is_daemon_dest(NULL));
}

static void test_config_module_wire_roundtrip() {
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("rel/path");
  send_cfg->module = str_dup("backup");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv_cfg = config_receive(p[0]);
    bool ok = recv_cfg != NULL && recv_cfg->module != NULL &&
              strcmp(recv_cfg->module, "backup") == 0 &&
              strcmp(recv_cfg->receive_root_directory, "rel/path") == 0;
    config_delete(recv_cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_config_module_wire_empty_canonicalizes_to_null() {
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("/dst");
  /* module left NULL -> serialized as "" -> received back as NULL. */

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv_cfg = config_receive(p[0]);
    bool ok = recv_cfg != NULL && recv_cfg->module == NULL;
    config_delete(recv_cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Daemon auth credentials (Wave B) ride the config frame: username + SHA-256
 * hex digest are present together, or both are absent.  Round-trip a present
 * pair. */
static void test_config_daemon_auth_wire_roundtrip() {
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("rel/path");
  send_cfg->module = str_dup("backup");
  send_cfg->auth_user = str_dup("alice");
  send_cfg->auth_password_hash =
      str_dup("9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv_cfg = config_receive(p[0]);
    bool ok = recv_cfg != NULL && recv_cfg->auth_user != NULL &&
              strcmp(recv_cfg->auth_user, "alice") == 0 && recv_cfg->auth_password_hash != NULL &&
              strcmp(recv_cfg->auth_password_hash,
                     "9b90e524e94995ee4aeae2ee3c428a53405d1e8db147f44facc46797d0caf4c3") == 0;
    config_delete(recv_cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* The receive side validates the auth payload: a present-but-malformed digest
 * is refused (config_receive returns NULL), so a hostile peer cannot slip a
 * garbage credential past the receive guard into the module gate. */
static void test_config_daemon_auth_wire_rejects_malformed() {
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("/dst");
  send_cfg->module = str_dup("m");
  send_cfg->auth_user = str_dup("alice");
  send_cfg->auth_password_hash = str_dup("not-a-valid-sha256-hex-digest!!");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv_cfg = config_receive(p[0]);
    bool ok = recv_cfg == NULL;
    config_delete(recv_cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_FALSE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* A module gate that rejects any connection that names a module. */
static const char* reject_named_module_gate(const Config* config, void* context) {
  (void)context;
  if (config && config->module && config->module[0] != '\0')
    return "test rejection";
  return NULL;
}

static void test_config_receive_with_validate_rejects() {
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("/dst");
  send_cfg->module = str_dup("any-module");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv = config_receive_with_validate(p[0], reject_named_module_gate, NULL);
    bool ok = recv == NULL;
    config_delete(recv);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_FALSE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_pipeline_sender_lifecycle() {
  Config* cfg = make_config("2.0", "/src2", "/dst2", false, false, true, true, false, 1, false, 0);
  Queue* q1 = queue_create(5, NULL);
  Queue* q2 = queue_create(15, NULL);

  PipelineContextSender* pcs = pipeline_context_sender_create(cfg, q1, q2);
  EXPECT_NOT_NULL(pcs);
  EXPECT_EQ_STR(pcs->config->version, "2.0");
  EXPECT_EQ_INT(pcs->queue_scanner->capacity, 5);
  EXPECT_EQ_INT(pcs->queue_loader->capacity, 15);
  EXPECT_FALSE(pcs->scanner_done);
  EXPECT_FALSE(pcs->loader_done);
  EXPECT_EQ_INT((int)pcs->allocation_session.max_alloc, (int)cfg->max_alloc);

  pipeline_context_sender_destroy(pcs);
}

static void test_pipeline_receiver_lifecycle() {
  Config* cfg = make_config("3.0", "/src3", "/dst3", true, true, true, true, false, 1, false, 0);
  Queue* q = queue_create(20, NULL);

  PipelineContextReceiver* pcr = pipeline_context_receiver_create(cfg, q, 42, NULL);
  EXPECT_NOT_NULL(pcr);
  EXPECT_EQ_STR(pcr->config->version, "3.0");
  EXPECT_EQ_INT(pcr->queue->capacity, 20);
  EXPECT_EQ_INT(pcr->file_descriptor, 42);
  EXPECT_FALSE(pcr->receiver_done);

  pipeline_context_receiver_destroy(pcr);
}

static void test_config_send_receive() {
  /* Create a config to send */
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/send/src");
  send_cfg->receive_root_directory = str_dup("/send/dst");
  send_cfg->save_to_disk = true;
  send_cfg->use_multithreading = true;
  send_cfg->use_chunk_serialization = false;
  send_cfg->use_compression = true;
  send_cfg->use_metadata = true;
  send_cfg->use_executability = true;
  send_cfg->preserve_hard_links = true;
  send_cfg->use_delta = true;
  send_cfg->whole_file = true;
  send_cfg->fuzzy = true;
  send_cfg->ignore_times = true;
  send_cfg->size_only = true;
  send_cfg->compression_level = 5;
  send_cfg->chunk_size = 1024;
  send_cfg->eight_bit_output = true;
  send_cfg->modify_window = 4;
  send_cfg->existing = true;
  send_cfg->ignore_existing = true;
  send_cfg->delay_updates = true;
  send_cfg->relative = true;
  send_cfg->mkpath = true;
  send_cfg->skip_compress_set = true;
  send_cfg->skip_compress_count = 1;
  send_cfg->skip_compress_suffixes = calloc(1, sizeof(char*));
  send_cfg->skip_compress_suffixes[0] = str_dup(".zip");
  send_cfg->max_alloc = MAX_SERVER_ALLOC + 1;

  /* Use socketpair for bidirectional communication */
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    /* Child: use p[0] for both read and write (connected to parent's p[1]) */
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv_cfg = config_receive(p[0]);

    bool ok = true;
    if (!recv_cfg)
      ok = false;
    else {
      if (strcmp(recv_cfg->version, PROTOCOL_VERSION) != 0)
        ok = false;
      if (strcmp(recv_cfg->send_directory, "/send/src") != 0)
        ok = false;
      if (strcmp(recv_cfg->receive_root_directory, "/send/dst") != 0)
        ok = false;
      if (!recv_cfg->save_to_disk)
        ok = false;
      if (!recv_cfg->use_multithreading)
        ok = false;
      if (recv_cfg->use_chunk_serialization)
        ok = false;
      if (recv_cfg->compression_level != 5)
        ok = false;
      if (recv_cfg->chunk_size != 1024)
        ok = false;
      if (!recv_cfg->use_executability)
        ok = false;
      if (!recv_cfg->preserve_hard_links)
        ok = false;
      if (!recv_cfg->size_only)
        ok = false;
      if (!recv_cfg->ignore_times)
        ok = false;
      if (!recv_cfg->eight_bit_output)
        ok = false;
      if (recv_cfg->use_delta)
        ok = false;
      if (!recv_cfg->fuzzy)
        ok = false;
      if (recv_cfg->modify_window != 4)
        ok = false;
      if (!recv_cfg->existing)
        ok = false;
      if (!recv_cfg->ignore_existing)
        ok = false;
      if (!recv_cfg->delay_updates)
        ok = false;
      if (!recv_cfg->relative)
        ok = false;
      if (!recv_cfg->mkpath)
        ok = false;
      if (!recv_cfg->skip_compress_set || recv_cfg->skip_compress_count != 1 ||
          strcmp(recv_cfg->skip_compress_suffixes[0], ".zip") != 0)
        ok = false;
      if (recv_cfg->max_alloc != MAX_SERVER_ALLOC)
        ok = false;
    }
    config_delete(recv_cfg);
    close(p[0]);
    close(p[1]);
    _exit(ok ? 0 : 1);
  } else {
    /* Parent: use p[1] for both read and write (connected to child's p[0]) */
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);

    int status;
    waitpid(pid, &status, 0);

    close(p[0]);
    close(p[1]);

    config_delete(send_cfg);

    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_config_send_receive_version_mismatch() {
  /* A peer using the previous wire format must be rejected. */
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  free(cfg->version);
  cfg->version = str_dup("2.3.0");
  cfg->send_directory = str_dup("/src");
  cfg->receive_root_directory = str_dup("/dst");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv = config_receive(p[0]);
    close(p[0]);
    _exit(recv == NULL ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], cfg);

    int status;
    waitpid(pid, &status, 0);

    close(p[0]);
    close(p[1]);

    config_delete(cfg);

    /* config_send receives STATUS_ERROR from config_receive, returns false */
    EXPECT_FALSE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_config_receive_truncated() {
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[0]);
  io_set_bwlimit(0);

  /* A valid prefix exercises cleanup after allocated wire strings and a
   * partially received scalar field. */
  EXPECT_TRUE(send_str(p[1], PROTOCOL_VERSION));
  unsigned long long max_alloc = DEFAULT_MAX_ALLOC;
  EXPECT_TRUE(send_n_data(p[1], &max_alloc, sizeof(max_alloc)));
  EXPECT_TRUE(send_str(p[1], "/src"));
  EXPECT_TRUE(send_str(p[1], "/dst"));
  EXPECT_TRUE(send_int(p[1], 1));
  shutdown(p[1], SHUT_WR);

  const Config* cfg = config_receive(p[0]);
  EXPECT_NULL(cfg);
  close(p[0]);
  close(p[1]);
}

static bool config_string_roundtrip_matches(const Config* send_cfg, Config* recv) {
  /* The sender serializes NULL strings as "" on the wire.  Receivers must
     canonicalize those empty values back to NULL for the options whose client
     default is NULL (backup_dir, temp_dir, partial_dir, suffix), while a real
     non-empty value round-trips unchanged. */
  const char* fields[4];
  char* const* recv_fields[4];
  fields[0] = send_cfg->backup_dir;
  recv_fields[0] = &recv->backup_dir;
  fields[1] = send_cfg->temp_dir;
  recv_fields[1] = &recv->temp_dir;
  fields[2] = send_cfg->partial_dir;
  recv_fields[2] = &recv->partial_dir;
  fields[3] = send_cfg->suffix;
  recv_fields[3] = &recv->suffix;
  for (int i = 0; i < 4; i++) {
    const char* sent = fields[i];
    const char* got = *recv_fields[i];
    if (sent == NULL || sent[0] == '\0') {
      if (got != NULL)
        return false;
    } else if (got == NULL || strcmp(sent, got) != 0) {
      return false;
    }
  }
  return true;
}

static bool roundtrip_config_ok(const Config* send_cfg) {
  int p[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) != 0)
    return false;
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv = config_receive(p[0]);
    bool ok = recv != NULL;
    if (ok) {
      ok = recv->version != NULL && strcmp(recv->version, PROTOCOL_VERSION) == 0;
      ok = ok && recv->send_directory && recv->receive_root_directory;
      ok = ok && config_string_roundtrip_matches(send_cfg, recv);
    }
    config_delete(recv);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    return sent && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  }
}

/* Issue #252: NULL-vs-empty must survive the wire for backup_dir, temp_dir,
   partial_dir, and suffix.  NULL and explicitly-empty client values are both
   serialized as "" and must be reconstructed as NULL so plain --backup (with
   no --suffix/--backup-dir) works exactly like the client configured it. */
static void test_config_string_null_vs_empty_roundtrip() {
  if (is_running_under_valgrind())
    return;

  /* NULL values on the wire must come back as NULL. */
  Config* a = config_create();
  EXPECT_NOT_NULL(a);
  a->send_directory = str_dup("/src");
  a->receive_root_directory = str_dup("/dst");
  EXPECT_TRUE(roundtrip_config_ok(a));
  config_delete(a);

  /* Explicitly empty strings (indistinguishable on the wire from NULL) must
     be canonicalized to NULL by the receiver. */
  Config* b = config_create();
  EXPECT_NOT_NULL(b);
  b->send_directory = str_dup("/src");
  b->receive_root_directory = str_dup("/dst");
  b->backup_dir = str_dup("");
  b->temp_dir = str_dup("");
  b->partial_dir = str_dup("");
  b->suffix = str_dup("");
  EXPECT_TRUE(roundtrip_config_ok(b));
  config_delete(b);

  /* Non-empty values must round-trip unchanged. */
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->backup_dir = str_dup("backups");
  c->temp_dir = str_dup("/tmp/fast");
  c->partial_dir = str_dup(".partial");
  c->suffix = str_dup(".bak");
  EXPECT_TRUE(roundtrip_config_ok(c));
  config_delete(c);
}

/* A --temp-dir value must survive config_send/config_receive unchanged on the
   receive side (round-trips through the resume-options wire block). */
static void test_config_temp_dir_roundtrip() {
  if (is_running_under_valgrind())
    return;
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->temp_dir = str_dup("scratch");
  EXPECT_TRUE(roundtrip_config_ok(c));
  config_delete(c);

  /* An empty-STRING wire value is canonicalized back to NULL (never an empty
     scratch-dir name). */
  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->temp_dir = str_dup("");
  EXPECT_TRUE(roundtrip_config_ok(c));
  config_delete(c);
}

static void test_config_delay_updates_reserved_backup_rejected() {
  if (is_running_under_valgrind())
    return;
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->delay_updates = true;
  c->backup_dir = str_dup(".fastsync-stage");
  /* The receiver-side wire validation must reject a --backup-dir that collides
     with the internal delay-updates staging directory. */
  EXPECT_FALSE(roundtrip_config_ok(c));
  config_delete(c);

  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->delay_updates = true;
  c->backup_dir = str_dup("backups");
  EXPECT_TRUE(roundtrip_config_ok(c));
  config_delete(c);
}

static void test_config_delete_timing_early_helper() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  EXPECT_FALSE(config_delete_timing_early(cfg));
  EXPECT_TRUE(config_has_valid_delete_timing(cfg));
  cfg->use_delete = true;
  EXPECT_TRUE(config_has_valid_delete_timing(cfg));
  EXPECT_FALSE(config_delete_timing_early(cfg));
  config_delete(cfg);

  cfg = config_create();
  cfg->use_delete = true;
  cfg->delete_before = true;
  EXPECT_TRUE(config_delete_timing_early(cfg));
  EXPECT_TRUE(config_has_valid_delete_timing(cfg));
  config_delete(cfg);

  cfg = config_create();
  cfg->use_delete = true;
  cfg->delete_during = true;
  EXPECT_TRUE(config_delete_timing_early(cfg));
  EXPECT_TRUE(config_has_valid_delete_timing(cfg));
  config_delete(cfg);

  cfg = config_create();
  cfg->use_delete = true;
  cfg->delete_delay = true;
  EXPECT_FALSE(config_delete_timing_early(cfg));
  EXPECT_TRUE(config_has_valid_delete_timing(cfg));
  config_delete(cfg);

  cfg = config_create();
  cfg->use_delete = true;
  cfg->delete_after = true;
  EXPECT_FALSE(config_delete_timing_early(cfg));
  EXPECT_TRUE(config_has_valid_delete_timing(cfg));
  config_delete(cfg);

  /* Two simultaneous timings are invalid. */
  cfg = config_create();
  cfg->use_delete = true;
  cfg->delete_before = true;
  cfg->delete_after = true;
  EXPECT_TRUE(config_delete_timing_early(cfg));
  EXPECT_FALSE(config_has_valid_delete_timing(cfg));
  config_delete(cfg);

  /* A timing flag without deletion is invalid. */
  cfg = config_create();
  cfg->delete_delay = true;
  EXPECT_FALSE(config_has_valid_delete_timing(cfg));
  EXPECT_FALSE(config_delete_timing_early(cfg));
  config_delete(cfg);
}

/* New delete-timing fields must survive config_send/config_receive unchanged,
   and a config carrying two conflicting timings must be rejected. */
static void test_config_delete_timing_wire_roundtrip() {
  if (is_running_under_valgrind())
    return;

  struct {
    bool before, during, delay, after;
  } cases[] = {
      {false, false, false, false}, {true, false, false, false}, {false, true, false, false},
      {false, false, true, false},  {false, false, false, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    int p[2];
    EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
    pid_t pid = fork();
    if (pid == 0) {
      close(p[1]);
      io_set_fds(p[0], p[0]);
      Config* recv = config_receive(p[0]);
      bool ok = recv != NULL;
      if (ok) {
        ok = recv->use_delete && recv->delete_before == cases[i].before &&
             recv->delete_during == cases[i].during && recv->delete_delay == cases[i].delay &&
             recv->delete_after == cases[i].after;
      }
      config_delete(recv);
      close(p[0]);
      _exit(ok ? 0 : 1);
    } else {
      close(p[0]);
      io_set_fds(p[1], p[1]);
      Config* send_cfg = config_create();
      EXPECT_NOT_NULL(send_cfg);
      send_cfg->send_directory = str_dup("/src");
      send_cfg->receive_root_directory = str_dup("/dst");
      send_cfg->use_delete = true;
      send_cfg->delete_before = cases[i].before;
      send_cfg->delete_during = cases[i].during;
      send_cfg->delete_delay = cases[i].delay;
      send_cfg->delete_after = cases[i].after;
      bool sent = config_send(p[1], send_cfg);
      int status;
      waitpid(pid, &status, 0);
      close(p[1]);
      config_delete(send_cfg);
      EXPECT_TRUE(sent);
      EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  }
}

/* The receiver-side wire validation rejects a keep-set config with two
   conflicting delete-timing flags. */
static void test_config_delete_timing_conflict_rejected() {
  if (is_running_under_valgrind())
    return;
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->use_delete = true;
  c->delete_before = true;
  c->delete_delay = true;
  EXPECT_FALSE(roundtrip_config_ok(c));
  config_delete(c);
}

/* The deletion-policy fields that cross the wire survive a config round trip:
   --force (force_delete), --delete-excluded, --prune-empty-dirs and the
   --max-delete number (default -1 == no client limit). */
static void test_config_delete_policy_wire_roundtrip() {
  if (is_running_under_valgrind())
    return;

  struct {
    bool force_delete, delete_excluded, prune_empty_dirs;
    int max_delete;
  } cases[] = {
      {false, false, false, -1},
      {true, false, false, 0},
      {false, true, true, 7},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    int p[2];
    EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
    pid_t pid = fork();
    if (pid == 0) {
      close(p[1]);
      io_set_fds(p[0], p[0]);
      Config* recv = config_receive(p[0]);
      bool ok = recv != NULL;
      if (ok) {
        ok = recv->force_delete == cases[i].force_delete &&
             recv->delete_excluded == cases[i].delete_excluded &&
             recv->prune_empty_dirs == cases[i].prune_empty_dirs &&
             recv->max_delete == cases[i].max_delete;
      }
      config_delete(recv);
      close(p[0]);
      _exit(ok ? 0 : 1);
    } else {
      close(p[0]);
      io_set_fds(p[1], p[1]);
      Config* send_cfg = config_create();
      EXPECT_NOT_NULL(send_cfg);
      send_cfg->send_directory = str_dup("/src");
      send_cfg->receive_root_directory = str_dup("/dst");
      send_cfg->force_delete = cases[i].force_delete;
      send_cfg->delete_excluded = cases[i].delete_excluded;
      send_cfg->prune_empty_dirs = cases[i].prune_empty_dirs;
      send_cfg->max_delete = cases[i].max_delete;
      bool sent = config_send(p[1], send_cfg);
      int status;
      waitpid(pid, &status, 0);
      close(p[1]);
      config_delete(send_cfg);
      EXPECT_TRUE(sent);
      EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  }
}

/* Phase 4 symlink-trust wire split: --munge-links and -K/--keep-dirlinks CROSS
   the wire (the receiver unmunges targets and follows an in-root dir-link),
   while -k/--copy-dirlinks is client/sender-only and must NOT reach the
   receiver (it would observe it false). */
static void test_config_symlink_trust_wire_roundtrip() {
  if (is_running_under_valgrind())
    return;

  struct {
    bool munge_links, keep_dirlinks, copy_dirlinks;
  } cases[] = {
      {false, false, false},
      {true, false, false},
      {false, true, false},
      {true, true, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    int p[2];
    EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
    pid_t pid = fork();
    if (pid == 0) {
      close(p[1]);
      io_set_fds(p[0], p[0]);
      Config* recv = config_receive(p[0]);
      bool ok = recv != NULL;
      if (ok) {
        ok = recv->munge_links == cases[i].munge_links &&
             recv->keep_dirlinks == cases[i].keep_dirlinks &&
             /* copy_dirlinks never crosses the wire. */
             recv->copy_dirlinks == false;
      }
      config_delete(recv);
      close(p[0]);
      _exit(ok ? 0 : 1);
    } else {
      close(p[0]);
      io_set_fds(p[1], p[1]);
      Config* send_cfg = config_create();
      EXPECT_NOT_NULL(send_cfg);
      send_cfg->send_directory = str_dup("/src");
      send_cfg->receive_root_directory = str_dup("/dst");
      send_cfg->munge_links = cases[i].munge_links;
      send_cfg->keep_dirlinks = cases[i].keep_dirlinks;
      send_cfg->copy_dirlinks = cases[i].copy_dirlinks;
      bool sent = config_send(p[1], send_cfg);
      int status;
      waitpid(pid, &status, 0);
      close(p[1]);
      config_delete(send_cfg);
      EXPECT_TRUE(sent);
      EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  }
}
static void test_config_delete_missing_args_wire_roundtrip() {
  if (is_running_under_valgrind())
    return;

  struct {
    bool delete_missing_args, ignore_missing_args;
  } cases[] = {
      {false, false},
      {true, false},
      {true, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    int p[2];
    EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
    pid_t pid = fork();
    if (pid == 0) {
      close(p[1]);
      io_set_fds(p[0], p[0]);
      Config* recv = config_receive(p[0]);
      bool ok = recv != NULL;
      if (ok) {
        ok = recv->delete_missing_args == cases[i].delete_missing_args &&
             /* ignore_missing_args never crosses the wire. */
             recv->ignore_missing_args == false;
      }
      config_delete(recv);
      close(p[0]);
      _exit(ok ? 0 : 1);
    } else {
      close(p[0]);
      io_set_fds(p[1], p[1]);
      Config* send_cfg = config_create();
      EXPECT_NOT_NULL(send_cfg);
      send_cfg->send_directory = str_dup("/src");
      send_cfg->receive_root_directory = str_dup("/dst");
      send_cfg->delete_missing_args = cases[i].delete_missing_args;
      send_cfg->ignore_missing_args = cases[i].ignore_missing_args;
      bool sent = config_send(p[1], send_cfg);
      int status;
      waitpid(pid, &status, 0);
      close(p[1]);
      config_delete(send_cfg);
      EXPECT_TRUE(sent);
      EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  }
}

/* Basis-dir lists survive the config wire: each entry's type and path must
   round-trip unchanged. */
static void test_config_basis_roundtrip() {
  if (is_running_under_valgrind())
    return;
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/send/src");
  send_cfg->receive_root_directory = str_dup("/send/dst");
  EXPECT_EQ_INT(config_basis_append(send_cfg, BASIS_DEST_LINK, "prior"), 0);
  EXPECT_EQ_INT(config_basis_append(send_cfg, BASIS_DEST_COMPARE, "snap/2026-01"), 0);
  EXPECT_EQ_INT(config_basis_append(send_cfg, BASIS_DEST_COPY, "copy"), 0);

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv = config_receive(p[0]);
    bool ok = recv != NULL && recv->basis_count == 3 && recv->basis_dirs != NULL;
    if (ok) {
      ok = recv->basis_dirs[0].type == BASIS_DEST_LINK &&
           strcmp(recv->basis_dirs[0].path, "prior") == 0;
      ok = ok && recv->basis_dirs[1].type == BASIS_DEST_COMPARE &&
           strcmp(recv->basis_dirs[1].path, "snap/2026-01") == 0;
      ok = ok && recv->basis_dirs[2].type == BASIS_DEST_COPY &&
           strcmp(recv->basis_dirs[2].path, "copy") == 0;
    }
    config_delete(recv);
    close(p[0]);
    close(p[1]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* The receiver must reject a basis-dir path that would escape the destination
   root.  The values are injected directly (bypassing the client-side append
   validator) so the receiver-side wire validation is what is exercised. */
static void test_config_basis_wire_rejects_escaping() {
  if (is_running_under_valgrind())
    return;
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->basis_count = 1;
  c->basis_dirs = calloc(1, sizeof(BasisDest));
  c->basis_dirs[0].type = BASIS_DEST_LINK;
  c->basis_dirs[0].path = str_dup("../../etc");
  EXPECT_FALSE(roundtrip_config_ok(c));
  config_delete(c);

  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->basis_count = 1;
  c->basis_dirs = calloc(1, sizeof(BasisDest));
  c->basis_dirs[0].type = BASIS_DEST_LINK;
  c->basis_dirs[0].path = str_dup("/abs");
  EXPECT_FALSE(roundtrip_config_ok(c));
  config_delete(c);

  /* A well-formed list still round-trips even with a manually built struct. */
  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->basis_count = 1;
  c->basis_dirs = calloc(1, sizeof(BasisDest));
  c->basis_dirs[0].type = BASIS_DEST_COPY;
  c->basis_dirs[0].path = str_dup("safe");
  EXPECT_TRUE(roundtrip_config_ok(c));
  config_delete(c);
}

/* Basis-dir paths are canonicalized on the way in: trailing slashes and
   interior empty / "." components are dropped so validation, the delete-walker
   prefix and the receiver lookup all agree on one stored form. */
static void test_config_basis_normalization() {
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_LINK, "prior/"), 0);
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_LINK, "a//b"), 0);
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_LINK, "./x/./y/"), 0);
  EXPECT_EQ_INT(c->basis_count, 3);
  EXPECT_EQ_STR(c->basis_dirs[0].path, "prior");
  EXPECT_EQ_STR(c->basis_dirs[1].path, "a/b");
  EXPECT_EQ_STR(c->basis_dirs[2].path, "x/y");

  /* Degenerate values that normalize away to nothing stay rejected. */
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_LINK, "."), -1);
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_LINK, ".."), -1);
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_LINK, "/abs"), -1);
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_LINK, "a/../b"), -1);
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_LINK, ""), -1);
  config_delete(c);
}

static void test_config_is_remote_dest() {
  /* Valid SSH-style destinations */
  EXPECT_TRUE(config_is_remote_dest("user@host:/path"));
  EXPECT_TRUE(config_is_remote_dest("host:/path"));
  EXPECT_TRUE(config_is_remote_dest("user@192.168.1.1:/remote/path"));

  /* Invalid destinations */
  EXPECT_FALSE(config_is_remote_dest(NULL));
  EXPECT_FALSE(config_is_remote_dest(""));
  EXPECT_FALSE(config_is_remote_dest(":"));
  EXPECT_FALSE(config_is_remote_dest("/local/path"));
  EXPECT_FALSE(config_is_remote_dest("relative/path"));
  /* C:/windows/path is treated as remote (colon with no preceding slash) */
  EXPECT_TRUE(config_is_remote_dest("C:/windows/path"));

  /* Edge cases */
  EXPECT_FALSE(config_is_remote_dest("noslash"));
  EXPECT_FALSE(config_is_remote_dest("/"));
  EXPECT_TRUE(config_is_remote_dest("host:"));
  EXPECT_TRUE(config_is_remote_dest("user@host:"));
}

/* The append-mode fields cross the wire unchanged: --append and --append-verify
   are negotiated to the receiver so it knows to reply STATUS_APPEND on a
   shorter destination. */
static void test_config_append_wire_roundtrip() {
  struct {
    bool append, append_verify;
  } cases[] = {{true, false}, {false, true}, {true, true}, {false, false}};
  if (is_running_under_valgrind())
    return;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    int p[2];
    EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
    pid_t pid = fork();
    if (pid == 0) {
      close(p[1]);
      io_set_fds(p[0], p[0]);
      Config* recv = config_receive(p[0]);
      bool ok = recv != NULL;
      if (ok)
        ok = recv->append == cases[i].append && recv->append_verify == cases[i].append_verify;
      config_delete(recv);
      close(p[0]);
      _exit(ok ? 0 : 1);
    } else {
      close(p[0]);
      io_set_fds(p[1], p[1]);
      Config* send_cfg = config_create();
      EXPECT_NOT_NULL(send_cfg);
      send_cfg->send_directory = str_dup("/src");
      send_cfg->receive_root_directory = str_dup("/dst");
      send_cfg->append = cases[i].append;
      send_cfg->append_verify = cases[i].append_verify;
      bool sent = config_send(p[1], send_cfg);
      int status;
      waitpid(pid, &status, 0);
      close(p[1]);
      config_delete(send_cfg);
      EXPECT_TRUE(sent);
      EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  }
}

/* --checksum-choice/--cc and --checksum-seed cross the wire intact so the
   receiver hashes the on-disk old file with the same algorithm and seed. */
static void test_config_checksum_options_wire_roundtrip() {
  struct {
    int algo;
    unsigned long long seed;
  } cases[] = {
      {CHECKSUM_ALGO_XXH64, 0},
      {CHECKSUM_ALGO_XXH64, 42},
      {CHECKSUM_ALGO_MD5, 7},
      {CHECKSUM_ALGO_MD5, 0},
  };
  if (is_running_under_valgrind())
    return;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    int p[2];
    EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
    pid_t pid = fork();
    if (pid == 0) {
      close(p[1]);
      io_set_fds(p[0], p[0]);
      Config* recv = config_receive(p[0]);
      bool ok = recv != NULL && recv->checksum_algo == cases[i].algo &&
                recv->checksum_seed == cases[i].seed;
      config_delete(recv);
      close(p[0]);
      _exit(ok ? 0 : 1);
    } else {
      close(p[0]);
      io_set_fds(p[1], p[1]);
      Config* send_cfg = config_create();
      EXPECT_NOT_NULL(send_cfg);
      send_cfg->send_directory = str_dup("/src");
      send_cfg->receive_root_directory = str_dup("/dst");
      send_cfg->checksum_algo = cases[i].algo;
      send_cfg->checksum_seed = cases[i].seed;
      bool sent = config_send(p[1], send_cfg);
      int status;
      waitpid(pid, &status, 0);
      close(p[1]);
      config_delete(send_cfg);
      EXPECT_TRUE(sent);
      EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  }
}

/* An out-of-range algorithm id on the wire must be rejected on receive, never
   accepted as-is (prevents mixing unsupported digests on a path). */
static void test_config_receive_rejects_invalid_checksum_algo() {
  if (is_running_under_valgrind())
    return;
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->checksum_algo = 99;
  EXPECT_FALSE(roundtrip_config_ok(c));
  config_delete(c);
}
/* The identity-mapping fields (--numeric-ids / --usermap / --groupmap /
   --chown) cross the config wire unchanged: the receiver needs them to apply
   ownership with the same policy the client requested. */
static void test_config_metadata_times_wire_roundtrip() {
  if (is_running_under_valgrind())
    return;
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/send/src");
  send_cfg->receive_root_directory = str_dup("/send/dst");
  send_cfg->preserve_atimes = true;
  send_cfg->preserve_crtimes = true;
  send_cfg->omit_dir_times = true;
  send_cfg->omit_link_times = true;
  /* --open-noatime is client-only and must NOT cross the wire. */
  send_cfg->open_noatime = true;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv = config_receive(p[0]);
    bool ok = recv != NULL;
    if (ok) {
      ok = recv->preserve_atimes && recv->preserve_crtimes && recv->omit_dir_times &&
           recv->omit_link_times && !recv->open_noatime;
    }
    config_delete(recv);
    close(p[0]);
    close(p[1]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_config_identity_wire_roundtrip() {
  if (is_running_under_valgrind())
    return;
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/send/src");
  send_cfg->receive_root_directory = str_dup("/send/dst");
  send_cfg->numeric_ids = true;
  send_cfg->chown_uid_set = true;
  send_cfg->chown_uid = 1001;
  send_cfg->chown_gid_set = true;
  send_cfg->chown_gid = IDENTITY_CURRENT;
  send_cfg->usermap_count = 2;
  send_cfg->usermap = calloc(2, sizeof(IdentityMap));
  send_cfg->usermap[0].from = IDENTITY_MATCH_ANY;
  send_cfg->usermap[0].to = 65534;
  send_cfg->usermap[1].from = 1000;
  send_cfg->usermap[1].to = 1000;
  send_cfg->groupmap_count = 1;
  send_cfg->groupmap = calloc(1, sizeof(IdentityMap));
  send_cfg->groupmap[0].from = 0;
  send_cfg->groupmap[0].to = IDENTITY_CURRENT;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv = config_receive(p[0]);
    bool ok = recv != NULL;
    if (ok) {
      ok = recv->numeric_ids && recv->chown_uid_set && recv->chown_uid == 1001 &&
           recv->chown_gid_set && recv->chown_gid == IDENTITY_CURRENT && recv->usermap_count == 2 &&
           recv->groupmap_count == 1 && recv->usermap[0].from == IDENTITY_MATCH_ANY &&
           recv->usermap[0].to == 65534 && recv->usermap[1].from == 1000 &&
           recv->usermap[1].to == 1000 && recv->groupmap[0].from == 0 &&
           recv->groupmap[0].to == IDENTITY_CURRENT;
    }
    config_delete(recv);
    close(p[0]);
    close(p[1]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* The receiver must reject an out-of-range identity-map count or id on the
   wire (defense against a malicious/oversized table). */
static void test_config_receive_rejects_invalid_identity() {
  if (is_running_under_valgrind())
    return;
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->usermap_count = 1;
  c->usermap = calloc(1, sizeof(IdentityMap));
  c->usermap[0].from = -2; /* below IDENTITY_MATCH_ANY */
  c->usermap[0].to = 0;
  EXPECT_FALSE(roundtrip_config_ok(c));
  config_delete(c);

  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->chown_uid_set = true;
  c->chown_uid = -5;
  EXPECT_FALSE(roundtrip_config_ok(c));
  config_delete(c);

  /* A well-formed identity config still round-trips through the shared helper. */
  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->numeric_ids = true;
  EXPECT_TRUE(roundtrip_config_ok(c));
  config_delete(c);
}

/* --preallocate crosses the wire unchanged (receiver-side flag): the receiver
   must learn to allocate the destination file's space before data flows. */
static void test_config_preallocate_wire_roundtrip() {
  struct {
    bool preallocate;
  } cases[] = {{false}, {true}};
  if (is_running_under_valgrind())
    return;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    int p[2];
    EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
    pid_t pid = fork();
    if (pid == 0) {
      close(p[1]);
      io_set_fds(p[0], p[0]);
      Config* recv = config_receive(p[0]);
      bool ok = recv != NULL && recv->preallocate == cases[i].preallocate;
      config_delete(recv);
      close(p[0]);
      _exit(ok ? 0 : 1);
    } else {
      close(p[0]);
      io_set_fds(p[1], p[1]);
      Config* send_cfg = config_create();
      EXPECT_NOT_NULL(send_cfg);
      send_cfg->send_directory = str_dup("/src");
      send_cfg->receive_root_directory = str_dup("/dst");
      send_cfg->preallocate = cases[i].preallocate;
      bool sent = config_send(p[1], send_cfg);
      int status;
      waitpid(pid, &status, 0);
      close(p[1]);
      config_delete(send_cfg);
      EXPECT_TRUE(sent);
      EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  }
}
static void test_config_devices_wire_roundtrip() {
  if (is_running_under_valgrind())
    return;
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/send/src");
  send_cfg->receive_root_directory = str_dup("/send/dst");
  send_cfg->preserve_devices = true;
  send_cfg->preserve_specials = true;
  send_cfg->copy_devices = true;
  send_cfg->write_devices = true;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv = config_receive(p[0]);
    bool ok = recv != NULL;
    if (ok) {
      ok = recv->preserve_devices && recv->preserve_specials && recv->copy_devices &&
           recv->write_devices;
    }
    config_delete(recv);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* Phase-4: preserve_xattrs/--acls (in file options) and --fake-super (trailing)
 * cross the config wire; the receiver recomputes the derived use_xattrs. */
static void test_config_phase4_xattr_wire_roundtrip() {
  if (is_running_under_valgrind())
    return;
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/send/src");
  send_cfg->receive_root_directory = str_dup("/send/dst");
  send_cfg->preserve_xattrs = true;
  send_cfg->preserve_acls = true;
  send_cfg->fake_super = true;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv = config_receive(p[0]);
    bool ok = recv != NULL;
    if (ok) {
      ok = recv->preserve_xattrs && recv->preserve_acls && recv->fake_super && recv->use_xattrs;
    }
    config_delete(recv);
    close(p[0]);
    close(p[1]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* --trust-sender defaults to OFF (a receiver-local policy). */
static void test_config_trust_sender_default_false() {
  Config* cfg = config_create();
  EXPECT_NOT_NULL(cfg);
  EXPECT_FALSE(cfg->trust_sender);
  EXPECT_NULL(cfg->remote_options);
  EXPECT_EQ_INT(cfg->remote_option_count, 0);
  config_delete(cfg);
}

/* --trust-sender and --remote-option are LOCAL to the process that sets them:
 * they must never cross the wire.  After a round-trip the receiver observes the
 * neutral defaults (trust_sender=false, no remote options), even when the
 * sender had them set. */
static void test_config_local_only_fields_not_serialized() {
  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv = config_receive(p[0]);
    bool ok = recv != NULL && !recv->trust_sender && recv->remote_options == NULL &&
              recv->remote_option_count == 0;
    config_delete(recv);
    close(p[0]);
    _exit(ok ? 0 : 1);
  }

  close(p[0]);
  io_set_fds(p[1], p[1]);
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->trust_sender = true;
  /* remote_options is client-side state; populate it like the CLI would. */
  send_cfg->remote_options = malloc(sizeof(char*));
  send_cfg->remote_options[0] = str_dup("--allow-delete");
  send_cfg->remote_option_count = 1;
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("/dst");
  bool sent = config_send(p[1], send_cfg);
  int status;
  waitpid(pid, &status, 0);
  close(p[1]);
  config_delete(send_cfg);

  EXPECT_TRUE(sent);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_config_iconv_spec_wire_roundtrip() {
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("rel/path");
  send_cfg->iconv_spec = str_dup("utf-8,iso-8859-1");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv_cfg = config_receive(p[0]);
    bool ok = recv_cfg != NULL && recv_cfg->iconv_spec != NULL &&
              strcmp(recv_cfg->iconv_spec, "utf-8,iso-8859-1") == 0;
    config_delete(recv_cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_config_iconv_spec_empty_canonicalizes_to_null() {
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("/dst");
  /* iconv_spec left NULL -> serialized as "" -> received back as NULL. */

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv_cfg = config_receive(p[0]);
    bool ok = recv_cfg != NULL && recv_cfg->iconv_spec == NULL;
    config_delete(recv_cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_TRUE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void test_config_receive_rejects_invalid_iconv_spec() {
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("/dst");
  send_cfg->iconv_spec = str_dup("no-such-charset,utf-8");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    /* A malformed/unsupported spec must be refused at the config handshake
       (STATUS_ERROR makes config_send fail on the parent). */
    Config* recv_cfg = config_receive(p[0]);
    config_delete(recv_cfg);
    close(p[0]);
    _exit(recv_cfg ? 1 : 0);
  } else {
    close(p[0]);
    io_set_fds(p[1], p[1]);
    bool sent = config_send(p[1], send_cfg);
    int status;
    waitpid(pid, &status, 0);
    close(p[1]);
    config_delete(send_cfg);
    EXPECT_FALSE(sent);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

/* P7 Wave E: the --super / --no-super tri-state crosses the config wire
   unchanged (AUTO/ON/OFF), so the receiver can enforce the privilege policy. */
static void test_config_super_mode_wire_roundtrip() {
  if (is_running_under_valgrind())
    return;
  int modes[] = {SUPER_MODE_AUTO, SUPER_MODE_ON, SUPER_MODE_OFF};
  for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
    int p[2];
    EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
    pid_t pid = fork();
    if (pid == 0) {
      close(p[1]);
      io_set_fds(p[0], p[0]);
      Config* recv = config_receive(p[0]);
      bool ok = recv != NULL && recv->super_mode == modes[i];
      config_delete(recv);
      close(p[0]);
      _exit(ok ? 0 : 1);
    } else {
      close(p[0]);
      io_set_fds(p[1], p[1]);
      Config* send_cfg = config_create();
      EXPECT_NOT_NULL(send_cfg);
      send_cfg->send_directory = str_dup("/src");
      send_cfg->receive_root_directory = str_dup("/dst");
      send_cfg->super_mode = modes[i];
      bool sent = config_send(p[1], send_cfg);
      int status;
      waitpid(pid, &status, 0);
      close(p[1]);
      config_delete(send_cfg);
      EXPECT_TRUE(sent);
      EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  }
}

/* An out-of-range super_mode value on the wire must be refused on receive
   (never silently clamped or accepted). */
static void test_config_receive_rejects_invalid_super_mode() {
  if (is_running_under_valgrind())
    return;
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->super_mode = 99;
  EXPECT_FALSE(roundtrip_config_ok(c));
  config_delete(c);

  /* A negative value is equally invalid. */
  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->super_mode = -1;
  EXPECT_FALSE(roundtrip_config_ok(c));
  config_delete(c);
}

/* P7 Wave E: privilege_super_permitted() maps the super_mode tri-state.  OFF
   forbids super-user activities even for root; ON permits them; AUTO follows
   the effective uid. */
static void test_privilege_super_permitted_modes() {
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->super_mode = SUPER_MODE_OFF;
  identity_set_active(c);
  EXPECT_FALSE(privilege_super_permitted());
  c->super_mode = SUPER_MODE_ON;
  identity_set_active(c);
  EXPECT_TRUE(privilege_super_permitted());
  c->super_mode = SUPER_MODE_AUTO;
  identity_set_active(c);
  EXPECT_EQ_INT(privilege_super_permitted() ? 1 : 0, geteuid() == 0 ? 1 : 0);
  config_delete(c);

  /* After clearing, the neutral default is AUTO (root-following), never a
     stale snapshot from a previous connection. */
  identity_clear_active();
  EXPECT_EQ_INT(privilege_super_permitted() ? 1 : 0, geteuid() == 0 ? 1 : 0);
}

void test_config() {
  test_config_lifecycle();
  test_config_ssh_dest();
  test_config_ssh_dest_local_path();
  test_config_ssh_dest_no_user();
  test_config_daemon_dest_parse();
  test_config_daemon_dest_no_path();
  test_config_daemon_dest_double_slash_normalized();
  test_config_daemon_dest_bad();
  test_config_transport_dest_daemon_beats_ssh();
  test_config_is_daemon_dest();
  test_config_trust_sender_default_false();
  test_pipeline_sender_lifecycle();
  test_pipeline_receiver_lifecycle();
  if (!is_running_under_valgrind()) {
    test_config_send_receive();
    test_config_local_only_fields_not_serialized();
    test_config_send_receive_version_mismatch();
    test_config_receive_truncated();
    test_config_string_null_vs_empty_roundtrip();
    test_config_temp_dir_roundtrip();
    test_config_delay_updates_reserved_backup_rejected();
    test_config_delete_timing_wire_roundtrip();
    test_config_delete_timing_conflict_rejected();
    test_config_delete_policy_wire_roundtrip();
    test_config_symlink_trust_wire_roundtrip();
    test_config_delete_missing_args_wire_roundtrip();
    test_config_append_wire_roundtrip();
    test_config_basis_roundtrip();
    test_config_basis_wire_rejects_escaping();
    test_config_basis_normalization();
    test_config_checksum_options_wire_roundtrip();
    test_config_receive_rejects_invalid_checksum_algo();
    test_config_identity_wire_roundtrip();
    test_config_receive_rejects_invalid_identity();
    test_config_metadata_times_wire_roundtrip();
    test_config_devices_wire_roundtrip();
    test_config_preallocate_wire_roundtrip();
    test_config_phase4_xattr_wire_roundtrip();
    test_config_module_wire_roundtrip();
    test_config_module_wire_empty_canonicalizes_to_null();
    test_config_daemon_auth_wire_roundtrip();
    test_config_daemon_auth_wire_rejects_malformed();
    test_config_iconv_spec_wire_roundtrip();
    test_config_iconv_spec_empty_canonicalizes_to_null();
    test_config_receive_rejects_invalid_iconv_spec();
    test_config_super_mode_wire_roundtrip();
    test_config_receive_rejects_invalid_super_mode();
    test_config_receive_with_validate_rejects();
  }
  test_privilege_super_permitted_modes();
  test_config_delete_timing_early_helper();
  test_config_is_remote_dest();
}
