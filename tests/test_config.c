#include "test_config.h"
#include "config.h"
#include "delta.h"
#include "identity.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "receiver_pipeline.h"
#include "test_utils.h"
#include "utils.h"
#include <signal.h>
#include <stddef.h>
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

/* C1: the user@host token is passed to ssh in option position, so a host or user
 * beginning with '-' (e.g. "-oProxyCommand=...") must be rejected before any
 * argv is built, and an empty host must be rejected too. */
static void test_config_ssh_dest_rejects_option_injection() {
  Config* cfg = make_config("1.0", "/src", "-oProxyCommand=id:/dst", true, false, false, false,
                            false, 1, false, 0);
  EXPECT_EQ_INT(config_parse_ssh_dest(cfg), -1);
  EXPECT_EQ_INT(cfg->transport, TRANSPORT_TCP);
  EXPECT_NULL(cfg->ssh_destination);
  config_delete(cfg);

  cfg =
      make_config("1.0", "/src", "-user@host:/dst", true, false, false, false, false, 1, false, 0);
  EXPECT_EQ_INT(config_parse_ssh_dest(cfg), -1);
  config_delete(cfg);

  cfg = make_config("1.0", "/src", "user@:/dst", true, false, false, false, false, 1, false, 0);
  EXPECT_EQ_INT(config_parse_ssh_dest(cfg), -1);
  config_delete(cfg);

  /* config_parse_transport_dest propagates the rejection (and still returns 1
   * for daemon syntax first). */
  cfg = make_config("1.0", "/src", "-oProxyCommand=id:/dst", true, false, false, false, false, 1,
                    false, 0);
  EXPECT_EQ_INT(config_parse_transport_dest(cfg), -1);
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

/* Daemon auth credentials (A7, protocol 2.19.0) ride the config frame as the
 * username ONLY; the literal password never crosses the wire.  Round-trip a
 * present username. */
static void test_config_daemon_auth_wire_roundtrip() {
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("rel/path");
  send_cfg->module = str_dup("backup");
  send_cfg->auth_user = str_dup("alice");
  send_cfg->auth_password = str_dup("alice-s3cret");

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    Config* recv_cfg = config_receive(p[0]);
    /* The plaintext password is client-only: it is never serialized. */
    bool ok = recv_cfg != NULL && recv_cfg->auth_user != NULL &&
              strcmp(recv_cfg->auth_user, "alice") == 0 && recv_cfg->auth_password == NULL;
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

/* The receive side validates the auth payload: a present-but-malformed username
 * is refused (config_receive returns NULL), so a hostile peer cannot slip a
 * garbage credential past the receive guard into the module gate. */
static void test_config_daemon_auth_wire_rejects_malformed() {
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("/dst");
  send_cfg->module = str_dup("m");
  send_cfg->auth_user = str_dup("bad user");

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
  config_delete(cfg); /* the context borrows cfg; the caller owns it */
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
  /* The preservation attributes now require the metadata frame to travel
   * (config_invariants_error rejects them otherwise). */
  send_cfg->use_metadata = true;
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
  SuperMode modes[] = {SUPER_MODE_AUTO, SUPER_MODE_ON, SUPER_MODE_OFF};
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

/* --copy-as (P7 Wave E, protocol 2.18.0) travels as a trailing config-frame
   block: a presence int, then the two int32 ids when set. */
static void test_config_copy_as_wire_roundtrip() {
  struct {
    bool set;
    int32_t uid;
    int32_t gid;
  } cases[] = {{false, 0, 0}, {true, 1000, 1001}};
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
      bool ok = recv != NULL && recv->copy_as_set == cases[i].set &&
                (!cases[i].set ||
                 (recv->copy_as_uid == cases[i].uid && recv->copy_as_gid == cases[i].gid));
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
      send_cfg->copy_as_set = cases[i].set;
      send_cfg->copy_as_uid = cases[i].uid;
      send_cfg->copy_as_gid = cases[i].gid;
      /* --copy-as requires the metadata path (the receiver chowns from the
         transmitted source ids); a raw frame with copy_as_set but no metadata
         is now rejected by validate_received_config. */
      send_cfg->use_metadata = cases[i].set;
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

/* A hostile peer must not smuggle a negative (sentinel) copy-as id into the
   ownership path: the receive side rejects it and the run fails the handshake. */
static void test_config_receive_rejects_negative_copy_as() {
  if (is_running_under_valgrind())
    return;
  Config* send_cfg = config_create();
  EXPECT_NOT_NULL(send_cfg);
  send_cfg->send_directory = str_dup("/src");
  send_cfg->receive_root_directory = str_dup("/dst");
  send_cfg->copy_as_set = true;
  send_cfg->copy_as_uid = -1;
  send_cfg->copy_as_gid = 0;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);

  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
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

/* --copy-as forces ownership through the metadata path.  A frame that sets
   copy_as_set but not use_metadata would pass the receiver's privilege gate
   while chowning nothing, so validate_received_config must reject it (and the
   sender observes the rejection as a failed config_send). */
static void test_config_receive_rejects_copy_as_without_metadata() {
  if (is_running_under_valgrind())
    return;
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->copy_as_set = true;
  c->copy_as_uid = 1000;
  c->copy_as_gid = 1000;
  c->use_metadata = false;
  EXPECT_FALSE(roundtrip_config_ok(c));
  config_delete(c);

  /* With metadata enabled the same block is accepted. */
  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->copy_as_set = true;
  c->copy_as_uid = 1000;
  c->copy_as_gid = 1000;
  c->use_metadata = true;
  EXPECT_TRUE(roundtrip_config_ok(c));
  config_delete(c);
}

/* Like roundtrip_config_ok, but the parent is the RECEIVER so the frame can be
   rejected MID-way, before the sender finishes writing it.  The sender child
   ignores SIGPIPE so the receiver closing early cannot kill it; the parent
   waits for the child to exit after observing the rejection. */
static bool roundtrip_config_rejected(const Config* send_cfg) {
  int p[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) != 0)
    return false;
  pid_t pid = fork();
  if (pid == 0) {
    (void)signal(SIGPIPE, SIG_IGN);
    close(p[0]);
    io_set_fds(p[1], p[1]);
    config_send(p[1], send_cfg);
    close(p[1]);
    _exit(0);
  }
  close(p[1]);
  io_set_fds(p[0], p[0]);
  Config* recv = config_receive(p[0]);
  bool rejected = recv == NULL;
  config_delete(recv);
  close(p[0]);
  int status;
  waitpid(pid, &status, 0);
  return rejected;
}

/* Build a Config with `count` --skip-compress suffixes, each `suffix_len` bytes
   long, for the pre-auth config-string budget tests. */
static Config* make_skip_compress_config(int count, size_t suffix_len) {
  Config* c = config_create();
  if (!c)
    return NULL;
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->skip_compress_set = true;
  c->skip_compress_count = count;
  c->skip_compress_suffixes = calloc((size_t)count, sizeof(char*));
  if (!c->skip_compress_suffixes) {
    config_delete(c);
    return NULL;
  }
  char* suffix = malloc(suffix_len + 1);
  if (!suffix) {
    config_delete(c);
    return NULL;
  }
  memset(suffix, 'x', suffix_len);
  suffix[suffix_len] = '\0';
  for (int i = 0; i < count; i++)
    c->skip_compress_suffixes[i] = str_dup(suffix);
  free(suffix);
  return c;
}

/* Pre-auth memory bound: one connection must not retain unbounded config
   strings.  An over-limit --skip-compress count is refused, and even an
   in-range count cannot exceed the aggregate per-connection string budget. */
static void test_config_receive_rejects_oversized_string_budget() {
  if (is_running_under_valgrind())
    return;

  /* Exactly MAX_SKIP_COMPRESS_SUFFIXES tiny suffixes are accepted. */
  Config* ok = make_skip_compress_config(MAX_SKIP_COMPRESS_SUFFIXES, 1);
  EXPECT_NOT_NULL(ok);
  EXPECT_TRUE(roundtrip_config_ok(ok));
  config_delete(ok);

  /* One suffix over the count cap is rejected before any suffix is read. */
  Config* over_count = make_skip_compress_config(MAX_SKIP_COMPRESS_SUFFIXES + 1, 1);
  EXPECT_NOT_NULL(over_count);
  EXPECT_TRUE(roundtrip_config_rejected(over_count));
  config_delete(over_count);

  /* In-range count, but the strings together exceed MAX_CONFIG_STRING_BYTES
     (64 suffixes * ~64 KiB > 1 MiB), so the aggregate budget rejects it. */
  Config* over_bytes = make_skip_compress_config(64, MAX_STRING_SIZE - 1);
  EXPECT_NOT_NULL(over_bytes);
  EXPECT_TRUE(roundtrip_config_rejected(over_bytes));
  config_delete(over_bytes);
}

/* identity_copy_as_refused() is the pure, pre-snapshot refusal predicate: a
   --copy-as is refused when the receiver is not root OR the effective super
   mode is OFF (an operator veto), and never when --copy-as is unset. */
static void test_identity_copy_as_refused() {
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  EXPECT_FALSE(identity_copy_as_refused(c));
  EXPECT_FALSE(identity_copy_as_refused(NULL));

  c->copy_as_set = true;
  c->super_mode = SUPER_MODE_AUTO;
  if (geteuid() == 0) {
    EXPECT_FALSE(identity_copy_as_refused(c)); /* AUTO permits as root */
    c->super_mode = SUPER_MODE_ON;
    EXPECT_FALSE(identity_copy_as_refused(c));
    c->super_mode = SUPER_MODE_OFF;
    EXPECT_TRUE(identity_copy_as_refused(c));
  } else {
    /* Unprivileged: refused regardless of the mode. */
    EXPECT_TRUE(identity_copy_as_refused(c));
    c->super_mode = SUPER_MODE_OFF;
    EXPECT_TRUE(identity_copy_as_refused(c));
  }
  config_delete(c);
}

/* P7 Wave E: privilege_super_permitted() maps the super_mode tri-state.  OFF
   forbids super-user activities even for root; ON and AUTO permit the confined
   attempt (matching FastSync's historical best-effort behavior, where the kernel
   refuses an unprivileged attempt and the caller skips it). */
static void test_privilege_super_permitted_modes() {
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->super_mode = SUPER_MODE_OFF;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_FALSE(privilege_super_permitted());
  c->super_mode = SUPER_MODE_ON;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_TRUE(privilege_super_permitted());
  c->super_mode = SUPER_MODE_AUTO;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_TRUE(privilege_super_permitted());
  config_delete(c);

  /* After clearing, the neutral default is AUTO (attempt), never a stale
     snapshot from a previous connection. */
  identity_clear_active();
  EXPECT_TRUE(privilege_super_permitted());
}

/* P7 Wave E hardening (A1): identity_ownership_requested() is the pure,
   config-only predicate the daemon module gate uses.  It must fire for every
   client-chosen ownership / super-user request and stay false for a plain
   transfer and for SUPER_MODE_AUTO (the default) alone. */
static void test_identity_ownership_requested() {
  EXPECT_FALSE(identity_ownership_requested(NULL));

  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  EXPECT_FALSE(identity_ownership_requested(c));
  c->super_mode = SUPER_MODE_AUTO;
  EXPECT_FALSE(identity_ownership_requested(c)); /* AUTO alone is not ownership */
  c->super_mode = SUPER_MODE_ON;
  EXPECT_TRUE(identity_ownership_requested(c)); /* explicit --super is */
  c->super_mode = SUPER_MODE_AUTO;

  c->numeric_ids = true;
  EXPECT_TRUE(identity_ownership_requested(c));
  c->numeric_ids = false;
  c->chown_uid_set = true;
  EXPECT_TRUE(identity_ownership_requested(c));
  c->chown_uid_set = false;
  c->chown_gid_set = true;
  EXPECT_TRUE(identity_ownership_requested(c));
  c->chown_gid_set = false;
  c->copy_as_set = true;
  EXPECT_TRUE(identity_ownership_requested(c));
  c->copy_as_set = false;
  c->fake_super = true;
  EXPECT_TRUE(identity_ownership_requested(c));
  config_delete(c);

  Config* um = config_create();
  EXPECT_NOT_NULL(um);
  EXPECT_EQ_INT(identity_parse_map(um, "@1:@2", false), 0);
  EXPECT_TRUE(identity_ownership_requested(um));
  config_delete(um);

  Config* gm = config_create();
  EXPECT_NOT_NULL(gm);
  EXPECT_EQ_INT(identity_parse_map(gm, "@1:@2", true), 0);
  EXPECT_TRUE(identity_ownership_requested(gm));
  config_delete(gm);
}

/* The narrow client-CHOSEN ownership predicate the daemon module gate refuses:
 * a preserve-source -o/-g (or -a) must NOT be in it (it is handled by forcing
 * super-user activity off instead), while every explicit identity flag is. */
static void test_identity_explicit_ownership_requested() {
  EXPECT_FALSE(identity_explicit_ownership_requested(NULL));

  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  EXPECT_FALSE(identity_explicit_ownership_requested(c));
  c->preserve_owner = true;
  EXPECT_FALSE(identity_explicit_ownership_requested(c));
  EXPECT_TRUE(identity_ownership_requested(c)); /* general awareness does see -o */
  c->preserve_group = true;
  EXPECT_FALSE(identity_explicit_ownership_requested(c));
  c->preserve_owner = false;
  c->preserve_group = false;

  c->numeric_ids = true;
  EXPECT_TRUE(identity_explicit_ownership_requested(c));
  c->numeric_ids = false;
  c->chown_uid_set = true;
  EXPECT_TRUE(identity_explicit_ownership_requested(c));
  c->chown_uid_set = false;
  c->chown_gid_set = true;
  EXPECT_TRUE(identity_explicit_ownership_requested(c));
  c->chown_gid_set = false;
  c->copy_as_set = true;
  EXPECT_TRUE(identity_explicit_ownership_requested(c));
  c->copy_as_set = false;
  c->fake_super = true;
  EXPECT_TRUE(identity_explicit_ownership_requested(c));
  c->fake_super = false;
  c->super_mode = SUPER_MODE_ON;
  EXPECT_TRUE(identity_explicit_ownership_requested(c));
  c->super_mode = SUPER_MODE_AUTO;
  EXPECT_EQ_INT(identity_parse_map(c, "@1:@2", false), 0);
  EXPECT_TRUE(identity_explicit_ownership_requested(c));
  config_delete(c);
}

/* P7 Wave E hardening (A3): --super no longer implies raw numeric-id
   preservation, so it must never enable ownership application on its own; an
   explicit identity flag is required. */
static void test_super_does_not_imply_numeric() {
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->super_mode = SUPER_MODE_ON;
  c->use_metadata = true;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_FALSE(identity_active_enabled());
  c->numeric_ids = true;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_TRUE(identity_active_enabled());
  identity_clear_active();
  config_delete(c);
}

/* The preserve-source -o/-g requests enable ownership application through the
 * active snapshot (identity_active_enabled) even though they are deliberately
 * absent from the narrow client-chosen identity_explicit_ownership_requested()
 * gate. */
static void test_identity_active_enabled_includes_preserve_attrs() {
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->use_metadata = true;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_FALSE(identity_active_enabled());

  c->preserve_owner = true;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_TRUE(identity_active_enabled());
  EXPECT_FALSE(identity_explicit_ownership_requested(c));

  c->preserve_owner = false;
  c->preserve_group = true;
  EXPECT_TRUE(identity_set_active(c));
  EXPECT_TRUE(identity_active_enabled());
  EXPECT_FALSE(identity_explicit_ownership_requested(c));

  identity_clear_active();
  config_delete(c);
}

/* The single shared predicate must reject every cross-field combination the
   client/server enforce and accept a plain valid config.  Because both
   validate_config() (client) and validate_received_config() (server) call it,
   this table documents the whole invariant set in one place. */
static void test_config_invariants_error_all_combinations() {
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  EXPECT_NULL(config_invariants_error(c));
  config_delete(c);

  c = config_create();
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_COMPARE, "sub"), 0);
  c->use_chunk_serialization = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* basis + chunk */
  config_delete(c);

  c = config_create();
  c->use_sendfile = true;
  c->use_compression = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* sendfile + compression */
  config_delete(c);

  c = config_create();
  c->use_sendfile = true;
  c->use_chunk_serialization = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* sendfile + chunk */
  config_delete(c);

  c = config_create();
  c->use_incremental = true;
  c->use_chunk_serialization = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* incremental + chunk */
  config_delete(c);

  c = config_create();
  c->skip_compress_set = true;
  c->use_chunk_serialization = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* skip-compress + chunk */
  config_delete(c);

  c = config_create();
  c->use_delta = true;                         /* whole_file false -> active */
  EXPECT_NOT_NULL(config_invariants_error(c)); /* delta without incremental */
  config_delete(c);

  c = config_create();
  c->use_delta = true;
  c->use_incremental = true;
  c->use_chunk_serialization = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* delta + chunk */
  config_delete(c);

  c = config_create();
  c->use_delta = true;
  c->use_incremental = true;
  c->use_sendfile = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* delta + sendfile */
  config_delete(c);

  c = config_create();
  c->append = true;
  c->use_chunk_serialization = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* append + chunk */
  config_delete(c);

  c = config_create();
  c->append = true;
  c->whole_file = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* append + whole-file */
  config_delete(c);

  c = config_create();
  c->preserve_hard_links = true;
  c->use_chunk_serialization = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* hard-links + chunk */
  config_delete(c);

  c = config_create();
  c->preserve_xattrs = true;
  c->use_chunk_serialization = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* xattrs + chunk */
  config_delete(c);

  c = config_create();
  c->preserve_hard_links = true;
  c->append = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* hard-links + append */
  config_delete(c);

  c = config_create();
  c->delay_updates = true;
  c->inplace = true;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* delay-updates + inplace */
  config_delete(c);

  c = config_create();
  c->delay_updates = true;
  c->backup_dir = str_dup(".fastsync-stage");
  EXPECT_NOT_NULL(config_invariants_error(c)); /* delay-updates staging conflict */
  config_delete(c);

  c = config_create();
  c->delete_delay = true;                      /* a timing flag without --delete */
  EXPECT_NOT_NULL(config_invariants_error(c)); /* invalid delete timing */
  config_delete(c);

  c = config_create();
  c->iconv_spec = str_dup("no-such-charset,utf-8");
  EXPECT_NOT_NULL(config_invariants_error(c)); /* malformed iconv spec */
  config_delete(c);

  c = config_create();
  c->copy_as_set = true;
  c->use_metadata = false;
  EXPECT_NOT_NULL(config_invariants_error(c)); /* copy-as without metadata */
  config_delete(c);
}

/* Every per-attribute preservation flag requires the metadata frame to travel:
 * the invariant rejects any of them while use_metadata is false, and setting
 * use_metadata clears the violation. */
static void test_config_preservation_requires_metadata() {
  static const size_t attrs[] = {
      offsetof(Config, preserve_perms),    offsetof(Config, preserve_times),
      offsetof(Config, preserve_owner),    offsetof(Config, preserve_group),
      offsetof(Config, preserve_atimes),   offsetof(Config, preserve_crtimes),
      offsetof(Config, use_executability),
  };
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  EXPECT_NULL(config_invariants_error(c));
  for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
    bool* field = (bool*)((char*)c + attrs[i]);
    *field = true;
    EXPECT_NOT_NULL(config_invariants_error(c));
    c->use_metadata = true;
    EXPECT_NULL(config_invariants_error(c));
    c->use_metadata = false;
    *field = false;
  }
  config_delete(c);
}

/* config_derived_use_metadata is the single source of truth for the derived
 * transport bit: each representative flag turns it on, and it stays off for a
 * bare config (numeric_ids alone, omit flags, whole-file, ...). */
static void test_config_derived_use_metadata() {
  static const size_t true_flags[] = {
      offsetof(Config, preserve_perms),    offsetof(Config, preserve_times),
      offsetof(Config, preserve_owner),    offsetof(Config, preserve_group),
      offsetof(Config, preserve_atimes),   offsetof(Config, preserve_crtimes),
      offsetof(Config, use_executability), offsetof(Config, preserve_xattrs),
      offsetof(Config, preserve_acls),     offsetof(Config, fake_super),
      offsetof(Config, preserve_devices),  offsetof(Config, preserve_specials),
      offsetof(Config, copy_devices),      offsetof(Config, write_devices),
      offsetof(Config, copy_as_set),       offsetof(Config, chown_uid_set),
      offsetof(Config, chown_gid_set),     offsetof(Config, update),
  };
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  EXPECT_FALSE(config_derived_use_metadata(c));
  EXPECT_FALSE(config_derived_use_metadata(NULL));
  for (size_t i = 0; i < sizeof(true_flags) / sizeof(true_flags[0]); i++) {
    bool* field = (bool*)((char*)c + true_flags[i]);
    *field = true;
    EXPECT_TRUE(config_derived_use_metadata(c));
    *field = false;
  }

  /* A non-empty --chmod spec. */
  c->chmod_spec = str_dup("u=rw");
  EXPECT_TRUE(config_derived_use_metadata(c));
  free(c->chmod_spec);
  c->chmod_spec = NULL;

  /* Identity-map counts. */
  c->usermap_count = 1;
  EXPECT_TRUE(config_derived_use_metadata(c));
  c->usermap_count = 0;
  c->groupmap_count = 1;
  EXPECT_TRUE(config_derived_use_metadata(c));
  c->groupmap_count = 0;

  /* Incremental/delta imply metadata unless --no-preserve disabled it. */
  c->use_incremental = true;
  EXPECT_TRUE(config_derived_use_metadata(c));
  c->metadata_explicitly_disabled = true;
  EXPECT_FALSE(config_derived_use_metadata(c));
  c->metadata_explicitly_disabled = false;
  c->use_incremental = false;
  c->use_delta = true;
  EXPECT_TRUE(config_derived_use_metadata(c));
  c->metadata_explicitly_disabled = true;
  EXPECT_FALSE(config_derived_use_metadata(c));
  c->metadata_explicitly_disabled = false;
  c->use_delta = false;

  /* Flags that must NOT imply metadata on their own. */
  c->numeric_ids = true;
  c->omit_dir_times = true;
  c->omit_link_times = true;
  c->whole_file = true;
  c->ignore_times = true;
  EXPECT_FALSE(config_derived_use_metadata(c));
  config_delete(c);
}

/* The receiver previously missed several of these; a forged frame that sets
   the offending serialized fields must now be refused at the config
   handshake.  (whole_file is client-only, so its rules cannot appear here.) */
static void test_config_receive_rejects_unified_invariants() {
  if (is_running_under_valgrind())
    return;
  struct {
    bool incremental, delta, chunk, sendfile, compression;
  } cases[] = {
      {true, false, true, false, false},  /* --incremental + -s */
      {false, true, true, false, false},  /* --delta + -s */
      {false, true, false, false, false}, /* --delta without --incremental */
      {false, false, false, true, true},  /* --sendfile + compression */
      {false, false, true, true, false},  /* --sendfile + -s */
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    Config* c = config_create();
    EXPECT_NOT_NULL(c);
    c->send_directory = str_dup("/src");
    c->receive_root_directory = str_dup("/dst");
    c->use_incremental = cases[i].incremental;
    c->use_delta = cases[i].delta;
    c->use_chunk_serialization = cases[i].chunk;
    c->use_sendfile = cases[i].sendfile;
    c->use_compression = cases[i].compression;
    EXPECT_FALSE(roundtrip_config_ok(c));
    config_delete(c);
  }
}

/* ---------------------------------------------------------------------------
 * Wire round-trip equivalence.
 *
 * config_wire_equal() is generated from the SAME CONFIG_WIRE_FIELDS table as
 * the serializer, so it can never miss a serialized field: adding a table
 * entry automatically extends this comparison.  Each KIND maps to a comparison
 * macro; STR_OPT/STR_KEEP normalize the NULL-vs-"" canonicalization the
 * receiver performs, RAW_MAXALLOC models the server-side clamp, and
 * DERIVED_DELTA compares the effective (whole_file-suppressed) bit.
 * ------------------------------------------------------------------------- */
static void golden_config_populate(Config* c);

static bool str_opt_equal(const char* a, const char* b) {
  if (a == NULL || a[0] == '\0')
    return b == NULL || b[0] == '\0';
  return b != NULL && strcmp(a, b) == 0;
}

static bool idmap_equal(const IdentityMap* a, int ac, const IdentityMap* b, int bc) {
  if (ac != bc)
    return false;
  for (int i = 0; i < ac; i++) {
    if (a[i].from != b[i].from || a[i].to != b[i].to)
      return false;
  }
  return true;
}

static bool skip_suffixes_equal(const Config* a, const Config* b) {
  if (a->skip_compress_count != b->skip_compress_count)
    return false;
  for (int i = 0; i < a->skip_compress_count; i++) {
    if (!str_opt_equal(a->skip_compress_suffixes[i], b->skip_compress_suffixes[i]))
      return false;
  }
  return true;
}

static bool basis_equal(const Config* a, const Config* b) {
  if (a->basis_count != b->basis_count)
    return false;
  for (int i = 0; i < a->basis_count; i++) {
    if (a->basis_dirs[i].type != b->basis_dirs[i].type ||
        !str_opt_equal(a->basis_dirs[i].path, b->basis_dirs[i].path))
      return false;
  }
  return true;
}

#define CONFIG_CMP_BOOL(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_INT(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_RAW(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_BOOL_8BIT(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_RAW_MAXALLOC(a, b, name)                                                        \
  ((b)->name == ((a)->name > MAX_SERVER_ALLOC ? MAX_SERVER_ALLOC : (a)->name))
#define CONFIG_CMP_DERIVED_DELTA(a, b, name) ((b)->name == ((a)->name && !(a)->whole_file))
#define CONFIG_CMP_STR(a, b, name)                                                                 \
  ((a)->name != NULL && (b)->name != NULL && strcmp((a)->name, (b)->name) == 0)
#define CONFIG_CMP_STR_OPT(a, b, name) str_opt_equal((a)->name, (b)->name)
#define CONFIG_CMP_STR_KEEP(a, b, name) str_opt_equal((a)->name, (b)->name)
#define CONFIG_CMP_STR_MODULE(a, b, name) str_opt_equal((a)->name, (b)->name)
#define CONFIG_CMP_STR_REDACTED_AUTH(a, b, name) str_opt_equal((a)->name, (b)->name)
#define CONFIG_CMP_INT_CHECKSUM_ALGO(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_SUPERMODE(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_INT_IDENTITY(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_INT_SKIPCOUNT(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_INT_BASISCOUNT(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_INT_IDMAPCOUNT(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_BOOL_XATTR_DERIVE(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_COPY_AS_PRESENCE(a, b, name) ((a)->name == (b)->name)
#define CONFIG_CMP_COPY_AS_ID(a, b, name) (!(a)->copy_as_set || (a)->name == (b)->name)
#define CONFIG_CMP_BLOCK_SKIP_SUFFIXES(a, b, name) skip_suffixes_equal((a), (b))
#define CONFIG_CMP_BLOCK_BASIS(a, b, name) basis_equal((a), (b))
#define CONFIG_CMP_BLOCK_IDMAP(a, b, name)                                                         \
  idmap_equal((a)->name, (a)->name##_count, (b)->name, (b)->name##_count)

#define WIRE_CMP(name, ctype, def, kind)                                                           \
  &&(CONFIG_CMP_##kind(a, b, name)                                                                 \
         ? true                                                                                    \
         : (fprintf(stderr, "    mismatched field: %s\n", #name), false))

static bool config_wire_equal(const Config* a, const Config* b) {
  return true CONFIG_WIRE_FIELDS(WIRE_CMP);
}

static bool roundtrip_and_compare(const Config* send_cfg) {
  int p[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) != 0)
    return false;
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    io_set_bwlimit(0);
    Config* recv = config_receive(p[0]);
    bool equal = recv != NULL && config_wire_equal(send_cfg, recv);
    config_delete(recv);
    close(p[0]);
    _exit(equal ? 0 : 1);
  }
  close(p[0]);
  io_set_fds(p[1], p[1]);
  io_set_bwlimit(0);
  bool sent = config_send(p[1], send_cfg);
  int status;
  waitpid(pid, &status, 0);
  close(p[1]);
  return sent && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Every serialized field must survive a frame round-trip, for a defaults config
 * and for a fully-populated config. */
static void test_config_wire_roundtrip_all_fields() {
  if (is_running_under_valgrind())
    return;

  Config* defaults = config_create();
  EXPECT_NOT_NULL(defaults);
  defaults->send_directory = str_dup("/src");
  defaults->receive_root_directory = str_dup("/dst");
  EXPECT_TRUE(roundtrip_and_compare(defaults));
  config_delete(defaults);

  Config* populated = config_create();
  EXPECT_NOT_NULL(populated);
  /* The golden fixture is already receiver-valid, so the same fully-populated
   * config that backs the byte-exact golden also round-trips unchanged. */
  golden_config_populate(populated);
  EXPECT_TRUE(roundtrip_and_compare(populated));
  config_delete(populated);
}

/* Each of the four split-out preservation bools must survive a frame
 * round-trip on its own.  The all-fields golden sets an alternating
 * true/false pattern precisely because a run of identical adjacent booleans
 * would let a same-KIND field swap produce the same bytes; isolating one true
 * bit at a time pins each new field's position and width independently. */
static void test_config_preserve_attribute_wire_roundtrip() {
  if (is_running_under_valgrind())
    return;
  static const size_t attrs[] = {
      offsetof(Config, preserve_perms),
      offsetof(Config, preserve_times),
      offsetof(Config, preserve_owner),
      offsetof(Config, preserve_group),
  };
  for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
    Config* c = config_create();
    EXPECT_NOT_NULL(c);
    c->send_directory = str_dup("/src");
    c->receive_root_directory = str_dup("/dst");
    /* The preservation invariant requires the metadata frame to travel, so set
     * the transport bit; otherwise config_receive() legitimately refuses. */
    c->use_metadata = true;
    *(bool*)((char*)c + attrs[i]) = true;
    EXPECT_TRUE(roundtrip_and_compare(c));
    config_delete(c);
  }
}

/* Populate every serialized field with a non-default value so the wire frame
 * exercises each table entry.  Boolean runs deliberately alternate true/false:
 * a run of identical booleans would make an adjacent swap (same KIND) produce
 * the same byte stream, hiding a table reorder from the golden hash.  The whole
 * frame stays receiver-valid so the receive-side golden can feed it straight
 * through config_receive() (hence the valid chmod grammar and delta bound). */
static void golden_config_populate(Config* c) {
  c->eight_bit_output = true;
  c->max_alloc = 123456789ULL;
  c->send_directory = str_dup("/golden/src");
  c->receive_root_directory = str_dup("/golden/dst");
  c->save_to_disk = true;
  c->use_multithreading = false;
  c->use_chunk_serialization = false;
  c->use_compression = true;
  c->use_metadata = true;
  c->use_executability = false;
  c->compression_level = 7;
  c->chunk_size = 65536;
  c->use_sendfile = false;
  c->dry_run = true;
  c->use_delete = true;
  c->use_incremental = true;
  c->size_only = false;
  c->ignore_times = true;
  c->use_delta = true;
  c->whole_file = false;
  c->delta_block_size = 4096;
  c->delta_max_file_size = 200000000ULL;
  c->backup = true;
  c->backup_dir = str_dup("/golden/backup");
  c->remove_source_files = false;
  c->follow_symlinks = true;
  c->copy_links = false;
  c->safe_links = true;
  c->copy_unsafe_links = false;
  c->preserve_hard_links = true;
  c->preserve_acls = false;
  c->preserve_xattrs = true;
  c->preserve_devices = false;
  c->preserve_sparse = true;
  c->preserve_specials = false;
  c->copy_devices = true;
  c->write_devices = false;
  c->ignore_existing = true;
  c->existing = false;
  c->update = true;
  c->inplace = false;
  c->delay_updates = true;
  c->append = false;
  c->use_fsync = true;
  c->append_verify = false;
  c->delete_excluded = true;
  c->force_delete = false;
  c->delete_missing_args = true;
  c->delete_after = false;
  c->preallocate = true;
  c->max_delete = 42;
  c->relative = false;
  c->prune_empty_dirs = true;
  c->mkpath = false;
  c->delete_during = true;
  c->delete_delay = false;
  c->temp_dir = str_dup("/golden/tmp");
  c->partial = true;
  c->partial_dir = str_dup("/golden/partial");
  c->suffix = str_dup(".golden");
  c->delete_before = false;
  c->checksum = true;
  c->modify_window = 3;
  c->compress_choice = str_dup("zstd");
  /* "u=rwx,go=rx" is the same 11 bytes as the original "u=rwX,go=rX" (so the
   * frame stays 653 bytes) but X is not in FastSync's chmod grammar, and the
   * receive-side golden validates the frame. */
  c->chmod_spec = str_dup("u=rwx,go=rx");
  c->skip_compress_set = true;
  c->skip_compress_count = 2;
  c->skip_compress_suffixes = calloc(2, sizeof(char*));
  c->skip_compress_suffixes[0] = str_dup(".gz");
  c->skip_compress_suffixes[1] = str_dup(".xz");
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_COMPARE, "compare"), 0);
  EXPECT_EQ_INT(config_basis_append(c, BASIS_DEST_LINK, "link"), 0);
  c->fuzzy = true;
  c->checksum_algo = CHECKSUM_ALGO_MD5;
  c->checksum_seed = 0x1122334455667788ULL;
  c->numeric_ids = true;
  c->chown_uid_set = false;
  c->chown_uid = 1234;
  c->chown_gid_set = true;
  c->chown_gid = 5678;
  c->usermap_count = 2;
  c->usermap = calloc(2, sizeof(IdentityMap));
  c->usermap[0].from = IDENTITY_MATCH_ANY;
  c->usermap[0].to = 1000;
  c->usermap[1].from = 5;
  c->usermap[1].to = 6;
  c->groupmap_count = 1;
  c->groupmap = calloc(1, sizeof(IdentityMap));
  c->groupmap[0].from = 7;
  c->groupmap[0].to = 8;
  c->preserve_atimes = true;
  c->preserve_crtimes = false;
  c->omit_dir_times = true;
  c->omit_link_times = false;
  /* Mixed true/false so a field reorder or a dropped attribute changes the
   * pinned hash rather than passing silently. */
  c->preserve_perms = true;
  c->preserve_times = false;
  c->preserve_owner = true;
  c->preserve_group = false;
  c->munge_links = true;
  c->keep_dirlinks = false;
  c->fake_super = true;
  c->module = str_dup("goldenmod");
  c->auth_user = str_dup("goldenuser");
  c->auth_password = str_dup("golden-pw");
  c->iconv_spec = str_dup("UTF-8,UTF-8");
  c->super_mode = SUPER_MODE_ON;
  c->copy_as_set = true;
  c->copy_as_uid = 111;
  c->copy_as_gid = 222;
}

/* The pinned golden frame (protocol 2.23.0).  The values below are the only
 * thing that ties the generated table to the historical wire format; update
 * them ONLY with a PROTOCOL_VERSION bump and a documented reason.  The 2.23.0
 * delete-semantics wave keeps the config-frame LAYOUT unchanged, but the
 * embedded version string moves to "2.23.0", so the byte-exact hash changes
 * while the length stays 653. */
#define GOLDEN_WIRE_LEN 653
#define GOLDEN_WIRE_HASH 3267254725292157519ULL

static unsigned long long fnv1a_64(const unsigned char* buf, size_t len) {
  unsigned long long h = 1469598103934665603ULL;
  for (size_t i = 0; i < len; i++) {
    h ^= (unsigned long long)buf[i];
    h *= 1099511628211ULL;
  }
  return h;
}

/* Capture the exact config-frame body emitted by config_send_wire_block() into
 * a heap buffer.  Returns NULL on any failure. */
static unsigned char* capture_wire_bytes(const Config* cfg, size_t* out_len) {
  int p[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) != 0)
    return NULL;
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    io_set_bwlimit(0);
    bool ok = config_send_wire_block(p[0], cfg);
    close(p[0]);
    _exit(ok ? 0 : 1);
  }
  close(p[0]);
  size_t capacity = 1024;
  size_t total = 0;
  unsigned char* bytes = malloc(capacity);
  if (!bytes) {
    close(p[1]);
    waitpid(pid, NULL, 0);
    return NULL;
  }
  for (;;) {
    if (total == capacity) {
      size_t grown_capacity = capacity * 2;
      unsigned char* grown = realloc(bytes, grown_capacity);
      if (!grown) {
        free(bytes);
        close(p[1]);
        waitpid(pid, NULL, 0);
        return NULL;
      }
      bytes = grown;
      capacity = grown_capacity;
    }
    ssize_t n = read(p[1], bytes + total, capacity - total);
    if (n < 0) {
      free(bytes);
      close(p[1]);
      waitpid(pid, NULL, 0);
      return NULL;
    }
    if (n == 0)
      break;
    total += (size_t)n;
  }
  close(p[1]);
  int status = 0;
  waitpid(pid, &status, 0);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    free(bytes);
    return NULL;
  }
  *out_len = total;
  return bytes;
}

/* FNV-1a 64 over the exact config-frame bytes emitted by
 * config_send_wire_block().  This pins field order and width: any reorder or
 * resize changes the hash. */
static unsigned long long capture_wire_hash(const Config* cfg, size_t* out_len) {
  unsigned char* bytes = capture_wire_bytes(cfg, out_len);
  if (!bytes)
    return 0;
  unsigned long long h = fnv1a_64(bytes, *out_len);
  free(bytes);
  return h;
}

/* Byte-for-byte wire compatibility guard (protocol 2.23.0).  The expected hash
 * pins the pre-X-macro byte stream; the refactor MUST NOT change it. */
static void test_config_wire_golden() {
  if (is_running_under_valgrind())
    return;
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  golden_config_populate(c);
  size_t len = 0;
  unsigned long long h = capture_wire_hash(c, &len);
  printf("    wire golden: len=%zu hash=%llu\n", len, h);
  EXPECT_TRUE(len == GOLDEN_WIRE_LEN);
  EXPECT_TRUE(h == GOLDEN_WIRE_HASH);
  config_delete(c);
}

/* Receive-side oracle.  Hashing the sender alone cannot catch a RECV KIND that
 * reads a different width/order yet still round-trips symmetrically, so feed
 * the SAME hash-pinned golden bytes through config_receive() and assert both
 * the decoded struct fields and the derived bits.  Because the bytes are
 * anchored to the send golden, a divergence on either side fails here. */
static void test_config_wire_golden_receive() {
  if (is_running_under_valgrind())
    return;
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  golden_config_populate(c);

  size_t len = 0;
  unsigned char* bytes = capture_wire_bytes(c, &len);
  EXPECT_NOT_NULL(bytes);
  EXPECT_TRUE(len == GOLDEN_WIRE_LEN);
  EXPECT_TRUE(fnv1a_64(bytes, len) == GOLDEN_WIRE_HASH);

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  io_set_fds(p[0], p[1]);
  io_set_bwlimit(0);
  pid_t pid = fork();
  if (pid == 0) {
    close(p[1]);
    io_set_fds(p[0], p[0]);
    io_set_bwlimit(0);
    Config* recv = config_receive(p[0]);
    bool ok = recv != NULL;
    if (ok) {
      /* Full field-by-field comparison (generated from CONFIG_WIRE_FIELDS). */
      ok = config_wire_equal(c, recv);
      /* Explicit spot checks of the decoded struct, including derived bits. */
      ok = ok && recv->eight_bit_output && recv->use_compression && recv->use_metadata &&
           !recv->use_multithreading;
      ok = ok && recv->compression_level == 7 && recv->chunk_size == 65536;
      ok = ok && recv->use_delta && !recv->whole_file && recv->use_xattrs;
      /* Per-attribute preservation split decoded from the pinned bytes. */
      ok = ok && recv->preserve_perms && !recv->preserve_times && recv->preserve_owner &&
           !recv->preserve_group;
      /* Bounded/validated KINDs decoded from the pinned bytes. */
      ok = ok && recv->checksum_algo == CHECKSUM_ALGO_MD5;
      ok = ok && recv->super_mode == SUPER_MODE_ON;
      ok = ok && recv->chown_uid == 1234 && recv->chown_gid == 5678;
      ok = ok && recv->usermap_count == 2 && recv->usermap[0].from == IDENTITY_MATCH_ANY &&
           recv->usermap[0].to == 1000 && recv->usermap[1].from == 5 && recv->usermap[1].to == 6;
      ok = ok && recv->basis_count == 2 && recv->basis_dirs[0].type == BASIS_DEST_COMPARE &&
           recv->basis_dirs[1].type == BASIS_DEST_LINK;
      ok = ok && recv->module != NULL && strcmp(recv->module, "goldenmod") == 0;
      ok = ok && recv->copy_as_set && recv->copy_as_uid == 111 && recv->copy_as_gid == 222;
    }
    config_delete(recv);
    close(p[0]);
    _exit(ok ? 0 : 1);
  }
  close(p[0]);
  io_set_fds(p[1], p[1]);
  io_set_bwlimit(0);
  size_t written = 0;
  bool wrote = true;
  while (written < len) {
    ssize_t n = write(p[1], bytes + written, len - written);
    if (n <= 0) {
      wrote = false;
      break;
    }
    written += (size_t)n;
  }
  Status status = STATUS_ERROR;
  bool got_status = wrote && receive_status(p[1], &status);
  close(p[1]);
  free(bytes);
  int child_status = 0;
  waitpid(pid, &child_status, 0);
  EXPECT_TRUE(got_status && status == STATUS_OK);
  EXPECT_TRUE(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
  config_delete(c);
}

/* Hand-build a frame that is valid up to the first core BOOL, then write an
 * out-of-range boolean (2): a BOOL receiver must reject anything but 0/1. */
static void write_frame_with_invalid_bool(int fd) {
  send_str(fd, PROTOCOL_VERSION);
  send_int(fd, 1); /* eight_bit_output */
  unsigned long long max_alloc = DEFAULT_MAX_ALLOC;
  send_n_data(fd, &max_alloc, sizeof(max_alloc));
  send_str(fd, "/src");
  send_str(fd, "/dst");
  send_int(fd, 2); /* save_to_disk: not 0/1 */
}

/* Feed a caller-built frame into config_receive() and report whether the
 * receiver rejected it.  The writer runs in a child (SIGPIPE ignored) so a
 * mid-frame rejection cannot kill the test process. */
static bool receive_hand_built_frame_rejected(void (*write_frame)(int fd)) {
  int p[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) != 0)
    return false;
  pid_t pid = fork();
  if (pid == 0) {
    (void)signal(SIGPIPE, SIG_IGN);
    close(p[0]);
    io_set_fds(p[1], p[1]);
    io_set_bwlimit(0);
    write_frame(p[1]);
    close(p[1]);
    _exit(0);
  }
  close(p[1]);
  io_set_fds(p[0], p[0]);
  io_set_bwlimit(0);
  Config* recv = config_receive(p[0]);
  bool rejected = recv == NULL;
  config_delete(recv);
  close(p[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  return rejected;
}

/* Receive-side bounds for the bounded/validated KINDs that the round-trip
 * helper cannot exercise (an illegal value has no symmetric sender). */
static void test_config_wire_receive_bounds() {
  if (is_running_under_valgrind())
    return;

  /* BOOL: only 0/1 is a legal wire value. */
  EXPECT_TRUE(receive_hand_built_frame_rejected(write_frame_with_invalid_bool));

  /* RAW_MAXALLOC: zero is rejected before it can become the session ceiling. */
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->max_alloc = 0;
  EXPECT_TRUE(roundtrip_config_rejected(c));
  config_delete(c);

  /* STR_MODULE: a name outside [A-Za-z0-9._-] is refused. */
  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->module = str_dup("bad module");
  EXPECT_TRUE(roundtrip_config_rejected(c));
  config_delete(c);

  /* INT_IDMAPCOUNT: one past the identity-map cap is refused at the count. */
  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->usermap_count = MAX_IDENTITY_MAP + 1;
  c->usermap = calloc((size_t)c->usermap_count, sizeof(IdentityMap));
  if (c->usermap) {
    for (int i = 0; i < c->usermap_count; i++) {
      c->usermap[i].from = 0;
      c->usermap[i].to = 0;
    }
  }
  EXPECT_TRUE(roundtrip_config_rejected(c));
  config_delete(c);

  /* INT_IDENTITY: an out-of-range chown_uid (below IDENTITY_MATCH_ANY) is
   * refused by the identity validator. */
  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->chown_uid_set = true;
  c->chown_uid = IDENTITY_MATCH_ANY - 1;
  EXPECT_TRUE(roundtrip_config_rejected(c));
  config_delete(c);
}

/* Regression (pre-auth NULL-deref): the *_count receive helpers used to write
 * the peer-controlled int through the Config member BEFORE validating it.  An
 * over-cap basis_count therefore left config->basis_count huge while
 * config->basis_dirs stayed NULL; the config_receive() error path then called
 * config_delete(), whose `for (i < basis_count) free(basis_dirs[i].path)` loop
 * dereferenced NULL.  A malicious client could crash the daemon before auth.
 *
 * The helpers now validate a LOCAL and publish only on success, so a rejected
 * count leaves the member at its safe default (0).  The idmap/skip helpers have
 * the same "write then validate" shape and are covered here too, as is the
 * config_delete() NULL-array guard that backstops the whole class. */
static void test_config_receive_rejects_overcap_counts() {
  if (is_running_under_valgrind())
    return;

  /* Over-cap basis count.  The values are injected directly (config_basis_append
   * enforces the cap) with a matching array so the sender can emit the block;
   * the receiver must reject at the count and remain crash-free while deleting
   * the partially populated Config. */
  Config* c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->basis_count = MAX_BASIS_DIRS + 1;
  c->basis_dirs = calloc((size_t)c->basis_count, sizeof(BasisDest));
  EXPECT_NOT_NULL(c->basis_dirs);
  for (int i = 0; i < c->basis_count; i++) {
    c->basis_dirs[i].type = BASIS_DEST_LINK;
    c->basis_dirs[i].path = str_dup("basis");
  }
  EXPECT_TRUE(roundtrip_config_rejected(c));
  config_delete(c);

  /* Over-cap identity-map count (usermap and groupmap share the helper). */
  c = config_create();
  EXPECT_NOT_NULL(c);
  c->send_directory = str_dup("/src");
  c->receive_root_directory = str_dup("/dst");
  c->usermap_count = MAX_IDENTITY_MAP + 1;
  c->usermap = calloc((size_t)c->usermap_count, sizeof(IdentityMap));
  EXPECT_NOT_NULL(c->usermap);
  for (int i = 0; i < c->usermap_count; i++) {
    c->usermap[i].from = 0;
    c->usermap[i].to = 0;
  }
  EXPECT_TRUE(roundtrip_config_rejected(c));
  config_delete(c);

  /* Over-cap skip-compress count. */
  Config* over_skip = make_skip_compress_config(MAX_SKIP_COMPRESS_SUFFIXES + 1, 1);
  EXPECT_NOT_NULL(over_skip);
  EXPECT_TRUE(roundtrip_config_rejected(over_skip));
  config_delete(over_skip);

  /* Defense-in-depth: config_delete() on a Config left with a non-zero count
   * but a NULL array (the exact partial state an over-cap count used to leave
   * behind) must be safe. */
  c = config_create();
  EXPECT_NOT_NULL(c);
  c->basis_count = MAX_BASIS_DIRS + 1;
  c->basis_dirs = NULL;
  config_delete(c);
}

void test_config() {
  test_config_lifecycle();
  test_config_ssh_dest();
  test_config_ssh_dest_local_path();
  test_config_ssh_dest_no_user();
  test_config_ssh_dest_rejects_option_injection();
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
    test_config_copy_as_wire_roundtrip();
    test_config_receive_rejects_negative_copy_as();
    test_config_receive_rejects_copy_as_without_metadata();
    test_config_receive_rejects_oversized_string_budget();
    test_config_receive_with_validate_rejects();
    test_config_invariants_error_all_combinations();
    test_config_preservation_requires_metadata();
    test_config_derived_use_metadata();
    test_config_receive_rejects_unified_invariants();
    test_config_wire_golden();
    test_config_wire_golden_receive();
    test_config_wire_receive_bounds();
    test_config_receive_rejects_overcap_counts();
    test_config_wire_roundtrip_all_fields();
    test_config_preserve_attribute_wire_roundtrip();
  }
  test_identity_copy_as_refused();
  test_identity_ownership_requested();
  test_identity_explicit_ownership_requested();
  test_identity_active_enabled_includes_preserve_attrs();
  test_super_does_not_imply_numeric();
  test_privilege_super_permitted_modes();
  test_config_delete_timing_early_helper();
  test_config_is_remote_dest();
}
