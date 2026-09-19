#include "test_shared_utils.h"
#include "utils.h"
#include "protocol.h"
#include "test_utils.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <threads.h>
#include <unistd.h>

/* ---- delete-walker tests ---- */

static char* make_walk_root(const char* tag) {
  char* path = malloc(256);
  if (!path)
    return NULL;
  snprintf(path, 256, "/tmp/fastsync_walk_%s_%d", tag, (int)getpid());
  rmdir(path);
  if (mkdir(path, 0755) != 0) {
    free(path);
    return NULL;
  }
  return path;
}

static bool write_file_at(const char* dir, const char* name, const char* content) {
  char* path = path_cat(dir, name);
  if (!path)
    return false;
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  bool ok = fd >= 0;
  if (fd >= 0) {
    if (content) {
      const char* p = content;
      size_t remaining = strlen(content);
      while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n <= 0) {
          ok = false;
          break;
        }
        p += n;
        remaining -= (size_t)n;
      }
    }
    close(fd);
  }
  free(path);
  return ok;
}

static bool file_exists(const char* dir, const char* name) {
  char* path = path_cat(dir, name);
  bool exists = path && access(path, F_OK) == 0;
  free(path);
  return exists;
}

static bool dir_exists(const char* dir, const char* name) {
  char* path = path_cat(dir, name);
  struct stat st;
  bool exists = path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
  free(path);
  return exists;
}

static int make_subdir(const char* root, const char* name) {
  char* path = path_cat(root, name);
  int rc = -1;
  if (path) {
    rc = mkdir(path, 0755);
    free(path);
  }
  return rc;
}

static void remove_walk_tree(const char* path) {
  DIR* dir = opendir(path);
  if (!dir) {
    rmdir(path);
    return;
  }
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    char* child = path_cat(path, entry->d_name);
    if (child) {
      struct stat st;
      if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
        remove_walk_tree(child);
      else
        unlink(child);
      free(child);
    }
  }
  closedir(dir);
  rmdir(path);
}

static ArrayList* make_manifest_strings(const char* const* entries, int count) {
  ArrayList* manifest = array_list_create(free);
  if (!manifest)
    return NULL;
  for (int i = 0; i < count; i++) {
    char* dup = str_dup(entries[i]);
    if (!dup || !array_list_add(manifest, dup)) {
      free(dup);
      array_list_delete(manifest);
      return NULL;
    }
  }
  return manifest;
}

static void test_walker_removes_extras_keeps_manifest_and_protected() {
  char* root = make_walk_root("basic");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "a.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "keep.txt", "kept"));
  EXPECT_EQ_INT(make_subdir(root, "d"), 0);
  EXPECT_TRUE(write_file_at(root, "d/e.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "d/k.txt", "kept"));
  EXPECT_EQ_INT(make_subdir(root, "prot"), 0);
  EXPECT_TRUE(write_file_at(root, "prot/f.txt", "untouched"));

  const char* keeps[] = {"keep.txt", "d/k.txt"};
  ArrayList* manifest = make_manifest_strings(keeps, 2);
  EXPECT_NOT_NULL(manifest);
  DeleteSkipEntry skip = {"prot", false};
  size_t deleted = 0;
  DeleteWalkResult result =
      delete_extras_limited(root, manifest, NULL, 100000, &skip, 1, NULL, &deleted, NULL);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_OK);
  EXPECT_FALSE(file_exists(root, "a.txt"));
  EXPECT_TRUE(file_exists(root, "keep.txt"));
  EXPECT_FALSE(file_exists(root, "d/e.txt"));
  EXPECT_TRUE(file_exists(root, "d/k.txt"));
  EXPECT_TRUE(dir_exists(root, "d"));
  EXPECT_TRUE(file_exists(root, "prot/f.txt"));
  EXPECT_TRUE(deleted >= 2);
  array_list_delete(manifest);
  remove_walk_tree(root);
  free(root);
}

static void test_walker_keeps_nested_manifest_dirs() {
  /* The keep-set index must preserve deep content: a directory is protected
     when its own name is a keep entry OR when kept content lives below it, and
     an exact kept file survives while its siblings are removed. */
  char* root = make_walk_root("nestedkeep");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "extra.txt", "extra"));
  EXPECT_EQ_INT(make_subdir(root, "keepdir"), 0);
  EXPECT_EQ_INT(make_subdir(root, "keepdir/deep"), 0);
  EXPECT_TRUE(write_file_at(root, "keepdir/deep/keep.txt", "kept"));
  EXPECT_TRUE(write_file_at(root, "keepdir/extra2.txt", "extra"));
  EXPECT_EQ_INT(make_subdir(root, "dropdir"), 0);
  EXPECT_EQ_INT(make_subdir(root, "keep2"), 0);
  EXPECT_TRUE(write_file_at(root, "keep2/inner.txt", "kept"));
  EXPECT_EQ_INT(make_subdir(root, "keep3"), 0);

  const char* keeps[] = {"keepdir/deep/keep.txt", "keep2/inner.txt", "keep3"};
  ArrayList* manifest = make_manifest_strings(keeps, 3);
  EXPECT_NOT_NULL(manifest);
  size_t deleted = 0;
  DeleteWalkResult result =
      delete_extras_limited(root, manifest, NULL, 100000, NULL, 0, NULL, &deleted, NULL);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_OK);
  EXPECT_FALSE(file_exists(root, "extra.txt"));
  EXPECT_TRUE(file_exists(root, "keepdir/deep/keep.txt"));
  EXPECT_FALSE(file_exists(root, "keepdir/extra2.txt"));
  EXPECT_TRUE(dir_exists(root, "keepdir"));
  EXPECT_TRUE(dir_exists(root, "keepdir/deep"));
  EXPECT_FALSE(dir_exists(root, "dropdir"));
  EXPECT_TRUE(dir_exists(root, "keep2"));
  EXPECT_TRUE(file_exists(root, "keep2/inner.txt"));
  EXPECT_TRUE(dir_exists(root, "keep3")); /* an exact directory keep entry survives */
  EXPECT_EQ_INT((int)deleted, 3);
  array_list_delete(manifest);
  remove_walk_tree(root);
  free(root);
}

/* --max-delete is a partial cap (rsync parity): delete up to the limit, skip
   the rest, and report DELETE_WALK_LIMIT_REACHED. */
static void test_walker_max_delete_partial_deletes_up_to_cap() {
  char* root = make_walk_root("maxdel");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "a.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "b.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "c.txt", "extra"));
  const char* keeps[1] = {NULL};
  ArrayList* manifest = make_manifest_strings(keeps, 0);
  EXPECT_NOT_NULL(manifest);
  size_t deleted = 999;
  size_t skipped = 0;
  DeleteWalkResult result =
      delete_extras_limited(root, manifest, NULL, 2, NULL, 0, NULL, &deleted, &skipped);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_LIMIT_REACHED);
  EXPECT_EQ_INT((int)deleted, 2);
  EXPECT_EQ_INT((int)skipped, 1);
  int remaining = (file_exists(root, "a.txt") ? 1 : 0) + (file_exists(root, "b.txt") ? 1 : 0) +
                  (file_exists(root, "c.txt") ? 1 : 0);
  EXPECT_EQ_INT(remaining, 1);
  array_list_delete(manifest);
  remove_walk_tree(root);
  free(root);
}

static void test_walker_max_delete_exact_bound_deletes() {
  char* root = make_walk_root("maxdel2");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "a.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "b.txt", "extra"));
  const char* keeps[1] = {NULL};
  ArrayList* manifest = make_manifest_strings(keeps, 0);
  EXPECT_NOT_NULL(manifest);
  size_t deleted = 0;
  DeleteWalkResult result =
      delete_extras_limited(root, manifest, NULL, 2, NULL, 0, NULL, &deleted, NULL);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_OK);
  EXPECT_EQ_INT((int)deleted, 2);
  EXPECT_FALSE(file_exists(root, "a.txt"));
  EXPECT_FALSE(file_exists(root, "b.txt"));
  array_list_delete(manifest);
  remove_walk_tree(root);
  free(root);
}

/* Extraneous destination symlinks (including one pointing at a directory) must
   be unlinked, never followed, so their targets survive. */
static void test_walker_removes_extraneous_symlinks() {
  char* root = make_walk_root("symlink");
  char* outside = make_walk_root("symlink_out");
  EXPECT_NOT_NULL(root);
  EXPECT_NOT_NULL(outside);
  EXPECT_TRUE(write_file_at(outside, "secret.txt", "keep"));
  EXPECT_TRUE(write_file_at(root, "keep.txt", "kept"));
  char* link_file = path_cat(root, "link_file");
  char* link_dir = path_cat(root, "link_dir");
  char* link_broken = path_cat(root, "link_broken");
  EXPECT_NOT_NULL(link_file);
  EXPECT_NOT_NULL(link_dir);
  EXPECT_NOT_NULL(link_broken);
  EXPECT_EQ_INT(symlink("keep.txt", link_file), 0);
  EXPECT_EQ_INT(symlink(outside, link_dir), 0);
  EXPECT_EQ_INT(symlink("/nonexistent-target", link_broken), 0);
  const char* keeps[] = {"keep.txt"};
  ArrayList* manifest = make_manifest_strings(keeps, 1);
  EXPECT_NOT_NULL(manifest);
  size_t deleted = 0;
  DeleteWalkResult result =
      delete_extras_limited(root, manifest, NULL, 100000, NULL, 0, NULL, &deleted, NULL);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_OK);
  EXPECT_FALSE(file_exists(root, "link_file"));
  EXPECT_FALSE(file_exists(root, "link_dir"));
  EXPECT_FALSE(file_exists(root, "link_broken"));
  EXPECT_TRUE(file_exists(root, "keep.txt"));
  EXPECT_TRUE(file_exists(outside, "secret.txt"));
  free(link_file);
  free(link_dir);
  free(link_broken);
  array_list_delete(manifest);
  remove_walk_tree(root);
  remove_walk_tree(outside);
  free(root);
  free(outside);
}

/* With a synchronized-dir set, extras outside it survive while extras directly
   inside a listed directory are removed; the receive root is the "." sentinel. */
static void test_walker_confines_deletion_to_synced_dirs() {
  char* root = make_walk_root("synced");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "rootextra.txt", "keep"));
  EXPECT_EQ_INT(make_subdir(root, "inscope"), 0);
  EXPECT_TRUE(write_file_at(root, "inscope/extra.txt", "delete"));
  EXPECT_TRUE(write_file_at(root, "inscope/keep.txt", "kept"));
  EXPECT_EQ_INT(make_subdir(root, "outscope"), 0);
  EXPECT_TRUE(write_file_at(root, "outscope/extra.txt", "keep"));
  const char* keeps[] = {"inscope/keep.txt"};
  ArrayList* manifest = make_manifest_strings(keeps, 1);
  ArrayList* dirs = array_list_create(free);
  EXPECT_NOT_NULL(manifest);
  EXPECT_NOT_NULL(dirs);
  EXPECT_TRUE(array_list_add(dirs, str_dup("inscope")));
  size_t deleted = 0;
  DeleteWalkResult result =
      delete_extras_limited(root, manifest, dirs, 100000, NULL, 0, NULL, &deleted, NULL);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_OK);
  EXPECT_TRUE(file_exists(root, "rootextra.txt"));
  EXPECT_FALSE(file_exists(root, "inscope/extra.txt"));
  EXPECT_TRUE(file_exists(root, "inscope/keep.txt"));
  EXPECT_TRUE(file_exists(root, "outscope/extra.txt"));
  array_list_delete(manifest);
  array_list_delete(dirs);
  remove_walk_tree(root);
  free(root);
}

static void test_walker_unlimited_deletes_all() {
  char* root = make_walk_root("unlim");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "a.txt", "extra"));
  EXPECT_TRUE(write_file_at(root, "b.txt", "extra"));
  EXPECT_EQ_INT(make_subdir(root, "emptydir"), 0);
  const char* keeps[1] = {NULL};
  ArrayList* manifest = make_manifest_strings(keeps, 0);
  EXPECT_NOT_NULL(manifest);
  EXPECT_TRUE(delete_extras(root, manifest));
  EXPECT_FALSE(file_exists(root, "a.txt"));
  EXPECT_FALSE(file_exists(root, "b.txt"));
  EXPECT_FALSE(dir_exists(root, "emptydir"));
  array_list_delete(manifest);
  remove_walk_tree(root);
  free(root);
}

/* Receiver-side filter protection (protocol 2.28.0): a compiled protect rule
   shields a DESTINATION-ONLY extra that never appeared on the sender, a risk
   rule cancels an earlier/later protect (first match wins), and a dir-only
   protect rule shields the whole subtree. */
static void test_walker_protect_rules_shield_dest_only() {
  char* root = make_walk_root("protectrules");
  EXPECT_NOT_NULL(root);
  EXPECT_TRUE(write_file_at(root, "keep.txt", "kept"));
  EXPECT_TRUE(write_file_at(root, "extra.log", "risk cancels protect"));
  EXPECT_TRUE(write_file_at(root, "safe.log", "protected"));
  EXPECT_TRUE(write_file_at(root, "other.txt", "deleted"));
  EXPECT_EQ_INT(make_subdir(root, "prot"), 0);
  EXPECT_TRUE(write_file_at(root, "prot/inside.txt", "shielded subtree"));
  EXPECT_TRUE(write_file_at(root, "prot/deep.log", "shielded subtree"));

  const char* keeps[] = {"keep.txt"};
  ArrayList* manifest = make_manifest_strings(keeps, 1);
  EXPECT_NOT_NULL(manifest);
  const char* rule_text[] = {"R extra.log", "P *.log", "P prot/"};
  char err[160];
  FilterRuleList* rules = filter_base_build(rule_text, 3, false, false, err, sizeof(err));
  EXPECT_NOT_NULL(rules);
  size_t deleted = 0;
  DeleteWalkResult result =
      delete_extras_limited(root, manifest, NULL, 100000, NULL, 0, rules, &deleted, NULL);
  EXPECT_EQ_INT((int)result, (int)DELETE_WALK_OK);
  EXPECT_TRUE(file_exists(root, "keep.txt"));
  EXPECT_FALSE(file_exists(root, "extra.log")); /* risk wins the first match */
  EXPECT_TRUE(file_exists(root, "safe.log"));   /* protect shields the extra */
  EXPECT_FALSE(file_exists(root, "other.txt"));
  EXPECT_TRUE(dir_exists(root, "prot"));
  EXPECT_TRUE(file_exists(root, "prot/inside.txt"));
  EXPECT_TRUE(file_exists(root, "prot/deep.log"));
  filter_rule_list_free(rules);
  array_list_delete(manifest);
  remove_walk_tree(root);
  free(root);
}

typedef struct {
  bool eight_bit_output;
  const char* expected;
  int failed;
} EscapeThreadArgs;

static int escape_thread(void* arg) {
  EscapeThreadArgs* args = arg;
  for (int i = 0; i < 1000; i++) {
    char* escaped = output_escape("x\xc3\xa9\n", args->eight_bit_output);
    if (!escaped || strcmp(escaped, args->expected) != 0)
      args->failed = 1;
    free(escaped);
  }
  return 0;
}

/* A7-3/S1 transport classification: the daemon auth gate and the client
   credential rule both key off these helpers, so cover the exact accepted
   forms plus the negative cases. */
static void test_loopback_helpers() {
  /* Host strings. */
  EXPECT_TRUE(utils_host_is_loopback("localhost"));
  EXPECT_TRUE(utils_host_is_loopback("127.0.0.1"));
  EXPECT_TRUE(utils_host_is_loopback("127.255.255.254"));
  EXPECT_TRUE(utils_host_is_loopback("127.0.0.0"));
  EXPECT_TRUE(utils_host_is_loopback("::1"));
  EXPECT_TRUE(utils_host_is_loopback("[::1]"));
  EXPECT_FALSE(utils_host_is_loopback("128.0.0.1"));
  EXPECT_FALSE(utils_host_is_loopback("10.0.0.1"));
  EXPECT_FALSE(utils_host_is_loopback("0.0.0.0"));
  EXPECT_FALSE(utils_host_is_loopback("example.com"));
  EXPECT_FALSE(utils_host_is_loopback(""));
  EXPECT_FALSE(utils_host_is_loopback(NULL));

  /* Raw sockaddr classification. */
  struct sockaddr_in v4;
  memset(&v4, 0, sizeof(v4));
  v4.sin_family = AF_INET;
  EXPECT_TRUE(inet_pton(AF_INET, "127.0.0.1", &v4.sin_addr) == 1);
  EXPECT_TRUE(utils_sockaddr_is_loopback((const struct sockaddr*)&v4));
  EXPECT_TRUE(inet_pton(AF_INET, "127.5.5.5", &v4.sin_addr) == 1);
  EXPECT_TRUE(utils_sockaddr_is_loopback((const struct sockaddr*)&v4));
  EXPECT_TRUE(inet_pton(AF_INET, "128.0.0.1", &v4.sin_addr) == 1);
  EXPECT_FALSE(utils_sockaddr_is_loopback((const struct sockaddr*)&v4));

  struct sockaddr_in6 v6;
  memset(&v6, 0, sizeof(v6));
  v6.sin6_family = AF_INET6;
  EXPECT_TRUE(inet_pton(AF_INET6, "::1", &v6.sin6_addr) == 1);
  EXPECT_TRUE(utils_sockaddr_is_loopback((const struct sockaddr*)&v6));
  EXPECT_TRUE(inet_pton(AF_INET6, "::ffff:127.0.0.1", &v6.sin6_addr) == 1);
  EXPECT_TRUE(utils_sockaddr_is_loopback((const struct sockaddr*)&v6));
  EXPECT_TRUE(inet_pton(AF_INET6, "::ffff:127.255.255.254", &v6.sin6_addr) == 1);
  EXPECT_TRUE(utils_sockaddr_is_loopback((const struct sockaddr*)&v6));
  EXPECT_TRUE(inet_pton(AF_INET6, "::ffff:10.0.0.1", &v6.sin6_addr) == 1);
  EXPECT_FALSE(utils_sockaddr_is_loopback((const struct sockaddr*)&v6));

  EXPECT_FALSE(utils_sockaddr_is_loopback(NULL));

  /* A pipe has no socket peer: getpeername fails with ENOTSOCK.  The helper is
     fail-closed, so an unprovable channel is NOT local (daemon auth modules are
     daemon-only and never run over the --stdio pipe). */
  int pipe_fds[2];
  EXPECT_EQ_INT(pipe(pipe_fds), 0);
  EXPECT_FALSE(utils_fd_peer_is_local(pipe_fds[0]));
  close(pipe_fds[0]);
  close(pipe_fds[1]);
  EXPECT_FALSE(utils_fd_peer_is_local(-1));

  /* A connected AF_UNIX socketpair is a socket, but its peer is not a loopback
     IP address, so it is not local either. */
  int pair_fds[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, pair_fds), 0);
  EXPECT_FALSE(utils_fd_peer_is_local(pair_fds[0]));
  close(pair_fds[0]);
  close(pair_fds[1]);

  /* A real loopback TCP peer is local. */
  int listener = socket(AF_INET, SOCK_STREAM, 0);
  EXPECT_TRUE(listener >= 0);
  struct sockaddr_in bind_addr;
  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind_addr.sin_port = 0;
  EXPECT_EQ_INT(bind(listener, (const struct sockaddr*)&bind_addr, sizeof(bind_addr)), 0);
  EXPECT_EQ_INT(listen(listener, 1), 0);
  socklen_t addr_len = sizeof(bind_addr);
  EXPECT_EQ_INT(getsockname(listener, (struct sockaddr*)&bind_addr, &addr_len), 0);
  int dialer = socket(AF_INET, SOCK_STREAM, 0);
  EXPECT_TRUE(dialer >= 0);
  EXPECT_EQ_INT(connect(dialer, (const struct sockaddr*)&bind_addr, sizeof(bind_addr)), 0);
  int accepted = accept(listener, NULL, NULL);
  EXPECT_TRUE(accepted >= 0);
  EXPECT_TRUE(utils_fd_peer_is_local(accepted));
  close(accepted);
  close(dialer);
  close(listener);
}

/* The daemon host ACL reads the numeric peer address through
 * utils_fd_peer_ip.  A real loopback TCP peer reports "127.0.0.1"; a pipe or an
 * AF_UNIX socketpair has no INET peer and must return false with an empty
 * buffer (the fail-closed "cannot tell" result). */
static void test_fd_peer_ip() {
  char ip[INET6_ADDRSTRLEN];
  EXPECT_FALSE(utils_fd_peer_ip(-1, ip, sizeof(ip)));
  EXPECT_EQ_STR(ip, "");
  EXPECT_FALSE(utils_fd_peer_ip(-1, NULL, 0));

  int pipe_fds[2];
  EXPECT_EQ_INT(pipe(pipe_fds), 0);
  EXPECT_FALSE(utils_fd_peer_ip(pipe_fds[0], ip, sizeof(ip)));
  EXPECT_EQ_STR(ip, "");
  close(pipe_fds[0]);
  close(pipe_fds[1]);

  int pair_fds[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, pair_fds), 0);
  EXPECT_FALSE(utils_fd_peer_ip(pair_fds[0], ip, sizeof(ip)));
  EXPECT_EQ_STR(ip, "");
  close(pair_fds[0]);
  close(pair_fds[1]);

  int listener = socket(AF_INET, SOCK_STREAM, 0);
  EXPECT_TRUE(listener >= 0);
  struct sockaddr_in bind_addr;
  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind_addr.sin_port = 0;
  EXPECT_EQ_INT(bind(listener, (const struct sockaddr*)&bind_addr, sizeof(bind_addr)), 0);
  EXPECT_EQ_INT(listen(listener, 1), 0);
  socklen_t addr_len = sizeof(bind_addr);
  EXPECT_EQ_INT(getsockname(listener, (struct sockaddr*)&bind_addr, &addr_len), 0);
  int dialer = socket(AF_INET, SOCK_STREAM, 0);
  EXPECT_TRUE(dialer >= 0);
  EXPECT_EQ_INT(connect(dialer, (const struct sockaddr*)&bind_addr, sizeof(bind_addr)), 0);
  int accepted = accept(listener, NULL, NULL);
  EXPECT_TRUE(accepted >= 0);
  EXPECT_TRUE(utils_fd_peer_ip(accepted, ip, sizeof(ip)));
  EXPECT_EQ_STR(ip, "127.0.0.1");

  /* utils_sockaddr_to_string includes the port for a real peer. */
  struct sockaddr_storage peer;
  socklen_t peer_len = sizeof(peer);
  EXPECT_EQ_INT(getpeername(accepted, (struct sockaddr*)&peer, &peer_len), 0);
  char peer_string[128];
  EXPECT_TRUE(
      utils_sockaddr_to_string((const struct sockaddr*)&peer, peer_string, sizeof(peer_string)));
  EXPECT_TRUE(strncmp(peer_string, "127.0.0.1:", strlen("127.0.0.1:")) == 0);
  close(accepted);
  close(dialer);
  close(listener);

  /* A non-INET family formats to "unknown" at the call site, not a bogus IP. */
  struct sockaddr sa_unix;
  memset(&sa_unix, 0, sizeof(sa_unix));
  sa_unix.sa_family = AF_UNIX;
  EXPECT_FALSE(utils_sockaddr_to_string(&sa_unix, peer_string, sizeof(peer_string)));
  EXPECT_EQ_STR(peer_string, "");
}

/* The keep/files-from indexes must store exactly the input entries (one node
   each), never a copied ancestor prefix per component.  This builds a PathIndex
   over paths thousands of components deep and checks the structural bound plus
   the exact / descendant query semantics. */
static void test_path_index_bounded() {
  enum { COUNT = 8, COMPONENTS = 5000 };
  size_t entry_len = (size_t)COMPONENTS * 2 + 2; /* trailing "xN" */
  char* storage = malloc((size_t)COUNT * (entry_len + 1));
  EXPECT_NOT_NULL(storage);
  const char** entries = calloc(COUNT, sizeof(char*));
  EXPECT_NOT_NULL(entries);
  for (int i = 0; i < COUNT; i++) {
    char* entry = storage + (size_t)i * (entry_len + 1);
    size_t pos = 0;
    for (int c = 0; c < COMPONENTS; c++) {
      entry[pos++] = 'a';
      entry[pos++] = '/';
    }
    entry[pos++] = 'x';
    entry[pos++] = (char)('0' + i);
    entry[pos] = '\0';
    entries[i] = entry;
  }

  PathIndex index;
  EXPECT_TRUE(path_index_build(&index, entries, COUNT));
  EXPECT_EQ_INT((int)index.sorted.count, COUNT);
  EXPECT_EQ_INT((int)index.exact.size, COUNT);
  EXPECT_TRUE(path_index_contains(&index, entries[0]));
  EXPECT_FALSE(path_index_contains(&index, "a"));
  EXPECT_TRUE(path_index_has_descendant(&index, "a"));
  EXPECT_TRUE(path_index_has_descendant(&index, "a/a"));
  EXPECT_FALSE(path_index_has_descendant(&index, "aa"));
  path_index_free(&index);

  free((void*)entries);
  free(storage);
}

static void test_path_index_semantics() {
  const char* entries[] = {"a/b/c.txt", "a/b/d.txt", "x.txt", "deep/deeper/deepest"};
  PathIndex index;
  EXPECT_TRUE(path_index_build(&index, entries, 4));
  EXPECT_TRUE(path_index_contains(&index, "a/b/c.txt"));
  EXPECT_FALSE(path_index_contains(&index, "a/b"));
  EXPECT_TRUE(path_index_contains_n(&index, "a/b/c.txt/ignored", 9));
  EXPECT_FALSE(path_index_contains_n(&index, "a/b/c.txt/ignored", 10));
  EXPECT_TRUE(path_index_has_descendant(&index, "a"));
  EXPECT_TRUE(path_index_has_descendant(&index, "a/b"));
  EXPECT_FALSE(path_index_has_descendant(&index, "a/b/c.txt"));
  EXPECT_FALSE(path_index_has_descendant(&index, "ab"));
  EXPECT_FALSE(path_index_has_descendant(&index, ""));
  path_index_free(&index);

  /* A zero-entry index answers no queries. */
  PathIndex empty;
  EXPECT_TRUE(path_index_build(&empty, NULL, 0));
  EXPECT_EQ_INT((int)empty.sorted.count, 0);
  EXPECT_FALSE(path_index_contains(&empty, "a"));
  EXPECT_FALSE(path_index_has_descendant(&empty, "a"));
  path_index_free(&empty);
}

/* utils_getdelim_bounded must return normal short lines unchanged and refuse an
 * over-long record with EFBIG rather than allocating without bound. */
static void test_getdelim_bounded() {
  FILE* fp = tmpfile();
  EXPECT_NOT_NULL(fp);
  const char* short_line = "short\n";
  EXPECT_EQ_INT((int)fwrite(short_line, 1, strlen(short_line), fp), (int)strlen(short_line));
  char big[32];
  memset(big, 'x', 20);
  big[20] = '\n';
  EXPECT_EQ_INT((int)fwrite(big, 1, 21, fp), 21);
  rewind(fp);

  char* line = NULL;
  size_t cap = 0;
  ssize_t n = utils_getdelim_bounded(fp, &line, &cap, '\n', 64);
  EXPECT_EQ_INT((int)n, 6);
  EXPECT_EQ_STR(line, "short\n");

  errno = 0;
  n = utils_getdelim_bounded(fp, &line, &cap, '\n', 10);
  EXPECT_EQ_INT((int)n, -1);
  EXPECT_EQ_INT(errno, EFBIG);

  free(line);
  fclose(fp);
}

static int test_env_resolver(const char* name) {
  if (strcasecmp(name, "alpha") == 0)
    return 10;
  if (strcasecmp(name, "beta") == 0)
    return 20;
  return -1;
}

static void test_env_choice_first_parsing() {
  const char* var = "FASTSYNC_TEST_CHOICE_LIST";
  bool specified = true;
  unsetenv(var);
  EXPECT_EQ_INT(env_choice_first(var, test_env_resolver, &specified), -1);
  EXPECT_FALSE(specified);

  /* Unknown entries are skipped, case-insensitive, first supported wins. */
  setenv(var, "bogus BETA alpha", 1);
  EXPECT_EQ_INT(env_choice_first(var, test_env_resolver, &specified), 20);
  EXPECT_TRUE(specified);

  /* The client half ends at '&'. */
  setenv(var, "alpha & beta", 1);
  EXPECT_EQ_INT(env_choice_first(var, test_env_resolver, &specified), 10);

  /* Blank means "unspecified"; all-unknown means "specified but no match". */
  setenv(var, "   ", 1);
  EXPECT_EQ_INT(env_choice_first(var, test_env_resolver, &specified), -1);
  EXPECT_FALSE(specified);
  setenv(var, "nope,alpha", 1);
  EXPECT_EQ_INT(env_choice_first(var, test_env_resolver, &specified), -1);
  EXPECT_TRUE(specified);

  unsetenv(var);
}

void test_shared_utils() {
  test_env_choice_first_parsing();
  test_path_index_bounded();
  test_path_index_semantics();
  test_getdelim_bounded();
  test_walker_removes_extras_keeps_manifest_and_protected();
  test_walker_keeps_nested_manifest_dirs();
  test_walker_max_delete_partial_deletes_up_to_cap();
  test_walker_max_delete_exact_bound_deletes();
  test_walker_removes_extraneous_symlinks();
  test_walker_confines_deletion_to_synced_dirs();
  test_walker_unlimited_deletes_all();
  test_walker_protect_rules_shield_dest_only();
  test_loopback_helpers();
  test_fd_peer_ip();

  /* --append / --append-verify tail-resume math: a resume is eligible only for
     a shorter existing destination, and the tail length is then the difference. */
  EXPECT_TRUE(append_resume_eligible(0, 10));
  EXPECT_TRUE(append_resume_eligible(7, 10));
  EXPECT_FALSE(append_resume_eligible(10, 10));
  EXPECT_FALSE(append_resume_eligible(11, 10));

  unsigned long long tail;
  EXPECT_TRUE(append_tail_length(0, 10, &tail));
  EXPECT_EQ_INT((int)tail, 10);
  EXPECT_TRUE(append_tail_length(7, 10, &tail));
  EXPECT_EQ_INT((int)tail, 3);
  EXPECT_FALSE(append_tail_length(10, 10, &tail));
  EXPECT_FALSE(append_tail_length(11, 10, &tail));
  EXPECT_FALSE(append_tail_length(7, 10, NULL));

  char formatted[32];
  EXPECT_TRUE(format_human_bytes(0, formatted, sizeof(formatted)));
  EXPECT_EQ_STR(formatted, "0 B");
  EXPECT_TRUE(format_human_bytes(1024, formatted, sizeof(formatted)));
  EXPECT_EQ_STR(formatted, "1.0 KB");
  EXPECT_TRUE(format_human_bytes(1536 * 1024, formatted, sizeof(formatted)));
  EXPECT_EQ_STR(formatted, "1.5 MB");
  EXPECT_FALSE(format_human_bytes(1024, formatted, 4));

  char high_bit[] = {'a', (char)0xc3, (char)0xa9, '\n', '\0'};
  char* escaped = output_escape(high_bit, false);
  EXPECT_EQ_STR(escaped, "a\\#303\\#251\\#012");
  free(escaped);
  escaped = output_escape(high_bit, true);
  EXPECT_EQ_STR(escaped, "a\xc3\xa9\\#012");
  free(escaped);

  ProtocolSession safe_session;
  ProtocolSession eight_bit_session;
  protocol_session_init(&safe_session, -1, -1);
  protocol_session_init(&eight_bit_session, -1, -1);
  protocol_session_set_8_bit_output(&safe_session, false);
  protocol_session_set_8_bit_output(&eight_bit_session, true);
  EXPECT_FALSE(safe_session.eight_bit_output);
  EXPECT_TRUE(eight_bit_session.eight_bit_output);

  EscapeThreadArgs safe_args = {false, "x\\#303\\#251\\#012", 0};
  EscapeThreadArgs eight_bit_args = {true, "x\xc3\xa9\\#012", 0};
  thrd_t safe_thread;
  thrd_t eight_bit_thread;
  EXPECT_EQ_INT(thrd_create(&safe_thread, escape_thread, &safe_args), thrd_success);
  EXPECT_EQ_INT(thrd_create(&eight_bit_thread, escape_thread, &eight_bit_args), thrd_success);
  EXPECT_EQ_INT(thrd_join(safe_thread, NULL), thrd_success);
  EXPECT_EQ_INT(thrd_join(eight_bit_thread, NULL), thrd_success);
  EXPECT_FALSE(safe_args.failed);
  EXPECT_FALSE(eight_bit_args.failed);

  // Test str_dup
  const char* dup_null = str_dup(NULL);
  EXPECT_NULL(dup_null);

  char* dup_empty = str_dup("");
  EXPECT_NOT_NULL(dup_empty);
  EXPECT_EQ_STR(dup_empty, "");
  free(dup_empty);

  char* dup_normal = str_dup("hello world");
  EXPECT_NOT_NULL(dup_normal);
  EXPECT_EQ_STR(dup_normal, "hello world");
  free(dup_normal);

  // Test path_cat
  char* cat1 = path_cat("/foo", "/bar");
  EXPECT_NOT_NULL(cat1);
  EXPECT_EQ_STR(cat1, "/foo/bar");
  free(cat1);

  char* cat2 = path_cat("/foo/", "/bar");
  EXPECT_NOT_NULL(cat2);
  EXPECT_EQ_STR(cat2, "/foo/bar");
  free(cat2);

  char* cat3 = path_cat("/foo", "bar");
  EXPECT_NOT_NULL(cat3);
  EXPECT_EQ_STR(cat3, "/foo/bar");
  free(cat3);

  char* cat4 = path_cat("/foo/", "bar");
  EXPECT_NOT_NULL(cat4);
  EXPECT_EQ_STR(cat4, "/foo/bar");
  free(cat4);

  char* cat_empty1 = path_cat("", "/bar");
  EXPECT_NOT_NULL(cat_empty1);
  EXPECT_EQ_STR(cat_empty1, "/bar");
  free(cat_empty1);

  char* cat_empty2 = path_cat("/foo", "");
  EXPECT_NOT_NULL(cat_empty2);
  EXPECT_EQ_STR(cat_empty2, "/foo");
  free(cat_empty2);

  char* cat_null1 = path_cat(NULL, "/bar");
  EXPECT_NOT_NULL(cat_null1);
  EXPECT_EQ_STR(cat_null1, "/bar");
  free(cat_null1);

  char* cat_null2 = path_cat("/foo", NULL);
  EXPECT_NOT_NULL(cat_null2);
  EXPECT_EQ_STR(cat_null2, "/foo");
  free(cat_null2);
}
