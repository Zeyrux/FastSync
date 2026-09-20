#include "delete_plan.h"

#include "charset.h"
#include "delay_updates.h"
#include "file.h"
#include "log.h"
#include "utils.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Mirrors MAX_SERVER_DELETE_COUNT in file_receive.c: the server's hard bound on
 * the number of entries one deletion commit may remove.  A client
 * --max-delete=NUM smaller than this replaces it for the run. */
#define DELETE_PLAN_SERVER_LIMIT 100000U

/* ------------------------------------------------------------------ */
/* Sender: plan builder                                               */
/* ------------------------------------------------------------------ */

typedef struct PlanNode {
  char* dir;
  ArrayList* files; /* basenames kept directly in dir */
  ArrayList* dirs;  /* basenames of kept child directories */
  bool sent;
  struct PlanNode* hash_next;
} PlanNode;

struct DeletePlanSender {
  PlanNode** buckets;
  size_t capacity;
  size_t count;
  bool config_sent;
  bool all_synced;
  const ArrayList* synced_dirs;
  /* Owned by the caller's synced_dirs list; non-NULL only for a general -R
     transfer, where it is the destination prefix the delete walk is confined
     to.  NULL means the whole receive root (or a --files-from scope). */
  const char* walk_root;
  const ArrayList* protected_prefixes;
  const ArrayList* size_skipped;
  const ArrayList* missing_args;
  size_t entries;
  /* Transmitted FILE entries only.  The caller's "empty scan" safety guard keys
     off this (an I/O error that hid every file must refuse to delete even when
     some directories were traversed), so directory keep entries do not count. */
  size_t file_entries;
};

static size_t plan_hash(const char* key) {
  size_t h = 5381;
  for (const unsigned char* p = (const unsigned char*)key; *p; p++)
    h = ((h << 5) + h) + *p;
  return h;
}

static bool list_contains_str(const ArrayList* list, const char* value) {
  if (!list)
    return false;
  for (int i = 0; i < list->size; i++) {
    if (strcmp((const char*)list->items[i], value) == 0)
      return true;
  }
  return false;
}

static bool list_add_str_unique(ArrayList* list, const char* value) {
  if (!list || !value)
    return false;
  if (list_contains_str(list, value))
    return true;
  char* copy = str_dup(value);
  if (!copy)
    return false;
  if (!array_list_add(list, copy)) {
    free(copy);
    return false;
  }
  return true;
}

DeletePlanSender* delete_plan_sender_create(void) {
  DeletePlanSender* sender = calloc(1, sizeof(DeletePlanSender));
  if (!sender)
    return NULL;
  sender->capacity = 64;
  sender->buckets = calloc(sender->capacity, sizeof(PlanNode*));
  if (!sender->buckets) {
    free(sender);
    return NULL;
  }
  sender->all_synced = true;
  return sender;
}

static void plan_node_destroy(PlanNode* node) {
  if (!node)
    return;
  free(node->dir);
  array_list_delete(node->files);
  array_list_delete(node->dirs);
  free(node);
}

void delete_plan_sender_destroy(DeletePlanSender* sender) {
  if (!sender)
    return;
  for (size_t i = 0; i < sender->capacity; i++) {
    PlanNode* node = sender->buckets[i];
    while (node) {
      PlanNode* next = node->hash_next;
      plan_node_destroy(node);
      node = next;
    }
  }
  free(sender->buckets);
  free(sender);
}

static PlanNode* plan_find(const DeletePlanSender* sender, const char* dir) {
  size_t index = plan_hash(dir) & (sender->capacity - 1);
  for (PlanNode* node = sender->buckets[index]; node; node = node->hash_next) {
    if (strcmp(node->dir, dir) == 0)
      return node;
  }
  return NULL;
}

static bool plan_grow(DeletePlanSender* sender) {
  size_t new_capacity = sender->capacity * 2;
  PlanNode** buckets = calloc(new_capacity, sizeof(PlanNode*));
  if (!buckets)
    return false;
  for (size_t i = 0; i < sender->capacity; i++) {
    PlanNode* node = sender->buckets[i];
    while (node) {
      PlanNode* next = node->hash_next;
      size_t index = plan_hash(node->dir) & (new_capacity - 1);
      node->hash_next = buckets[index];
      buckets[index] = node;
      node = next;
    }
  }
  free(sender->buckets);
  sender->buckets = buckets;
  sender->capacity = new_capacity;
  return true;
}

static PlanNode* plan_ensure(DeletePlanSender* sender, const char* dir) {
  PlanNode* node = plan_find(sender, dir);
  if (node)
    return node;
  if (sender->count + 1 > sender->capacity * 3 / 4 && !plan_grow(sender))
    return NULL;
  node = calloc(1, sizeof(PlanNode));
  if (!node)
    return NULL;
  node->dir = str_dup(dir);
  node->files = array_list_create(free);
  node->dirs = array_list_create(free);
  if (!node->dir || !node->files || !node->dirs) {
    plan_node_destroy(node);
    return NULL;
  }
  size_t index = plan_hash(dir) & (sender->capacity - 1);
  node->hash_next = sender->buckets[index];
  sender->buckets[index] = node;
  sender->count++;
  return node;
}

static char* path_parent_dir(const char* path) {
  const char* slash = strrchr(path, '/');
  if (!slash)
    return str_dup(".");
  if (slash == path)
    return str_dup(".");
  size_t len = (size_t)(slash - path);
  char* parent = malloc(len + 1);
  if (!parent)
    return NULL;
  memcpy(parent, path, len);
  parent[len] = '\0';
  return parent;
}

static char* path_base_name(const char* path) {
  const char* slash = strrchr(path, '/');
  return str_dup(slash ? slash + 1 : path);
}

/* Copy `path`, stripping a leading '/' and any trailing '/'. */
static char* plan_clean_path(const char* path) {
  while (*path == '/')
    path++;
  size_t len = strlen(path);
  while (len > 0 && path[len - 1] == '/')
    len--;
  char* clean = malloc(len + 1);
  if (!clean)
    return NULL;
  memcpy(clean, path, len);
  clean[len] = '\0';
  return clean;
}

static bool plan_ensure_ancestors(DeletePlanSender* sender, const char* dir) {
  char* current = str_dup(dir);
  if (!current)
    return false;
  bool ok = true;
  while (strcmp(current, ".") != 0) {
    char* parent = path_parent_dir(current);
    char* base = path_base_name(current);
    PlanNode* parent_node = parent ? plan_ensure(sender, parent) : NULL;
    if (!parent || !base || !parent_node || !list_add_str_unique(parent_node->dirs, base)) {
      ok = false;
      free(parent);
      free(base);
      break;
    }
    free(base);
    free(current);
    current = parent;
  }
  free(current);
  return ok;
}

bool delete_plan_sender_add(DeletePlanSender* sender, const char* path, bool is_dir) {
  if (!sender || !path)
    return false;
  char* clean = plan_clean_path(path);
  if (!clean)
    return false;
  if (*clean == '\0') {
    free(clean);
    return true;
  }
  char* parent = path_parent_dir(clean);
  char* base = path_base_name(clean);
  PlanNode* parent_node = parent ? plan_ensure(sender, parent) : NULL;
  bool ok = parent && base && parent_node;
  if (ok) {
    if (is_dir) {
      ok = list_add_str_unique(parent_node->dirs, base) && plan_ensure(sender, clean) != NULL;
    } else {
      ok = list_add_str_unique(parent_node->files, base);
    }
  }
  if (ok)
    ok = plan_ensure_ancestors(sender, parent);
  if (ok) {
    sender->entries++;
    if (!is_dir)
      sender->file_entries++;
  }
  free(clean);
  free(parent);
  free(base);
  return ok;
}

void delete_plan_sender_finalize(DeletePlanSender* sender, const ArrayList* synced_dirs,
                                 const char* walk_root) {
  if (!sender)
    return;
  sender->synced_dirs = synced_dirs;
  sender->all_synced = synced_dirs == NULL && walk_root == NULL;
  sender->walk_root = walk_root;
}

bool delete_plan_sender_empty(const DeletePlanSender* sender) {
  return !sender || sender->file_entries == 0;
}

void delete_plan_sender_set_config(DeletePlanSender* sender, const ArrayList* protected_prefixes,
                                   const ArrayList* size_skipped, const ArrayList* missing_args) {
  if (!sender)
    return;
  sender->protected_prefixes = protected_prefixes;
  sender->size_skipped = size_skipped;
  sender->missing_args = missing_args;
}

/* True when `dir` is `root` itself or a descendant of it (path-component
 * aware, so "foo" does not match "foobar"). */
static bool path_at_or_under(const char* dir, const char* root) {
  if (!dir || !root)
    return false;
  size_t n = strlen(root);
  return strncmp(dir, root, n) == 0 && (dir[n] == '\0' || dir[n] == '/');
}

static bool plan_is_allowed(const DeletePlanSender* sender, const char* dir) {
  if (sender->all_synced)
    return true;
  if (sender->walk_root)
    return path_at_or_under(dir, sender->walk_root);
  return list_contains_str(sender->synced_dirs, dir);
}

static int send_str_section(int fd, const ArrayList* list) {
  int count = list ? list->size : 0;
  if (!send_int(fd, count))
    return -1;
  for (int i = 0; i < count; i++) {
    if (!send_wire_str(fd, (const char*)list->items[i]))
      return -1;
  }
  return 0;
}

static int send_plan_node(int fd, DeletePlanSender* sender, PlanNode* node) {
  if (!send_status(fd, STATUS_DELETE_PLAN))
    return -1;
  if (!send_int(fd, sender->config_sent ? 0 : 1))
    return -1;
  if (!sender->config_sent) {
    if (send_str_section(fd, sender->protected_prefixes) != 0 ||
        send_str_section(fd, sender->size_skipped) != 0 ||
        send_str_section(fd, sender->missing_args) != 0)
      return -1;
    sender->config_sent = true;
  }
  if (!send_int(fd, 1)) /* apply = true */
    return -1;
  if (!send_wire_str(fd, node->dir))
    return -1;
  if (send_str_section(fd, node->dirs) != 0 || send_str_section(fd, node->files) != 0)
    return -1;
  node->sent = true;
  return 0;
}

/* Transmit the one-shot per-run config block (protected prefixes, size-pruned
 * mirrors, --delete-missing-args exact paths) on its own carrier frame, with
 * apply=false so the receiver consumes the config but walks nothing.  This is
 * how the config still reaches the receiver when the scope allows no directory
 * plan at all (a --files-from list of bare files synchronizes no directory):
 * without it, the missing-args exact deletions would be lost.  Idempotent. */
static int send_config_only(int fd, DeletePlanSender* sender) {
  if (!sender || sender->config_sent)
    return 0;
  if (!send_status(fd, STATUS_DELETE_PLAN) || !send_int(fd, 1))
    return -1;
  if (send_str_section(fd, sender->protected_prefixes) != 0 ||
      send_str_section(fd, sender->size_skipped) != 0 ||
      send_str_section(fd, sender->missing_args) != 0)
    return -1;
  sender->config_sent = true;
  if (!send_int(fd, 0)) /* apply = false */
    return -1;
  if (!send_wire_str(fd, ".") || !send_int(fd, 0) || !send_int(fd, 0))
    return -1;
  return 0;
}

static int send_prefix_plan(int fd, DeletePlanSender* sender, const char* dir) {
  PlanNode* node = plan_find(sender, dir);
  if (!node || node->sent)
    return 0;
  if (!plan_is_allowed(sender, dir))
    return 0;
  return send_plan_node(fd, sender, node);
}

int delete_plan_send_root(int fd, DeletePlanSender* sender) {
  if (!sender)
    return -1;
  const char* root = sender->walk_root ? sender->walk_root : ".";
  if (!plan_ensure(sender, root))
    return -1;
  /* Put the config block on the wire first, on its own carrier frame, so the
     receiver always sees it even when the scope permits no directory plan. */
  if (send_config_only(fd, sender) != 0)
    return -1;
  return send_prefix_plan(fd, sender, root);
}

int delete_plan_send_for_path(int fd, DeletePlanSender* sender, const char* path, bool is_dir) {
  if (!sender || !path)
    return -1;
  char* clean = plan_clean_path(path);
  if (!clean)
    return -1;
  /* The walk root (the -R prefix, or ".") is sent up front by
     delete_plan_send_root(); never emit the receive-root plan for a scoped -R
     run, whose "." keep list would delete the prefix's siblings. */
  int rc = sender->walk_root ? 0 : send_prefix_plan(fd, sender, ".");
  if (rc == 0 && *clean != '\0') {
    size_t len = strlen(clean);
    size_t end = len;
    if (!is_dir) {
      const char* slash = strrchr(clean, '/');
      end = slash ? (size_t)(slash - clean) : 0;
    }
    for (size_t i = 1; i <= end && rc == 0; i++) {
      if (i == end || clean[i] == '/') {
        char* prefix = malloc(i + 1);
        if (!prefix) {
          rc = -1;
          break;
        }
        memcpy(prefix, clean, i);
        prefix[i] = '\0';
        rc = send_prefix_plan(fd, sender, prefix);
        free(prefix);
      }
    }
  }
  free(clean);
  return rc;
}

int delete_plan_send_remaining(int fd, DeletePlanSender* sender, const ArrayList* dirs) {
  if (!sender || !dirs)
    return 0;
  for (int i = 0; i < dirs->size; i++) {
    const char* dir = (const char*)dirs->items[i];
    if (delete_plan_send_for_path(fd, sender, dir, true) != 0)
      return -1;
  }
  return 0;
}

int delete_plan_send_all(int fd, DeletePlanSender* sender, const ArrayList* dirs) {
  if (!sender)
    return -1;
  /* Root first: this also transmits the one-shot per-run config block on its
     own carrier frame (see send_config_only), so it reaches the receiver even
     when the scope permits no directory plan at all. */
  if (delete_plan_send_root(fd, sender) != 0)
    return -1;
  return delete_plan_send_remaining(fd, sender, dirs);
}

/* ------------------------------------------------------------------ */
/* Receiver: delete session                                           */
/* ------------------------------------------------------------------ */

struct DeletePlanSession {
  bool defer;
  bool dry_run;
  size_t max_delete;
  size_t deleted;
  /* Removals charged against --max-delete.  The budget is charged on ACTUAL
     removals (an unlink/rmdir that succeeded), matching rsync: a snapshotted
     entry that fails removal consumes nothing, so a later extra is still
     deleted.  `planned` and `deleted` advance together for the inline paths and
     `apply_missing`; `deleted` is the reported count. */
  size_t planned;
  /* Hard bound on the deferred snapshot list.  Because the budget is no longer
     charged at snapshot time, this independent cap keeps a huge destination
     from growing the list without limit (it matches the receiver's overall
     deletion bound). */
  size_t defer_cap;
  size_t skipped;
  bool limit_hit;
  bool limit_logged;
  bool config_seen;
  bool missing_applied;
  ArrayList* protected_prefixes;
  ArrayList* size_skipped;
  ArrayList* missing;
  ArrayList* deferred;
  DeletePathObserver observer;
  void* observer_context;
};

/* Report one path the session truly removed (no-op without an observer). */
static void notify_deleted(DeletePlanSession* session, const char* rel) {
  if (session && session->observer && rel)
    session->observer(session->observer_context, rel);
}

/* A removed directory is reported with rsync's trailing slash (`deleting dir/`)
   while files keep their bare path. */
static void notify_deleted_dir(DeletePlanSession* session, const char* rel) {
  if (!session || !session->observer || !rel)
    return;
  size_t len = strlen(rel);
  char* with_slash = malloc(len + 2);
  if (!with_slash) {
    session->observer(session->observer_context, rel);
    return;
  }
  memcpy(with_slash, rel, len);
  with_slash[len] = '/';
  with_slash[len + 1] = '\0';
  session->observer(session->observer_context, with_slash);
  free(with_slash);
}

DeletePlanSession* delete_plan_session_create(const Config* config) {
  if (!config)
    return NULL;
  DeletePlanSession* session = calloc(1, sizeof(DeletePlanSession));
  if (!session)
    return NULL;
  session->defer = config->delete_delay;
  session->dry_run = config->dry_run;
  bool user_limited =
      config->max_delete >= 0 && (size_t)config->max_delete < DELETE_PLAN_SERVER_LIMIT;
  session->max_delete =
      user_limited ? (size_t)config->max_delete : (size_t)DELETE_PLAN_SERVER_LIMIT;
  session->defer_cap = DELETE_PLAN_SERVER_LIMIT;
  session->protected_prefixes = array_list_create(free);
  session->size_skipped = array_list_create(free);
  session->missing = array_list_create(free);
  session->deferred = array_list_create(free);
  if (!session->protected_prefixes || !session->size_skipped || !session->missing ||
      !session->deferred) {
    delete_plan_session_destroy(session);
    return NULL;
  }
  return session;
}

void delete_plan_session_destroy(DeletePlanSession* session) {
  if (!session)
    return;
  array_list_delete(session->protected_prefixes);
  array_list_delete(session->size_skipped);
  array_list_delete(session->missing);
  array_list_delete(session->deferred);
  free(session);
}

bool delete_plan_session_limit_reached(const DeletePlanSession* session) {
  return session && session->limit_hit;
}

size_t delete_plan_session_deleted(const DeletePlanSession* session) {
  return session ? session->deleted : 0;
}

/* True for a destination-relative path section entry (non-empty, relative,
 * traversal-free). */
static bool valid_rel_path(const char* value) {
  return value && value[0] != '\0' && value[0] != '/' && !has_path_traversal(value);
}

/* True for a single child name (non-empty, no slash, not "."/".."). */
static bool valid_name(const char* value) {
  return value && value[0] != '\0' && strcmp(value, ".") != 0 && strcmp(value, "..") != 0 &&
         strchr(value, '/') == NULL;
}

/* Read one count-prefixed section.  `bytes` is the running per-frame budget,
 * shared across every section of the frame so a hostile peer cannot retain more
 * than MAX_MANIFEST_BYTES from one STATUS_DELETE_PLAN frame. */
static bool read_section(int fd, ArrayList* list, bool rel_path, size_t* bytes) {
  int count;
  if (!receive_int(fd, &count) || count < 0 || count > MAX_MANIFEST_ENTRIES)
    return false;
  for (int i = 0; i < count; i++) {
    char* value = receive_wire_str(fd);
    bool ok = value && (rel_path ? valid_rel_path(value) : valid_name(value));
    if (ok) {
      size_t entry_size = strlen(value) + sizeof(char*) + 16;
      if (entry_size > MAX_MANIFEST_BYTES - *bytes) {
        ok = false;
      } else {
        *bytes += entry_size;
        ok = array_list_add(list, value);
      }
    }
    if (!ok) {
      free(value);
      return false;
    }
  }
  return true;
}

static int open_plan_dir(const Config* config, const char* dir) {
  char* full = (strcmp(dir, ".") == 0) ? str_dup(config->receive_root_directory)
                                       : path_cat(config->receive_root_directory, dir);
  if (!full)
    return -1;
  int root_fd = utils_get_authorized_root_fd();
  int fd = -1;
  if (root_fd >= 0) {
    if (utils_get_authorized_root_path())
      fd = utils_open_authorized_destination(full);
    else if (strcmp(dir, ".") == 0)
      fd = dup(root_fd);
  } else {
    fd = open(full, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  }
  free(full);
  return fd;
}

typedef struct PlanSkips {
  DeleteSkipEntry* entries;
  int count;
  /* Receiver-side delete-protection rules received on the config frame (NULL
     when the sender sent none).  Evaluated per extra so a protect/risk rule is
     honored under --delete-during/--delete-delay exactly like the whole-tree
     commit walker. */
  const FilterRuleList* protect_rules;
} PlanSkips;

static bool build_plan_skips(const Config* config, const DeletePlanSession* session,
                             PlanSkips* out) {
  out->entries = NULL;
  out->count = 0;
  out->protect_rules = config->protect_rules;
  int count = (config->delay_updates ? 1 : 0) + config->basis_count +
              session->protected_prefixes->size + session->size_skipped->size;
  if (count == 0)
    return true;
  out->entries = calloc((size_t)count, sizeof(DeleteSkipEntry));
  if (!out->entries)
    return false;
  int idx = 0;
  if (config->delay_updates) {
    out->entries[idx].prefix = DELAY_UPDATES_STAGING_DIR;
    out->entries[idx].top_level_only = true;
    idx++;
  }
  for (int i = 0; i < config->basis_count; i++) {
    out->entries[idx].prefix = config->basis_dirs[i].path;
    out->entries[idx].top_level_only = false;
    idx++;
  }
  for (int i = 0; i < session->protected_prefixes->size; i++) {
    out->entries[idx].prefix = (const char*)session->protected_prefixes->items[i];
    out->entries[idx].top_level_only = false;
    idx++;
  }
  for (int i = 0; i < session->size_skipped->size; i++) {
    out->entries[idx].prefix = (const char*)session->size_skipped->items[i];
    out->entries[idx].top_level_only = false;
    idx++;
  }
  out->count = idx;
  return true;
}

static bool budget_available(const DeletePlanSession* session) {
  return session->planned < session->max_delete;
}

static void note_skipped(DeletePlanSession* session) {
  session->limit_hit = true;
  session->skipped++;
}

static void log_deleted(const char* rel) {
  char* escaped = output_escape(rel, log_get_8_bit_output());
  fprintf(stderr, "  Deleted: %s\n", escaped ? escaped : "<allocation failed>");
  free(escaped);
}

/* Append a snapshot path for --delete-delay.  The budget is NOT charged here:
 * the remover charges --max-delete only when a path is actually unlinked (see
 * apply_deferred_path), so a snapshotted entry that survives ENOTEMPTY cannot
 * deny budget to a later extra.  The independent `defer_cap` bounds the list. */
static bool defer_add(DeletePlanSession* session, const char* rel) {
  if ((size_t)session->deferred->size >= session->defer_cap) {
    note_skipped(session);
    return true;
  }
  char* copy = str_dup(rel);
  if (!copy)
    return false;
  if (!array_list_add(session->deferred, copy)) {
    free(copy);
    return false;
  }
  return true;
}

/* Process the direct children of one directory.  `keep_dirs`/`keep_files`
 * (basenames) are the source entries that must be kept; NULL means every child
 * is an extra (the forced path used inside a removed extra directory tree).
 * `survives` reports that at least one child remains (kept, protected, or
 * skipped by the budget).  `force_now` removes even in --delete-delay mode
 * (type conflicts must clear before the incoming data). */
static bool process_children(int dirfd, const char* dir_rel, const ArrayList* keep_dirs,
                             const ArrayList* keep_files, bool at_root, bool force_now,
                             const PlanSkips* skips, DeletePlanSession* session, bool* survives);

static bool process_extra_dir(int dirfd, const char* name, const char* child_rel, bool force_now,
                              const PlanSkips* skips, DeletePlanSession* session, bool* removed) {
  *removed = false;
  int childfd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (childfd < 0) {
    if (errno == ENOENT) {
      *removed = true;
      return true;
    }
    return false;
  }
  bool survives = false;
  bool ok =
      process_children(childfd, child_rel, NULL, NULL, false, force_now, skips, session, &survives);
  close(childfd);
  if (!ok)
    return false;
  if (survives)
    return true;
  if (session->defer && !force_now) {
    if (!defer_add(session, child_rel))
      return false;
    *removed = true;
    return true;
  }
  if (!budget_available(session)) {
    note_skipped(session);
    return true;
  }
  if (unlinkat(dirfd, name, AT_REMOVEDIR) == 0) {
    session->deleted++;
    session->planned++;
    log_deleted(child_rel);
    notify_deleted_dir(session, child_rel);
    *removed = true;
    return true;
  }
  if (errno == ENOENT) {
    *removed = true;
    return true;
  }
  /* ENOTEMPTY/EEXIST: a protected entry the walker leaves behind survived, so
     the directory stays; any other errno is a genuine failure. */
  return errno == ENOTEMPTY || errno == EEXIST;
}

static bool process_extra_file(int dirfd, const char* name, const char* child_rel, bool force_now,
                               DeletePlanSession* session) {
  if (session->defer && !force_now) {
    return defer_add(session, child_rel);
  }
  if (!budget_available(session)) {
    note_skipped(session);
    return true;
  }
  if (unlinkat(dirfd, name, 0) == 0) {
    session->deleted++;
    session->planned++;
    log_deleted(child_rel);
    notify_deleted(session, child_rel);
  } else if (errno != ENOENT) {
    return false;
  }
  return true;
}

static bool process_children(int dirfd, const char* dir_rel, const ArrayList* keep_dirs,
                             const ArrayList* keep_files, bool at_root, bool force_now,
                             const PlanSkips* skips, DeletePlanSession* session, bool* survives) {
  *survives = false;
  DeleteDirEntry* entries = NULL;
  size_t count = 0;
  bool collect_ok = true;
  if (!delete_dir_entries_collect(dirfd, &entries, &count, &collect_ok))
    return false;
  bool operation_ok = collect_ok;
  bool local_survives = false;
  bool* shielded = calloc(count ? count : 1, sizeof(bool));
  bool* is_extra = calloc(count ? count : 1, sizeof(bool));
  bool* force = calloc(count ? count : 1, sizeof(bool));
  if (!shielded || !is_extra || !force) {
    free(shielded);
    free(is_extra);
    free(force);
    delete_dir_entries_free(entries, count);
    return false;
  }

  /* rsync's order: extraneous subdirectories in descending name order, then
     extraneous files in descending name order (kept entries survive and are not
     touched here — a kept subdirectory gets its own per-directory plan). */
  if (count > 1)
    qsort(entries, count, sizeof(*entries), delete_dir_entry_cmp_desc);
  size_t dir_count = 0;
  while (dir_count < count && entries[dir_count].is_dir)
    dir_count++;

  for (size_t i = 0; i < count; i++) {
    char* child_rel =
        (strcmp(dir_rel, ".") == 0) ? str_dup(entries[i].name) : path_cat(dir_rel, entries[i].name);
    if (!child_rel) {
      operation_ok = false;
      continue;
    }
    if (path_under_skip_prefix(child_rel, at_root, skips->entries, skips->count)) {
      shielded[i] = true;
      local_survives = true;
      free(child_rel);
      continue;
    }
    bool is_dir = entries[i].is_dir;
    bool in_keep_dirs = is_dir && list_contains_str(keep_dirs, entries[i].name);
    bool in_keep_files = !is_dir && list_contains_str(keep_files, entries[i].name);
    bool rule_protected =
        skips->protect_rules &&
        filter_rules_apply_side(skips->protect_rules, child_rel, entries[i].name, is_dir,
                                FILTER_SIDE_RECEIVER) == FILTER_ACTION_PROTECT;
    if (in_keep_dirs || in_keep_files || rule_protected) {
      shielded[i] = true;
      local_survives = true;
    } else if (is_dir) {
      /* A destination directory blocks a source file of the same name: remove
         it now, whatever the delete timing, so the file can be created. */
      is_extra[i] = true;
      force[i] = keep_files && list_contains_str(keep_files, entries[i].name);
    } else {
      /* A destination file blocks a source directory of the same name: clear it
         now so the directory can be created. */
      is_extra[i] = true;
      force[i] = keep_dirs && list_contains_str(keep_dirs, entries[i].name);
    }
    free(child_rel);
  }

  /* Pass 1: extraneous subdirectories, descending. */
  for (size_t i = 0; i < dir_count; i++) {
    if (!is_extra[i])
      continue;
    char* child_rel =
        (strcmp(dir_rel, ".") == 0) ? str_dup(entries[i].name) : path_cat(dir_rel, entries[i].name);
    if (!child_rel) {
      operation_ok = false;
      continue;
    }
    bool removed = false;
    if (!process_extra_dir(dirfd, entries[i].name, child_rel, force[i] || force_now, skips, session,
                           &removed))
      operation_ok = false;
    else if (!removed)
      local_survives = true;
    free(child_rel);
  }

  /* Pass 2: extraneous files, descending. */
  for (size_t i = dir_count; i < count; i++) {
    if (!is_extra[i])
      continue;
    char* child_rel =
        (strcmp(dir_rel, ".") == 0) ? str_dup(entries[i].name) : path_cat(dir_rel, entries[i].name);
    if (!child_rel) {
      operation_ok = false;
      continue;
    }
    if (!process_extra_file(dirfd, entries[i].name, child_rel, force[i] || force_now, session))
      operation_ok = false;
    free(child_rel);
  }

  free(shielded);
  free(is_extra);
  free(force);
  delete_dir_entries_free(entries, count);
  *survives = local_survives;
  return operation_ok;
}

static bool apply_plan_dir(DeletePlanSession* session, const Config* config, const char* dir,
                           const ArrayList* dirs, const ArrayList* files) {
  int dirfd = open_plan_dir(config, dir);
  if (dirfd < 0) {
    /* An absent destination directory has nothing to delete. */
    return errno == ENOENT || errno == ENOTDIR;
  }
  PlanSkips skips;
  if (!build_plan_skips(config, session, &skips)) {
    close(dirfd);
    return false;
  }
  bool survives = false;
  bool ok = process_children(dirfd, dir, dirs, files, strcmp(dir, ".") == 0, false, &skips, session,
                             &survives);
  free(skips.entries);
  close(dirfd);
  if (!ok)
    log_message(LOG_LEVEL_ERROR, "deletion failed while removing extraneous files");
  return ok;
}

static bool apply_missing(DeletePlanSession* session, const Config* config) {
  if (session->missing_applied)
    return true;
  session->missing_applied = true;
  /* The server clears delete_missing_args when its --allow-delete policy is
     off; never honor the client's exact-path requests then. */
  if (!config->delete_missing_args || session->missing->size == 0)
    return true;
  DeleteManifest manifest = {
      .keeps = NULL, .protected = NULL, .missing = session->missing, .dirs = NULL};
  size_t remaining = budget_available(session) ? session->max_delete - session->planned : 0;
  size_t deleted = 0;
  size_t skipped = 0;
  bool limit = false;
  bool ok = manifest_delete_missing_args_limited_observed(config, &manifest, remaining, &deleted,
                                                          &skipped, &limit, session->observer,
                                                          session->observer_context);
  session->deleted += deleted;
  session->planned += deleted;
  session->skipped += skipped;
  if (limit)
    session->limit_hit = true;
  return ok;
}

int delete_plan_session_receive(DeletePlanSession* session, const Config* config, int fd) {
  if (!session || !config) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  int has_config;
  if (!receive_int(fd, &has_config) || (has_config != 0 && has_config != 1)) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  size_t bytes = 0;
  if (has_config) {
    if (session->config_seen || !read_section(fd, session->protected_prefixes, true, &bytes) ||
        !read_section(fd, session->size_skipped, true, &bytes) ||
        !read_section(fd, session->missing, true, &bytes)) {
      send_status(fd, STATUS_ERROR);
      return -1;
    }
    session->config_seen = true;
  }
  /* apply=false is the config-only carrier frame: the receiver consumes the
     config (and the missing-args exact deletions) but must not walk any
     directory.  Every real plan carries apply=true. */
  int apply;
  if (!receive_int(fd, &apply) || (apply != 0 && apply != 1)) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  char* dir = receive_wire_str(fd);
  ArrayList* dirs = array_list_create(free);
  ArrayList* files = array_list_create(free);
  bool parsed = dir && (strcmp(dir, ".") == 0 || valid_rel_path(dir)) && dirs && files &&
                read_section(fd, dirs, false, &bytes) && read_section(fd, files, false, &bytes);
  if (!parsed) {
    free(dir);
    array_list_delete(dirs);
    array_list_delete(files);
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  bool enabled = config->use_delete || config->delete_missing_args;
  bool ok = true;
  if (!session->dry_run && enabled) {
    if (!session->defer && !apply_missing(session, config))
      ok = false;
    if (ok && apply && !apply_plan_dir(session, config, dir, dirs, files))
      ok = false;
  }
  free(dir);
  array_list_delete(dirs);
  array_list_delete(files);
  if (!ok) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  if (session->limit_hit && !session->limit_logged) {
    session->limit_logged = true;
    log_message(LOG_LEVEL_WARNING, "Deletions stopped due to the delete limit (%zu skipped)",
                session->skipped);
  }
  return 0;
}

/* Apply one snapshotted --delete-delay path (post-order: children precede their
 * parent directory).  A directory that is still present is re-scanned so content
 * created after the plan is removed too; every actual removal charges
 * --max-delete. */
static bool apply_deferred_path(DeletePlanSession* session, const Config* config, const char* rel) {
  char* full = path_cat(config->receive_root_directory, rel);
  if (!full)
    return false;
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(full, &leaf, false);
  free(full);
  if (parent_fd < 0) {
    free(leaf);
    return errno == ENOENT || errno == ENOTDIR;
  }
  struct stat st;
  if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) {
    bool absent = errno == ENOENT || errno == ENOTDIR;
    close(parent_fd);
    free(leaf);
    return absent;
  }
  if (S_ISDIR(st.st_mode)) {
    if (!budget_available(session)) {
      note_skipped(session);
      close(parent_fd);
      free(leaf);
      return true;
    }
    int dirfd = openat(parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0) {
      bool absent = errno == ENOENT || errno == ENOTDIR;
      close(parent_fd);
      free(leaf);
      return absent;
    }
    PlanSkips skips;
    if (!build_plan_skips(config, session, &skips)) {
      close(dirfd);
      close(parent_fd);
      free(leaf);
      return false;
    }
    bool survives = false;
    bool ok = process_children(dirfd, rel, NULL, NULL, false, true, &skips, session, &survives);
    free(skips.entries);
    close(dirfd);
    if (!ok) {
      close(parent_fd);
      free(leaf);
      return false;
    }
    if (!survives) {
      if (!budget_available(session)) {
        note_skipped(session);
      } else if (unlinkat(parent_fd, leaf, AT_REMOVEDIR) == 0) {
        session->deleted++;
        session->planned++;
        log_deleted(rel);
        notify_deleted_dir(session, rel);
      } else if (errno != ENOENT && errno != ENOTEMPTY && errno != EEXIST) {
        close(parent_fd);
        free(leaf);
        return false;
      }
    }
    close(parent_fd);
    free(leaf);
    return true;
  }
  if (!budget_available(session)) {
    note_skipped(session);
    close(parent_fd);
    free(leaf);
    return true;
  }
  if (unlinkat(parent_fd, leaf, 0) == 0) {
    session->deleted++;
    session->planned++;
    log_deleted(rel);
    notify_deleted(session, rel);
  } else if (errno != ENOENT) {
    close(parent_fd);
    free(leaf);
    return false;
  }
  close(parent_fd);
  free(leaf);
  return true;
}

void delete_plan_session_set_delete_observer(DeletePlanSession* session,
                                             DeletePathObserver observer, void* context) {
  if (!session)
    return;
  session->observer = observer;
  session->observer_context = context;
}

DeleteCommitResult delete_plan_session_commit(DeletePlanSession* session, const Config* config) {
  if (!session || !config)
    return DELETE_COMMIT_ERROR;
  /* Central no-mutation guard (mirrors manifest_delete_all): a dry-run never
     deletes.  The receive path already skips plan application, but a hostile or
     buggy peer could still reach the commit, so treat it as a no-op. */
  if (session->dry_run)
    return DELETE_COMMIT_OK;
  bool ok = true;
  if (session->defer) {
    for (int i = 0; i < session->deferred->size && ok; i++)
      ok = apply_deferred_path(session, config, (const char*)session->deferred->items[i]);
  }
  if (ok)
    ok = apply_missing(session, config);
  if (!ok)
    return DELETE_COMMIT_ERROR;
  if (session->limit_hit)
    return DELETE_COMMIT_LIMIT_REACHED;
  return DELETE_COMMIT_OK;
}
