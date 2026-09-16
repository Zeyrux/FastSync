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
/* Per-frame entry cap for the name sections (the dir/file child lists). */
#define DELETE_PLAN_MAX_NAMES MAX_MANIFEST_ENTRIES

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
  const ArrayList* protected_prefixes;
  const ArrayList* size_skipped;
  const ArrayList* missing_args;
  size_t entries;
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
  if (ok)
    sender->entries++;
  free(clean);
  free(parent);
  free(base);
  return ok;
}

void delete_plan_sender_finalize(DeletePlanSender* sender, const ArrayList* synced_dirs) {
  if (!sender)
    return;
  sender->synced_dirs = synced_dirs;
  sender->all_synced = synced_dirs == NULL;
}

bool delete_plan_sender_empty(const DeletePlanSender* sender) {
  return !sender || sender->entries == 0;
}

void delete_plan_sender_set_config(DeletePlanSender* sender, const ArrayList* protected_prefixes,
                                   const ArrayList* size_skipped, const ArrayList* missing_args) {
  if (!sender)
    return;
  sender->protected_prefixes = protected_prefixes;
  sender->size_skipped = size_skipped;
  sender->missing_args = missing_args;
}

static bool plan_is_allowed(const DeletePlanSender* sender, const char* dir) {
  if (sender->all_synced)
    return true;
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
  if (!send_wire_str(fd, node->dir))
    return -1;
  if (send_str_section(fd, node->dirs) != 0 || send_str_section(fd, node->files) != 0)
    return -1;
  node->sent = true;
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
  if (!plan_ensure(sender, "."))
    return -1;
  return send_prefix_plan(fd, sender, ".");
}

int delete_plan_send_for_path(int fd, DeletePlanSender* sender, const char* path, bool is_dir) {
  if (!sender || !path)
    return -1;
  char* clean = plan_clean_path(path);
  if (!clean)
    return -1;
  int rc = send_prefix_plan(fd, sender, ".");
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

/* ------------------------------------------------------------------ */
/* Receiver: delete session                                           */
/* ------------------------------------------------------------------ */

struct DeletePlanSession {
  bool defer;
  bool dry_run;
  size_t max_delete;
  size_t deleted;
  size_t skipped;
  bool limit_hit;
  bool config_seen;
  bool missing_applied;
  ArrayList* protected_prefixes;
  ArrayList* size_skipped;
  ArrayList* missing;
  ArrayList* deferred;
};

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

static bool read_section(int fd, ArrayList* list, bool rel_path) {
  int count;
  if (!receive_int(fd, &count) || count < 0 || count > MAX_MANIFEST_ENTRIES)
    return false;
  size_t bytes = 0;
  for (int i = 0; i < count; i++) {
    char* value = receive_wire_str(fd);
    bool ok = value && (rel_path ? valid_rel_path(value) : valid_name(value));
    if (ok) {
      size_t entry_size = strlen(value) + sizeof(char*) + 16;
      if (entry_size > MAX_MANIFEST_BYTES - bytes) {
        ok = false;
      } else {
        bytes += entry_size;
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
} PlanSkips;

static bool build_plan_skips(const Config* config, const DeletePlanSession* session,
                             PlanSkips* out) {
  out->entries = NULL;
  out->count = 0;
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
  return session->deleted < session->max_delete;
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

/* Append a snapshot path for --delete-delay. */
static bool defer_add(DeletePlanSession* session, const char* rel) {
  char* copy = str_dup(rel);
  if (!copy)
    return false;
  if (!array_list_add(session->deferred, copy)) {
    free(copy);
    return false;
  }
  session->deleted++;
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
  if (!budget_available(session)) {
    note_skipped(session);
    return true;
  }
  if (session->defer && !force_now) {
    if (!defer_add(session, child_rel))
      return false;
    *removed = true;
    return true;
  }
  if (unlinkat(dirfd, name, AT_REMOVEDIR) == 0) {
    session->deleted++;
    log_deleted(child_rel);
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
  if (!budget_available(session)) {
    note_skipped(session);
    return true;
  }
  if (session->defer && !force_now) {
    return defer_add(session, child_rel);
  }
  if (unlinkat(dirfd, name, 0) == 0) {
    session->deleted++;
    log_deleted(child_rel);
  } else if (errno != ENOENT) {
    return false;
  }
  return true;
}

static bool process_children(int dirfd, const char* dir_rel, const ArrayList* keep_dirs,
                             const ArrayList* keep_files, bool at_root, bool force_now,
                             const PlanSkips* skips, DeletePlanSession* session, bool* survives) {
  *survives = false;
  int scanfd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (scanfd < 0)
    return false;
  DIR* dir = fdopendir(scanfd);
  if (!dir) {
    close(scanfd);
    return false;
  }
  bool operation_ok = true;
  bool local_survives = false;
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    char* child_rel =
        (strcmp(dir_rel, ".") == 0) ? str_dup(entry->d_name) : path_cat(dir_rel, entry->d_name);
    if (!child_rel) {
      operation_ok = false;
      continue;
    }
    if (path_under_skip_prefix(child_rel, at_root, skips->entries, skips->count)) {
      local_survives = true;
      free(child_rel);
      continue;
    }
    struct stat st;
    if (fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno != ENOENT)
        operation_ok = false;
      free(child_rel);
      continue;
    }
    bool is_dir = S_ISDIR(st.st_mode);
    bool in_keep_dirs = is_dir && list_contains_str(keep_dirs, entry->d_name);
    bool in_keep_files = !is_dir && list_contains_str(keep_files, entry->d_name);
    if (in_keep_dirs) {
      local_survives = true;
    } else if (keep_dirs && !is_dir && list_contains_str(keep_dirs, entry->d_name)) {
      /* Destination file blocks a source directory: clear it now, whatever the
         delete timing, so the directory can be created. */
      if (!process_extra_file(dirfd, entry->d_name, child_rel, true, session))
        operation_ok = false;
    } else if (in_keep_files) {
      local_survives = true;
    } else if (keep_files && is_dir && list_contains_str(keep_files, entry->d_name)) {
      /* Destination directory blocks a source file: remove it now. */
      bool removed = false;
      if (!process_extra_dir(dirfd, entry->d_name, child_rel, true, skips, session, &removed))
        operation_ok = false;
      else if (!removed)
        local_survives = true;
    } else if (is_dir) {
      bool removed = false;
      if (!process_extra_dir(dirfd, entry->d_name, child_rel, force_now, skips, session, &removed))
        operation_ok = false;
      else if (!removed)
        local_survives = true;
    } else {
      if (!process_extra_file(dirfd, entry->d_name, child_rel, force_now, session))
        operation_ok = false;
    }
    free(child_rel);
  }
  closedir(dir);
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
  if (session->missing->size == 0)
    return true;
  DeleteManifest manifest = {
      .keeps = NULL, .protected = NULL, .missing = session->missing, .dirs = NULL};
  size_t remaining = budget_available(session) ? session->max_delete - session->deleted : 0;
  size_t deleted = 0;
  size_t skipped = 0;
  bool limit = false;
  bool ok = manifest_delete_missing_args_limited(config, &manifest, remaining, &deleted, &skipped,
                                                 &limit);
  session->deleted += deleted;
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
  if (has_config) {
    if (session->config_seen || !read_section(fd, session->protected_prefixes, true) ||
        !read_section(fd, session->size_skipped, true) ||
        !read_section(fd, session->missing, true)) {
      send_status(fd, STATUS_ERROR);
      return -1;
    }
    session->config_seen = true;
  }
  char* dir = receive_wire_str(fd);
  ArrayList* dirs = array_list_create(free);
  ArrayList* files = array_list_create(free);
  bool parsed = dir && (strcmp(dir, ".") == 0 || valid_rel_path(dir)) && dirs && files &&
                read_section(fd, dirs, false) && read_section(fd, files, false);
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
    if (ok && !apply_plan_dir(session, config, dir, dirs, files))
      ok = false;
  }
  free(dir);
  array_list_delete(dirs);
  array_list_delete(files);
  if (!ok) {
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  if (session->limit_hit)
    log_message(LOG_LEVEL_WARNING, "Deletions stopped due to the delete limit (%zu skipped)",
                session->skipped);
  return 0;
}

/* Apply one snapshotted --delete-delay path (post-order: children precede their
 * parent directory). */
static bool apply_deferred_path(DeletePlanSession* session, const Config* config, const char* rel) {
  (void)session;
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
    bool absent = errno == ENOENT;
    close(parent_fd);
    free(leaf);
    return absent;
  }
  int rc;
  if (S_ISDIR(st.st_mode))
    rc = unlinkat(parent_fd, leaf, AT_REMOVEDIR);
  else
    rc = unlinkat(parent_fd, leaf, 0);
  bool ok = rc == 0 || errno == ENOENT || errno == ENOTEMPTY || errno == EEXIST;
  if (rc == 0)
    log_deleted(rel);
  close(parent_fd);
  free(leaf);
  return ok;
}

DeleteCommitResult delete_plan_session_commit(DeletePlanSession* session, const Config* config) {
  if (!session || !config)
    return DELETE_COMMIT_ERROR;
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
