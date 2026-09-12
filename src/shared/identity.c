#include "identity.h"
#include "log.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The active identity snapshot lives in a per-process global.  The TCP server
 * forks one child process per connection, so a connection never shares this
 * with another; within a connection the multithreaded receiver reads it without
 * mutation.  This is what lets the fd-relative metadata path consult the
 * negotiated policy without threading a Config through every write helper. */
typedef struct {
  bool numeric_ids;
  bool chown_uid_set;
  int32_t chown_uid;
  bool chown_gid_set;
  int32_t chown_gid;
  IdentityMap* usermap;
  int usermap_count;
  IdentityMap* groupmap;
  int groupmap_count;
  /* --super / --no-super tri-state (SUPER_MODE_AUTO when unset).  Snapshotted
   * per connection so privilege_super_permitted() can gate super-user
   * activities without a Config argument. */
  int super_mode;
  /* --copy-as=USER[:GROUP]: snapshotted so the ownership resolver can force the
   * target ids without a Config argument. */
  bool copy_as_set;
  int32_t copy_as_uid;
  int32_t copy_as_gid;
  bool set;
} IdentityActive;

static IdentityActive g_identity;

static void identity_active_reset(void) {
  free(g_identity.usermap);
  free(g_identity.groupmap);
  g_identity.usermap = NULL;
  g_identity.groupmap = NULL;
  g_identity.usermap_count = 0;
  g_identity.groupmap_count = 0;
  g_identity.numeric_ids = false;
  g_identity.chown_uid_set = false;
  g_identity.chown_uid = 0;
  g_identity.chown_gid_set = false;
  g_identity.chown_gid = 0;
  g_identity.super_mode = SUPER_MODE_AUTO;
  g_identity.copy_as_set = false;
  g_identity.copy_as_uid = 0;
  g_identity.copy_as_gid = 0;
  g_identity.set = false;
}

void identity_clear_active(void) {
  identity_active_reset();
}

bool identity_set_active(const Config* config) {
  identity_active_reset();
  if (!config)
    return true;
  g_identity.numeric_ids = config->numeric_ids;
  g_identity.chown_uid_set = config->chown_uid_set;
  g_identity.chown_uid = config->chown_uid;
  g_identity.chown_gid_set = config->chown_gid_set;
  g_identity.chown_gid = config->chown_gid;
  g_identity.super_mode = config->super_mode;
  g_identity.copy_as_set = config->copy_as_set;
  g_identity.copy_as_uid = config->copy_as_uid;
  g_identity.copy_as_gid = config->copy_as_gid;
  if (config->usermap_count > 0) {
    g_identity.usermap = calloc((size_t)config->usermap_count, sizeof(IdentityMap));
    if (!g_identity.usermap)
      goto alloc_failed;
    memcpy(g_identity.usermap, config->usermap,
           (size_t)config->usermap_count * sizeof(IdentityMap));
    g_identity.usermap_count = config->usermap_count;
  }
  if (config->groupmap_count > 0) {
    g_identity.groupmap = calloc((size_t)config->groupmap_count, sizeof(IdentityMap));
    if (!g_identity.groupmap)
      goto alloc_failed;
    memcpy(g_identity.groupmap, config->groupmap,
           (size_t)config->groupmap_count * sizeof(IdentityMap));
    g_identity.groupmap_count = config->groupmap_count;
  }
  g_identity.set = true;
  /* A root receiver would honor any client-supplied ownership request (a
     --usermap/--groupmap/--chown/--copy-as, or raw ids under --numeric-ids).
     Surface that prominently; a privileged daemon applying arbitrary client
     ownership is a deliberate, opt-in choice the operator should be aware of. */
  if (geteuid() == 0)
    log_message(LOG_LEVEL_WARNING,
                "identity mapping active and running as root: client-supplied "
                "ownership (usermap/groupmap/chown/numeric-ids) will be honored; "
                "run the daemon as an unprivileged user unless intended");
  /* --super explicitly requests super-user activities, but FastSync never
     elevates privileges: when the receiver is not already root the kernel will
     refuse those confined attempts and each is skipped per entry.  Warn exactly
     once at activation time (never abort) so the operator knows the flag cannot
     succeed on this host. */
  if (g_identity.super_mode == SUPER_MODE_ON && geteuid() != 0)
    log_message(LOG_LEVEL_WARNING,
                "--super requested but the receiver is not privileged; super-user "
                "activities (ownership, device nodes) will be attempted but refused "
                "by the kernel and skipped per entry");
  return true;

alloc_failed:
  /* Never proceed with a partial (count-left-zero) map: that would silently
     apply the WRONG ownership policy.  Fail closed and let the caller refuse
     the connection. */
  log_message(LOG_LEVEL_ERROR, "memory allocation failed while activating identity policy");
  identity_active_reset();
  return false;
}

bool privilege_super_permitted(void) {
  return privilege_super_mode_permitted(g_identity.super_mode);
}

bool privilege_super_mode_permitted(int mode) {
  /* AUTO and ON both attempt the confined operation; OFF forbids it even for a
   * root receiver.  AUTO is the historical FastSync behavior (always attempt
   * and let the kernel refuse an unprivileged call, which the caller skips), so
   * it must stay permissive or a group-only chown that a non-root receiver is
   * allowed to make would regress. */
  return mode != SUPER_MODE_OFF;
}

bool identity_active_enabled(void) {
  /* numeric_ids is included: this set only gates identity_apply_ownership,
     which runs only when metadata is present (a -M/--preserve transfer).  A
     standalone --numeric-ids (no ownership-affecting flag) carries no
     metadata, never reaches identity_apply_ownership, and therefore correctly
     stays inert; combined with -M it activates raw-id application.  --super /
     --no-super does NOT enable ownership: it only permits or forbids the
     already-requested super-user activities, so a --super with no explicit
     identity flag must never silently apply client-chosen ownership. */
  return g_identity.set &&
         (g_identity.numeric_ids || g_identity.chown_uid_set || g_identity.chown_gid_set ||
          g_identity.usermap_count > 0 || g_identity.groupmap_count > 0 || g_identity.copy_as_set);
}

bool identity_ownership_requested(const Config* config) {
  if (!config)
    return false;
  /* Every value that makes the receiver act on a client-chosen owner, plus an
   * explicit --super (super-user device-node activities).  Pure config, so the
   * daemon gate can evaluate it before identity_set_active(). */
  return config->numeric_ids || config->chown_uid_set || config->chown_gid_set ||
         config->usermap_count > 0 || config->groupmap_count > 0 || config->copy_as_set ||
         config->fake_super || config->super_mode == SUPER_MODE_ON;
}

bool identity_copy_as_active(void) {
  return g_identity.set && g_identity.copy_as_set;
}

bool identity_copy_as_refused(const Config* config) {
  if (!config || !config->copy_as_set)
    return false;
  /* The safe-subset --copy-as needs a privileged (root) receiver, and an
   * operator/--no-super veto forbids the ownership change even for root.  This
   * is deliberately a pure function of the config and the current effective uid
   * (never the active snapshot) because the server evaluates it at the
   * pre-STATUS_OK config gate, before identity_set_active() has run. */
  return geteuid() != 0 || config->super_mode == SUPER_MODE_OFF;
}

bool identity_wire_valid(const Config* config) {
  if (!config)
    return false;
  if (config->usermap_count < 0 || config->usermap_count > MAX_IDENTITY_MAP ||
      config->groupmap_count < 0 || config->groupmap_count > MAX_IDENTITY_MAP)
    return false;
  if (config->chown_uid_set && config->chown_uid < IDENTITY_MATCH_ANY)
    return false;
  if (config->chown_gid_set && config->chown_gid < IDENTITY_MATCH_ANY)
    return false;
  for (int i = 0; i < config->usermap_count; i++) {
    if (config->usermap[i].from < IDENTITY_MATCH_ANY || config->usermap[i].to < IDENTITY_CURRENT)
      return false;
  }
  for (int i = 0; i < config->groupmap_count; i++) {
    if (config->groupmap[i].from < IDENTITY_MATCH_ANY || config->groupmap[i].to < IDENTITY_CURRENT)
      return false;
  }
  /* Defense-in-depth: a --copy-as block must never carry a negative (sentinel)
   * id into the ownership path.  receive_copy_as_options already rejects them,
   * but identity_wire_valid is the shared validation used by both the receiver
   * and unit tests, so re-assert it here. */
  if (config->copy_as_set && (config->copy_as_uid < 0 || config->copy_as_gid < 0))
    return false;
  return true;
}

/* ---- CLI-time name/number resolution ---- */

/* Parse a single FROM/TO token into an int32 id.  Returns 0 on success, -1 on a
 * malformed or unresolvable token.  When is_group, name lookups use the group
 * database; otherwise the user database.  A `*` token returns IDENTITY_MATCH_ANY
 * / IDENTITY_CURRENT (the same -1 value, disambiguated by the caller's
 * position).  An `@`-prefixed or bare-decimal token is a numeric id. */
static int identity_resolve_token(const char* token, bool is_group, int32_t* out) {
  if (!token || *token == '\0')
    return -1;
  if (strcmp(token, "*") == 0) {
    *out = IDENTITY_MATCH_ANY;
    return 0;
  }
  const char* num = (token[0] == '@') ? token + 1 : token;
  if (*num != '\0') {
    bool all_digits = true;
    for (const char* p = num; *p; p++)
      if (*p < '0' || *p > '9')
        all_digits = false;
    if (all_digits) {
      char* endptr = NULL;
      errno = 0;
      long val = strtol(num, &endptr, 10);
      if (errno == 0 && endptr && *endptr == '\0' && val >= 0 && val <= INT32_MAX) {
        *out = (int32_t)val;
        return 0;
      }
      return -1;
    }
  }
  /* A name (or a name-like numeric that failed strict numeric parse). */
  if (is_group) {
    struct group* gr = getgrnam(token);
    if (!gr)
      return -1;
    *out = (int32_t)gr->gr_gid;
    return 0;
  }
  struct passwd* pw = getpwnam(token);
  if (!pw)
    return -1;
  *out = (int32_t)pw->pw_uid;
  return 0;
}

static int identity_append_rule(IdentityMap** map, int* count, int32_t from, int32_t to) {
  if (*count >= MAX_IDENTITY_MAP)
    return -1;
  IdentityMap* grown = realloc(*map, (size_t)(*count + 1) * sizeof(IdentityMap));
  if (!grown)
    return -1;
  *map = grown;
  (*map)[*count].from = from;
  (*map)[*count].to = to;
  (*count)++;
  return 0;
}

int identity_parse_map(Config* config, const char* value, bool is_group) {
  if (!config || !value || *value == '\0') {
    log_message(LOG_LEVEL_ERROR, "%smap requires a value", is_group ? "--group" : "--user");
    return -1;
  }
  char* list = str_dup(value);
  if (!list)
    return -1;
  const char* optname = is_group ? "--groupmap" : "--usermap";
  char* saveptr = NULL;
  for (char* rule = strtok_r(list, ",", &saveptr); rule; rule = strtok_r(NULL, ",", &saveptr)) {
    char* colon = strchr(rule, ':');
    if (!colon || colon == rule) {
      /* Log before freeing: `rule` points into the str_dup'd list. */
      log_message(LOG_LEVEL_ERROR, "%s rules must be FROM:TO (got '%s')", optname, rule);
      free(list);
      return -1;
    }
    *colon = '\0';
    char* from_token = rule;
    char* to_token = colon + 1;
    if (*to_token == '\0') {
      free(list);
      log_message(LOG_LEVEL_ERROR, "%s rule 'FROM:' is missing the TO value (got '%s')", optname,
                  value);
      return -1;
    }
    int32_t from_id, to_id;
    if (identity_resolve_token(from_token, is_group, &from_id) != 0 ||
        identity_resolve_token(to_token, is_group, &to_id) != 0) {
      free(list);
      log_message(LOG_LEVEL_ERROR,
                  "%s could not resolve '%s' (name must exist on the source; use "
                  "@N for a numeric id)",
                  optname, value);
      return -1;
    }
    if (identity_append_rule(is_group ? &config->groupmap : &config->usermap,
                             is_group ? &config->groupmap_count : &config->usermap_count, from_id,
                             to_id) != 0) {
      free(list);
      log_message(LOG_LEVEL_ERROR, "%s has too many rules (max %d)", optname, MAX_IDENTITY_MAP);
      return -1;
    }
  }
  free(list);
  return 0;
}

/* Split --chown=USER:GROUP on the first UNESCAPED colon, honoring backslash
 * escapes (a `\:` is a literal colon inside a name; a lone backslash before any
 * other character is kept verbatim).  Both sides are returned as malloc'd
 * strings (the absent side is NULL). */
static int identity_split_chown(const char* value, char** puser, char** pgroup) {
  size_t len = strlen(value);
  char* user = malloc(len + 1);
  char* group = malloc(len + 1);
  if (!user || !group) {
    free(user);
    free(group);
    return -1;
  }
  const char* p = value;
  size_t ui = 0;
  bool split_seen = false;
  size_t gi = 0;
  while (*p) {
    if (*p == '\\' && p[1] == ':') {
      /* an escaped colon: a literal ':' in the current side's name */
      if (split_seen)
        group[gi++] = ':';
      else
        user[ui++] = ':';
      p += 2;
      continue;
    }
    if (*p == ':') {
      split_seen = true;
      p++;
      continue;
    }
    if (split_seen)
      group[gi++] = *p;
    else
      user[ui++] = *p;
    p++;
  }
  user[ui] = '\0';
  group[gi] = '\0';
  char* u = str_dup(user);
  char* g = str_dup(group);
  free(user);
  free(group);
  if (!u || !g) {
    free(u);
    free(g);
    return -1;
  }
  *puser = u;
  *pgroup = g;
  return 0;
}

int identity_parse_chown(Config* config, const char* value) {
  if (!config || !value || *value == '\0') {
    log_message(LOG_LEVEL_ERROR, "--chown requires a value (USER:GROUP, USER, or :GROUP)");
    return -1;
  }
  /* Reject more than one UNESCAPED colon (a name or group may not contain an
   * unescaped ':' in the spec).  The scan is escape-aware: a `\:` is a literal
   * colon inside a name, not a field separator. */
  int colons = 0;
  bool saw_colon = false;
  const char* p = value;
  while (*p) {
    if (*p == '\\' && p[1] == ':') {
      p += 2;
      continue;
    }
    if (*p == ':') {
      colons++;
      saw_colon = true;
    }
    p++;
  }
  if (colons > 1) {
    log_message(LOG_LEVEL_ERROR, "--chown must have at most one ':' (got '%s')", value);
    return -1;
  }

  char *user = NULL, *group = NULL;
  if (identity_split_chown(value, &user, &group) != 0) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for --chown");
    return -1;
  }
  int ret = 0;
  if (!saw_colon) {
    /* --chown=USER: owner only. */
    if (*user == '\0') {
      log_message(LOG_LEVEL_ERROR, "--chown requires a user or group (got '%s')", value);
      ret = -1;
    } else if (identity_resolve_token(user, false, &config->chown_uid) != 0) {
      log_message(LOG_LEVEL_ERROR,
                  "--chown could not resolve user '%s' (use a name that exists "
                  "on the source, '*', or @N)",
                  value);
      ret = -1;
    } else {
      config->chown_uid_set = true;
    }
  } else {
    /* --chown=USER:GROUP, --chown=:GROUP, --chown=USER: */
    if (*user != '\0') {
      if (identity_resolve_token(user, false, &config->chown_uid) != 0) {
        log_message(LOG_LEVEL_ERROR, "--chown could not resolve user '%s'", value);
        ret = -1;
        goto done;
      }
      config->chown_uid_set = true;
    }
    if (*group != '\0') {
      if (identity_resolve_token(group, true, &config->chown_gid) != 0) {
        log_message(LOG_LEVEL_ERROR, "--chown could not resolve group '%s'", value);
        ret = -1;
        goto done;
      }
      config->chown_gid_set = true;
    }
    if (!*user && !*group) {
      log_message(LOG_LEVEL_ERROR, "--chown must set a user, a group, or both (got '%s')", value);
      ret = -1;
    }
  }
done:
  free(user);
  free(group);
  return ret;
}

/* uid_t/gid_t are unsigned and may hold a value wider than the signed int32 the
 * wire (and the identity policy) uses.  Reject such an id instead of truncating
 * it to an out-of-range (possibly negative sentinel) value. */
static bool identity_id_fits_int32(unsigned long id) {
  return id <= (unsigned long)INT32_MAX;
}

/* Resolve one --copy-as id token.  A '*' token means the caller's current
 * effective uid (user) or gid (group).  Returns 0 on success.  On failure sets
 * *overflow when a '*' id was wider than int32 so the caller can log the
 * specific message; otherwise the token was simply unresolvable. */
static int identity_resolve_copy_as_id(const char* token, bool is_group, int32_t* out,
                                       bool* overflow) {
  *overflow = false;
  if (strcmp(token, "*") == 0) {
    unsigned long current = is_group ? (unsigned long)getegid() : (unsigned long)geteuid();
    if (!identity_id_fits_int32(current)) {
      *overflow = true;
      return -1;
    }
    *out = (int32_t)current;
    return 0;
  }
  return identity_resolve_token(token, is_group, out);
}

int identity_parse_copy_as(Config* config, const char* value) {
  if (!config || !value || *value == '\0') {
    log_message(LOG_LEVEL_ERROR, "--copy-as requires USER[:GROUP]");
    return -1;
  }
  /* --copy-as=USER[:GROUP] is the whole grammar: at most one field separator.
   * (Unlike --chown there is no escaped-colon form; a name containing ':' is
   * simply not expressible, and the extra colon is a clear parse error.) */
  int colons = 0;
  for (const char* p = value; *p; p++)
    if (*p == ':')
      colons++;
  if (colons > 1) {
    char* escaped = output_escape(value, false);
    log_message(LOG_LEVEL_ERROR, "--copy-as must be USER[:GROUP] (got '%s')",
                escaped ? escaped : "<allocation failed>");
    free(escaped);
    return -1;
  }

  char* spec = str_dup(value);
  if (!spec) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed for --copy-as");
    return -1;
  }
  const char* user_token = spec;
  const char* group_token = NULL;
  char* colon = strchr(spec, ':');
  if (colon) {
    *colon = '\0';
    group_token = colon + 1;
  }

  /* The spec is untrusted user input echoed back in error paths: escape it once
   * (8-bit-safe) so a control byte cannot forge a log line. */
  char* escaped_spec = output_escape(value, false);
  const char* shown = escaped_spec ? escaped_spec : "<allocation failed>";
  int ret = -1;

  if (*user_token == '\0') {
    log_message(LOG_LEVEL_ERROR, "--copy-as is missing the user (got '%s')", shown);
    goto done;
  }
  bool overflow = false;
  int32_t uid;
  if (identity_resolve_copy_as_id(user_token, false, &uid, &overflow) != 0) {
    if (overflow)
      log_message(LOG_LEVEL_ERROR, "--copy-as: current user id %lu exceeds INT32_MAX",
                  (unsigned long)geteuid());
    else
      log_message(LOG_LEVEL_ERROR,
                  "--copy-as could not resolve user (use a name that exists on the "
                  "source, '*', or @N): %s",
                  shown);
    goto done;
  }

  int32_t gid;
  if (group_token) {
    if (*group_token == '\0') {
      log_message(LOG_LEVEL_ERROR, "--copy-as group is empty (got '%s')", shown);
      goto done;
    }
    if (identity_resolve_copy_as_id(group_token, true, &gid, &overflow) != 0) {
      if (overflow)
        log_message(LOG_LEVEL_ERROR, "--copy-as: current group id %lu exceeds INT32_MAX",
                    (unsigned long)getegid());
      else
        log_message(LOG_LEVEL_ERROR, "--copy-as could not resolve group (got '%s')", shown);
      goto done;
    }
  } else {
    /* Group omitted: use the user's primary gid.  A numeric id with no local
     * passwd entry has no primary gid to look up, so fall back to gid == uid
     * (the rsync-style numeric convention; documented divergence). */
    struct passwd* pw = getpwuid((uid_t)uid);
    if (pw) {
      if (!identity_id_fits_int32((unsigned long)pw->pw_gid)) {
        log_message(LOG_LEVEL_ERROR,
                    "--copy-as: primary group id %lu for the requested user exceeds INT32_MAX",
                    (unsigned long)pw->pw_gid);
        goto done;
      }
      gid = (int32_t)pw->pw_gid;
    } else {
      gid = uid;
    }
  }
  /* The group-default and gid==uid fallbacks must never store a negative
   * (sentinel) value; the explicit numeric path is already capped by
   * identity_resolve_token. */
  if (uid < 0 || gid < 0) {
    log_message(LOG_LEVEL_ERROR, "--copy-as resolved id does not fit in int32 (got '%s')", shown);
    goto done;
  }

  config->copy_as_set = true;
  config->copy_as_uid = uid;
  config->copy_as_gid = gid;
  /* Ownership application needs the metadata path (the source uid/gid must be
   * transmitted); imply it exactly like --chown/--usermap/--groupmap. */
  config->use_metadata = true;
  ret = 0;

done:
  free(escaped_spec);
  free(spec);
  return ret;
}

/* ---- Receiver-side ownership application ---- */

static bool identity_map_lookup(const IdentityMap* map, int count, int32_t source_id,
                                int32_t* out_to) {
  for (int i = 0; i < count; i++) {
    if (map[i].from == IDENTITY_MATCH_ANY || map[i].from == source_id) {
      *out_to = map[i].to;
      return true;
    }
  }
  return false;
}

/* Resolve the target ownership from the negotiated policy against the entry's
 * current stat.  Shared by the fd (regular file) and no-follow (symlink) apply
 * paths.  Returns false when no side is to be changed. */
static bool identity_resolve_targets(const struct stat* st, int32_t source_uid, int32_t source_gid,
                                     uid_t* out_uid, gid_t* out_gid) {
  bool set_uid = false;
  bool set_gid = false;
  uid_t uid = 0;
  gid_t gid = 0;

  /* --copy-as (P7 Wave E) has the highest priority: it forces BOTH the owner
   * and group of every written entry to the requested ids, beating usermap /
   * groupmap / --chown / --numeric-ids and the best-effort name lookup.  Only
   * skip when the entry already carries exactly those ids. */
  if (g_identity.copy_as_set) {
    uid = (uid_t)g_identity.copy_as_uid;
    gid = (gid_t)g_identity.copy_as_gid;
    if (st->st_uid == uid && st->st_gid == gid)
      return false;
    *out_uid = uid;
    *out_gid = gid;
    return true;
  }

  int32_t target;
  if (identity_map_lookup(g_identity.usermap, g_identity.usermap_count, source_uid, &target)) {
    uid = target == IDENTITY_CURRENT ? geteuid() : (uid_t)target;
    set_uid = true;
  } else if (g_identity.chown_uid_set) {
    uid = g_identity.chown_uid == IDENTITY_CURRENT ? geteuid() : (uid_t)g_identity.chown_uid;
    set_uid = true;
  } else if (g_identity.numeric_ids) {
    uid = (uid_t)source_uid;
    set_uid = true;
  } else {
    /* Best-effort name mapping against the receiver's own database: if the
     * transmitted (numeric) id resolves to a name present on this machine,
     * re-resolve it.  On a shared-account host this is the identity operation;
     * when the id has no name here, the user side is left alone. */
    struct passwd* pw = getpwuid((uid_t)source_uid);
    if (pw) {
      const struct passwd* mapped = getpwnam(pw->pw_name);
      if (mapped) {
        uid = mapped->pw_uid;
        set_uid = true;
      }
    }
  }

  if (identity_map_lookup(g_identity.groupmap, g_identity.groupmap_count, source_gid, &target)) {
    gid = target == IDENTITY_CURRENT ? getegid() : (gid_t)target;
    set_gid = true;
  } else if (g_identity.chown_gid_set) {
    gid = g_identity.chown_gid == IDENTITY_CURRENT ? getegid() : (gid_t)g_identity.chown_gid;
    set_gid = true;
  } else if (g_identity.numeric_ids) {
    gid = (gid_t)source_gid;
    set_gid = true;
  } else {
    struct group* gr = getgrgid((gid_t)source_gid);
    if (gr) {
      const struct group* mapped = getgrnam(gr->gr_name);
      if (mapped) {
        gid = mapped->gr_gid;
        set_gid = true;
      }
    }
  }

  if (!set_uid && !set_gid)
    return false;
  /* An unset side keeps the file's current id so the other side can change. */
  if (!set_uid)
    uid = st->st_uid;
  if (!set_gid)
    gid = st->st_gid;
  /* Only change ownership when the target differs (avoid needless syscalls and
   * any chance of clearing setuid/setgid on an already-correct entry). */
  if (st->st_uid == uid && st->st_gid == gid)
    return false;
  *out_uid = uid;
  *out_gid = gid;
  return true;
}

static void identity_log_chown_failure(const char* what, uid_t uid, gid_t gid) {
  /* EPERM/EACCES are expected when the receiver is not privileged (e.g. the CI
   * `nobody` user): warn and continue, never abort the transfer.  Any other
   * error (EIO/EROFS/ENOSPC/...) is a real failure and must not be silently
   * downgraded to a warning.
   *
   * --copy-as is different: the whole point of the flag is that the target
   * ownership is REQUIRED (the pre-flight gate already refused an unprivileged
   * receiver).  If the chown still fails with EPERM/EACCES (a capability-
   * restricted root, root-squash, or a read-only mount) the run would be
   * silently producing the WRONG ownership, so surface it at ERROR.  The
   * caller (identity_apply_ownership*) then reports the ENTRY as failed rather
   * than as written, which becomes a FILE_SAVE_ERROR and fails the transfer
   * (fail-fast) instead of reporting overall success with the wrong owner. */
  if (errno == EPERM || errno == EACCES) {
    if (identity_copy_as_active())
      log_message(LOG_LEVEL_ERROR,
                  "could not apply --copy-as ownership on %s (uid=%ld gid=%ld): %s; "
                  "entry was written with the wrong owner",
                  what, (long)uid, (long)gid, strerror(errno));
    else
      log_message(LOG_LEVEL_WARNING,
                  "could not apply ownership (uid=%ld gid=%ld): %s; leaving as-is", (long)uid,
                  (long)gid, strerror(errno));
  } else {
    log_message(LOG_LEVEL_ERROR, "failed to apply ownership on %s (uid=%ld gid=%ld): %s", what,
                (long)uid, (long)gid, strerror(errno));
  }
}

bool identity_apply_ownership(int fd, int32_t source_uid, int32_t source_gid) {
  /* Ownership application is OFF unless the client requested an identity flag.
   * This is the controlled gate: a default (or plain -M) transfer never changes
   * ownership, byte-for-byte preserving FastSync's existing behavior.  --no-super
   * additionally forbids it even when the receiver is root. */
  if (!identity_active_enabled() || !privilege_super_permitted() || fd < 0)
    return true;
  struct stat st;
  if (fstat(fd, &st) != 0)
    return !identity_copy_as_active();
  uid_t uid;
  gid_t gid;
  if (!identity_resolve_targets(&st, source_uid, source_gid, &uid, &gid))
    return true;
  if (fchown(fd, uid, gid) != 0) {
    identity_log_chown_failure("file", uid, gid);
    /* A required --copy-as ownership that did not land is a per-entry failure;
     * every other policy stays best-effort (rsync parity). */
    return !identity_copy_as_active();
  }
  return true;
}

bool identity_apply_ownership_link(int parent_fd, const char* leaf, int32_t source_uid,
                                   int32_t source_gid) {
  if (!identity_active_enabled() || !privilege_super_permitted() || parent_fd < 0 || !leaf)
    return true;
  struct stat st;
  if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0)
    return !identity_copy_as_active();
  uid_t uid;
  gid_t gid;
  if (!identity_resolve_targets(&st, source_uid, source_gid, &uid, &gid))
    return true;
  if (fchownat(parent_fd, leaf, uid, gid, AT_SYMLINK_NOFOLLOW) != 0) {
    identity_log_chown_failure("no-follow entry", uid, gid);
    return !identity_copy_as_active();
  }
  return true;
}
