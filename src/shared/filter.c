#include "filter.h"
#include "log.h"
#include "utils.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Write a diagnostic message into the caller's optional buffer.  A NULL `err`
 * (or a zero size) is a no-op, so a caller that only needs the boolean status
 * may pass NULL without the snprintf-on-NULL undefined behaviour. */
static void filter_set_error(char* err, size_t err_size, const char* fmt, ...) {
  if (!err || err_size == 0)
    return;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(err, err_size, fmt, ap);
  va_end(ap);
}

/* ---- Ordered rule lists ---- */

void filter_rule_free(FilterRule* rule) {
  if (!rule)
    return;
  free(rule->pattern);
  free(rule->owner);
  free(rule);
}

FilterRuleList* filter_rule_list_create(void) {
  return calloc(1, sizeof(FilterRuleList));
}

bool filter_rule_list_add(FilterRuleList* list, FilterRule* rule) {
  if (!list || !rule)
    return false;
  if (list->count == list->capacity) {
    if (list->capacity > INT_MAX / 2)
      return false;
    int new_cap = list->capacity > 0 ? list->capacity * 2 : 8;
    FilterRule** grown = realloc(list->items, (size_t)new_cap * sizeof(FilterRule*));
    if (!grown)
      return false;
    list->items = grown;
    list->capacity = new_cap;
  }
  list->items[list->count++] = rule;
  return true;
}

void filter_rule_list_free(FilterRuleList* list) {
  if (!list)
    return;
  for (int i = 0; i < list->count; i++)
    filter_rule_free(list->items[i]);
  for (int i = 0; i < list->dir_merge_count; i++)
    free(list->dir_merge_names[i]);
  free(list->dir_merge_names);
  free(list->items);
  free(list);
}

/* Register a per-directory merge-file basename (for "dir-merge NAME"/": NAME"
 * and -F's .rsync-filter).  Duplicate names are ignored. */
bool filter_rule_list_add_dir_merge(FilterRuleList* list, const char* name) {
  if (!list || !name || name[0] == '\0')
    return false;
  for (int i = 0; i < list->dir_merge_count; i++) {
    if (strcmp(list->dir_merge_names[i], name) == 0)
      return true;
  }
  if (list->dir_merge_count == list->dir_merge_capacity) {
    int new_cap = list->dir_merge_capacity > 0 ? list->dir_merge_capacity * 2 : 4;
    char** grown = realloc(list->dir_merge_names, (size_t)new_cap * sizeof(char*));
    if (!grown)
      return false;
    list->dir_merge_names = grown;
    list->dir_merge_capacity = new_cap;
  }
  char* dup = str_dup(name);
  if (!dup)
    return false;
  list->dir_merge_names[list->dir_merge_count++] = dup;
  return true;
}

static bool set_rule_owner(FilterRule* rule, const char* owner) {
  char* dup = str_dup(owner ? owner : "");
  if (!dup)
    return false;
  free(rule->owner);
  rule->owner = dup;
  return true;
}

/* ---- Rule parsing ---- */

/* A short rule prefix is a single character; a long rule name is alphabetic
 * (with '-').  `is_short` distinguishes the modifier-attachment rules. */
typedef enum {
  RULE_KIND_EXCLUDE,
  RULE_KIND_INCLUDE,
  RULE_KIND_HIDE,
  RULE_KIND_SHOW,
  RULE_KIND_PROTECT,
  RULE_KIND_RISK,
  RULE_KIND_MERGE,
  RULE_KIND_DIR_MERGE,
  RULE_KIND_CLEAR,
  RULE_KIND_UNKNOWN,
} RuleKind;

static bool short_rule_char(char c, RuleKind* kind) {
  switch (c) {
  case '-':
    *kind = RULE_KIND_EXCLUDE;
    return true;
  case '+':
    *kind = RULE_KIND_INCLUDE;
    return true;
  case 'H':
    *kind = RULE_KIND_HIDE;
    return true;
  case 'S':
    *kind = RULE_KIND_SHOW;
    return true;
  case 'P':
    *kind = RULE_KIND_PROTECT;
    return true;
  case 'R':
    *kind = RULE_KIND_RISK;
    return true;
  case '.':
    *kind = RULE_KIND_MERGE;
    return true;
  case ':':
    *kind = RULE_KIND_DIR_MERGE;
    return true;
  case '!':
    *kind = RULE_KIND_CLEAR;
    return true;
  default:
    return false;
  }
}

static bool long_rule_name(const char* name, size_t len, RuleKind* kind) {
  struct {
    const char* word;
    RuleKind kind;
  } table[] = {
      {"exclude", RULE_KIND_EXCLUDE}, {"include", RULE_KIND_INCLUDE},
      {"hide", RULE_KIND_HIDE},       {"show", RULE_KIND_SHOW},
      {"protect", RULE_KIND_PROTECT}, {"risk", RULE_KIND_RISK},
      {"merge", RULE_KIND_MERGE},     {"dir-merge", RULE_KIND_DIR_MERGE},
      {"clear", RULE_KIND_CLEAR},
  };
  for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
    if (strlen(table[i].word) == len && strncmp(name, table[i].word, len) == 0) {
      *kind = table[i].kind;
      return true;
    }
  }
  return false;
}

static bool is_modifier_char(char c) {
  return c == 's' || c == 'r' || c == 'p' || c == 'x' || c == '/' || c == '!' || c == 'C';
}

/* Parse "RULE[,MODIFIERS] [PATTERN]".  On success `kind`, `sides`,
 * `sides_explicit`, `negate`, `anchored_mod`, `perishable`, `xattr`,
 * `cvs_inject` and the pattern span (`pat_start`/`pat_len`, possibly 0 for
 * merge/clear) are filled.  Returns true on success. */
static bool parse_rule_syntax(const char* text, RuleKind* kind, unsigned* sides,
                              bool* sides_explicit, bool* negate, bool* anchored_mod,
                              bool* perishable, bool* xattr, bool* cvs_inject,
                              const char** pat_start, size_t* pat_len) {
  const char* p = text;
  *sides = FILTER_SIDE_SENDER | FILTER_SIDE_RECEIVER;
  *sides_explicit = false;
  *negate = false;
  *anchored_mod = false;
  *perishable = false;
  *xattr = false;
  *cvs_inject = false;
  *pat_start = NULL;
  *pat_len = 0;

  bool is_short = false;
  if (short_rule_char(*p, kind)) {
    is_short = true;
    p++;
  } else {
    const char* name_start = p;
    while (isalpha((unsigned char)*p) || *p == '-')
      p++;
    size_t name_len = (size_t)(p - name_start);
    if (name_len == 0 || !long_rule_name(name_start, name_len, kind))
      return false;
    /* A long name must be followed by a separator, a comma or the end. */
    if (*p != '\0' && *p != ',' && *p != ' ' && *p != '_')
      return false;
  }

  /* Modifiers: long names require a comma; short names may attach directly.
     Only commit a modifier run that terminates at a separator or the end, so a
     pattern such as "*.tmp" written as "-*.tmp" is not mistaken for modifiers. */
  const char* mod_start = p;
  const char* mod_end = p;
  if (*p == ',') {
    p++;
    mod_start = p;
    while (is_modifier_char(*p))
      p++;
    mod_end = p;
  } else if (is_short) {
    const char* scan = p;
    while (is_modifier_char(*scan))
      scan++;
    if (*scan == '\0' || *scan == ' ' || *scan == '_') {
      mod_start = p;
      mod_end = scan;
      p = scan;
    }
  }
  for (const char* m = mod_start; m < mod_end; m++) {
    switch (*m) {
    case 's':
      *sides = FILTER_SIDE_SENDER;
      *sides_explicit = true;
      break;
    case 'r':
      *sides = FILTER_SIDE_RECEIVER;
      *sides_explicit = true;
      break;
    case '!':
      *negate = true;
      break;
    case '/':
      *anchored_mod = true;
      break;
    case 'p':
      *perishable = true;
      break;
    case 'x':
      *xattr = true;
      break;
    case 'C':
      *cvs_inject = true;
      break;
    default:
      break;
    }
  }

  /* A single space or underscore separates the rule/modifiers from the
     pattern; further spaces/underscores belong to the pattern. */
  const char* pat = p;
  if (*pat == ' ' || *pat == '_')
    pat++;
  /* Trim a trailing newline/CR (the caller may pass a raw file line). */
  *pat_start = pat;
  *pat_len = strlen(pat);
  while (*pat_len > 0 && (pat[*pat_len - 1] == '\n' || pat[*pat_len - 1] == '\r'))
    (*pat_len)--;
  return true;
}

FilterRule* filter_rule_parse(const char* line, const FilterParseOptions* opts, char* err,
                              size_t err_size) {
  if (err && err_size > 0)
    err[0] = '\0';
  if (!line)
    return NULL;
  const char* p = line;
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p == '\0' || *p == '\n' || *p == '\r') {
    filter_set_error(err, err_size, "empty filter rule");
    return NULL;
  }

  RuleKind kind = RULE_KIND_UNKNOWN;
  unsigned sides;
  bool sides_explicit, negate, anchored_mod, perishable, xattr, cvs_inject;
  const char* pat;
  size_t pat_len;
  if (!parse_rule_syntax(p, &kind, &sides, &sides_explicit, &negate, &anchored_mod, &perishable,
                         &xattr, &cvs_inject, &pat, &pat_len)) {
    filter_set_error(err, err_size, "unrecognized filter rule syntax");
    return NULL;
  }
  if (cvs_inject) {
    /* The C modifier expands to the CVS defaults in place; the rule itself
       carries no pattern and is handled by the caller. */
    filter_set_error(err, err_size, "the C modifier is handled by the rule-list parser");
    return NULL;
  }
  if (xattr) {
    filter_set_error(err, err_size, "xattr-name filter rules (the x modifier) are not supported");
    return NULL;
  }
  if (kind == RULE_KIND_MERGE || kind == RULE_KIND_DIR_MERGE) {
    filter_set_error(err, err_size, "merge/dir-merge rules are handled by the rule-list parser");
    return NULL;
  }
  if (kind == RULE_KIND_CLEAR) {
    if (pat_len != 0) {
      filter_set_error(err, err_size, "clear takes no pattern");
      return NULL;
    }
    FilterRule* rule = calloc(1, sizeof(FilterRule));
    if (!rule) {
      filter_set_error(err, err_size, "memory allocation failed");
      return NULL;
    }
    rule->action = FILTER_ACTION_NONE; /* clear marker: no pattern */
    rule->sides = 0;
    return rule;
  }

  FilterAction action;
  switch (kind) {
  case RULE_KIND_INCLUDE:
  case RULE_KIND_SHOW:
  case RULE_KIND_RISK:
    action = FILTER_ACTION_INCLUDE;
    break;
  default:
    action = FILTER_ACTION_EXCLUDE;
    break;
  }
  if (kind == RULE_KIND_HIDE)
    sides = FILTER_SIDE_SENDER;
  else if (kind == RULE_KIND_SHOW)
    sides = FILTER_SIDE_SENDER;
  else if (kind == RULE_KIND_PROTECT)
    sides = FILTER_SIDE_RECEIVER;
  else if (kind == RULE_KIND_RISK)
    sides = FILTER_SIDE_RECEIVER;
  if (kind == RULE_KIND_HIDE || kind == RULE_KIND_SHOW || kind == RULE_KIND_PROTECT ||
      kind == RULE_KIND_RISK)
    sides_explicit = true;
  /* --delete-excluded turns an unqualified (no explicit s/r) rule into a
     sender-side-only rule, so it no longer protects the receiver. */
  if (opts && opts->delete_excluded && !sides_explicit)
    sides = FILTER_SIDE_SENDER;

  if (pat_len == 0) {
    filter_set_error(err, err_size, "filter rule has no pattern");
    return NULL;
  }

  bool anchored = anchored_mod;
  const char* pat_begin = pat;
  if (*pat_begin == '/') {
    anchored = true;
    pat_begin++;
    /* Drop the spaces that could follow the anchor in the "-/ foo" form. */
    while (*pat_begin == ' ' || *pat_begin == '\t')
      pat_begin++;
    pat_len = strlen(pat_begin);
    while (pat_len > 0 && (pat_begin[pat_len - 1] == '\n' || pat_begin[pat_len - 1] == '\r'))
      pat_len--;
  }
  if (pat_len == 0) {
    filter_set_error(err, err_size, "filter rule has no pattern after '/' anchor");
    return NULL;
  }
  bool dir_only = false;
  if (pat_len > 1 && pat_begin[pat_len - 1] == '/') {
    dir_only = true;
    pat_len--;
  }
  if (pat_len == 0) {
    filter_set_error(err, err_size, "filter rule has no pattern");
    return NULL;
  }

  FilterRule* rule = calloc(1, sizeof(FilterRule));
  if (!rule) {
    filter_set_error(err, err_size, "memory allocation failed");
    return NULL;
  }
  rule->pattern = malloc(pat_len + 1);
  if (!rule->pattern) {
    free(rule);
    filter_set_error(err, err_size, "memory allocation failed");
    return NULL;
  }
  memcpy(rule->pattern, pat_begin, pat_len);
  rule->pattern[pat_len] = '\0';
  rule->action = action;
  rule->sides = sides;
  rule->anchored = anchored;
  rule->dir_only = dir_only;
  rule->negate = negate;
  rule->perishable = perishable;
  (void)xattr; /* xattr-name rules never match file/dir names; accepted/ignored */
  return rule;
}

/* ---- CVS default excludes (-C and the C modifier) ---- */

typedef struct {
  const char* pattern;
  bool dir_only;
} CvsDefaultRule;

static const CvsDefaultRule CVS_DEFAULTS[] = {
    {"RCS", false},         {"SCCS", false},         {"CVS", false},   {"CVS.adm", false},
    {"RCSLOG", false},      {"cvslog.*", false},     {"tags", false},  {"TAGS", false},
    {".make.state", false}, {".nse_depinfo", false}, {"*~", false},    {"#*", false},
    {".#*", false},         {",*", false},           {"_$*", false},   {"*$", false},
    {"*.old", false},       {"*.bak", false},        {"*.BAK", false}, {"*.orig", false},
    {"*.rej", false},       {".del-*", false},       {"*.a", false},   {"*.olb", false},
    {"*.o", false},         {"*.obj", false},        {"*.so", false},  {"*.exe", false},
    {"*.Z", false},         {"*.elc", false},        {"*.ln", false},  {"core", false},
    {".svn/", true},        {".git/", true},         {".hg/", true},   {".bzr/", true},
};

static bool filter_list_append_cvs(FilterRuleList* list, unsigned sides) {
  for (size_t i = 0; i < sizeof(CVS_DEFAULTS) / sizeof(CVS_DEFAULTS[0]); i++) {
    FilterRule* rule = calloc(1, sizeof(FilterRule));
    if (!rule)
      return false;
    rule->action = FILTER_ACTION_EXCLUDE;
    rule->sides = sides;
    rule->dir_only = CVS_DEFAULTS[i].dir_only;
    size_t plen = strlen(CVS_DEFAULTS[i].pattern);
    if (rule->dir_only && plen > 0 && CVS_DEFAULTS[i].pattern[plen - 1] == '/')
      plen--; /* keep the cleaned pattern, matching filter_rule_parse */
    rule->pattern = malloc(plen + 1);
    if (!rule->pattern) {
      free(rule);
      return false;
    }
    memcpy(rule->pattern, CVS_DEFAULTS[i].pattern, plen);
    rule->pattern[plen] = '\0';
    if (!set_rule_owner(rule, "")) {
      filter_rule_free(rule);
      return false;
    }
    if (!filter_rule_list_add(list, rule)) {
      filter_rule_free(rule);
      return false;
    }
  }
  return true;
}

#define FILTER_MAX_MERGE_DEPTH 16

static bool filter_list_parse_append_depth(FilterRuleList* list, const char* line,
                                           const FilterParseOptions* opts, const char* base_dir,
                                           int depth, char* err, size_t err_size);

/* Read a merge file and splice its rules into `list`.  A relative path is
 * resolved below `base_dir` when given, else used as-is (rsync resolves a
 * command-line merge file relative to the current directory). */
static bool filter_list_merge_file(FilterRuleList* list, const char* name,
                                   const FilterParseOptions* opts, const char* base_dir, int depth,
                                   char* err, size_t err_size) {
  if (name[0] == '\0') {
    filter_set_error(err, err_size, "merge requires a filename");
    return false;
  }
  char* path =
      (base_dir && base_dir[0] && name[0] != '/') ? path_cat(base_dir, name) : str_dup(name);
  if (!path) {
    filter_set_error(err, err_size, "memory allocation failed");
    return false;
  }
  FILE* fp = fopen(path, "r");
  if (!fp) {
    filter_set_error(err, err_size, "could not read merge file '%s': %s", path, strerror(errno));
    free(path);
    return false;
  }
  char* line = NULL;
  size_t cap = 0;
  bool ok = true;
  while (true) {
    ssize_t n = utils_getdelim_bounded(fp, &line, &cap, '\n', UTILS_MAX_LINE_LEN);
    if (n < 0) {
      filter_set_error(err, err_size, "error reading merge file '%s'", path);
      ok = false;
      break;
    }
    if (n == 0)
      break;
    const char* lp = line;
    while (*lp == ' ' || *lp == '\t')
      lp++;
    if (*lp == '\0' || *lp == '\n' || *lp == '\r' || *lp == '#')
      continue;
    if (!filter_list_parse_append_depth(list, lp, opts, base_dir, depth + 1, err, err_size)) {
      ok = false;
      break;
    }
  }
  free(line);
  fclose(fp);
  free(path);
  return ok;
}

/* Parse one line and append/merge it into `list`.  Handles clear, merge and
 * dir-merge at the list level. */
static bool filter_list_parse_append_depth(FilterRuleList* list, const char* line,
                                           const FilterParseOptions* opts, const char* base_dir,
                                           int depth, char* err, size_t err_size) {
  if (depth > FILTER_MAX_MERGE_DEPTH) {
    filter_set_error(err, err_size, "merge files nested too deeply");
    return false;
  }
  const char* p = line;
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p == '\0' || *p == '\n' || *p == '\r')
    return true;

  RuleKind kind = RULE_KIND_UNKNOWN;
  unsigned sides;
  bool sides_explicit, negate, anchored_mod, perishable, xattr, cvs_inject;
  const char* pat;
  size_t pat_len;
  if (!parse_rule_syntax(p, &kind, &sides, &sides_explicit, &negate, &anchored_mod, &perishable,
                         &xattr, &cvs_inject, &pat, &pat_len)) {
    filter_set_error(err, err_size, "unrecognized filter rule syntax: %s", p);
    return false;
  }
  (void)sides_explicit;
  (void)negate;
  (void)anchored_mod;
  (void)perishable;
  (void)xattr;

  if (cvs_inject) {
    /* "C" injects the CVS defaults in place; no pattern is expected. */
    return filter_list_append_cvs(list, sides);
  }
  if (kind == RULE_KIND_CLEAR) {
    if (pat_len != 0) {
      filter_set_error(err, err_size, "clear takes no pattern");
      return false;
    }
    for (int i = 0; i < list->count; i++)
      filter_rule_free(list->items[i]);
    list->count = 0;
    return true;
  }
  if (kind == RULE_KIND_MERGE) {
    if (pat_len == 0) {
      filter_set_error(err, err_size, "merge requires a filename");
      return false;
    }
    char* name = malloc(pat_len + 1);
    if (!name) {
      filter_set_error(err, err_size, "memory allocation failed");
      return false;
    }
    memcpy(name, pat, pat_len);
    name[pat_len] = '\0';
    bool ok = filter_list_merge_file(list, name, opts, base_dir, depth, err, err_size);
    free(name);
    return ok;
  }
  if (kind == RULE_KIND_DIR_MERGE) {
    if (pat_len == 0) {
      filter_set_error(err, err_size, "dir-merge requires a filename");
      return false;
    }
    char* name = malloc(pat_len + 1);
    if (!name) {
      filter_set_error(err, err_size, "memory allocation failed");
      return false;
    }
    memcpy(name, pat, pat_len);
    name[pat_len] = '\0';
    bool ok = filter_rule_list_add_dir_merge(list, name);
    free(name);
    if (!ok) {
      filter_set_error(err, err_size, "memory allocation failed");
      return false;
    }
    return true;
  }

  FilterRule* rule = filter_rule_parse(p, opts, err, err_size);
  if (!rule)
    return false;
  if (!filter_rule_list_add(list, rule)) {
    filter_rule_free(rule);
    filter_set_error(err, err_size, "memory allocation failed");
    return false;
  }
  return true;
}

bool filter_rule_list_parse_append(FilterRuleList* list, const char* line,
                                   const FilterParseOptions* opts, const char* merge_base_dir,
                                   char* err, size_t err_size) {
  if (err && err_size > 0)
    err[0] = '\0';
  if (!list)
    return false;
  return filter_list_parse_append_depth(list, line, opts, merge_base_dir, 0, err, err_size);
}

FilterRuleList* filter_base_build(const char* const* rule_texts, int rule_count, bool cvs_exclude,
                                  bool delete_excluded, char* err, size_t err_size) {
  if (err && err_size > 0)
    err[0] = '\0';
  FilterRuleList* list = filter_rule_list_create();
  if (!list) {
    filter_set_error(err, err_size, "memory allocation failed");
    return NULL;
  }
  FilterParseOptions opts = {.delete_excluded = delete_excluded, .cvs_exclude = cvs_exclude};
  for (int i = 0; i < rule_count; i++) {
    if (!rule_texts || !rule_texts[i])
      continue;
    if (!filter_rule_list_parse_append(list, rule_texts[i], &opts, NULL, err, err_size)) {
      filter_rule_list_free(list);
      return NULL;
    }
  }
  if (cvs_exclude && !filter_list_append_cvs(list, FILTER_SIDE_SENDER | FILTER_SIDE_RECEIVER)) {
    filter_rule_list_free(list);
    filter_set_error(err, err_size, "memory allocation failed");
    return NULL;
  }
  return list;
}

/* ---- Per-directory merge files ---- */

/* Undo the rules and dir-merge registrations that one merge file appended,
 * leaving the caller's earlier content intact.  A "clear" rule inside the file
 * frees every rule, including the caller's; clamp to the surviving count so
 * those already-freed rules are never resurrected and freed a second time. */
static void filter_file_rollback(FilterRuleList* list, int rules_before, int dir_merges_before) {
  int first = rules_before < list->count ? rules_before : list->count;
  for (int i = first; i < list->count; i++)
    filter_rule_free(list->items[i]);
  list->count = first;
  for (int i = dir_merges_before; i < list->dir_merge_count; i++)
    free(list->dir_merge_names[i]);
  list->dir_merge_count = dir_merges_before;
}

bool filter_file_append(FilterRuleList* list, const char* dir_path, const char* name,
                        const char* owner_rel, const FilterParseOptions* opts, bool* exists,
                        char* err, size_t err_size) {
  if (err && err_size > 0)
    err[0] = '\0';
  if (exists)
    *exists = false;
  if (!list)
    return false;
  char* filter_path = path_cat(dir_path, name);
  if (!filter_path) {
    filter_set_error(err, err_size, "memory allocation failed");
    return false;
  }
  FILE* fp = fopen(filter_path, "r");
  free(filter_path);
  if (!fp) {
    if (errno == ENOENT || errno == ENOTDIR)
      return true;
    char* escaped_dir = output_escape(dir_path, log_get_8_bit_output());
    log_message(LOG_LEVEL_WARNING, "Could not read %s in %s: %s", name,
                escaped_dir ? escaped_dir : "<allocation failed>", strerror(errno));
    free(escaped_dir);
    return true;
  }
  if (exists)
    *exists = true;
  int rules_before = list->count;
  int dir_merges_before = list->dir_merge_count;
  char* line = NULL;
  size_t line_cap = 0;
  bool ok = true;
  while (true) {
    ssize_t n = utils_getdelim_bounded(fp, &line, &line_cap, '\n', UTILS_MAX_LINE_LEN);
    if (n < 0) {
      if (errno == EFBIG) {
        filter_set_error(err, err_size, "line in %s exceeds %d bytes", name,
                         (int)UTILS_MAX_LINE_LEN);
      } else {
        filter_set_error(err, err_size, "error reading %s: %s", name, strerror(errno));
      }
      ok = false;
      break;
    }
    if (n == 0)
      break;
    const char* p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '#')
      continue;
    /* Merge files inside a per-directory file resolve relative to that
       directory. */
    if (!filter_list_parse_append_depth(list, p, opts, dir_path, 0, err, err_size)) {
      ok = false;
      break;
    }
  }
  free(line);
  fclose(fp);
  if (!ok) {
    filter_file_rollback(list, rules_before, dir_merges_before);
    return false;
  }
  for (int i = rules_before; i < list->count; i++) {
    if (!set_rule_owner(list->items[i], owner_rel)) {
      filter_set_error(err, err_size, "memory allocation failed");
      filter_file_rollback(list, rules_before, dir_merges_before);
      return false;
    }
  }
  return true;
}

FilterRuleList* filter_file_read_named(const char* dir_path, const char* name,
                                       const char* owner_rel, const FilterParseOptions* opts,
                                       bool* exists, char* err, size_t err_size) {
  FilterRuleList* list = filter_rule_list_create();
  if (!list) {
    if (err && err_size > 0)
      filter_set_error(err, err_size, "memory allocation failed");
    return NULL;
  }
  if (!filter_file_append(list, dir_path, name, owner_rel, opts, exists, err, err_size)) {
    filter_rule_list_free(list);
    return NULL;
  }
  return list;
}

FilterRuleList* filter_file_read(const char* dir_path, const char* owner_rel, bool* exists,
                                 char* err, size_t err_size) {
  return filter_file_read_named(dir_path, ".rsync-filter", owner_rel, NULL, exists, err, err_size);
}

/* ---- Rule matching ---- */

/* Match a pattern that contains '/' (non-anchored) against the end of the
 * relative path, starting at any path-component boundary. */
static bool glob_suffix_match(const char* pattern, const char* str) {
  if (glob_match(pattern, str))
    return true;
  for (const char* slash = strchr(str, '/'); slash; slash = strchr(slash + 1, '/')) {
    if (glob_match(pattern, slash + 1))
      return true;
  }
  return false;
}

static FilterAction rule_matches(const FilterRule* rule, const char* rel_path, const char* leaf,
                                 bool is_dir, unsigned side) {
  if (!rule || !rule->pattern)
    return FILTER_ACTION_NONE;
  if (!(rule->sides & side))
    return FILTER_ACTION_NONE;
  /* A rule applies only to entries below its owner directory. */
  const char* rel2 = rel_path;
  if (rule->owner && rule->owner[0] != '\0') {
    size_t owner_len = strlen(rule->owner);
    if (strncmp(rule->owner, rel_path, owner_len) != 0)
      return FILTER_ACTION_NONE;
    if (rel_path[owner_len] != '/')
      return FILTER_ACTION_NONE;
    rel2 = rel_path + owner_len + 1;
  }
  if (rel2[0] == '\0')
    return FILTER_ACTION_NONE;
  bool matched;
  if (rule->dir_only && !is_dir)
    matched = false;
  else if (rule->anchored)
    matched = glob_match(rule->pattern, rel2);
  else if (strchr(rule->pattern, '/') != NULL)
    matched = glob_suffix_match(rule->pattern, rel2);
  else
    matched = glob_match(rule->pattern, leaf);
  if (rule->negate)
    matched = !matched;
  if (!matched)
    return FILTER_ACTION_NONE;
  if (side == FILTER_SIDE_RECEIVER)
    return rule->action == FILTER_ACTION_EXCLUDE ? FILTER_ACTION_PROTECT : FILTER_ACTION_RISK;
  return rule->action;
}

FilterAction filter_rules_apply_side(const FilterRuleList* list, const char* rel_path,
                                     const char* leaf, bool is_dir, unsigned side) {
  if (!list)
    return FILTER_ACTION_NONE;
  for (int i = 0; i < list->count; i++) {
    FilterAction action = rule_matches(list->items[i], rel_path, leaf, is_dir, side);
    if (action != FILTER_ACTION_NONE)
      return action;
  }
  return FILTER_ACTION_NONE;
}

FilterAction filter_rules_apply(const FilterRuleList* list, const char* rel_path, const char* leaf,
                                bool is_dir) {
  return filter_rules_apply_side(list, rel_path, leaf, is_dir, FILTER_SIDE_SENDER);
}
