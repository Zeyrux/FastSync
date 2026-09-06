#include "filter.h"
#include "log.h"
#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Single rule parsing ---- */

static bool rule_text_is_unsupported_word(const char* p, size_t len) {
  static const char* const words[] = {"merge",   "dir-merge", "hide", "show",
                                      "protect", "risk",      "clear"};
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    size_t wl = strlen(words[i]);
    if (len == wl && strncmp(p, words[i], wl) == 0)
      return true;
  }
  return false;
}

FilterRule* filter_rule_parse(const char* line, char* err, size_t err_size) {
  if (err && err_size > 0)
    err[0] = '\0';
  if (!line)
    return NULL;
  char* text = str_dup(line);
  if (!text) {
    if (err)
      snprintf(err, err_size, "memory allocation failed");
    return NULL;
  }
  size_t len = strlen(text);
  while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r'))
    text[--len] = '\0';

  FilterAction action = FILTER_ACTION_EXCLUDE;
  const char* p = text;
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p == '\0') {
    snprintf(err, err_size, "empty filter rule");
    free(text);
    return NULL;
  }

  if (*p == '+' || *p == '-') {
    action = *p == '+' ? FILTER_ACTION_INCLUDE : FILTER_ACTION_EXCLUDE;
    p++;
    /* Accept the rsync word forms include/exclude. */
  } else {
    const char* sp = p;
    while (*sp != '\0' && *sp != ' ' && *sp != '\t')
      sp++;
    size_t word_len = (size_t)(sp - p);
    if (rule_text_is_unsupported_word(p, word_len)) {
      snprintf(err, err_size,
               "'%.*s' filter directives are not supported (only +/- include/exclude rules "
               "with an optional '/' anchor and trailing '/' dir marker)",
               (int)word_len, p);
      free(text);
      return NULL;
    }
    if (word_len == strlen("include") && strncmp(p, "include", word_len) == 0) {
      action = FILTER_ACTION_INCLUDE;
      p = sp;
    } else if (word_len == strlen("exclude") && strncmp(p, "exclude", word_len) == 0) {
      action = FILTER_ACTION_EXCLUDE;
      p = sp;
    }
  }

  while (*p == ' ' || *p == '\t')
    p++;
  if (*p == '\0') {
    snprintf(err, err_size, "filter rule has no pattern");
    free(text);
    return NULL;
  }

  bool anchored = false;
  if (*p == '/') {
    anchored = true;
    p++;
    while (*p == ' ' || *p == '\t')
      p++;
  }
  if (*p == '\0') {
    snprintf(err, err_size, "filter rule has no pattern after '/' anchor");
    free(text);
    return NULL;
  }

  /* Pattern runs to the end of the rule; a single trailing '/' marks dir-only. */
  size_t pat_len = strlen(p);
  bool dir_only = false;
  if (pat_len > 1 && p[pat_len - 1] == '/') {
    dir_only = true;
    pat_len--;
  } else if (pat_len == 1 && p[0] == '/') {
    /* "//" anchored with nothing after: meaningless. */
    snprintf(err, err_size, "filter rule has no pattern");
    free(text);
    return NULL;
  }

  FilterRule* rule = calloc(1, sizeof(FilterRule));
  if (!rule) {
    snprintf(err, err_size, "memory allocation failed");
    free(text);
    return NULL;
  }
  rule->pattern = malloc(pat_len + 1);
  if (!rule->pattern) {
    free(rule);
    snprintf(err, err_size, "memory allocation failed");
    free(text);
    return NULL;
  }
  memcpy(rule->pattern, p, pat_len);
  rule->pattern[pat_len] = '\0';
  rule->action = action;
  rule->anchored = anchored;
  rule->dir_only = dir_only;
  rule->owner = NULL;
  free(text);
  return rule;
}

void filter_rule_free(FilterRule* rule) {
  if (!rule)
    return;
  free(rule->pattern);
  free(rule->owner);
  free(rule);
}

/* ---- Ordered rule lists ---- */

FilterRuleList* filter_rule_list_create(void) {
  return calloc(1, sizeof(FilterRuleList));
}

bool filter_rule_list_add(FilterRuleList* list, FilterRule* rule) {
  if (!list || !rule)
    return false;
  if (list->count == list->capacity) {
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

bool filter_rule_list_parse_append(FilterRuleList* list, const char* line, char* err,
                                   size_t err_size) {
  FilterRule* rule = filter_rule_parse(line, err, err_size);
  if (!rule)
    return false;
  if (!filter_rule_list_add(list, rule)) {
    filter_rule_free(rule);
    snprintf(err, err_size, "memory allocation failed");
    return false;
  }
  return true;
}

void filter_rule_list_free(FilterRuleList* list) {
  if (!list)
    return;
  for (int i = 0; i < list->count; i++)
    filter_rule_free(list->items[i]);
  free(list->items);
  free(list);
}

static bool set_rule_owner(FilterRule* rule, const char* owner) {
  char* dup = str_dup(owner ? owner : "");
  if (!dup)
    return false;
  free(rule->owner);
  rule->owner = dup;
  return true;
}

/* ---- CVS default excludes (-C) ---- */

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

static bool cvs_rule_list_append(FilterRuleList* list) {
  for (size_t i = 0; i < sizeof(CVS_DEFAULTS) / sizeof(CVS_DEFAULTS[0]); i++) {
    FilterRule* rule = calloc(1, sizeof(FilterRule));
    if (!rule)
      return false;
    rule->action = FILTER_ACTION_EXCLUDE;
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

FilterRuleList* filter_base_build(const char* const* rule_texts, int rule_count, bool cvs_exclude,
                                  char* err, size_t err_size) {
  if (err && err_size > 0)
    err[0] = '\0';
  FilterRuleList* list = filter_rule_list_create();
  if (!list) {
    snprintf(err, err_size, "memory allocation failed");
    return NULL;
  }
  for (int i = 0; i < rule_count; i++) {
    if (!rule_texts || !rule_texts[i])
      continue;
    FilterRule* rule = filter_rule_parse(rule_texts[i], err, err_size);
    if (!rule) {
      filter_rule_list_free(list);
      return NULL;
    }
    if (!set_rule_owner(rule, "")) {
      filter_rule_free(rule);
      filter_rule_list_free(list);
      snprintf(err, err_size, "memory allocation failed");
      return NULL;
    }
    if (!filter_rule_list_add(list, rule)) {
      filter_rule_free(rule);
      filter_rule_list_free(list);
      snprintf(err, err_size, "memory allocation failed");
      return NULL;
    }
  }
  if (cvs_exclude && !cvs_rule_list_append(list)) {
    filter_rule_list_free(list);
    snprintf(err, err_size, "memory allocation failed");
    return NULL;
  }
  return list;
}

/* ---- Per-directory .rsync-filter files ---- */

FilterRuleList* filter_file_read(const char* dir_path, const char* owner_rel, bool* exists,
                                 char* err, size_t err_size) {
  if (err && err_size > 0)
    err[0] = '\0';
  if (exists)
    *exists = false;
  char* filter_path = path_cat(dir_path, ".rsync-filter");
  if (!filter_path) {
    snprintf(err, err_size, "memory allocation failed");
    return NULL;
  }
  FILE* fp = fopen(filter_path, "r");
  free(filter_path);
  if (!fp) {
    if (errno == ENOENT || errno == ENOTDIR)
      return filter_rule_list_create();
    log_message(LOG_LEVEL_WARNING, "Could not read .rsync-filter in %s: %s", dir_path,
                strerror(errno));
    return filter_rule_list_create();
  }
  if (exists)
    *exists = true;
  FilterRuleList* list = filter_rule_list_create();
  if (!list) {
    fclose(fp);
    snprintf(err, err_size, "memory allocation failed");
    return NULL;
  }
  char* line = NULL;
  size_t line_cap = 0;
  ssize_t n;
  bool ok = true;
  while ((n = getline(&line, &line_cap, fp)) != -1) {
    const char* p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '#')
      continue;
    FilterRule* rule = filter_rule_parse(p, err, err_size);
    if (!rule) {
      ok = false;
      break;
    }
    if (!set_rule_owner(rule, owner_rel)) {
      filter_rule_free(rule);
      snprintf(err, err_size, "memory allocation failed");
      ok = false;
      break;
    }
    if (!filter_rule_list_add(list, rule)) {
      filter_rule_free(rule);
      snprintf(err, err_size, "memory allocation failed");
      ok = false;
      break;
    }
  }
  free(line);
  fclose(fp);
  if (!ok) {
    filter_rule_list_free(list);
    return NULL;
  }
  return list;
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
                                 bool is_dir) {
  if (!rule || !rule->pattern)
    return FILTER_ACTION_NONE;
  if (rule->dir_only && !is_dir)
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
  if (rule->anchored) {
    matched = glob_match(rule->pattern, rel2);
  } else if (strchr(rule->pattern, '/') != NULL) {
    matched = glob_suffix_match(rule->pattern, rel2);
  } else {
    matched = glob_match(rule->pattern, leaf);
  }
  return matched ? rule->action : FILTER_ACTION_NONE;
}

FilterAction filter_rules_apply(const FilterRuleList* list, const char* rel_path, const char* leaf,
                                bool is_dir) {
  if (!list)
    return FILTER_ACTION_NONE;
  for (int i = 0; i < list->count; i++) {
    FilterAction action = rule_matches(list->items[i], rel_path, leaf, is_dir);
    if (action != FILTER_ACTION_NONE)
      return action;
  }
  return FILTER_ACTION_NONE;
}
