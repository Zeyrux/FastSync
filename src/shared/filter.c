#include "filter.h"
#include "log.h"
#include "utils.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Write a diagnostic message into the caller's optional buffer. */
#define filter_set_error utils_set_error

/* ---- Ordered rule lists ---- */

void filter_rule_free(FilterRule* rule) {
  if (!rule)
    return;
  free(rule->pattern);
  free(rule->owner);
  free(rule);
}

FilterRule* filter_rule_clone(const FilterRule* rule) {
  if (!rule)
    return NULL;
  FilterRule* copy = calloc(1, sizeof(FilterRule));
  if (!copy)
    return NULL;
  copy->action = rule->action;
  copy->sides = rule->sides;
  copy->anchored = rule->anchored;
  copy->dir_only = rule->dir_only;
  copy->negate = rule->negate;
  copy->perishable = rule->perishable;
  copy->no_inherit = rule->no_inherit;
  copy->owner = str_dup(rule->owner ? rule->owner : "");
  copy->pattern = str_dup(rule->pattern ? rule->pattern : "");
  if (!copy->owner || !copy->pattern) {
    filter_rule_free(copy);
    return NULL;
  }
  return copy;
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
    free(list->dir_merges[i].name);
  free(list->dir_merges);
  free(list->items);
  free(list);
}

/* Append an implicit exclude rule for the merge file itself (rsync's 'e'
 * modifier).  The rule is owned by the transfer root and matches the basename
 * anywhere, exactly like rsync's EXCLUDE_SELF (a dual-sided exclude: it hides
 * the file and protects its destination mirror from --delete). */
static bool filter_list_add_exclude_self(FilterRuleList* list, const char* name) {
  const char* base = strrchr(name, '/');
  base = base ? base + 1 : name;
  if (base[0] == '\0')
    return true;
  FilterRule* rule = calloc(1, sizeof(FilterRule));
  if (!rule)
    return false;
  rule->action = FILTER_ACTION_EXCLUDE;
  rule->sides = FILTER_SIDE_SENDER | FILTER_SIDE_RECEIVER;
  rule->pattern = str_dup(base);
  if (!rule->pattern || !filter_rule_set_owner(rule, "")) {
    filter_rule_free(rule);
    return false;
  }
  if (!filter_rule_list_add(list, rule)) {
    filter_rule_free(rule);
    return false;
  }
  return true;
}

/* Register a per-directory merge-file basename (for "dir-merge NAME"/": NAME"
 * and -F's .rsync-filter).  Duplicate names are ignored. */
bool filter_rule_list_add_dir_merge(FilterRuleList* list, const char* name) {
  return filter_rule_list_add_dir_merge_ex(list, name, false, false, false, false, false);
}

bool filter_rule_list_add_dir_merge_ex(FilterRuleList* list, const char* name, bool no_prefixes,
                                       bool include, bool word_split, bool no_inherit,
                                       bool exclude_self) {
  if (!list || !name || name[0] == '\0')
    return false;
  for (int i = 0; i < list->dir_merge_count; i++) {
    if (strcmp(list->dir_merges[i].name, name) == 0) {
      /* rsync keeps the first registration (first-wins), but the 'e' modifier
         is a list side effect, not a registration field: honor it on the
         duplicate path too, adding the implicit exclude-self rule at most
         once. */
      if (exclude_self && !list->dir_merges[i].exclude_self) {
        if (!filter_list_add_exclude_self(list, name))
          return false;
        list->dir_merges[i].exclude_self = true;
      }
      return true;
    }
  }
  if (list->dir_merge_count == list->dir_merge_capacity) {
    if (list->dir_merge_capacity > INT_MAX / 2)
      return false;
    int new_cap = list->dir_merge_capacity > 0 ? list->dir_merge_capacity * 2 : 4;
    FilterDirMerge* grown = realloc(list->dir_merges, (size_t)new_cap * sizeof(*grown));
    if (!grown)
      return false;
    list->dir_merges = grown;
    list->dir_merge_capacity = new_cap;
  }
  char* dup = str_dup(name);
  if (!dup)
    return false;
  if (exclude_self && !filter_list_add_exclude_self(list, name)) {
    free(dup);
    return false;
  }
  FilterDirMerge* entry = &list->dir_merges[list->dir_merge_count];
  entry->name = dup;
  entry->no_prefixes = no_prefixes;
  entry->include = include;
  entry->word_split = word_split;
  entry->no_inherit = no_inherit;
  entry->exclude_self = exclude_self;
  list->dir_merge_count++;
  return true;
}

bool filter_rule_set_owner(FilterRule* rule, const char* owner) {
  if (!rule)
    return false;
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

/* merge/dir-merge rules are the only rules rsync accepts the merge-file
 * modifiers on. */
static bool is_merge_rule(RuleKind kind) {
  return kind == RULE_KIND_MERGE || kind == RULE_KIND_DIR_MERGE;
}

/* Merge-file modifiers rsync defines but FastSync does not implement:
 * 'e' exclude the merge file itself, 'n' do not inherit the merge file, 'w'
 * word-split the merge file.  They are recognized as part of a modifier run on
 * every rule (so a pure e/n/w token is rejected rather than folded into the
 * pattern), but are accepted (and ignored) only on merge/dir-merge rules. */
static bool is_unsupported_modifier_char(char c) {
  return c == 'e' || c == 'n' || c == 'w';
}

/* Merge-file modifiers rsync accepts on merge/dir-merge rules: 'e' (exclude
 * self), 'n' (no inherit), 'w' (word split), '-' (bare excludes) and '+'
 * (bare includes). */
static bool is_merge_modifier_char(char c) {
  return c == 'e' || c == 'n' || c == 'w' || c == '-' || c == '+';
}

/* Characters that count as part of a modifier run for `kind` when deciding
 * whether a token is a pure modifier run.  e/n/w count on every rule so that a
 * pure e/n/w token is rejected on non-merge rules; '-' only on merge rules. */
static bool is_modifier_scan_char(char c, RuleKind kind) {
  return is_modifier_char(c) || is_unsupported_modifier_char(c) ||
         (is_merge_rule(kind) && is_merge_modifier_char(c));
}

/* Characters actually consumed as modifiers for `kind`.  The merge-file
 * modifiers are consumed only on merge/dir-merge rules; elsewhere e/n/w fall
 * through to the pattern (so mixed tokens such as "H,!secret" keep their
 * historical "ecret" pattern). */
static bool is_consumed_modifier_char(char c, RuleKind kind) {
  return is_modifier_char(c) || (is_merge_rule(kind) && is_merge_modifier_char(c));
}

/* Inspect the token that follows a rule name (up to the first space/underscore
 * or the end).  If the token is composed *solely* of modifier characters and
 * includes one that is invalid for `kind`, it is unambiguously a modifier run:
 * return that character so the caller can reject it.  A token that contains any
 * non-modifier character is a pattern (e.g. "-newfile") and returns '\0', which
 * keeps the historical parsing of mixed tokens such as "H,!secret" intact. */
static char unsupported_modifier_in_token(const char* tok, RuleKind kind) {
  if (*tok == '\0' || *tok == ' ' || *tok == '_')
    return '\0';
  char bad = '\0';
  for (const char* q = tok; *q != '\0' && *q != ' ' && *q != '_'; q++) {
    if (!is_modifier_scan_char(*q, kind))
      return '\0';
    if (!is_merge_rule(kind) && is_unsupported_modifier_char(*q))
      bad = *q;
  }
  return bad;
}

/* Parse "RULE[,MODIFIERS] [PATTERN]".  On success `kind`, `sides`,
 * `sides_explicit`, `negate`, `anchored_mod`, `perishable`, `xattr`,
 * `cvs_inject` and the pattern span (`pat_start`/`pat_len`, possibly 0 for
 * merge/clear) are filled.  Returns true on success.
 *
 * On failure `*bad_mod` is set to the offending modifier character when the
 * rule carried a modifier FastSync does not implement, and left '\0' for a
 * generic syntax error so callers can emit a precise diagnostic. */
static bool parse_rule_syntax(const char* text, RuleKind* kind, unsigned* sides,
                              bool* sides_explicit, bool* negate, bool* anchored_mod,
                              bool* perishable, bool* xattr, bool* cvs_inject, bool* no_prefixes,
                              bool* include_defaults, bool* word_split, bool* no_inherit,
                              bool* exclude_self, const char** pat_start, size_t* pat_len,
                              char* bad_mod) {
  const char* p = text;
  *sides = FILTER_SIDE_SENDER | FILTER_SIDE_RECEIVER;
  *sides_explicit = false;
  *negate = false;
  *anchored_mod = false;
  *perishable = false;
  *xattr = false;
  *cvs_inject = false;
  *no_prefixes = false;
  *include_defaults = false;
  *word_split = false;
  *no_inherit = false;
  *exclude_self = false;
  *pat_start = NULL;
  *pat_len = 0;
  *bad_mod = '\0';

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
  if (*p == ',') {
    *bad_mod = unsupported_modifier_in_token(p + 1, *kind);
  } else if (is_short) {
    *bad_mod = unsupported_modifier_in_token(p, *kind);
  }
  if (*bad_mod != '\0')
    return false;

  const char* mod_start = p;
  const char* mod_end = p;
  if (*p == ',') {
    p++;
    mod_start = p;
    while (is_consumed_modifier_char(*p, *kind))
      p++;
    mod_end = p;
  } else if (is_short) {
    const char* scan = p;
    while (is_consumed_modifier_char(*scan, *kind))
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
    case '-':
      *no_prefixes = true;
      break;
    case '+':
      *include_defaults = true;
      break;
    case 'e':
      *exclude_self = true;
      break;
    case 'n':
      *no_inherit = true;
      break;
    case 'w':
      *word_split = true;
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
  bool no_prefixes, include_defaults, word_split, no_inherit, exclude_self;
  const char* pat;
  size_t pat_len;
  char bad_mod;
  if (!parse_rule_syntax(p, &kind, &sides, &sides_explicit, &negate, &anchored_mod, &perishable,
                         &xattr, &cvs_inject, &no_prefixes, &include_defaults, &word_split,
                         &no_inherit, &exclude_self, &pat, &pat_len, &bad_mod)) {
    if (bad_mod != '\0')
      filter_set_error(err, err_size, "unsupported filter modifier '%c'", bad_mod);
    else
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
    if (!filter_rule_set_owner(rule, "")) {
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

/* Append one merge-file token/line to `list`, honoring the merge rule's
 * no-prefix/include mode.  In no-prefix mode the token is a bare pattern whose
 * include/exclude default comes from the merge rule (rsync's "-"/"+" merge
 * modifiers); otherwise the token is parsed as a full filter rule. */
static bool filter_merge_append_token(FilterRuleList* list, const char* token,
                                      const FilterDirMerge* spec, const FilterParseOptions* opts,
                                      const char* base_dir, int depth, char* err, size_t err_size) {
  if (spec->no_prefixes || spec->include) {
    size_t tlen = strlen(token);
    char* text = malloc(tlen + 3);
    if (!text) {
      filter_set_error(err, err_size, "memory allocation failed");
      return false;
    }
    text[0] = spec->include ? '+' : '-';
    text[1] = ' ';
    memcpy(text + 2, token, tlen + 1);
    bool ok = filter_list_parse_append_depth(list, text, opts, base_dir, depth + 1, err, err_size);
    free(text);
    return ok;
  }
  return filter_list_parse_append_depth(list, token, opts, base_dir, depth + 1, err, err_size);
}

/* Read a merge file's tokens/lines into `list` for `spec`.  A `w` merge rule
 * word-splits on whitespace (turning comments off); otherwise lines are parsed
 * and whole-line `#` comments skipped.  When `owner_rel` is non-NULL the newly
 * added rules are owned by that directory; a no-inherit spec marks them so they
 * apply only there.  Returns false on parse/allocation failure. */
static bool filter_merge_read(FilterRuleList* list, FILE* fp, const char* display_path,
                              const FilterDirMerge* spec, const FilterParseOptions* opts,
                              const char* base_dir, const char* owner_rel, int depth, char* err,
                              size_t err_size) {
  /* Lowest list index this read is responsible for.  A "clear"/"!" inside the
   * file resets list->count to 0 (freeing the caller's earlier rules too), so
   * the base must follow it down: otherwise post-clear rules sit below the
   * original count and never receive an owner (nor no-inherit) and are missed
   * by the rollback. */
  int floor = list->count;
  char* line = NULL;
  size_t cap = 0;
  bool ok = true;
  while (ok) {
    ssize_t n = utils_getdelim_bounded(fp, &line, &cap, '\n', UTILS_MAX_LINE_LEN);
    if (n < 0) {
      if (errno == EFBIG)
        filter_set_error(err, err_size, "line in %s exceeds %d bytes", display_path,
                         (int)UTILS_MAX_LINE_LEN);
      else
        filter_set_error(err, err_size, "error reading %s: %s", display_path, strerror(errno));
      ok = false;
      break;
    }
    if (n == 0)
      break;
    if (spec->word_split) {
      /* Whitespace-separated tokens; newlines are ordinary separators and
       * comments are disabled. */
      const char* s = line;
      while (*s) {
        while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
          s++;
        if (*s == '\0')
          break;
        const char* start = s;
        while (*s != '\0' && *s != ' ' && *s != '\t' && *s != '\n' && *s != '\r')
          s++;
        size_t tlen = (size_t)(s - start);
        char* token = malloc(tlen + 1);
        if (!token) {
          filter_set_error(err, err_size, "memory allocation failed");
          ok = false;
          break;
        }
        memcpy(token, start, tlen);
        token[tlen] = '\0';
        if (!filter_merge_append_token(list, token, spec, opts, base_dir, depth, err, err_size))
          ok = false;
        if (list->count < floor)
          floor = list->count; /* a "clear" reset the list below this read's base */
        free(token);
      }
    } else {
      const char* lp = line;
      while (*lp == ' ' || *lp == '\t')
        lp++;
      if (*lp == '\0' || *lp == '\n' || *lp == '\r' || *lp == '#')
        continue;
      if (!filter_merge_append_token(list, lp, spec, opts, base_dir, depth, err, err_size))
        ok = false;
      if (list->count < floor)
        floor = list->count; /* a "clear" reset the list below this read's base */
    }
  }
  free(line);
  if (!ok) {
    /* Drop every live rule this read is responsible for.  After a "clear" that
     * base is 0, so the post-clear rules are freed too instead of leaking. */
    for (int i = floor; i < list->count; i++)
      filter_rule_free(list->items[i]);
    list->count = floor;
    return false;
  }
  for (int i = floor; i < list->count; i++) {
    FilterRule* rule = list->items[i];
    if (spec->no_inherit)
      rule->no_inherit = true;
    if (owner_rel && !filter_rule_set_owner(rule, owner_rel)) {
      filter_set_error(err, err_size, "memory allocation failed");
      for (int j = floor; j < list->count; j++)
        filter_rule_free(list->items[j]);
      list->count = floor;
      return false;
    }
  }
  return true;
}

/* Read a single-instance merge file and splice its rules into `list`.  A
 * relative path is resolved below `base_dir` when given, else used as-is (rsync
 * resolves a command-line merge file relative to the current directory). */
static bool filter_list_merge_file(FilterRuleList* list, const char* name,
                                   const FilterDirMerge* spec, const FilterParseOptions* opts,
                                   const char* base_dir, int depth, char* err, size_t err_size) {
  if (name[0] == '\0') {
    filter_set_error(err, err_size, "merge requires a filename");
    return false;
  }
  if (spec->exclude_self && !filter_list_add_exclude_self(list, name)) {
    filter_set_error(err, err_size, "memory allocation failed");
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
  bool ok = filter_merge_read(list, fp, path, spec, opts, base_dir, NULL, depth, err, err_size);
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
  bool no_prefixes, include_defaults, word_split, no_inherit, exclude_self;
  const char* pat;
  size_t pat_len;
  char bad_mod;
  if (!parse_rule_syntax(p, &kind, &sides, &sides_explicit, &negate, &anchored_mod, &perishable,
                         &xattr, &cvs_inject, &no_prefixes, &include_defaults, &word_split,
                         &no_inherit, &exclude_self, &pat, &pat_len, &bad_mod)) {
    if (bad_mod != '\0')
      filter_set_error(err, err_size, "unsupported filter modifier '%c': %s", bad_mod, p);
    else
      filter_set_error(err, err_size, "unrecognized filter rule syntax: %s", p);
    return false;
  }
  (void)sides_explicit;
  (void)negate;
  (void)anchored_mod;
  (void)perishable;

  /* xattr-name rules are not implemented; reject them everywhere (including on
   * merge/dir-merge, where the flag would otherwise be silently dropped) with
   * the same diagnostic the standalone parser gives. */
  if (xattr) {
    filter_set_error(err, err_size, "xattr-name filter rules (the x modifier) are not supported");
    return false;
  }

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
    /* A single-instance merge has no inheritance, so 'n' is meaningless; the
     * other merge modifiers still shape how the file is read. */
    FilterDirMerge spec = {.name = name,
                           .no_prefixes = no_prefixes,
                           .include = include_defaults,
                           .word_split = word_split,
                           .no_inherit = false,
                           .exclude_self = exclude_self};
    bool ok = filter_list_merge_file(list, name, &spec, opts, base_dir, depth, err, err_size);
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
    bool ok = filter_rule_list_add_dir_merge_ex(list, name, no_prefixes, include_defaults,
                                                word_split, no_inherit, exclude_self);
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
 * those already-freed rules are never resurrected and freed a second time.
 * (filter_merge_read() has already rolled its own range back by the time this
 * runs, so on a post-clear failure `list->count` is below `rules_before` and
 * this is a no-op for the rules.) */
static void filter_file_rollback(FilterRuleList* list, int rules_before, int dir_merges_before) {
  int first = rules_before < list->count ? rules_before : list->count;
  for (int i = first; i < list->count; i++)
    filter_rule_free(list->items[i]);
  list->count = first;
  for (int i = dir_merges_before; i < list->dir_merge_count; i++)
    free(list->dir_merges[i].name);
  list->dir_merge_count = dir_merges_before;
}

bool filter_dir_merge_append(FilterRuleList* list, const char* dir_path, const FilterDirMerge* spec,
                             const char* owner_rel, const FilterParseOptions* opts, bool* exists,
                             char* err, size_t err_size) {
  if (err && err_size > 0)
    err[0] = '\0';
  if (exists)
    *exists = false;
  if (!list || !spec || !spec->name)
    return false;
  char* filter_path = path_cat(dir_path, spec->name);
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
    log_message(LOG_LEVEL_WARNING, "Could not read %s in %s: %s", spec->name,
                escaped_dir ? escaped_dir : "<allocation failed>", strerror(errno));
    free(escaped_dir);
    return true;
  }
  if (exists)
    *exists = true;
  int rules_before = list->count;
  int dir_merges_before = list->dir_merge_count;
  /* Merge files inside a per-directory file resolve relative to that
     directory. */
  bool ok =
      filter_merge_read(list, fp, spec->name, spec, opts, dir_path, owner_rel, 0, err, err_size);
  fclose(fp);
  if (!ok) {
    filter_file_rollback(list, rules_before, dir_merges_before);
    return false;
  }
  return true;
}

bool filter_file_append(FilterRuleList* list, const char* dir_path, const char* name,
                        const char* owner_rel, const FilterParseOptions* opts, bool* exists,
                        char* err, size_t err_size) {
  FilterDirMerge spec = {.name = (char*)name};
  return filter_dir_merge_append(list, dir_path, &spec, owner_rel, opts, exists, err, err_size);
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
  /* A rule applies only to entries below its owner directory.  The receive
   * root's destination-relative coordinate may be written as "." (the
   * synced-directory sentinel), which is the same scope as the empty owner. */
  const char* owner = rule->owner;
  if (owner && strcmp(owner, ".") == 0)
    owner = "";
  const char* rel2 = rel_path;
  if (owner && owner[0] != '\0') {
    size_t owner_len = strlen(owner);
    if (strncmp(owner, rel_path, owner_len) != 0)
      return FILTER_ACTION_NONE;
    if (rel_path[owner_len] != '/')
      return FILTER_ACTION_NONE;
    rel2 = rel_path + owner_len + 1;
  }
  if (rel2[0] == '\0')
    return FILTER_ACTION_NONE;
  /* A no-inherit rule ('n' on its dir-merge) applies only to direct children of
   * its owner directory, never to deeper entries. */
  if (rule->no_inherit && strchr(rel2, '/') != NULL)
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

FilterAction filter_dir_rules_apply_side(const FilterRuleList* dir_rules, const char* rel_path,
                                         const char* leaf, bool is_dir) {
  if (!dir_rules || !rel_path)
    return FILTER_ACTION_NONE;
  size_t len = strlen(rel_path);
  if (len == 0)
    return FILTER_ACTION_NONE;
  /* The containing directory of rel_path is the prefix before its final '/'. */
  size_t owner_len = 0;
  for (size_t i = 0; i < len; i++) {
    if (rel_path[i] == '/')
      owner_len = i;
  }
  for (;;) {
    for (int i = 0; i < dir_rules->count; i++) {
      const FilterRule* rule = dir_rules->items[i];
      const char* rule_owner = rule && rule->owner ? rule->owner : "";
      /* "." is the receive root's coordinate (see rule_matches). */
      if (strcmp(rule_owner, ".") == 0)
        rule_owner = "";
      size_t rule_owner_len = strlen(rule_owner);
      if (rule_owner_len != owner_len)
        continue;
      if (owner_len != 0 && memcmp(rule_owner, rel_path, owner_len) != 0)
        continue;
      FilterAction action = rule_matches(rule, rel_path, leaf, is_dir, FILTER_SIDE_RECEIVER);
      if (action != FILTER_ACTION_NONE)
        return action;
    }
    if (owner_len == 0)
      break;
    /* Move to the parent directory: the last '/' before owner_len. */
    size_t parent = 0;
    for (size_t j = 0; j < owner_len; j++) {
      if (rel_path[j] == '/')
        parent = j;
    }
    owner_len = parent;
  }
  return FILTER_ACTION_NONE;
}
