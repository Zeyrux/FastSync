#ifndef FILTER_H
#define FILTER_H

#include <stdbool.h>
#include <stddef.h>

/* rsync-style filter rule engine (client-side file selection).
 *
 * Supported rule syntax (documented subset):
 *   [+|-] [anchored '/' prefix] pattern [trailing '/' for dir-only]
 *
 *   "+ PATTERN"   include rule (first match wins)
 *   "- PATTERN"   exclude rule
 *   "PATTERN"     implicit exclude rule (rsync default)
 *   "include PATTERN" / "exclude PATTERN"  word forms
 *   leading '/' after the +/- anchors the pattern to its owner directory
 *     (the transfer root for command-line/-C rules, the directory that
 *      contains a .rsync-filter file for per-directory rules)
 *   a trailing '/' makes the rule match directories only
 *
 * Rejected explicitly (no silent no-ops): the rsync merge/dir-merge/list-clear
 * shorthands written as a rule that starts with ':' or '.' or '!', the
 * merge/dir-merge/hide/show/protect/risk/clear words, and every include/exclude
 * rule modifier other than '/' (! C s r p x). The pattern must be separated
 * from +/- by a space (or a single '/' anchor), exactly like rsync's
 * "-s foo"/"-p ..." modifier syntax is refused.
 */

typedef enum {
  FILTER_ACTION_NONE = 0, /* no rule matched */
  FILTER_ACTION_EXCLUDE = -1,
  FILTER_ACTION_INCLUDE = 1
} FilterAction;

typedef struct {
  FilterAction action;
  bool anchored; /* pattern anchored to the rule's owner directory */
  bool dir_only; /* pattern had a trailing '/': matches directories only */
  char* owner;   /* owning directory rel path ("" == transfer root) */
  char* pattern; /* cleaned glob pattern (no leading '/', no trailing '/') */
} FilterRule;

typedef struct {
  FilterRule** items; /* owned array of rule pointers */
  int count;
  int capacity;
} FilterRuleList;

/* Parse a single filter-rule line (no trailing newline required). Returns an
 * owned rule, or NULL on unsupported/invalid syntax with a message in `err`. */
FilterRule* filter_rule_parse(const char* line, char* err, size_t err_size);
void filter_rule_free(FilterRule* rule);

FilterRuleList* filter_rule_list_create(void);
/* Append a fully-parsed rule (takes ownership). Returns false on OOM. */
bool filter_rule_list_add(FilterRuleList* list, FilterRule* rule);
/* Parse `line` and append it. Returns false and fills `err` on bad syntax. */
bool filter_rule_list_parse_append(FilterRuleList* list, const char* line, char* err,
                                   size_t err_size);
void filter_rule_list_free(FilterRuleList* list);

/* Build the command-line filter set: `rule_texts` (--filter=RULE in the order
 * given, 0..rule_count) followed by the -C CVS default excludes when
 * cvs_exclude is true. All rules are owned by "" (the transfer root).
 * Returns NULL on unsupported rule text (message in `err`). */
FilterRuleList* filter_base_build(const char* const* rule_texts, int rule_count, bool cvs_exclude,
                                  char* err, size_t err_size);

/* Read "<dir_path>/.rsync-filter" and return its rules, each owned by
 * `owner_rel`. A missing file yields an empty list with *exists=false; an
 * unreadable file is treated as missing. Returns NULL only on parse or
 * allocation failure (message in `err`). */
FilterRuleList* filter_file_read(const char* dir_path, const char* owner_rel, bool* exists,
                                 char* err, size_t err_size);

/* Evaluate an entry against one ordered rule list. Returns FILTER_ACTION_NONE
 * when no rule matched, otherwise the first matching rule's action.
 * `rel_path` is the entry's path relative to the transfer root ("" == root),
 * `leaf` its final name, `is_dir` whether it is a directory. */
FilterAction filter_rules_apply(const FilterRuleList* list, const char* rel_path, const char* leaf,
                                bool is_dir);

#endif
