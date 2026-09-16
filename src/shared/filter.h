#ifndef FILTER_H
#define FILTER_H

#include <stdbool.h>
#include <stddef.h>

/* rsync-style filter rule engine (client-side file selection and the
 * receiver-side protection set it feeds).
 *
 * Rule syntax (see the rsync man page FILTER RULES section):
 *   RULE [PATTERN_OR_FILENAME]
 *   RULE,MODIFIERS [PATTERN_OR_FILENAME]
 * Short RULE names may attach MODIFIERS directly ("-sr foo"); the long name
 * form requires the comma.  The pattern/filename is separated from the rule by
 * one space or underscore.  Rule names:
 *   exclude/-   exclude (by default both sender-hide and receiver-protect)
 *   include/+   include (by default both sender-show and receiver-risk)
 *   hide/H      sender-only exclude
 *   show/S      sender-only include
 *   protect/P   receiver-only exclude (protect from deletion)
 *   risk/R      receiver-only include (allow deletion)
 *   merge/.     read a client-side merge file for more rules
 *   dir-merge/: per-directory merge file (registered for the scanner)
 *   clear/!     clear the current rule list (takes no argument)
 * Modifiers: '/' absolute anchor, '!' negate match, 'C' inject CVS defaults,
 * 's' sender side, 'r' receiver side, 'p' perishable, 'x' xattr name rule.
 * A trailing '/' makes a pattern match directories only.  A leading '/' anchors
 * the pattern to its owner directory.
 */

typedef enum {
  FILTER_ACTION_NONE = 0, /* no rule matched */
  FILTER_ACTION_EXCLUDE = -1,
  FILTER_ACTION_INCLUDE = 1,
  /* Receiver-side-only verdicts: the entry is transferred but its destination
   * mirror is protected from --delete (PROTECT) or explicitly left at risk
   * (RISK). */
  FILTER_ACTION_PROTECT = 2,
  FILTER_ACTION_RISK = 3,
} FilterAction;

#define FILTER_SIDE_SENDER 1u
#define FILTER_SIDE_RECEIVER 2u

typedef struct {
  FilterAction action; /* EXCLUDE or INCLUDE (the base pattern action) */
  unsigned sides;      /* FILTER_SIDE_SENDER | FILTER_SIDE_RECEIVER */
  bool anchored;       /* pattern anchored to the rule's owner directory */
  bool dir_only;       /* pattern had a trailing '/': matches directories only */
  bool negate;         /* '!' modifier: match succeeds when the pattern does not */
  bool perishable;     /* 'p' modifier (ignored in deleted directories) */
  char* owner;         /* owning directory rel path ("" == transfer root) */
  char* pattern;       /* cleaned glob pattern (no leading '/', no trailing '/') */
} FilterRule;

typedef struct {
  FilterRule** items; /* owned array of rule pointers */
  int count;
  int capacity;
  /* Per-directory merge-file basenames registered by "dir-merge NAME"/": NAME"
   * or by -F (.rsync-filter).  Owned strings; the scanner reads each name in
   * every directory it traverses. */
  char** dir_merge_names;
  int dir_merge_count;
  int dir_merge_capacity;
} FilterRuleList;

/* Context needed while parsing a rule list (merge files, --delete-excluded). */
typedef struct {
  bool delete_excluded; /* --delete-excluded: default sides become sender-only */
  bool cvs_exclude;     /* -C: expand the CVS default excludes */
} FilterParseOptions;

/* Parse a single filter-rule line (no trailing newline required). Returns an
 * owned rule, or NULL on unsupported/invalid syntax with a message in `err`.
 * `opts` may be NULL (no merge expansion / no delete-excluded). */
FilterRule* filter_rule_parse(const char* line, const FilterParseOptions* opts, char* err,
                              size_t err_size);
void filter_rule_free(FilterRule* rule);

FilterRuleList* filter_rule_list_create(void);
/* Append a fully-parsed rule (takes ownership). Returns false on OOM. */
bool filter_rule_list_add(FilterRuleList* list, FilterRule* rule);
/* Register a per-directory merge-file basename (idempotent). Returns false on
 * OOM.  Used by the scanner to read custom "dir-merge" files. */
bool filter_rule_list_add_dir_merge(FilterRuleList* list, const char* name);
/* Parse `line` and append it.  Handles "clear"/"!" (resets the list), "merge
 * FILE"/". FILE" (splices the file's rules) and "dir-merge NAME"/": NAME"
 * (registers a per-directory filename).  Returns false and fills `err` on bad
 * syntax or an unreadable merge file.  `merge_base_dir` resolves a relative
 * merge-file path (NULL means the process working directory). */
bool filter_rule_list_parse_append(FilterRuleList* list, const char* line,
                                   const FilterParseOptions* opts, const char* merge_base_dir,
                                   char* err, size_t err_size);
void filter_rule_list_free(FilterRuleList* list);

/* Build the command-line filter set: `rule_texts` (--filter=RULE in the order
 * given, 0..rule_count) followed by the -C CVS default excludes when
 * cvs_exclude is true.  All rules are owned by "" (the transfer root).
 * Returns NULL on unsupported rule text (message in `err`). */
FilterRuleList* filter_base_build(const char* const* rule_texts, int rule_count, bool cvs_exclude,
                                  bool delete_excluded, char* err, size_t err_size);

/* Read "<dir_path>/<name>" and return its rules, each owned by `owner_rel`.  A
 * missing file yields an empty list with *exists=false; an unreadable file is
 * treated as missing.  Returns NULL only on parse or allocation failure
 * (message in `err`).  `opts` may be NULL. */
FilterRuleList* filter_file_read_named(const char* dir_path, const char* name,
                                       const char* owner_rel, const FilterParseOptions* opts,
                                       bool* exists, char* err, size_t err_size);

/* Append the rules of "<dir_path>/<name>" into an existing list (each owned by
 * `owner_rel`).  A missing file yields *exists=false and no error.  Returns
 * false only on parse/allocation failure (message in `err`). */
bool filter_file_append(FilterRuleList* list, const char* dir_path, const char* name,
                        const char* owner_rel, const FilterParseOptions* opts, bool* exists,
                        char* err, size_t err_size);

/* filter_file_read_named with the default ".rsync-filter" name. */
FilterRuleList* filter_file_read(const char* dir_path, const char* owner_rel, bool* exists,
                                 char* err, size_t err_size);

/* Evaluate an entry against one ordered rule list for one side.  Returns
 * FILTER_ACTION_NONE when no rule matched, otherwise the first matching rule's
 * action (for the receiver side an EXCLUDE is reported as
 * FILTER_ACTION_PROTECT and an INCLUDE as FILTER_ACTION_RISK).  `rel_path` is
 * the entry's path relative to the transfer root ("" == root), `leaf` its final
 * name, `is_dir` whether it is a directory. */
FilterAction filter_rules_apply_side(const FilterRuleList* list, const char* rel_path,
                                     const char* leaf, bool is_dir, unsigned side);

/* Sender-side convenience wrapper (kept for callers/tests that only need the
 * transfer decision). */
FilterAction filter_rules_apply(const FilterRuleList* list, const char* rel_path, const char* leaf,
                                bool is_dir);

#endif
