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
 * 's' sender side, 'r' receiver side, 'p' perishable.  The rsync 'x'
 * (xattr-name) modifier is not implemented and is rejected explicitly
 * everywhere.  The merge-only modifiers are accepted only on merge/dir-merge
 * rules (rejected on every other rule, matching rsync): 'e' excludes the merge
 * file itself, 'n' makes the merged rules non-inheriting (they apply only to
 * the directory that holds the merge file), 'w' word-splits the merge file on
 * whitespace instead of lines, and '-' reads the merge file as a list of bare
 * exclude patterns with no rule prefixes.
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
  bool no_inherit;     /* 'n' on the owning dir-merge: applies only in `owner` */
  char* owner;         /* owning directory rel path ("" == transfer root) */
  char* pattern;       /* cleaned glob pattern (no leading '/', no trailing '/') */
} FilterRule;

/* One per-directory merge-file registration ("dir-merge NAME"/": NAME", "merge
 * NAME"/". NAME" and -F's .rsync-filter) together with the merge-only modifiers
 * parsed from the rule.  The scanner reads `name` in every directory it
 * traverses and applies `no_prefixes`/`include`/`word_split`/`no_inherit`/
 * `exclude_self` while merging the file's rules. */
typedef struct {
  char* name;
  bool no_prefixes;  /* '-' : file holds only bare exclude patterns */
  bool include;      /* '+' : file holds only bare include patterns */
  bool word_split;   /* 'w' : split the file on whitespace, not lines */
  bool no_inherit;   /* 'n' : the merged rules do not inherit below their dir */
  bool exclude_self; /* 'e' : exclude the merge file itself from the transfer */
} FilterDirMerge;

typedef struct FilterRuleList {
  FilterRule** items; /* owned array of rule pointers */
  int count;
  int capacity;
  /* Per-directory merge-file registrations.  Owned; the scanner reads each
   * name in every directory it traverses. */
  FilterDirMerge* dir_merges;
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
/* Deep-copy a rule (owned pattern/owner).  Returns NULL on allocation failure. */
FilterRule* filter_rule_clone(const FilterRule* rule);
/* Replace a rule's owner directory (owned copy of `owner`, "" for the transfer
 * root).  Returns false on allocation failure, leaving the rule unchanged.
 * Used to re-express a mirrored per-directory rule in the receiver's
 * destination-relative coordinate system. */
bool filter_rule_set_owner(FilterRule* rule, const char* owner);

FilterRuleList* filter_rule_list_create(void);
/* Append a fully-parsed rule (takes ownership). Returns false on OOM. */
bool filter_rule_list_add(FilterRuleList* list, FilterRule* rule);
/* Register a per-directory merge-file basename (idempotent, no modifiers).
 * Returns false on OOM.  Used by the scanner to read custom "dir-merge" files. */
bool filter_rule_list_add_dir_merge(FilterRuleList* list, const char* name);
/* Register a per-directory merge file with its merge-only modifiers.  On a
 * duplicate name the existing registration is kept (rsync's first wins) and true
 * is returned.  When `exclude_self` is set an implicit exclude rule for the
 * merge file's basename is appended to the list at this position, matching
 * rsync's `e` modifier.  Returns false on OOM. */
bool filter_rule_list_add_dir_merge_ex(FilterRuleList* list, const char* name, bool no_prefixes,
                                       bool include, bool word_split, bool no_inherit,
                                       bool exclude_self);
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

/* Append a per-directory merge file honoring its merge-only modifiers: `-`
 * reads every (word-split, when `w`) token as a bare exclude, `+` as a bare
 * include, and `n` marks each read rule non-inheriting.  A plain name behaves
 * like filter_file_append.  A missing file yields *exists=false with no error;
 * returns false only on a parse/allocation failure (message in `err`). */
bool filter_dir_merge_append(FilterRuleList* list, const char* dir_path, const FilterDirMerge* spec,
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

/* Evaluate a received per-directory rule set for the receiver side, using
 * rsync's per-directory-before-ancestors order: the entry's containing
 * directory's rules are tried first, then each ancestor's, then the receive
 * root's.  `dir_rules` is a flat list whose rules carry `owner`; a rule applies
 * only when `owner` is exactly the directory being examined (a no-inherit rule
 * therefore applies only to that directory's direct children).  Returns the
 * first matching rule's receiver verdict (PROTECT/RISK) or FILTER_ACTION_NONE.
 * The caller evaluates the command-line base rules after this chain. */
FilterAction filter_dir_rules_apply_side(const FilterRuleList* dir_rules, const char* rel_path,
                                         const char* leaf, bool is_dir);

#endif
