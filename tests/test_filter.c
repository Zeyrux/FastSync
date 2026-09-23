#include "test_filter.h"
#include "filter.h"
#include "test_utils.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Every `-f`/`--filter` rule string is validated through the list parser, so
 * the list parser must reject the modifiers the standalone parser rejects
 * rather than silently folding them into a pattern. */

static void test_filter_list_rejects_xattr_modifier() {
  static const char* const rules[] = {
      "-x user.foo",             /* short exclude + x */
      "exclude,x user.foo",      /* long exclude + x */
      "+x user.foo",             /* include + x */
      "hide,x *.tmp",            /* hide + x */
      "dir-merge,x .rules",      /* x must not be dropped on dir-merge */
      "merge,x /tmp/nonexistent" /* x must not be dropped on merge */
  };
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
    FilterRuleList* list = filter_rule_list_create();
    EXPECT_NOT_NULL(list);
    char err[256] = "";
    bool ok = filter_rule_list_parse_append(list, rules[i], NULL, NULL, err, sizeof(err));
    EXPECT_FALSE(ok);
    EXPECT_TRUE(strstr(err, "xattr") != NULL);
    filter_rule_list_free(list);
  }

  /* A bare "x" is not a rule at all: rejected as generic bad syntax. */
  FilterRuleList* list = filter_rule_list_create();
  EXPECT_NOT_NULL(list);
  char err[256] = "";
  EXPECT_FALSE(filter_rule_list_parse_append(list, "x user.foo", NULL, NULL, err, sizeof(err)));
  EXPECT_TRUE(err[0] != '\0');
  filter_rule_list_free(list);
}

static void test_filter_list_rejects_unsupported_modifiers() {
  /* The merge-file modifiers e/n/w/- are invalid on every non-merge rule; a
     token made up solely of modifier characters is a modifier run, so it must
     be rejected rather than folded into the pattern. */
  static const char* const rules[] = {
      "-e foo", /* e: merge-only in rsync */
      "-n foo", /* n: merge-only in rsync */
      "-w foo", /* w: merge-only in rsync */
      "-new",   /* pure modifier letters (n/e/w) */
      "-press", /* pure modifier letters (p/r/e/s) */
      "exclude,w foo", "exclude,e foo", "exclude,n foo",
      "hide,w foo",    "protect,n foo", "risk,e foo",
  };
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
    FilterRuleList* list = filter_rule_list_create();
    EXPECT_NOT_NULL(list);
    char err[256] = "";
    bool ok = filter_rule_list_parse_append(list, rules[i], NULL, NULL, err, sizeof(err));
    EXPECT_FALSE(ok);
    EXPECT_TRUE(strstr(err, "unsupported filter modifier") != NULL);
    filter_rule_list_free(list);
  }
}

/* rsync accepts the merge-file modifiers e/n/w/- on merge and dir-merge rules.
 * They must be consumed so they never leak into the merge filename, and their
 * semantics (exclude-self, no-inherit, word-split, no-prefixes) must be
 * applied while the file is read. */
static void test_filter_list_accepts_merge_modifiers() {
  char tmpl[] = "/tmp/fastsync_filter_mmod_XXXXXX";
  EXPECT_TRUE(mkdtemp(tmpl) != NULL);
  char prefixed[512];
  char bare[512];
  char words[512];
  snprintf(prefixed, sizeof(prefixed), "%s/prefixed", tmpl);
  snprintf(bare, sizeof(bare), "%s/bare", tmpl);
  snprintf(words, sizeof(words), "%s/words", tmpl);
  FILE* fp = fopen(prefixed, "w");
  EXPECT_NOT_NULL(fp);
  fputs("- *.tmp\n", fp);
  fclose(fp);
  fp = fopen(bare, "w");
  EXPECT_NOT_NULL(fp);
  fputs("*.log\n*.tmp\n", fp);
  fclose(fp);
  fp = fopen(words, "w");
  EXPECT_NOT_NULL(fp);
  fputs("*.log *.tmp\n", fp);
  fclose(fp);

  /* dir-merge with e/n/w/- registers the basename without the modifiers and
   * records the modifier flags; 'e' appends an exclude-self rule. */
  static const struct {
    const char* rule;
    const char* want;
    bool no_prefixes;
    bool word_split;
    bool no_inherit;
    bool exclude_self;
  } drules[] = {
      {"dir-merge,e .rules", ".rules", false, false, false, true},
      {"dir-merge,n .rules", ".rules", false, false, true, false},
      {"dir-merge,w .rules", ".rules", false, true, false, false},
      {"dir-merge,- .rules", ".rules", true, false, false, false},
      {":e .rules", ".rules", false, false, false, true},
      {":- .rules", ".rules", true, false, false, false},
  };
  for (size_t i = 0; i < sizeof(drules) / sizeof(drules[0]); i++) {
    FilterRuleList* list = filter_rule_list_create();
    EXPECT_NOT_NULL(list);
    char err[256] = "";
    bool ok = filter_rule_list_parse_append(list, drules[i].rule, NULL, NULL, err, sizeof(err));
    if (!ok)
      printf("    dir-merge rule '%s' errored: %s\n", drules[i].rule, err);
    EXPECT_TRUE(ok);
    EXPECT_EQ_INT(list->dir_merge_count, 1);
    EXPECT_EQ_STR(list->dir_merges[0].name, drules[i].want);
    EXPECT_EQ_INT(list->dir_merges[0].no_prefixes, drules[i].no_prefixes);
    EXPECT_EQ_INT(list->dir_merges[0].word_split, drules[i].word_split);
    EXPECT_EQ_INT(list->dir_merges[0].no_inherit, drules[i].no_inherit);
    EXPECT_EQ_INT(list->dir_merges[0].exclude_self, drules[i].exclude_self);
    if (drules[i].exclude_self) {
      EXPECT_EQ_INT(list->count, 1);
      EXPECT_EQ_STR(list->items[0]->pattern, ".rules");
      EXPECT_EQ_INT(list->items[0]->action, FILTER_ACTION_EXCLUDE);
    } else {
      EXPECT_EQ_INT(list->count, 0);
    }
    filter_rule_list_free(list);
  }

  /* merge,n reads the file normally; no-inherit is meaningless for a single
   * merge so the rule is not marked. */
  {
    FilterRuleList* list = filter_rule_list_create();
    char err[256] = "";
    char rule[600];
    snprintf(rule, sizeof(rule), "merge,n %s", prefixed);
    EXPECT_TRUE(filter_rule_list_parse_append(list, rule, NULL, NULL, err, sizeof(err)));
    EXPECT_EQ_INT(list->count, 1);
    EXPECT_EQ_STR(list->items[0]->pattern, "*.tmp");
    EXPECT_FALSE(list->items[0]->no_inherit);
    filter_rule_list_free(list);
  }

  /* merge,e adds an implicit exclude for the merge file's basename. */
  {
    FilterRuleList* list = filter_rule_list_create();
    char err[256] = "";
    char rule[600];
    snprintf(rule, sizeof(rule), "merge,e %s", prefixed);
    EXPECT_TRUE(filter_rule_list_parse_append(list, rule, NULL, NULL, err, sizeof(err)));
    EXPECT_EQ_INT(list->count, 2);
    EXPECT_EQ_STR(list->items[0]->pattern, "prefixed");
    EXPECT_EQ_INT(list->items[0]->action, FILTER_ACTION_EXCLUDE);
    EXPECT_EQ_STR(list->items[1]->pattern, "*.tmp");
    filter_rule_list_free(list);
  }

  /* merge,- reads the file as bare exclude patterns with no prefix parsing. */
  {
    FilterRuleList* list = filter_rule_list_create();
    char err[256] = "";
    char rule[600];
    snprintf(rule, sizeof(rule), "merge,- %s", bare);
    EXPECT_TRUE(filter_rule_list_parse_append(list, rule, NULL, NULL, err, sizeof(err)));
    EXPECT_EQ_INT(list->count, 2);
    EXPECT_EQ_STR(list->items[0]->pattern, "*.log");
    EXPECT_EQ_STR(list->items[1]->pattern, "*.tmp");
    filter_rule_list_free(list);
  }

  /* merge,-w word-splits bare patterns on whitespace. */
  {
    FilterRuleList* list = filter_rule_list_create();
    char err[256] = "";
    char rule[600];
    snprintf(rule, sizeof(rule), "merge,w- %s", words);
    EXPECT_TRUE(filter_rule_list_parse_append(list, rule, NULL, NULL, err, sizeof(err)));
    EXPECT_EQ_INT(list->count, 2);
    EXPECT_EQ_STR(list->items[0]->pattern, "*.log");
    EXPECT_EQ_STR(list->items[1]->pattern, "*.tmp");
    filter_rule_list_free(list);
  }

  unlink(prefixed);
  unlink(bare);
  unlink(words);
  rmdir(tmpl);
}

static void test_filter_list_accepts_supported_rules_and_modifiers() {
  static const char* const rules[] = {
      "- *.tmp",  "+ /a.txt",         "-s foo",     "-r foo",     "-p foo",
      "-! *.o",   "-/ foo",           "hide *.tmp", "show *.txt", "protect *.bak",
      "risk *.o", "dir-merge .rules", "-C",
  };
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
    FilterRuleList* list = filter_rule_list_create();
    EXPECT_NOT_NULL(list);
    char err[256] = "";
    bool ok = filter_rule_list_parse_append(list, rules[i], NULL, NULL, err, sizeof(err));
    if (!ok)
      printf("    rule '%s' errored: %s\n", rules[i], err);
    EXPECT_TRUE(ok);
    filter_rule_list_free(list);
  }

  /* A glued word is a pattern, not a modifier run (no separator). */
  {
    FilterRuleList* list = filter_rule_list_create();
    char err[128] = "";
    EXPECT_TRUE(filter_rule_list_parse_append(list, "-newfile", NULL, NULL, err, sizeof(err)));
    EXPECT_EQ_INT(list->count, 1);
    EXPECT_EQ_STR(list->items[0]->pattern, "newfile");
    filter_rule_list_free(list);

    list = filter_rule_list_create();
    EXPECT_TRUE(filter_rule_list_parse_append(list, "-e2e", NULL, NULL, err, sizeof(err)));
    EXPECT_EQ_INT(list->count, 1);
    EXPECT_EQ_STR(list->items[0]->pattern, "e2e");
    filter_rule_list_free(list);

    list = filter_rule_list_create();
    EXPECT_TRUE(filter_rule_list_parse_append(list, "-*.o", NULL, NULL, err, sizeof(err)));
    EXPECT_EQ_INT(list->count, 1);
    EXPECT_EQ_STR(list->items[0]->pattern, "*.o");
    filter_rule_list_free(list);

    /* A comma with no modifier still treats the rest as the pattern. */
    list = filter_rule_list_create();
    EXPECT_TRUE(filter_rule_list_parse_append(list, "exclude,foo", NULL, NULL, err, sizeof(err)));
    EXPECT_EQ_INT(list->count, 1);
    EXPECT_EQ_STR(list->items[0]->pattern, "foo");
    filter_rule_list_free(list);
  }

  /* `!` clears the list. */
  {
    FilterRuleList* list = filter_rule_list_create();
    char err[128] = "";
    EXPECT_TRUE(filter_rule_list_parse_append(list, "- *.tmp", NULL, NULL, err, sizeof(err)));
    EXPECT_EQ_INT(list->count, 1);
    EXPECT_TRUE(filter_rule_list_parse_append(list, "!", NULL, NULL, err, sizeof(err)));
    EXPECT_EQ_INT(list->count, 0);
    filter_rule_list_free(list);
  }

  /* -C injects the CVS defaults. */
  {
    FilterRuleList* list = filter_rule_list_create();
    char err[128] = "";
    EXPECT_TRUE(filter_rule_list_parse_append(list, "-C", NULL, NULL, err, sizeof(err)));
    EXPECT_TRUE(list->count > 0);
    filter_rule_list_free(list);
  }
}

/* A "clear"/"!" inside a merge file resets the list to empty.  Rules read after
 * it must still be owned by the merge file's directory (and marked no-inherit
 * when the dir-merge says so).  The base index must follow the clear down: when
 * it was captured before the clear, post-clear rules sat below it and were left
 * globally owned by "" (and unmarked). */
static void test_filter_merge_clear_then_owner() {
  char tmpl[] = "/tmp/fastsync_filter_clear_XXXXXX";
  EXPECT_TRUE(mkdtemp(tmpl) != NULL);
  char path[512];
  snprintf(path, sizeof(path), "%s/.rsync-filter", tmpl);
  FILE* fp = fopen(path, "w");
  EXPECT_NOT_NULL(fp);
  fputs("- *.tmp\n!\nP *.log\n", fp);
  fclose(fp);

  FilterRuleList* list = filter_rule_list_create();
  EXPECT_NOT_NULL(list);
  char err[256] = "";
  /* A pre-existing rule that the in-file clear must discard. */
  EXPECT_TRUE(filter_rule_list_parse_append(list, "- keep.txt", NULL, NULL, err, sizeof(err)));
  EXPECT_EQ_INT(list->count, 1);

  FilterDirMerge spec = {.name = ".rsync-filter", .no_inherit = true};
  bool exists = false;
  EXPECT_TRUE(filter_dir_merge_append(list, tmpl, &spec, "sub", NULL, &exists, err, sizeof(err)));
  EXPECT_TRUE(exists);
  /* Only the post-clear rule survives, owned by "sub" and no-inherit. */
  EXPECT_EQ_INT(list->count, 1);
  EXPECT_EQ_STR(list->items[0]->pattern, "*.log");
  EXPECT_EQ_STR(list->items[0]->owner, "sub");
  EXPECT_TRUE(list->items[0]->no_inherit);
  filter_rule_list_free(list);

  /* A parse failure after the clear must roll the list back to the post-clear
   * base (empty here), freeing the post-clear rule rather than retaining it. */
  fp = fopen(path, "w");
  EXPECT_NOT_NULL(fp);
  fputs("- *.tmp\n!\nP *.log\n-e bogus\n", fp);
  fclose(fp);
  list = filter_rule_list_create();
  EXPECT_NOT_NULL(list);
  EXPECT_TRUE(filter_rule_list_parse_append(list, "- keep.txt", NULL, NULL, err, sizeof(err)));
  EXPECT_EQ_INT(list->count, 1);
  exists = false;
  EXPECT_FALSE(filter_dir_merge_append(list, tmpl, &spec, "sub", NULL, &exists, err, sizeof(err)));
  EXPECT_TRUE(exists);
  EXPECT_EQ_INT(list->count, 0);
  filter_rule_list_free(list);

  unlink(path);
  rmdir(tmpl);
}

static void test_filter_list_merge_file_still_supported() {
  char tmpl[] = "/tmp/fastsync_filter_XXXXXX";
  EXPECT_TRUE(mkdtemp(tmpl) != NULL);
  char path[512];
  snprintf(path, sizeof(path), "%s/rules", tmpl);
  FILE* fp = fopen(path, "w");
  EXPECT_NOT_NULL(fp);
  fputs("- *.tmp\n", fp);
  fclose(fp);

  FilterRuleList* list = filter_rule_list_create();
  char err[256] = "";
  char rule[600];
  snprintf(rule, sizeof(rule), "merge %s", path);
  EXPECT_TRUE(filter_rule_list_parse_append(list, rule, NULL, NULL, err, sizeof(err)));
  EXPECT_EQ_INT(list->count, 1);
  filter_rule_list_free(list);

  /* The same merge with the x modifier is rejected, not silently read. */
  list = filter_rule_list_create();
  snprintf(rule, sizeof(rule), "merge,x %s", path);
  EXPECT_FALSE(filter_rule_list_parse_append(list, rule, NULL, NULL, err, sizeof(err)));
  EXPECT_TRUE(strstr(err, "xattr") != NULL);
  filter_rule_list_free(list);

  unlink(path);
  rmdir(tmpl);
}

static void test_filter_rule_parse_rejects_unsupported_and_keeps_supported() {
  char err[256] = "";

  EXPECT_NULL(filter_rule_parse("-x user.foo", NULL, err, sizeof(err)));
  EXPECT_TRUE(strstr(err, "xattr") != NULL);

  EXPECT_NULL(filter_rule_parse("-e foo", NULL, err, sizeof(err)));
  EXPECT_TRUE(strstr(err, "unsupported filter modifier") != NULL);

  FilterRule* rule = filter_rule_parse("- *.tmp", NULL, err, sizeof(err));
  EXPECT_NOT_NULL(rule);
  EXPECT_EQ_STR(rule->pattern, "*.tmp");
  filter_rule_free(rule);

  rule = filter_rule_parse("-newfile", NULL, err, sizeof(err));
  EXPECT_NOT_NULL(rule);
  EXPECT_EQ_STR(rule->pattern, "newfile");
  filter_rule_free(rule);
}

static void test_filter_rules_apply_supported_modifiers() {
  /* exclude */
  {
    const char* texts[] = {"- *.tmp"};
    FilterRuleList* list = filter_base_build(texts, 1, false, false, NULL, 0);
    EXPECT_NOT_NULL(list);
    EXPECT_EQ_INT(filter_rules_apply_side(list, "b.tmp", "b.tmp", false, FILTER_SIDE_SENDER),
                  FILTER_ACTION_EXCLUDE);
    EXPECT_EQ_INT(filter_rules_apply_side(list, "a.txt", "a.txt", false, FILTER_SIDE_SENDER),
                  FILTER_ACTION_NONE);
    filter_rule_list_free(list);
  }
  /* anchored include then exclude-all */
  {
    const char* texts[] = {"+ /a.txt", "- *"};
    FilterRuleList* list = filter_base_build(texts, 2, false, false, NULL, 0);
    EXPECT_NOT_NULL(list);
    EXPECT_EQ_INT(filter_rules_apply_side(list, "a.txt", "a.txt", false, FILTER_SIDE_SENDER),
                  FILTER_ACTION_INCLUDE);
    EXPECT_EQ_INT(filter_rules_apply_side(list, "b.txt", "b.txt", false, FILTER_SIDE_SENDER),
                  FILTER_ACTION_EXCLUDE);
    filter_rule_list_free(list);
  }
  /* negate */
  {
    const char* texts[] = {"-! *.o"};
    FilterRuleList* list = filter_base_build(texts, 1, false, false, NULL, 0);
    EXPECT_NOT_NULL(list);
    EXPECT_EQ_INT(filter_rules_apply_side(list, "foo.c", "foo.c", false, FILTER_SIDE_SENDER),
                  FILTER_ACTION_EXCLUDE);
    EXPECT_EQ_INT(filter_rules_apply_side(list, "foo.o", "foo.o", false, FILTER_SIDE_SENDER),
                  FILTER_ACTION_NONE);
    filter_rule_list_free(list);
  }
  /* dir-only trailing slash */
  {
    const char* texts[] = {"+ dir/", "- *"};
    FilterRuleList* list = filter_base_build(texts, 2, false, false, NULL, 0);
    EXPECT_NOT_NULL(list);
    EXPECT_EQ_INT(filter_rules_apply_side(list, "dir", "dir", true, FILTER_SIDE_SENDER),
                  FILTER_ACTION_INCLUDE);
    EXPECT_EQ_INT(filter_rules_apply_side(list, "dir", "dir", false, FILTER_SIDE_SENDER),
                  FILTER_ACTION_EXCLUDE);
    filter_rule_list_free(list);
  }
}

static FilterRule* chain_rule(const char* owner, const char* pattern, FilterAction action,
                              bool no_inherit) {
  FilterRule* rule = calloc(1, sizeof(FilterRule));
  if (!rule)
    return NULL;
  rule->action = action;
  rule->sides = FILTER_SIDE_SENDER | FILTER_SIDE_RECEIVER;
  rule->owner = str_dup(owner);
  rule->pattern = str_dup(pattern);
  rule->no_inherit = no_inherit;
  if (!rule->owner || !rule->pattern) {
    filter_rule_free(rule);
    return NULL;
  }
  return rule;
}

/* The receiver's per-directory chain: a containing directory's rules win over
 * an ancestor's (deepest-first), root rules are inherited, and a no-inherit
 * rule applies only to its own directory's direct children. */
static void test_filter_dir_rules_chain(void) {
  FilterRuleList* list = filter_rule_list_create();
  EXPECT_NOT_NULL(list);
  FilterRule* root_log = chain_rule("", "*.log", FILTER_ACTION_EXCLUDE, false);
  FilterRule* sub_keep = chain_rule("sub", "keep.log", FILTER_ACTION_INCLUDE, false);
  FilterRule* sub_tmp = chain_rule("sub", "*.tmp", FILTER_ACTION_EXCLUDE, true);
  EXPECT_NOT_NULL(root_log);
  EXPECT_NOT_NULL(sub_keep);
  EXPECT_NOT_NULL(sub_tmp);
  EXPECT_TRUE(filter_rule_list_add(list, root_log));
  EXPECT_TRUE(filter_rule_list_add(list, sub_keep));
  EXPECT_TRUE(filter_rule_list_add(list, sub_tmp));

  /* Root rule inherited by every directory (leaf match). */
  EXPECT_EQ_INT(filter_dir_rules_apply_side(list, "a.log", "a.log", false), FILTER_ACTION_PROTECT);
  EXPECT_EQ_INT(filter_dir_rules_apply_side(list, "sub/a.log", "a.log", false),
                FILTER_ACTION_PROTECT);
  /* The deeper include overrides the inherited root exclude. */
  EXPECT_EQ_INT(filter_dir_rules_apply_side(list, "sub/keep.log", "keep.log", false),
                FILTER_ACTION_RISK);
  /* No-inherit applies directly in its owner... */
  EXPECT_EQ_INT(filter_dir_rules_apply_side(list, "sub/x.tmp", "x.tmp", false),
                FILTER_ACTION_PROTECT);
  /* ...but not below it. */
  EXPECT_EQ_INT(filter_dir_rules_apply_side(list, "sub/deep/x.tmp", "x.tmp", false),
                FILTER_ACTION_NONE);
  /* No matching rule. */
  EXPECT_EQ_INT(filter_dir_rules_apply_side(list, "sub/deep/plain.txt", "plain.txt", false),
                FILTER_ACTION_NONE);
  filter_rule_list_free(list);
}

static void test_filter_rule_clone_copies_every_field(void) {
  char err[128] = "";
  FilterRule* original = filter_rule_parse("-!p /a/*.o", NULL, err, sizeof(err));
  EXPECT_NOT_NULL(original);
  FilterRule* copy = filter_rule_clone(original);
  EXPECT_NOT_NULL(copy);
  EXPECT_TRUE(copy != original);
  EXPECT_EQ_INT(copy->action, original->action);
  EXPECT_EQ_INT(copy->sides, original->sides);
  EXPECT_EQ_INT(copy->anchored, original->anchored);
  EXPECT_EQ_INT(copy->dir_only, original->dir_only);
  EXPECT_EQ_INT(copy->negate, original->negate);
  EXPECT_EQ_INT(copy->perishable, original->perishable);
  EXPECT_EQ_STR(copy->pattern, original->pattern);
  filter_rule_free(original);
  filter_rule_free(copy);
}

void test_filter() {
  test_filter_list_rejects_xattr_modifier();
  test_filter_list_rejects_unsupported_modifiers();
  test_filter_list_accepts_merge_modifiers();
  test_filter_list_accepts_supported_rules_and_modifiers();
  test_filter_list_merge_file_still_supported();
  test_filter_merge_clear_then_owner();
  test_filter_rule_parse_rejects_unsupported_and_keeps_supported();
  test_filter_rules_apply_supported_modifiers();
  test_filter_dir_rules_chain();
  test_filter_rule_clone_copies_every_field();
}
