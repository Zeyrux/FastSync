#include "test_filter.h"
#include "filter.h"
#include "test_utils.h"
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
 * They must be consumed so they never leak into the merge filename. */
static void test_filter_list_accepts_merge_modifiers() {
  char tmpl[] = "/tmp/fastsync_filter_mmod_XXXXXX";
  EXPECT_TRUE(mkdtemp(tmpl) != NULL);
  char path[512];
  snprintf(path, sizeof(path), "%s/rules", tmpl);
  FILE* fp = fopen(path, "w");
  EXPECT_NOT_NULL(fp);
  fputs("- *.tmp\n", fp);
  fclose(fp);

  /* merge with e/n/w/- consumes the modifiers and reads the right file. */
  static const char* const fmts[] = {
      "merge,e %s", "merge,n %s", "merge,w %s", "merge,- %s", ".e %s", ".- %s",
  };
  for (size_t i = 0; i < sizeof(fmts) / sizeof(fmts[0]); i++) {
    FilterRuleList* list = filter_rule_list_create();
    EXPECT_NOT_NULL(list);
    char rule[600];
    char err[256] = "";
    snprintf(rule, sizeof(rule), fmts[i], path);
    bool ok = filter_rule_list_parse_append(list, rule, NULL, NULL, err, sizeof(err));
    if (!ok)
      printf("    merge rule '%s' errored: %s\n", rule, err);
    EXPECT_TRUE(ok);
    EXPECT_EQ_INT(list->count, 1);
    EXPECT_EQ_STR(list->items[0]->pattern, "*.tmp");
    filter_rule_list_free(list);
  }

  /* dir-merge with e/n/w/- registers the basename without the modifiers. */
  static const struct {
    const char* rule;
    const char* want;
  } drules[] = {
      {"dir-merge,e .rules", ".rules"}, {"dir-merge,n .rules", ".rules"},
      {"dir-merge,w .rules", ".rules"}, {"dir-merge,- .rules", ".rules"},
      {":e .rules", ".rules"},          {":- .rules", ".rules"},
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
    EXPECT_EQ_STR(list->dir_merge_names[0], drules[i].want);
    filter_rule_list_free(list);
  }

  unlink(path);
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

void test_filter() {
  test_filter_list_rejects_xattr_modifier();
  test_filter_list_rejects_unsupported_modifiers();
  test_filter_list_accepts_merge_modifiers();
  test_filter_list_accepts_supported_rules_and_modifiers();
  test_filter_list_merge_file_still_supported();
  test_filter_rule_parse_rejects_unsupported_and_keeps_supported();
  test_filter_rules_apply_supported_modifiers();
}
