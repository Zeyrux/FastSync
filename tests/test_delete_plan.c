#include "test_delete_plan.h"
#include "charset.h"
#include "config.h"
#include "delete_plan.h"
#include "protocol.h"
#include "test_utils.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* Send one STATUS_DELETE_PLAN body (the leading status is consumed by the
 * caller/receiver entry point) describing `dir` with no kept children. */
static void send_plan_frame(int fd, const char* dir) {
  EXPECT_TRUE(send_int(fd, 0)); /* has_config */
  EXPECT_TRUE(send_int(fd, 1)); /* apply: a real plan */
  EXPECT_TRUE(send_wire_str(fd, dir));
  EXPECT_TRUE(send_int(fd, 0)); /* kept child dirs */
  EXPECT_TRUE(send_int(fd, 0)); /* kept child files */
}

/* --delete-delay: a directory snapshotted into the plan that is refilled before
 * the commit is re-scanned and removed recursively (rsync parity).  Regression
 * for the old single-unlink ENOTEMPTY path that left the directory behind. */
static void test_delete_delay_refilled_dir_removed_recursively(void) {
  char root[] = "/tmp/fastsync_dp_refill_XXXXXX";
  EXPECT_TRUE(mkdtemp(root) != NULL);
  char extra[1024];
  snprintf(extra, sizeof(extra), "%s/extra", root);
  EXPECT_EQ_INT(mkdir(extra, 0700), 0);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  config->receive_root_directory = str_dup(root);
  config->use_delete = true;
  config->delete_delay = true;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);

  DeletePlanSession* session = delete_plan_session_create(config);
  EXPECT_NOT_NULL(session);
  send_plan_frame(p[1], ".");
  EXPECT_EQ_INT(delete_plan_session_receive(session, config, p[0]), 0);
  /* The empty extra directory was snapshotted, not removed yet. */
  EXPECT_EQ_INT((int)delete_plan_session_deleted(session), 0);

  /* Refill the directory while the deferred commit is pending. */
  char refill[1200];
  snprintf(refill, sizeof(refill), "%s/new.txt", extra);
  int fd = open(refill, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  EXPECT_TRUE(fd >= 0);
  close(fd);

  EXPECT_EQ_INT(delete_plan_session_commit(session, config), DELETE_COMMIT_OK);
  /* The late content and the directory itself are both removed. */
  EXPECT_EQ_INT((int)delete_plan_session_deleted(session), 2);
  struct stat st;
  EXPECT_TRUE(lstat(extra, &st) != 0);

  delete_plan_session_destroy(session);
  close(p[0]);
  close(p[1]);
  rmdir(root);
  config_delete(config);
}

/* The complement: a deferred regular extra that DOES get removed is counted. */
static void test_delete_delay_removed_file_counted(void) {
  char root[] = "/tmp/fastsync_dp_file_XXXXXX";
  EXPECT_TRUE(mkdtemp(root) != NULL);
  char extra[1024];
  snprintf(extra, sizeof(extra), "%s/extra.txt", root);
  int fd = open(extra, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  EXPECT_TRUE(fd >= 0);
  close(fd);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  config->receive_root_directory = str_dup(root);
  config->use_delete = true;
  config->delete_delay = true;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);

  DeletePlanSession* session = delete_plan_session_create(config);
  EXPECT_NOT_NULL(session);
  send_plan_frame(p[1], ".");
  EXPECT_EQ_INT(delete_plan_session_receive(session, config, p[0]), 0);
  EXPECT_EQ_INT((int)delete_plan_session_deleted(session), 0);
  EXPECT_EQ_INT(delete_plan_session_commit(session, config), DELETE_COMMIT_OK);
  EXPECT_EQ_INT((int)delete_plan_session_deleted(session), 1);
  EXPECT_TRUE(lstat(extra, &(struct stat){0}) != 0);

  delete_plan_session_destroy(session);
  close(p[0]);
  close(p[1]);
  rmdir(root);
  config_delete(config);
}

/* --max-delete is charged on actual removals, not at plan/snapshot time: after
 * receiving the plans the budget is untouched, and only the commit removes up to
 * the limit. */
static void test_delete_delay_max_delete_bounds_actual(void) {
  char root[] = "/tmp/fastsync_dp_max_XXXXXX";
  EXPECT_TRUE(mkdtemp(root) != NULL);
  for (int i = 0; i < 3; i++) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/e%d.txt", root, i);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    EXPECT_TRUE(fd >= 0);
    close(fd);
  }

  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  config->receive_root_directory = str_dup(root);
  config->use_delete = true;
  config->delete_delay = true;
  config->max_delete = 1;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);

  DeletePlanSession* session = delete_plan_session_create(config);
  EXPECT_NOT_NULL(session);
  send_plan_frame(p[1], ".");
  EXPECT_EQ_INT(delete_plan_session_receive(session, config, p[0]), 0);
  /* Nothing removed yet, so the budget is not consumed at snapshot time. */
  EXPECT_FALSE(delete_plan_session_limit_reached(session));
  EXPECT_EQ_INT((int)delete_plan_session_deleted(session), 0);
  EXPECT_EQ_INT(delete_plan_session_commit(session, config), DELETE_COMMIT_LIMIT_REACHED);
  EXPECT_TRUE(delete_plan_session_limit_reached(session));
  EXPECT_EQ_INT((int)delete_plan_session_deleted(session), 1);

  delete_plan_session_destroy(session);
  close(p[0]);
  close(p[1]);
  for (int i = 0; i < 3; i++) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/e%d.txt", root, i);
    unlink(path);
  }
  rmdir(root);
  config_delete(config);
}

/* --max-delete is charged on ACTUAL removals: the refilled directory's late
 * content is removed first (consuming the single budget slot), so the directory
 * itself and the later extra are skipped, matching rsync.  The two plans are
 * sent as separate frames for "a" then "b", so the ordering that decides which
 * entry gets the budget is deterministic (unlike readdir order). */
static void test_delete_delay_actual_removal_charges_budget(void) {
  char root[] = "/tmp/fastsync_dp_planbudget_XXXXXX";
  EXPECT_TRUE(mkdtemp(root) != NULL);
  char adir[1024], bdir[1024], xdir[1024], ydir[1024];
  snprintf(adir, sizeof(adir), "%s/a", root);
  snprintf(bdir, sizeof(bdir), "%s/b", root);
  snprintf(xdir, sizeof(xdir), "%s/a/x", root);
  snprintf(ydir, sizeof(ydir), "%s/b/y", root);
  EXPECT_EQ_INT(mkdir(adir, 0700), 0);
  EXPECT_EQ_INT(mkdir(bdir, 0700), 0);
  EXPECT_EQ_INT(mkdir(xdir, 0700), 0);
  EXPECT_EQ_INT(mkdir(ydir, 0700), 0);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  config->receive_root_directory = str_dup(root);
  config->use_delete = true;
  config->delete_delay = true;
  config->max_delete = 1;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);

  DeletePlanSession* session = delete_plan_session_create(config);
  EXPECT_NOT_NULL(session);
  /* Both plan snapshots are taken; neither consumes budget yet. */
  send_plan_frame(p[1], "a");
  EXPECT_EQ_INT(delete_plan_session_receive(session, config, p[0]), 0);
  EXPECT_FALSE(delete_plan_session_limit_reached(session));
  send_plan_frame(p[1], "b");
  EXPECT_EQ_INT(delete_plan_session_receive(session, config, p[0]), 0);
  EXPECT_FALSE(delete_plan_session_limit_reached(session));
  EXPECT_EQ_INT((int)delete_plan_session_deleted(session), 0);

  /* Refill a/x after its plan: the recursive commit must remove this content. */
  char refill[1200];
  snprintf(refill, sizeof(refill), "%s/new.txt", xdir);
  int fd = open(refill, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  EXPECT_TRUE(fd >= 0);
  close(fd);

  EXPECT_EQ_INT(delete_plan_session_commit(session, config), DELETE_COMMIT_LIMIT_REACHED);
  /* The one budget slot removed the late content; the two directories survive. */
  EXPECT_EQ_INT((int)delete_plan_session_deleted(session), 1);
  EXPECT_TRUE(delete_plan_session_limit_reached(session));
  struct stat st;
  EXPECT_TRUE(lstat(refill, &st) != 0);
  EXPECT_EQ_INT(lstat(xdir, &st), 0);
  EXPECT_EQ_INT(lstat(ydir, &st), 0);

  delete_plan_session_destroy(session);
  close(p[0]);
  close(p[1]);
  rmdir(xdir);
  rmdir(ydir);
  rmdir(adir);
  rmdir(bdir);
  rmdir(root);
  config_delete(config);
}

/* Send a config-only carrier frame (apply=false): the per-run config block with
 * one --delete-missing-args exact path, and no directory walk. */
static void send_config_only_frame(int fd, const char* missing_path) {
  EXPECT_TRUE(send_int(fd, 1)); /* has_config */
  EXPECT_TRUE(send_int(fd, 0)); /* protected prefixes */
  EXPECT_TRUE(send_int(fd, 0)); /* size-skipped */
  EXPECT_TRUE(send_int(fd, 1)); /* missing args */
  EXPECT_TRUE(send_wire_str(fd, missing_path));
  EXPECT_TRUE(send_int(fd, 0)); /* per-directory filter-rule block is empty */
  EXPECT_TRUE(send_int(fd, 0)); /* apply = false */
  EXPECT_TRUE(send_wire_str(fd, "."));
  EXPECT_TRUE(send_int(fd, 0));
  EXPECT_TRUE(send_int(fd, 0));
}

/* The config-only carrier frame (apply=false) still applies the
 * --delete-missing-args exact deletions even though it walks no directory.  This
 * is the fix for a --files-from list that synchronizes no directory. */
static void test_config_only_frame_applies_missing_args(void) {
  char root[] = "/tmp/fastsync_dp_cfgonly_XXXXXX";
  EXPECT_TRUE(mkdtemp(root) != NULL);
  char gone[1024];
  snprintf(gone, sizeof(gone), "%s/gone.txt", root);
  int fd = open(gone, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  EXPECT_TRUE(fd >= 0);
  close(fd);

  Config* config = config_create();
  EXPECT_NOT_NULL(config);
  config->receive_root_directory = str_dup(root);
  config->delete_missing_args = true;

  int p[2];
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);

  DeletePlanSession* session = delete_plan_session_create(config);
  EXPECT_NOT_NULL(session);
  send_config_only_frame(p[1], "gone.txt");
  EXPECT_EQ_INT(delete_plan_session_receive(session, config, p[0]), 0);
  EXPECT_EQ_INT((int)delete_plan_session_deleted(session), 1);
  EXPECT_TRUE(lstat(gone, &(struct stat){0}) != 0);

  delete_plan_session_destroy(session);
  close(p[0]);
  close(p[1]);
  rmdir(root);
  config_delete(config);
}

/* The per-directory filter-rule block (protocol 2.30.0) must be bounded on
 * receive: every count, the action/sides domain, the owner-directory syntax and
 * the pattern length are validated so a hostile peer can neither overread nor
 * allocate unboundedly.  It also round-trips a valid group faithfully. */
static void test_filter_dir_rules_receive_bounds(void) {
  int p[2];
  FilterRuleList* out = NULL;

  /* Group count beyond the cap is rejected. */
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  EXPECT_TRUE(send_int(p[1], MAX_FILTER_RULES + 1));
  EXPECT_FALSE(delete_filter_dir_rules_receive(p[0], &out));
  EXPECT_NULL(out);
  close(p[0]);
  close(p[1]);

  /* A negative group count is rejected. */
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  EXPECT_TRUE(send_int(p[1], -1));
  EXPECT_FALSE(delete_filter_dir_rules_receive(p[0], &out));
  EXPECT_NULL(out);
  close(p[0]);
  close(p[1]);

  /* An empty block is valid and yields NULL. */
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  EXPECT_TRUE(send_int(p[1], 0));
  EXPECT_TRUE(delete_filter_dir_rules_receive(p[0], &out));
  EXPECT_NULL(out);
  close(p[0]);
  close(p[1]);

  /* An unknown action is a protocol error. */
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_wire_str(p[1], ""));
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_int(p[1], 999));
  EXPECT_FALSE(delete_filter_dir_rules_receive(p[0], &out));
  EXPECT_NULL(out);
  close(p[0]);
  close(p[1]);

  /* An absolute owner directory is rejected (confinement). */
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_wire_str(p[1], "/etc"));
  EXPECT_TRUE(send_int(p[1], 0));
  EXPECT_FALSE(delete_filter_dir_rules_receive(p[0], &out));
  EXPECT_NULL(out);
  close(p[0]);
  close(p[1]);

  /* An over-long pattern is rejected before allocation. */
  {
    char* big = malloc(MAX_PROTECT_PATTERN_LEN + 2);
    EXPECT_NOT_NULL(big);
    memset(big, 'a', MAX_PROTECT_PATTERN_LEN + 1);
    big[MAX_PROTECT_PATTERN_LEN + 1] = '\0';
    EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
    EXPECT_TRUE(send_int(p[1], 1));
    EXPECT_TRUE(send_wire_str(p[1], ""));
    EXPECT_TRUE(send_int(p[1], 1));
    EXPECT_TRUE(send_int(p[1], (int)FILTER_ACTION_EXCLUDE));
    EXPECT_TRUE(send_int(p[1], (int)(FILTER_SIDE_SENDER | FILTER_SIDE_RECEIVER)));
    EXPECT_TRUE(send_int(p[1], 0));
    EXPECT_TRUE(send_int(p[1], 0));
    EXPECT_TRUE(send_int(p[1], 0));
    EXPECT_TRUE(send_int(p[1], 0));
    EXPECT_TRUE(send_wire_str(p[1], big));
    EXPECT_FALSE(delete_filter_dir_rules_receive(p[0], &out));
    EXPECT_NULL(out);
    close(p[0]);
    close(p[1]);
    free(big);
  }

  /* A valid group round-trips its owner, no-inherit flag and pattern. */
  EXPECT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_wire_str(p[1], "sub"));
  EXPECT_TRUE(send_int(p[1], 1));
  EXPECT_TRUE(send_int(p[1], (int)FILTER_ACTION_EXCLUDE));
  EXPECT_TRUE(send_int(p[1], (int)(FILTER_SIDE_SENDER | FILTER_SIDE_RECEIVER)));
  EXPECT_TRUE(send_int(p[1], 0));
  EXPECT_TRUE(send_int(p[1], 0));
  EXPECT_TRUE(send_int(p[1], 0));
  EXPECT_TRUE(send_int(p[1], 1)); /* no_inherit */
  EXPECT_TRUE(send_wire_str(p[1], "*.log"));
  EXPECT_TRUE(delete_filter_dir_rules_receive(p[0], &out));
  EXPECT_NOT_NULL(out);
  EXPECT_EQ_INT(out->count, 1);
  EXPECT_EQ_STR(out->items[0]->owner, "sub");
  EXPECT_EQ_STR(out->items[0]->pattern, "*.log");
  EXPECT_TRUE(out->items[0]->no_inherit);
  filter_rule_list_free(out);
  close(p[0]);
  close(p[1]);
}

void test_delete_plan(void) {
  test_delete_delay_refilled_dir_removed_recursively();
  test_delete_delay_removed_file_counted();
  test_delete_delay_max_delete_bounds_actual();
  test_delete_delay_actual_removal_charges_budget();
  test_config_only_frame_applies_missing_args();
  test_filter_dir_rules_receive_bounds();
}
