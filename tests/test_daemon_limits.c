#include "test_daemon_limits.h"
#include "daemon_limits.h"
#include "test_utils.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The per-source hash is a pure helper: numeric addresses hash to a nonzero,
 * stable value and unparseable input reports failure. */
static void test_daemon_limits_host_hash() {
  bool ok = false;
  uint64_t v4 = daemon_limits_host_hash("127.0.0.1", &ok);
  EXPECT_TRUE(ok);
  EXPECT_TRUE(v4 != 0);
  EXPECT_EQ_INT((int)(daemon_limits_host_hash("127.0.0.1", NULL) == v4), 1);

  bool ok6 = false;
  uint64_t v6 = daemon_limits_host_hash("2001:db8::1", &ok6);
  EXPECT_TRUE(ok6);
  EXPECT_TRUE(v6 != 0);
  /* Distinct textual forms of different addresses must differ. */
  EXPECT_TRUE(v4 != v6);

  bool bad = true;
  EXPECT_TRUE(daemon_limits_host_hash("not-an-ip", &bad) == 0);
  EXPECT_FALSE(bad);
  bad = true;
  EXPECT_TRUE(daemon_limits_host_hash(NULL, &bad) == 0);
  EXPECT_FALSE(bad);
  bad = true;
  EXPECT_TRUE(daemon_limits_host_hash("", &bad) == 0);
  EXPECT_FALSE(bad);
}

/* Slot reservation is a plain parent-side resource: claim until exhausted,
 * reclaim, then claim again. */
static void test_daemon_limits_slots() {
  DaemonLimitRegistry* registry = daemon_limits_create(DAEMON_LIMITS_MIN_SLOTS, 2, 0, 0, 0);
  EXPECT_NOT_NULL(registry);
  int slots[DAEMON_LIMITS_MIN_SLOTS];
  for (int i = 0; i < DAEMON_LIMITS_MIN_SLOTS; i++) {
    slots[i] = daemon_limits_claim_slot(registry);
    EXPECT_EQ_INT(slots[i], i);
  }
  EXPECT_EQ_INT(daemon_limits_claim_slot(registry), DAEMON_LIMITS_NO_SLOT);
  daemon_limits_reclaim_slot(registry, slots[3]);
  int reclaimed = daemon_limits_claim_slot(registry);
  EXPECT_EQ_INT(reclaimed, slots[3]);
  daemon_limits_destroy(registry);
}

/* Per-module accounting: the cap is enforced across slots and a reclaimed slot
 * frees a module count. */
static void test_daemon_limits_module_cap() {
  DaemonLimitRegistry* registry = daemon_limits_create(DAEMON_LIMITS_MIN_SLOTS, 2, 0, 0, 0);
  EXPECT_NOT_NULL(registry);

  int slot0 = daemon_limits_claim_slot(registry);
  int slot1 = daemon_limits_claim_slot(registry);
  int slot2 = daemon_limits_claim_slot(registry);
  int slot3 = daemon_limits_claim_slot(registry);
  EXPECT_TRUE(slot0 >= 0 && slot1 >= 0 && slot2 >= 0 && slot3 >= 0);

  EXPECT_EQ_INT(daemon_limits_register(registry, slot0, 0, "10.0.0.1", 2), DAEMON_LIMIT_OK);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot1, 0, "10.0.0.2", 2), DAEMON_LIMIT_OK);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot2, 0, "10.0.0.3", 2),
                DAEMON_LIMIT_MODULE_FULL);
  /* A different module has its own counter. */
  EXPECT_EQ_INT(daemon_limits_register(registry, slot2, 1, "10.0.0.3", 2), DAEMON_LIMIT_OK);
  /* A module cap of 0 is unlimited. */
  EXPECT_EQ_INT(daemon_limits_register(registry, slot3, 0, "10.0.0.3", 0), DAEMON_LIMIT_OK);

  daemon_limits_reclaim_slot(registry, slot0);
  daemon_limits_reclaim_slot(registry, slot1);
  daemon_limits_recompute(registry);
  int slot4 = daemon_limits_claim_slot(registry);
  EXPECT_TRUE(slot4 >= 0);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot4, 0, "10.0.0.4", 2), DAEMON_LIMIT_OK);

  daemon_limits_destroy(registry);
}

/* Per-source accounting: the same peer hits the cap, a different peer does not. */
static void test_daemon_limits_host_cap() {
  DaemonLimitRegistry* registry = daemon_limits_create(DAEMON_LIMITS_MIN_SLOTS, 1, 1, 0, 0);
  EXPECT_NOT_NULL(registry);

  int slot0 = daemon_limits_claim_slot(registry);
  int slot1 = daemon_limits_claim_slot(registry);
  int slot2 = daemon_limits_claim_slot(registry);
  EXPECT_TRUE(slot0 >= 0 && slot1 >= 0 && slot2 >= 0);

  EXPECT_EQ_INT(daemon_limits_register(registry, slot0, 0, "10.0.0.1", 0), DAEMON_LIMIT_OK);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot1, 0, "10.0.0.1", 0), DAEMON_LIMIT_HOST_FULL);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot2, 0, "10.0.0.2", 0), DAEMON_LIMIT_OK);
  /* Reclaiming the first source frees its per-host allowance. */
  daemon_limits_reclaim_slot(registry, slot0);
  daemon_limits_recompute(registry);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot1, 0, "10.0.0.1", 0), DAEMON_LIMIT_OK);

  daemon_limits_destroy(registry);
}

/* The pid-indexed reclaim is what the parent's SIGCHLD handler uses: a dead
 * child's module/source counts must be released. */
static void test_daemon_limits_reclaim_pid() {
  DaemonLimitRegistry* registry = daemon_limits_create(DAEMON_LIMITS_MIN_SLOTS, 1, 1, 0, 0);
  EXPECT_NOT_NULL(registry);

  int slot0 = daemon_limits_claim_slot(registry);
  int slot1 = daemon_limits_claim_slot(registry);
  EXPECT_TRUE(slot0 >= 0 && slot1 >= 0);
  daemon_limits_set_slot_pid(registry, slot0, 4242);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot0, 0, "10.0.0.1", 1), DAEMON_LIMIT_OK);
  /* Cap (module 1) and per-host (1) are both saturated. */
  EXPECT_EQ_INT(daemon_limits_register(registry, slot1, 0, "10.0.0.1", 1),
                DAEMON_LIMIT_MODULE_FULL);

  daemon_limits_reclaim_pid(registry, 4242);
  daemon_limits_recompute(registry);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot1, 0, "10.0.0.1", 1), DAEMON_LIMIT_OK);
  /* Reclaiming an unknown pid is a no-op. */
  daemon_limits_reclaim_pid(registry, 999999);

  daemon_limits_destroy(registry);
}

/* Cross-process lockout: failures counted in the shared mapping lock the source
 * out after the threshold; a success clears it; threshold 0 disables it. */
static void test_daemon_limits_auth_lockout() {
  DaemonLimitRegistry* registry = daemon_limits_create(DAEMON_LIMITS_MIN_SLOTS, 1, 0, 2, 300);
  EXPECT_NOT_NULL(registry);

  int remaining = 0;
  EXPECT_FALSE(daemon_limits_auth_locked(registry, "10.0.0.1", &remaining));
  daemon_limits_auth_record_failure(registry, "10.0.0.1");
  EXPECT_FALSE(daemon_limits_auth_locked(registry, "10.0.0.1", &remaining));
  daemon_limits_auth_record_failure(registry, "10.0.0.1");
  EXPECT_TRUE(daemon_limits_auth_locked(registry, "10.0.0.1", &remaining));
  EXPECT_TRUE(remaining > 0 && remaining <= 300);
  /* Another source is unaffected. */
  EXPECT_FALSE(daemon_limits_auth_locked(registry, "10.0.0.2", &remaining));
  /* A successful authentication clears the lockout. */
  daemon_limits_auth_record_success(registry, "10.0.0.1");
  EXPECT_FALSE(daemon_limits_auth_locked(registry, "10.0.0.1", &remaining));
  daemon_limits_destroy(registry);

  /* threshold 0 disables the lockout entirely. */
  registry = daemon_limits_create(DAEMON_LIMITS_MIN_SLOTS, 1, 0, 0, 300);
  EXPECT_NOT_NULL(registry);
  for (int i = 0; i < 50; i++)
    daemon_limits_auth_record_failure(registry, "10.0.0.1");
  EXPECT_FALSE(daemon_limits_auth_locked(registry, "10.0.0.1", &remaining));
  daemon_limits_destroy(registry);
}

/* The registry must be visible across fork(): a child's registration is seen by
 * the parent, and the parent's pid reclaim releases it. */
static void test_daemon_limits_fork_shared() {
  if (is_running_under_valgrind())
    return; /* fork + shared mapping is slow/noisy under valgrind */
  DaemonLimitRegistry* registry = daemon_limits_create(DAEMON_LIMITS_MIN_SLOTS, 1, 0, 0, 0);
  EXPECT_NOT_NULL(registry);

  int slot0 = daemon_limits_claim_slot(registry);
  EXPECT_TRUE(slot0 >= 0);
  pid_t pid = fork();
  if (pid == 0) {
    if (daemon_limits_register(registry, slot0, 0, "10.0.0.1", 1) != DAEMON_LIMIT_OK)
      _exit(1);
    _exit(0);
  }
  EXPECT_TRUE(pid > 0);
  daemon_limits_set_slot_pid(registry, slot0, (long)pid);
  int status = 0;
  EXPECT_TRUE(waitpid(pid, &status, 0) == pid);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  /* The child's module count is still held in the shared mapping. */
  int slot1 = daemon_limits_claim_slot(registry);
  EXPECT_TRUE(slot1 >= 0);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot1, 0, "10.0.0.2", 1),
                DAEMON_LIMIT_MODULE_FULL);
  /* The parent reclaims the dead child's slot by pid. */
  daemon_limits_reclaim_pid(registry, (long)pid);
  daemon_limits_recompute(registry);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot1, 0, "10.0.0.2", 1), DAEMON_LIMIT_OK);
  daemon_limits_destroy(registry);
}

/* The occupancy arrays are derived from the slot table: recompute rebuilds them
 * and is the self-heal path the SIGCHLD handler uses after a child dies. */
static void test_daemon_limits_recompute() {
  DaemonLimitRegistry* registry = daemon_limits_create(DAEMON_LIMITS_MIN_SLOTS, 2, 1, 0, 0);
  EXPECT_NOT_NULL(registry);
  int slot0 = daemon_limits_claim_slot(registry);
  int slot1 = daemon_limits_claim_slot(registry);
  int slot2 = daemon_limits_claim_slot(registry);
  EXPECT_TRUE(slot0 >= 0 && slot1 >= 0 && slot2 >= 0);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot0, 0, "10.0.0.1", 0), DAEMON_LIMIT_OK);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot1, 0, "10.0.0.2", 0), DAEMON_LIMIT_OK);

  /* Recompute is idempotent and re-derives the same counts from REGISTERED
   * slots (a CLAIMED slot is never counted). */
  daemon_limits_recompute(registry);
  daemon_limits_recompute(registry);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot2, 0, "10.0.0.3", 2),
                DAEMON_LIMIT_MODULE_FULL);

  /* Freeing a slot and recomputing releases its module/per-source count. */
  daemon_limits_reclaim_slot(registry, slot0);
  daemon_limits_recompute(registry);
  EXPECT_EQ_INT(daemon_limits_register(registry, slot2, 0, "10.0.0.3", 2), DAEMON_LIMIT_OK);
  daemon_limits_destroy(registry);
}

/* The per-source table has a bounded lifetime.  When every bucket is occupied
 * but not yet reclaimable, a new source is fail-open: the per-host cap is not
 * enforced and the probe must terminate.  Once the occupied buckets' lockouts
 * expire (or they go idle), a new source reclaims a bucket and enforcement comes
 * back.  This covers the "table never evicts -> cap silently fails open forever"
 * review finding. */
static void test_daemon_limits_host_table_eviction() {
  char ip[32];

  /* Part A: all buckets locked out with a long deadline and no active
   * connection are not reclaimable yet.  A new source cannot be interned, so the
   * per-host cap is documented fail-open (both connections admitted) -- and the
   * bounded probe returns instead of looping forever. */
  DaemonLimitRegistry* registry = daemon_limits_create(DAEMON_LIMITS_MIN_SLOTS, 1, 1, 1, 300);
  EXPECT_NOT_NULL(registry);
  for (int i = 0; i < 64; i++) {
    snprintf(ip, sizeof(ip), "10.0.0.%d", i + 1);
    daemon_limits_auth_record_failure(registry, ip);
  }
  int a = daemon_limits_claim_slot(registry);
  int b = daemon_limits_claim_slot(registry);
  EXPECT_TRUE(a >= 0 && b >= 0);
  EXPECT_EQ_INT(daemon_limits_register(registry, a, 0, "10.9.9.9", 0), DAEMON_LIMIT_OK);
  EXPECT_EQ_INT(daemon_limits_register(registry, b, 0, "10.9.9.9", 0), DAEMON_LIMIT_OK);
  daemon_limits_destroy(registry);

  /* Part B: with an already-expired lockout every bucket is reclaimable, so a
   * new source reclaims one and the per-host cap is enforced again. */
  registry = daemon_limits_create(DAEMON_LIMITS_MIN_SLOTS, 1, 1, 1, 1);
  EXPECT_NOT_NULL(registry);
  for (int i = 0; i < 64; i++) {
    snprintf(ip, sizeof(ip), "10.0.0.%d", i + 1);
    daemon_limits_auth_record_failure(registry, ip);
  }
  struct timespec pause = {2, 0};
  nanosleep(&pause, NULL);
  int c = daemon_limits_claim_slot(registry);
  int d = daemon_limits_claim_slot(registry);
  EXPECT_TRUE(c >= 0 && d >= 0);
  EXPECT_EQ_INT(daemon_limits_register(registry, c, 0, "10.9.9.9", 0), DAEMON_LIMIT_OK);
  EXPECT_EQ_INT(daemon_limits_register(registry, d, 0, "10.9.9.9", 0), DAEMON_LIMIT_HOST_FULL);
  daemon_limits_destroy(registry);
}

void test_daemon_limits() {
  test_daemon_limits_host_hash();
  test_daemon_limits_slots();
  test_daemon_limits_module_cap();
  test_daemon_limits_host_cap();
  test_daemon_limits_reclaim_pid();
  test_daemon_limits_recompute();
  test_daemon_limits_auth_lockout();
  test_daemon_limits_host_table_eviction();
  test_daemon_limits_fork_shared();
}
