#ifndef DAEMON_LIMITS_H
#define DAEMON_LIMITS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Cross-process daemon connection registry.
 *
 * The daemon listener forks ONE child per accepted connection, so any
 * per-module / per-source accounting must live in state shared across the
 * forked children.  This module owns a fixed-size registry carved out of an
 * anonymous shared mapping (mmap(MAP_SHARED | MAP_ANONYMOUS)) created by the
 * accept-loop PARENT before it forks; every child inherits the mapping (and the
 * pointer to it) across fork().
 *
 * Rules:
 *  - ONLY C11 atomics (atomic_*); never mtx_t/pthread locks, which can deadlock
 *    in a forked child if another thread held them at fork time.
 *  - No heap allocation after fork: the mapping is fixed-size and all access is
 *    atomic load/store/CAS over preallocated arrays.
 *
 * Slot lifecycle (the parent reclaims even when a child is SIGKILLed):
 *   FREE --(parent claim_slot)--> CLAIMED
 *   CLAIMED --(child register)--> REGISTERED
 *   any --(parent reclaim)--> FREE
 * The child records its module index and per-source bucket into the slot before
 * publishing REGISTERED; the parent's SIGCHLD handler matches the reaped pid to
 * the slot and, when REGISTERED, decrements the module/per-source counters.
 * A child killed before registering holds no counts, so reclaiming a CLAIMED
 * slot only frees the slot.
 *
 * Per-source identity is the normalized numeric peer IP (IPv4-mapped IPv6 is
 * already collapsed to IPv4 by utils_fd_peer_ip); it is interned into an
 * open-addressed, linear-probing table keyed by a 64-bit hash.  The same table
 * also carries the cross-process auth-failure counter and lockout deadline.
 *
 * Per-source table lifetime: a bucket's key is never cleared back to empty (that
 * would break every later probe chain that passed through it).  Instead the
 * table has a bounded-lifetime eviction policy: when no empty bucket exists, the
 * first bucket that is reclaimable -- no active connection AND (its lockout
 * deadline has passed OR it has been idle for
 * DAEMON_LIMITS_HOST_EVICT_IDLE_SEC) -- is atomically repurposed for the new
 * source via a CAS of its key, and its counters are reset.  The table therefore
 * cannot fill permanently, and a full table degrades to fail-open for the
 * per-source cap/lockout of new sources (the per-module cap and host ACLs still
 * apply) instead of staying fail-open forever.  A rate-limited warning is logged
 * on the fail-open path.  The eviction race with a concurrent
 * registration/reclaim on the same bucket is benign: it can at worst lose one
 * source's counter (fail-open), never corrupt memory or the module caps.
 */

typedef struct DaemonLimitRegistry DaemonLimitRegistry;

/* Result of a per-connection admission check. */
typedef enum {
  DAEMON_LIMIT_OK = 0,      /* admitted; slot is now REGISTERED */
  DAEMON_LIMIT_MODULE_FULL, /* module's `max connections` cap reached */
  DAEMON_LIMIT_HOST_FULL,   /* global `max connections per host` cap reached */
  DAEMON_LIMIT_UNAVAILABLE, /* registry/slot unusable (caller fails open) */
} DaemonLimitResult;

/* Bounds for registry sizing.  A slot is one concurrently live child. */
#define DAEMON_LIMITS_MIN_SLOTS 16
#define DAEMON_LIMITS_MAX_SLOTS 65536
#define DAEMON_LIMITS_MAX_HOST_SLOTS 65536
#define DAEMON_LIMITS_NO_SLOT (-1)
/* Upper bound on `module_count`, matching daemon_conf.h's DAEMON_CONF_MAX_MODULES
 * (asserted in daemon_limits.c) so a caller can never size the per-module counter
 * array larger than the config parser can produce. */
#define DAEMON_LIMITS_MAX_MODULES 256

/* Per-source table lifetime: a bucket with no active connection and no pending
 * lockout is reclaimable once it has been idle this long, so a flood of distinct
 * sources cannot pin the table full forever.  A bucket whose lockout deadline
 * has passed is reclaimable immediately (independent of this idle window). */
#define DAEMON_LIMITS_HOST_EVICT_IDLE_SEC 300
/* Minimum spacing between "per-source table is full" warnings, so a table-full
 * attack cannot flood the log. */
#define DAEMON_LIMITS_HOST_FULL_WARN_SEC 60

/* Create the shared registry in the calling (parent) process.  `max_slots` is
 * the number of concurrently live children to track (clamped to
 * [DAEMON_LIMITS_MIN_SLOTS, DAEMON_LIMITS_MAX_SLOTS]); `module_count` is the
 * number of daemon modules (clamped to
 * [1, DAEMON_LIMITS_MAX_MODULES]); `per_host_cap` and the lockout pair come
 * from the daemon config (0 disables).  Returns NULL on failure (e.g. mmap
 * allocation); callers must degrade gracefully (global cap + ACLs still
 * apply). */
DaemonLimitRegistry* daemon_limits_create(int max_slots, int module_count, int per_host_cap,
                                          int lockout_threshold, int lockout_duration_sec);

/* Unmap the registry.  Only the creating process may call this. */
void daemon_limits_destroy(DaemonLimitRegistry* registry);

/* Parent side: reserve a slot for the next fork.  Returns the slot index or
 * DAEMON_LIMITS_NO_SLOT when every slot is in use. */
int daemon_limits_claim_slot(DaemonLimitRegistry* registry);
/* Parent side: record the forked child's pid in a claimed slot. */
void daemon_limits_set_slot_pid(DaemonLimitRegistry* registry, int slot, long pid);
/* Parent side: release a slot.  The slot becomes FREE; the module/per-source
 * occupancy arrays are DERIVED state and are only refreshed by
 * daemon_limits_recompute, which callers must invoke afterwards when they rely
 * on the derived counts (the SIGCHLD handler batches one recompute for the whole
 * reap).  Idempotent. */
void daemon_limits_reclaim_slot(DaemonLimitRegistry* registry, int slot);
/* Parent SIGCHLD side: release the slot owned by `pid` (no-op when not found).
 * Like reclaim_slot this does not touch the derived occupancy arrays; call
 * daemon_limits_recompute after a batch of releases. */
void daemon_limits_reclaim_pid(DaemonLimitRegistry* registry, long pid);

/* Parent side (async-signal-safe; atomics only, no malloc/log): rebuild
 * module_active[] / host_active[] from scratch by scanning the REGISTERED slots.
 * The slot table is the single source of truth, so this self-heals any
 * count leaked by a child that was SIGKILLed mid-registration (it zeroes the
 * arrays and re-derives them).  Bounded by max_slots + host_slots.  A
 * registration racing this call can be transiently undercounted until the next
 * recompute, which can only relax a cap briefly -- never corrupt memory. */
void daemon_limits_recompute(DaemonLimitRegistry* registry);

/* Child side: admit the connection for `module_index` from `peer_ip`.  Always
 * tracks the module/per-source occupancy (so the parent's reclaim is
 * symmetric); when `module_cap` > 0 it additionally enforces the per-module
 * cap.  A NULL/empty or non-numeric `peer_ip` skips the per-source track (the
 * callers use that to exempt a trusted loopback peer from the per-host cap; the
 * per-module cap still applies).  Returns DAEMON_LIMIT_OK and publishes the
 * slot, or a refusal reason. */
DaemonLimitResult daemon_limits_register(DaemonLimitRegistry* registry, int slot, int module_index,
                                         const char* peer_ip, int module_cap);

/* Child side: true when `peer_ip` is currently locked out after too many failed
 * authentications.  `seconds_remaining` may be NULL. */
bool daemon_limits_auth_locked(DaemonLimitRegistry* registry, const char* peer_ip,
                               int* seconds_remaining);
/* Child side: count one failed authentication for `peer_ip`; once the threshold
 * is reached the source is locked out for the configured duration. */
void daemon_limits_auth_record_failure(DaemonLimitRegistry* registry, const char* peer_ip);
/* Child side: clear the failure counter/lockout for a source that authenticated
 * successfully (no-op when the source has no table entry). */
void daemon_limits_auth_record_success(DaemonLimitRegistry* registry, const char* peer_ip);

/* Pure helper: 64-bit FNV-1a hash of a numeric peer IP plus its family, used to
 * index the per-source table.  *ok is set false (and 0 returned) for a NULL or
 * non-numeric address.  Exposed for unit testing. */
uint64_t daemon_limits_host_hash(const char* peer_ip, bool* ok);

#endif
