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

/* Create the shared registry in the calling (parent) process.  `max_slots` is
 * the number of concurrently live children to track (clamped to
 * [DAEMON_LIMITS_MIN_SLOTS, DAEMON_LIMITS_MAX_SLOTS]); `module_count` is the
 * number of daemon modules (clamped to >= 1); `per_host_cap` and the lockout
 * pair come from the daemon config (0 disables).  Returns NULL on failure (e.g.
 * mmap allocation); callers must degrade gracefully (global cap + ACLs still
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
/* Parent side: release a slot, decrementing the module/per-source counters when
 * the slot was actually REGISTERED.  Idempotent. */
void daemon_limits_reclaim_slot(DaemonLimitRegistry* registry, int slot);
/* Parent SIGCHLD side: reclaim the slot owned by `pid` (no-op when not found). */
void daemon_limits_reclaim_pid(DaemonLimitRegistry* registry, long pid);

/* Child side: admit the connection for `module_index` from `peer_ip`.  Always
 * tracks the module/per-source occupancy (so the parent's reclaim is
 * symmetric); when `module_cap` > 0 it additionally enforces the per-module
 * cap.  Returns DAEMON_LIMIT_OK and publishes the slot, or a refusal reason. */
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
