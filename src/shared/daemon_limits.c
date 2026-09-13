#include "daemon_limits.h"
#include "daemon_conf.h"
#include "log.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

/* The two module-count bounds must agree: the daemon config parser never
 * produces more than DAEMON_CONF_MAX_MODULES modules, so the shared registry's
 * per-module counter array is sized from the same bound. */
_Static_assert(DAEMON_LIMITS_MAX_MODULES == DAEMON_CONF_MAX_MODULES,
               "daemon_limits module bound must match daemon_conf");

/* Slot lifecycle states (stored in slot_state). */
enum {
  SLOT_FREE = 0,
  SLOT_CLAIMED = 1,
  SLOT_REGISTERED = 2,
};

/* The registry header lives at the base of the shared mapping; the pointer
 * fields point at the arrays carved out of the same mapping.  Absolute pointers
 * remain valid in a forked child because fork() clones the address space and
 * mapping, so parent and child observe the same virtual addresses. */
struct DaemonLimitRegistry {
  int max_slots;
  int module_count;
  int host_slots; /* power of two; 1 when no per-source tracking is needed */
  int per_host_cap;
  int lockout_threshold;
  int lockout_duration_sec;
  size_t map_size;
  _Atomic long long host_full_warn; /* last "table full" warning epoch */
  _Atomic int* slot_state;
  _Atomic int* slot_pid;
  _Atomic int* slot_module;
  _Atomic int* slot_host; /* per-source table bucket, or -1 */
  _Atomic int* module_active;
  _Atomic uint64_t* host_key; /* 0 == empty bucket */
  _Atomic int* host_active;
  _Atomic int* host_fail;
  _Atomic long long* host_until;    /* epoch seconds the lockout expires */
  _Atomic long long* host_last_use; /* epoch seconds the bucket was last touched */
};

static size_t round_up(size_t n, size_t align) {
  return (n + align - 1) & ~(align - 1);
}

static size_t next_pow2(size_t n) {
  size_t p = 1;
  while (p < n)
    p <<= 1;
  return p;
}

/* Parse a numeric IPv4/IPv6 peer string into family + raw bytes. */
static bool parse_peer_ip(const char* peer_ip, int* family, unsigned char* bytes) {
  if (!peer_ip || *peer_ip == '\0')
    return false;
  struct in_addr v4;
  if (inet_pton(AF_INET, peer_ip, &v4) == 1) {
    memcpy(bytes, &v4, sizeof(v4));
    *family = AF_INET;
    return true;
  }
  struct in6_addr v6;
  if (inet_pton(AF_INET6, peer_ip, &v6) == 1) {
    memcpy(bytes, &v6, sizeof(v6));
    *family = AF_INET6;
    return true;
  }
  return false;
}

uint64_t daemon_limits_host_hash(const char* peer_ip, bool* ok) {
  if (ok)
    *ok = false;
  unsigned char bytes[16];
  int family = AF_UNSPEC;
  if (!parse_peer_ip(peer_ip, &family, bytes))
    return 0;
  uint64_t hash = 14695981039346656037ULL ^ (uint64_t)(uint32_t)family;
  size_t length = family == AF_INET ? 4 : 16;
  for (size_t i = 0; i < length; i++) {
    hash ^= bytes[i];
    hash *= 1099511628211ULL;
  }
  if (hash == 0)
    hash = 0x9e3779b97f4a7c15ULL;
  if (ok)
    *ok = true;
  return hash;
}

/* True when the registry must maintain per-source buckets: either the per-host
 * cap is configured, or the auth lockout is (threshold AND duration > 0).  A
 * lockout threshold without a duration is a no-op, so it must not size or intern
 * the table.  create(), register() and the lockout paths all agree on this. */
static bool registry_tracks_hosts(const DaemonLimitRegistry* registry) {
  return registry->per_host_cap > 0 ||
         (registry->lockout_threshold > 0 && registry->lockout_duration_sec > 0);
}

/* Find the bucket holding `peer_ip`, or -1 when it has no entry.  Finding a
 * bucket refreshes its last-use time so the eviction policy sees it as live. */
static int host_lookup(DaemonLimitRegistry* registry, const char* peer_ip) {
  bool ok = false;
  uint64_t key = daemon_limits_host_hash(peer_ip, &ok);
  if (!ok)
    return -1;
  size_t mask = (size_t)registry->host_slots - 1;
  size_t start = (size_t)(key & mask);
  for (size_t i = 0; i < (size_t)registry->host_slots; i++) {
    size_t idx = (start + i) & mask;
    uint64_t current = atomic_load_explicit(&registry->host_key[idx], memory_order_acquire);
    if (current == key) {
      atomic_store_explicit(&registry->host_last_use[idx], (long long)time(NULL),
                            memory_order_relaxed);
      return (int)idx;
    }
    if (current == 0)
      return -1; /* no tombstones: an empty bucket ends the probe chain */
  }
  return -1;
}

/* A bucket with no live connection may be repurposed: immediately when its
 * lockout deadline has already passed (the review's "expired" case), or after an
 * idle window when it holds no pending lockout.  A bucket with a future lockout
 * deadline is retained so the lockout actually lasts its configured duration. */
static bool host_bucket_reclaimable(DaemonLimitRegistry* registry, size_t idx, long long now) {
  if (atomic_load_explicit(&registry->host_active[idx], memory_order_relaxed) != 0)
    return false;
  long long until = atomic_load_explicit(&registry->host_until[idx], memory_order_relaxed);
  if (until != 0)
    return until <= now;
  long long last_use = atomic_load_explicit(&registry->host_last_use[idx], memory_order_relaxed);
  return last_use == 0 || now - last_use >= DAEMON_LIMITS_HOST_EVICT_IDLE_SEC;
}

/* Emit at most one "per-source table full" warning per
 * DAEMON_LIMITS_HOST_FULL_WARN_SEC across all forked children.  Called from a
 * normal (non-signal) child path, so logging is safe here. */
static void host_warn_table_full(DaemonLimitRegistry* registry, long long now) {
  long long last = atomic_load_explicit(&registry->host_full_warn, memory_order_relaxed);
  if (last != 0 && now - last < DAEMON_LIMITS_HOST_FULL_WARN_SEC)
    return;
  if (atomic_compare_exchange_strong_explicit(&registry->host_full_warn, &last, now,
                                              memory_order_relaxed, memory_order_relaxed)) {
    log_message(LOG_LEVEL_WARNING,
                "daemon: per-source registry is full (%d slots) and no bucket can be reclaimed; "
                "'max connections per host' and the auth lockout are temporarily not enforced for "
                "new sources (the per-module cap and host ACLs still apply)",
                registry->host_slots);
  }
}

/* Find or insert the bucket for `peer_ip`.  Insertion is a lock-free CAS so two
 * forked children racing on the same source converge on one bucket.
 *
 * When the probe finds no empty bucket it reclaims, via a key CAS, the first
 * bucket that is reclaimable (expired lockout or idle, and no active
 * connection) and resets its counters.  This bounds the table's lifetime so it
 * cannot fill permanently and stay fail-open.  Returns -1 only when the address
 * is unparseable or the table is genuinely full of live/locked buckets
 * (callers fail open: the global/module caps and ACLs still apply). */
static int host_intern(DaemonLimitRegistry* registry, const char* peer_ip) {
  bool ok = false;
  uint64_t key = daemon_limits_host_hash(peer_ip, &ok);
  if (!ok)
    return -1;
  long long now = (long long)time(NULL);
  size_t mask = (size_t)registry->host_slots - 1;
  size_t start = (size_t)(key & mask);
  /* A couple of passes bound the work: the first normally claims/seeds a bucket;
   * a lost eviction CAS retries once against the freshly observed table. */
  for (int pass = 0; pass < 2; pass++) {
    int evict = -1;
    uint64_t evict_key = 0;
    for (size_t i = 0; i < (size_t)registry->host_slots; i++) {
      size_t idx = (start + i) & mask;
      uint64_t current = atomic_load_explicit(&registry->host_key[idx], memory_order_acquire);
      if (current == key) {
        atomic_store_explicit(&registry->host_last_use[idx], now, memory_order_relaxed);
        return (int)idx;
      }
      if (current == 0) {
        uint64_t expected = 0;
        if (atomic_compare_exchange_strong_explicit(&registry->host_key[idx], &expected, key,
                                                    memory_order_acq_rel, memory_order_acquire)) {
          atomic_store_explicit(&registry->host_last_use[idx], now, memory_order_relaxed);
          return (int)idx;
        }
        if (atomic_load_explicit(&registry->host_key[idx], memory_order_acquire) == key) {
          atomic_store_explicit(&registry->host_last_use[idx], now, memory_order_relaxed);
          return (int)idx;
        }
        continue; /* another child won this empty bucket; keep probing */
      }
      if (evict < 0 && host_bucket_reclaimable(registry, idx, now)) {
        evict = (int)idx;
        evict_key = current;
      }
    }
    if (evict >= 0) {
      uint64_t expected = evict_key;
      if (atomic_compare_exchange_strong_explicit(&registry->host_key[evict], &expected, key,
                                                  memory_order_acq_rel, memory_order_acquire)) {
        /* The bucket now belongs to the new source; clear the evicted source's
         * stale lockout/failure state. */
        atomic_store_explicit(&registry->host_active[evict], 0, memory_order_relaxed);
        atomic_store_explicit(&registry->host_fail[evict], 0, memory_order_relaxed);
        atomic_store_explicit(&registry->host_until[evict], 0, memory_order_relaxed);
        atomic_store_explicit(&registry->host_last_use[evict], now, memory_order_relaxed);
        return evict;
      }
      continue; /* lost the race; re-probe with fresh observations */
    }
    break; /* no free and no reclaimable bucket: genuinely full */
  }
  host_warn_table_full(registry, now);
  return -1;
}

DaemonLimitRegistry* daemon_limits_create(int max_slots, int module_count, int per_host_cap,
                                          int lockout_threshold, int lockout_duration_sec) {
  if (max_slots < DAEMON_LIMITS_MIN_SLOTS)
    max_slots = DAEMON_LIMITS_MIN_SLOTS;
  if (max_slots > DAEMON_LIMITS_MAX_SLOTS)
    max_slots = DAEMON_LIMITS_MAX_SLOTS;
  if (module_count < 1)
    module_count = 1;
  if (module_count > DAEMON_LIMITS_MAX_MODULES)
    module_count = DAEMON_LIMITS_MAX_MODULES;
  if (per_host_cap < 0)
    per_host_cap = 0;
  if (lockout_threshold < 0)
    lockout_threshold = 0;
  if (lockout_duration_sec < 0)
    lockout_duration_sec = 0;

  bool need_hosts = per_host_cap > 0 || (lockout_threshold > 0 && lockout_duration_sec > 0);
  int host_slots = 1;
  if (need_hosts) {
    size_t want = (size_t)max_slots * 4;
    if (want < 64)
      want = 64;
    if (want > DAEMON_LIMITS_MAX_HOST_SLOTS)
      want = DAEMON_LIMITS_MAX_HOST_SLOTS;
    host_slots = (int)next_pow2(want);
  }

  size_t header = round_up(sizeof(DaemonLimitRegistry), 16);
  size_t slot_bytes =
      round_up((size_t)max_slots * sizeof(_Atomic int), 16) * 4; /* state,pid,module,host */
  size_t module_bytes = round_up((size_t)module_count * sizeof(_Atomic int), 16);
  size_t host_key_bytes = round_up((size_t)host_slots * sizeof(_Atomic uint64_t), 16);
  size_t host_int_bytes = round_up((size_t)host_slots * sizeof(_Atomic int), 16) * 2;
  size_t host_until_bytes = round_up((size_t)host_slots * sizeof(_Atomic long long), 16) * 2;
  size_t total =
      header + slot_bytes + module_bytes + host_key_bytes + host_int_bytes + host_until_bytes + 16;

  void* map = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (map == MAP_FAILED)
    return NULL;
  memset(map, 0, total);

  DaemonLimitRegistry* registry = (DaemonLimitRegistry*)map;
  registry->max_slots = max_slots;
  registry->module_count = module_count;
  registry->host_slots = host_slots;
  registry->per_host_cap = per_host_cap;
  registry->lockout_threshold = lockout_threshold;
  registry->lockout_duration_sec = lockout_duration_sec;
  registry->map_size = total;

  unsigned char* cursor = (unsigned char*)map + header;
  registry->slot_state = (atomic_int*)cursor;
  cursor += (size_t)max_slots * sizeof(_Atomic int);
  registry->slot_pid = (atomic_int*)cursor;
  cursor += (size_t)max_slots * sizeof(_Atomic int);
  registry->slot_module = (atomic_int*)cursor;
  cursor += (size_t)max_slots * sizeof(_Atomic int);
  registry->slot_host = (atomic_int*)cursor;
  cursor += (size_t)max_slots * sizeof(_Atomic int);
  registry->module_active = (atomic_int*)cursor;
  cursor += (size_t)module_count * sizeof(_Atomic int);
  cursor = (unsigned char*)round_up((size_t)(uintptr_t)cursor, 16);
  registry->host_key = (_Atomic uint64_t*)cursor;
  cursor += (size_t)host_slots * sizeof(_Atomic uint64_t);
  registry->host_active = (atomic_int*)cursor;
  cursor += (size_t)host_slots * sizeof(_Atomic int);
  registry->host_fail = (atomic_int*)cursor;
  cursor += (size_t)host_slots * sizeof(_Atomic int);
  cursor = (unsigned char*)round_up((size_t)(uintptr_t)cursor, 16);
  registry->host_until = (atomic_llong*)cursor;
  cursor += (size_t)host_slots * sizeof(_Atomic long long);
  registry->host_last_use = (atomic_llong*)cursor;

  for (int i = 0; i < max_slots; i++) {
    atomic_store(&registry->slot_module[i], -1);
    atomic_store(&registry->slot_host[i], -1);
  }
  return registry;
}

void daemon_limits_destroy(DaemonLimitRegistry* registry) {
  if (!registry)
    return;
  munmap(registry, registry->map_size);
}

int daemon_limits_claim_slot(DaemonLimitRegistry* registry) {
  if (!registry)
    return DAEMON_LIMITS_NO_SLOT;
  for (int i = 0; i < registry->max_slots; i++) {
    int expected = SLOT_FREE;
    if (atomic_compare_exchange_strong(&registry->slot_state[i], &expected, SLOT_CLAIMED)) {
      atomic_store(&registry->slot_pid[i], 0);
      atomic_store(&registry->slot_module[i], -1);
      atomic_store(&registry->slot_host[i], -1);
      return i;
    }
  }
  return DAEMON_LIMITS_NO_SLOT;
}

void daemon_limits_set_slot_pid(DaemonLimitRegistry* registry, int slot, long pid) {
  if (!registry || slot < 0 || slot >= registry->max_slots)
    return;
  atomic_store(&registry->slot_pid[slot], (int)pid);
}

void daemon_limits_reclaim_slot(DaemonLimitRegistry* registry, int slot) {
  if (!registry || slot < 0 || slot >= registry->max_slots)
    return;
  atomic_exchange_explicit(&registry->slot_state[slot], SLOT_FREE, memory_order_acq_rel);
  atomic_store_explicit(&registry->slot_pid[slot], 0, memory_order_relaxed);
  /* The module/host occupancy arrays are derived from the slot table; do not
   * decrement here or a SIGKILL between a child's increment and its REGISTERED
   * publish would leak a count.  Callers that need the derived counts call
   * daemon_limits_recompute. */
}

void daemon_limits_reclaim_pid(DaemonLimitRegistry* registry, long pid) {
  if (!registry || pid <= 0)
    return;
  for (int i = 0; i < registry->max_slots; i++) {
    if (atomic_load(&registry->slot_state[i]) == SLOT_FREE)
      continue;
    if (atomic_load(&registry->slot_pid[i]) == (int)pid) {
      daemon_limits_reclaim_slot(registry, i);
      return;
    }
  }
}

void daemon_limits_recompute(DaemonLimitRegistry* registry) {
  if (!registry)
    return;
  /* Zero the derived arrays, then re-derive solely from the REGISTERED slots.
   * A child that was SIGKILLed after incrementing a counter but before
   * publishing REGISTERED is not counted, and its leaked increment is erased by
   * the zeroing, so the leak cannot persist. */
  for (int m = 0; m < registry->module_count; m++)
    atomic_store_explicit(&registry->module_active[m], 0, memory_order_relaxed);
  for (int h = 0; h < registry->host_slots; h++)
    atomic_store_explicit(&registry->host_active[h], 0, memory_order_relaxed);
  for (int i = 0; i < registry->max_slots; i++) {
    if (atomic_load_explicit(&registry->slot_state[i], memory_order_acquire) != SLOT_REGISTERED)
      continue;
    int module = atomic_load_explicit(&registry->slot_module[i], memory_order_relaxed);
    if (module >= 0 && module < registry->module_count)
      atomic_fetch_add_explicit(&registry->module_active[module], 1, memory_order_relaxed);
    int host = atomic_load_explicit(&registry->slot_host[i], memory_order_relaxed);
    if (host >= 0 && host < registry->host_slots)
      atomic_fetch_add_explicit(&registry->host_active[host], 1, memory_order_relaxed);
  }
}

DaemonLimitResult daemon_limits_register(DaemonLimitRegistry* registry, int slot, int module_index,
                                         const char* peer_ip, int module_cap) {
  if (!registry || slot < 0 || slot >= registry->max_slots)
    return DAEMON_LIMIT_UNAVAILABLE;
  if (module_index < 0 || module_index >= registry->module_count)
    return DAEMON_LIMIT_UNAVAILABLE;
  if (atomic_load_explicit(&registry->slot_state[slot], memory_order_acquire) != SLOT_CLAIMED)
    return DAEMON_LIMIT_UNAVAILABLE;

  int host = -1;
  if (registry_tracks_hosts(registry))
    host = host_intern(registry, peer_ip);

  int module_count = atomic_fetch_add(&registry->module_active[module_index], 1) + 1;
  if (module_cap > 0 && module_count > module_cap) {
    atomic_fetch_sub(&registry->module_active[module_index], 1);
    return DAEMON_LIMIT_MODULE_FULL;
  }
  if (host >= 0) {
    int host_count = atomic_fetch_add(&registry->host_active[host], 1) + 1;
    if (registry->per_host_cap > 0 && host_count > registry->per_host_cap) {
      atomic_fetch_sub(&registry->host_active[host], 1);
      atomic_fetch_sub(&registry->module_active[module_index], 1);
      return DAEMON_LIMIT_HOST_FULL;
    }
  }
  atomic_store(&registry->slot_module[slot], module_index);
  atomic_store(&registry->slot_host[slot], host);
  atomic_store_explicit(&registry->slot_state[slot], SLOT_REGISTERED, memory_order_release);
  return DAEMON_LIMIT_OK;
}

bool daemon_limits_auth_locked(DaemonLimitRegistry* registry, const char* peer_ip,
                               int* seconds_remaining) {
  if (!registry || registry->lockout_threshold <= 0 || registry->lockout_duration_sec <= 0)
    return false;
  int bucket = host_lookup(registry, peer_ip);
  if (bucket < 0)
    return false;
  long long until = atomic_load(&registry->host_until[bucket]);
  long long now = (long long)time(NULL);
  if (until > now) {
    if (seconds_remaining)
      *seconds_remaining = (int)(until - now);
    return true;
  }
  if (until != 0) {
    /* The previous lockout has expired: clear the stale counter so the source
     * gets a fresh allowance. */
    atomic_store(&registry->host_fail[bucket], 0);
    atomic_store(&registry->host_until[bucket], 0);
  }
  return false;
}

void daemon_limits_auth_record_failure(DaemonLimitRegistry* registry, const char* peer_ip) {
  if (!registry || registry->lockout_threshold <= 0 || registry->lockout_duration_sec <= 0)
    return;
  int bucket = host_intern(registry, peer_ip);
  if (bucket < 0)
    return;
  int failures = atomic_fetch_add(&registry->host_fail[bucket], 1) + 1;
  if (failures >= registry->lockout_threshold) {
    long long now = (long long)time(NULL);
    atomic_store(&registry->host_until[bucket], now + (long long)registry->lockout_duration_sec);
  }
}

void daemon_limits_auth_record_success(DaemonLimitRegistry* registry, const char* peer_ip) {
  if (!registry)
    return;
  int bucket = host_lookup(registry, peer_ip);
  if (bucket < 0)
    return;
  atomic_store(&registry->host_fail[bucket], 0);
  atomic_store(&registry->host_until[bucket], 0);
}
