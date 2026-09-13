#include "daemon_limits.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

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
  _Atomic int* slot_state;
  _Atomic int* slot_pid;
  _Atomic int* slot_module;
  _Atomic int* slot_host; /* per-source table bucket, or -1 */
  _Atomic int* module_active;
  _Atomic uint64_t* host_key; /* 0 == empty bucket */
  _Atomic int* host_active;
  _Atomic int* host_fail;
  _Atomic long long* host_until; /* epoch seconds the lockout expires */
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

/* Find the bucket holding `peer_ip`, or -1 when it has no entry. */
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
    if (current == key)
      return (int)idx;
    if (current == 0)
      return -1; /* no tombstones: an empty bucket ends the probe chain */
  }
  return -1;
}

/* Find or insert the bucket for `peer_ip`.  Insertion is a lock-free CAS so two
 * forked children racing on the same source converge on one bucket.  Returns -1
 * when the table is full or the address is unparseable (callers fail open: the
 * global/module caps and ACLs still apply). */
static int host_intern(DaemonLimitRegistry* registry, const char* peer_ip) {
  bool ok = false;
  uint64_t key = daemon_limits_host_hash(peer_ip, &ok);
  if (!ok)
    return -1;
  size_t mask = (size_t)registry->host_slots - 1;
  size_t start = (size_t)(key & mask);
  for (size_t i = 0; i < (size_t)registry->host_slots; i++) {
    size_t idx = (start + i) & mask;
    uint64_t current = atomic_load_explicit(&registry->host_key[idx], memory_order_acquire);
    if (current == key)
      return (int)idx;
    if (current == 0) {
      uint64_t expected = 0;
      if (atomic_compare_exchange_strong_explicit(&registry->host_key[idx], &expected, key,
                                                  memory_order_acq_rel, memory_order_acquire))
        return (int)idx;
      if (atomic_load_explicit(&registry->host_key[idx], memory_order_acquire) == key)
        return (int)idx;
    }
  }
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
  size_t host_until_bytes = round_up((size_t)host_slots * sizeof(_Atomic long long), 16);
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
  int previous =
      atomic_exchange_explicit(&registry->slot_state[slot], SLOT_FREE, memory_order_acq_rel);
  if (previous == SLOT_REGISTERED) {
    int module = atomic_load(&registry->slot_module[slot]);
    int host = atomic_load(&registry->slot_host[slot]);
    if (module >= 0 && module < registry->module_count) {
      int current = atomic_load(&registry->module_active[module]);
      while (current > 0 &&
             !atomic_compare_exchange_weak(&registry->module_active[module], &current, current - 1))
        ;
    }
    if (host >= 0 && host < registry->host_slots) {
      int current = atomic_load(&registry->host_active[host]);
      while (current > 0 &&
             !atomic_compare_exchange_weak(&registry->host_active[host], &current, current - 1))
        ;
    }
  }
  atomic_store(&registry->slot_pid[slot], 0);
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

DaemonLimitResult daemon_limits_register(DaemonLimitRegistry* registry, int slot, int module_index,
                                         const char* peer_ip, int module_cap) {
  if (!registry || slot < 0 || slot >= registry->max_slots)
    return DAEMON_LIMIT_UNAVAILABLE;
  if (module_index < 0 || module_index >= registry->module_count)
    return DAEMON_LIMIT_UNAVAILABLE;
  if (atomic_load_explicit(&registry->slot_state[slot], memory_order_acquire) != SLOT_CLAIMED)
    return DAEMON_LIMIT_UNAVAILABLE;

  int host = -1;
  if (registry->per_host_cap > 0 || registry->lockout_threshold > 0)
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
