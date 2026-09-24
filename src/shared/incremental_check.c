#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "array_list.h"
#include "charset.h"
#include "chmod.h"
#include "chunk.h"
#include "compression.h"
#include "config.h"
#include "data.h"
#include "delay_updates.h"
#include "delta.h"
#include "file.h"
#include "format.h"
#include "identity.h"
#include "incremental_check.h"
#include "log.h"
#include "metadata.h"
#include "protocol.h"
#include "utils.h"
#include "xattr.h"

/* Receive a file's xattr block (when the config enables xattr transport) and
 * attach it to `file`.  Returns false on a malformed/oversized frame. */
bool receive_file_xattrs(File* file, int fd, const Config* config) {
  if (!config->use_xattrs)
    return true;
  int xok = 0;
  FileXattrList* list = xattr_receive(fd, &xok, config->preserve_acls);
  if (!xok) {
    xattr_list_free(list);
    return false;
  }
  file->xattrs = list;
  return true;
}

static bool receive_file_payload_into(File* file, int fd, const Config* config,
                                      const char* dest_path, unsigned long long expected_size);

/* Receive a STATUS_DELTA_DATA response: the sender's delta against the basis we
   signed.  Deserializes, decompresses and applies the delta (in memory or
   through a spool temp file), then receives the metadata/xattr block and
   installs the reconstructed payload.  Takes ownership of `old_data` and `sig`,
   releasing both on every path. */
static File* receive_delta_data_branch(int fd, const Config* config, const char* check_path,
                                       void* old_data, unsigned long long old_size, int basis_fd,
                                       DeltaSignature* sig, bool* failed) {
  Data* raw_delta = NULL;
  Delta* delta = NULL;
  void* new_data = NULL;
  char* spool = NULL;
  File* file = NULL;

  raw_delta = receive_data_limited(fd, MAX_RECEIVE_WHOLE_FILE_SIZE);
  if (!raw_delta)
    goto fail;

  if (config->use_compression &&
      !compression_should_skip_with_suffixes(check_path, config->skip_compress_suffixes,
                                             config->skip_compress_set ? config->skip_compress_count
                                                                       : -1)) {
    ProtocolSession* owner = raw_delta->owner;
    Data* decompressed = data_decompress_limited(raw_delta, MAX_RECEIVE_WHOLE_FILE_SIZE);
    data_destroy(raw_delta);
    raw_delta = decompressed;
    if (!raw_delta)
      goto fail;
    /* Charge the decompressed delta to the connection budget (the paired
       wire buffer's charge was just released). */
    if (!data_charge_session(raw_delta, owner, raw_delta->size))
      goto fail;
  }

  delta = delta_deserialize(raw_delta);
  data_destroy(raw_delta);
  raw_delta = NULL;
  if (!delta)
    goto fail;

  uint64_t new_size = delta->new_file_size;
  if (new_size > SIZE_MAX) {
    send_status(fd, STATUS_ERROR);
    goto fail;
  }
  /* Wire-stats tally: bytes taken straight from the basis file (matched
     delta blocks) and bytes shipped literally (protocol 2.28.0).  Computed
     before the delta is destroyed. */
  unsigned long long matched = 0;
  unsigned long long literal = 0;
  for (uint32_t k = 0; k < delta->instruction_count; k++) {
    if (delta->instructions[k].type == DELTA_INSTR_BLOCK_MATCH)
      matched += delta->instructions[k].match.length;
    else if (delta->instructions[k].type == DELTA_INSTR_LITERAL)
      literal += delta->instructions[k].literal.length;
  }

  /* A reconstructed file above the streaming bound is written into a spool
     temp file through delta_apply_to_fd; a smaller one keeps the historical
     in-memory reconstruction. */
  if (new_size > protocol_whole_file_receive_limit()) {
    char* dest_path = path_cat(config->receive_root_directory, check_path);
    int spool_fd = dest_path ? file_spool_for_payload(dest_path, &spool) : -1;
    free(dest_path);
    if (spool_fd < 0) {
      send_status(fd, STATUS_ERROR);
      goto fail;
    }
    bool applied =
        delta_apply_to_fd(old_data, basis_fd, old_size, delta, config->delta_block_size, spool_fd);
    if (close(spool_fd) != 0)
      applied = false;
    delta_destroy(delta);
    delta = NULL;
    if (!applied) {
      send_status(fd, STATUS_ERROR);
      goto fail;
    }
  } else {
    new_data = old_data ? delta_apply(old_data, old_size, delta, config->delta_block_size)
                        : delta_apply_fd(basis_fd, old_size, delta, config->delta_block_size);
    delta_destroy(delta);
    delta = NULL;
    if (!new_data)
      goto fail;
  }

  file = file_create(check_path);
  if (!file)
    goto fail;
  file->matched_bytes = matched;
  file->literal_bytes = literal;

  if (config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(fd, &meta_ok);
    if (!meta_ok)
      goto fail;
  }
  if (!receive_file_xattrs(file, fd, config))
    goto fail;

  if (spool) {
    Data* reserved = data_create_reserve((size_t)new_size);
    if (reserved == NULL) {
      send_status(fd, STATUS_ERROR);
      goto fail;
    }
    data_destroy(file->data);
    file->data = reserved;
    file->basis_copy = spool;
    spool = NULL; /* ownership moved into file->basis_copy */
    file->data_spool = true;
  } else {
    Data* replacement = data_create(new_data, (size_t)new_size);
    new_data = NULL; /* data_create owns, and frees, the buffer on failure */
    if (replacement == NULL) {
      send_status(fd, STATUS_ERROR);
      goto fail;
    }
    data_destroy(file->data);
    file->data = replacement;
  }

  free(old_data);
  delta_signature_destroy(sig);
  return file;

fail:
  free(new_data);
  if (spool) {
    unlink(spool);
    free(spool);
  }
  file_destroy(file);
  delta_destroy(delta);
  data_destroy(raw_delta);
  free(old_data);
  delta_signature_destroy(sig);
  *failed = true;
  return NULL;
}

/* Receive a STATUS_NEXT response: the sender declined the delta and will send
   the whole file.  Releases the basis signature and snapshot, then receives the
   metadata/xattr block and the full payload.  Takes ownership of `old_data` and
   `sig`, releasing both immediately. */
static File* receive_next_branch(int fd, const Config* config, const char* check_path,
                                 unsigned long long expected_size, void* old_data,
                                 DeltaSignature* sig, bool* failed) {
  delta_signature_destroy(sig);
  free(old_data);

  File* file = file_create(check_path);
  if (!file)
    goto fail;

  if (config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(fd, &meta_ok);
    if (!meta_ok)
      goto fail;
  }
  if (!receive_file_xattrs(file, fd, config))
    goto fail;

  char* dest_path = path_cat(config->receive_root_directory, check_path);
  if (!dest_path)
    goto fail;
  bool payload_ok = receive_file_payload_into(file, fd, config, dest_path, expected_size);
  free(dest_path);
  if (!payload_ok)
    goto fail;
  return file;

fail:
  file_destroy(file);
  *failed = true;
  return NULL;
}

/* Delta handshake dispatcher: sign the basis, ship the signature, then hand the
   response off to the matching branch helper.  Takes ownership of `old_data`
   (and, once created, `sig`); sets `*failed` on every error path. */
static File* receive_delta_file(int fd, const Config* config, const char* check_path,
                                void* old_data, unsigned long long old_size,
                                unsigned long long expected_size, int basis_fd, bool* failed) {
  /* The basis is either an in-memory snapshot (the destination file, bounded) or
   * a confined descriptor (a --fuzzy sibling, possibly larger than memory) that
   * is signed/applied in bounded chunks. */
  Data* sig_data = NULL;
  Status resp = STATUS_ERROR;
  bool sig_sent = false;
  /* A delta check needs at least one basis source: the in-memory destination
   * snapshot or a confined basis descriptor. */
  if (!old_data && basis_fd < 0) {
    *failed = true;
    return NULL;
  }
  DeltaSignature* sig =
      old_data ? delta_signature_create_seeded(old_data, old_size, config->delta_block_size,
                                               (uint32_t)config->checksum_seed)
               : delta_signature_create_fd_seeded(basis_fd, old_size, config->delta_block_size,
                                                  (uint32_t)config->checksum_seed);
  if (!sig)
    goto fail;

  sig_data = delta_signature_serialize(sig);
  if (!sig_data)
    goto fail;

  sig_sent = send_status(fd, STATUS_DELTA_SIGNATURE) && send_data(fd, sig_data);
  data_destroy(sig_data);
  sig_data = NULL;

  if (!sig_sent || !receive_status(fd, &resp))
    goto fail;

  if (resp == STATUS_DELTA_DATA)
    return receive_delta_data_branch(fd, config, check_path, old_data, old_size, basis_fd, sig,
                                     failed);

  if (resp == STATUS_NEXT)
    return receive_next_branch(fd, config, check_path, expected_size, old_data, sig, failed);

  send_status(fd, STATUS_ERROR);
fail:
  data_destroy(sig_data);
  delta_signature_destroy(sig);
  free(old_data);
  *failed = true;
  return NULL;
}

/* ---- Alternate basis directories (--compare-dest / --copy-dest / --link-dest) ----
 * The receiver consults the ordered basis-dir list only when the destination
 * entry is NOT already up to date.  By default an "exact match" is rsync's
 * metadata quick-check: an equal size and an equal mtime (unless --size-only).
 * The FastSync-only --verify-basis additionally requires an equal whole-file
 * content digest, so a hard link / local copy is only then made from
 * byte-verified content. */

typedef struct BasisMatch {
  bool hit;
  BasisDestType type;
  char* basis_path; /* owned absolute path of the matched basis file */
  struct stat st;   /* fstat() of the matched basis file */
} BasisMatch;

static void basis_match_free(BasisMatch* match) {
  if (!match)
    return;
  free(match->basis_path);
  match->basis_path = NULL;
  match->hit = false;
  match->type = BASIS_DEST_NONE;
}

/* Open `path` (via the secure, root-confined primitives) and require it to be
   a regular file of exactly `expected_size` bytes.  Returns an open read-only
   descriptor and its fstat on success. */
static bool basis_open_regular(const char* path, unsigned long long expected_size, int* out_fd,
                               struct stat* out_st) {
  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(path, &leaf, false);
  if (parent_fd < 0)
    return false;
  /* O_NONBLOCK: a client-planted FIFO must not block the receiver's openat()
     forever; the fstat()/S_ISREG gate below rejects it immediately. */
  int fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  free(leaf);
  close(parent_fd);
  if (fd < 0)
    return false;
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
      (unsigned long long)st.st_size != expected_size) {
    close(fd);
    return false;
  }
  *out_fd = fd;
  *out_st = st;
  return true;
}

/* --ignore-times forces every file to be updated, so no basis hit is ever
   declared (matching rsync, where -I prevents link-dest from linking). */
bool file_basis_quick_match(const Config* config, const struct stat* st, time_t check_mtime,
                            long check_mtime_nsec) {
  if (config->size_only)
    return true;
  long mtime_nsec = 0;
#ifdef __linux__
  mtime_nsec = st->st_mtim.tv_nsec;
#endif
  return metadata_mtime_matches(st->st_mtime, mtime_nsec, check_mtime, check_mtime_nsec,
                                config->modify_window);
}

/* True when a basis hit must be confirmed by a whole-file content digest
   (--verify-basis).  False is the rsync-parity default: the metadata
   quick-check alone decides a hit. */
bool file_basis_content_required(const Config* config) {
  return config != NULL && config->verify_basis;
}

/* Probe one candidate basis file: open it (confined, O_NOFOLLOW) and apply
   rsync's metadata quick-check; under --verify-basis also hash its bytes and
   require the sender's digest.  On a hit record `candidate` in `out` and return
   true.  The caller retains ownership of `candidate`. */
static bool basis_match_probe(const Config* config, const char* candidate,
                              unsigned long long check_size, time_t check_mtime,
                              long check_mtime_nsec, const uint8_t* check_digest,
                              size_t check_digest_len, BasisDestType type, BasisMatch* out) {
  int fd;
  struct stat st;
  if (!basis_open_regular(candidate, check_size, &fd, &st))
    return false;
  bool hit = false;
  if (file_basis_quick_match(config, &st, check_mtime, check_mtime_nsec)) {
    hit = true;
    if (file_basis_content_required(config)) {
      uint8_t basis_digest[CHECKSUM_MAX_DIGEST_LEN];
      size_t basis_len = 0;
      bool hashed = checksum_digest_fd((ChecksumAlgo)config->checksum_algo, config->checksum_seed,
                                       fd, basis_digest, sizeof(basis_digest), &basis_len);
      hit = hashed && basis_len == check_digest_len && check_digest_len > 0 &&
            memcmp(basis_digest, check_digest, check_digest_len) == 0;
    }
  }
  close(fd);
  if (!hit)
    return false;
  char* owned = str_dup(candidate);
  if (!owned)
    return false;
  out->hit = true;
  out->type = type;
  out->basis_path = owned;
  out->st = st;
  return true;
}

/* Search the basis-dir list in command-line order and return the first match.
   By default (no --verify-basis) rsync's metadata quick-check is sufficient:
   basis_open_regular has already required an equal size, and
   file_basis_quick_match applies rsync's mtime (or --size-only) rule.
   --verify-basis additionally requires the basis bytes' whole-file digest to
   equal the sender's, restoring FastSync's historical content equality; that
   digest is computed by streaming the open basis descriptor, so an arbitrarily
   large basis is verified without buffering it.  A copy/link install re-reads
   the basis from its path in bounded buffers, so no content buffer is kept.

   `hash_content` gates content READS under --verify-basis: a server-contacting
   --dry-run passes false because hashing a basis against a client-supplied
   digest would be a 1-bit content oracle.  Without --verify-basis a dry-run can
   still confirm the metadata-only hit without reading any basis bytes, matching
   rsync's read-only quick-check.

   Path resolution (rsync 3.4.1 parity): rsync resolves a relative
   --compare-dest/--copy-dest/--link-dest DIR against the destination directory
   (the receiver's cwd) and appends the file's TRANSFER-RELATIVE name, e.g.
   `--compare-dest=basis` with `rsync src/ dst/` probes `dst/basis/<name-inside-src>`.
   FastSync's receive root IS the destination directory, but its default transfer
   mirrors the absolute source path below that root, so check_path carries the
   source-root scaffolding rsync would not append.  Recover rsync's spelling with
   utils_strip_transfer_root for a relative DIR; under -R/--files-from the wire
   path is already transfer-relative, so it is used as-is.  A relative DIR also
   probes the historical mirror-appended spelling as a fallback, so existing
   FastSync-laid-out snapshot trees keep resolving.  An absolute DIR is used
   verbatim and keeps appending the destination-relative check_path (FastSync's
   mirrored layout).  Every candidate stays confined to the authorized root by
   file_open_secure_parent. */
static bool basis_match_find(const Config* config, const char* check_path,
                             unsigned long long check_size, time_t check_mtime,
                             long check_mtime_nsec, const uint8_t* check_digest,
                             size_t check_digest_len, bool hash_content, BasisMatch* out) {
  memset(out, 0, sizeof(*out));
  if (!config || !config_has_basis(config) || config->ignore_times)
    return false;
  /* --verify-basis needs the basis content; a content-blind (dry-run) pass can
     never confirm it and must not read the file, so decline without touching
     the basis bytes. */
  if (file_basis_content_required(config) && !hash_content)
    return false;
  const char* transfer_rel = check_path;
  if (!config->relative && config->files_from_set == NULL)
    transfer_rel = utils_strip_transfer_root(check_path, config->send_directory);
  for (int i = 0; i < config->basis_count; i++) {
    const BasisDest* entry = &config->basis_dirs[i];
    /* An absolute basis path is used verbatim (rsync semantics); a relative one
       is resolved below the receive root.  Both remain subject to the receiver's
       authorized-root confinement inside file_open_secure_parent. */
    bool absolute = entry->path[0] == '/';
    char* basis_dir =
        absolute ? str_dup(entry->path) : path_cat(config->receive_root_directory, entry->path);
    if (!basis_dir)
      continue;
    const char* names[2];
    int name_count = 0;
    if (absolute)
      names[name_count++] = check_path;
    else
      names[name_count++] = transfer_rel;
    if (!absolute && strcmp(transfer_rel, check_path) != 0)
      names[name_count++] = check_path; /* historical mirror-appended spelling */
    bool found = false;
    for (int n = 0; n < name_count && !found; n++) {
      char* candidate = path_cat(basis_dir, names[n]);
      if (!candidate)
        continue;
      found = basis_match_probe(config, candidate, check_size, check_mtime, check_mtime_nsec,
                                check_digest, check_digest_len, entry->type, out);
      free(candidate);
    }
    free(basis_dir);
    if (found)
      return true;
  }
  return false;
}

/* ---------------------------------------------------------------------------
 * -y/--fuzzy similar-file delta basis.
 *
 * When a file must be transferred and the destination holds no usable content
 * at the exact path (the destination file is absent, or is outside the delta
 * engine's size bounds), --fuzzy lets the receiver reuse an EXISTING regular
 * file in the SAME destination directory as the delta basis, so the sender
 * transmits only the differences instead of the whole file.  This is the
 * rsync "find a similar file to use as a basis for a transfer" case (e.g. a
 * file recreated under a new name whose old-named sibling is still present).
 *
 * The delta handshake is unchanged and receiver-driven, so the sender never
 * learns the basis was a different file and needs no new protocol.  Byte
 * exactness never depends on which bytes the basis holds: the delta protocol
 * only references basis blocks whose Adler-32 + xxHash32 checksums match the
 * source, delta_apply validates every reference against the basis size, and a
 * basis that shares nothing simply makes the sender reply STATUS_NEXT (full
 * transfer).  A fuzzy basis can therefore waste bandwidth but never corrupt a
 * file.
 *
 * Similarity heuristic (rsync 3.4.1 parity, util1.c fuzzy_distance /
 * find_filename_suffix + generator.c find_fuzzy):
 *   * candidates are the target's sibling entries in its destination
 *     directory, opened through the confined root (file_open_secure_parent +
 *     openat O_NOFOLLOW, fstatat AT_SYMLINK_NOFOLLOW) -- symlinks are never
 *     followed and nothing outside the destination root is ever read;
 *   * dotfiles, directories, the target's own name, and the .fastsync-stage /
 *     temp scratch names are never candidates;
 *   * size gate = rsync's, NOT the ordinary delta engine's bounds: any
 *     non-empty regular sibling up to the receiver's whole-file buffer cap is
 *     eligible, regardless of the 16 KiB delta minimum or the 10x delta size
 *     ratio (rsync's find_fuzzy has no delta-size gate at all).  The delta
 *     engine consumes the fuzzy basis through the same signature handshake
 *     whether or not it is inside delta_should_attempt's window;
 *   * first pass = an exact size+mtime match wins regardless of name (rsync's
 *     "fuzzy size/modtime match");
 *   * otherwise the winner minimizes rsync's weighted Levenshtein distance
 *     (substitution ± byte difference, insertion UNIT+byte, 16.16 fixed point)
 *     plus ten times the suffix distance, accepted only when <= 25*UNIT; the
 *     tie-break (smallest size gap, then lexical name) keeps the result
 *     deterministic across filesystem readdir order (rsync leaves equal
 *     distances to its file-list order).
 * ------------------------------------------------------------------------- */

/* A directory scan is linear in the number of entries; the fuzzy search stops
 * after this many so a pathological huge directory cannot stall a transfer.
 * The cap bounds the readdir() ITERATIONS, not the per-entry work: every
 * entry that survives the (cheap) size and pre-name gates still runs an
 * edit-distance DP, so the per-entry DP cost is separately bounded below by
 * pre-pruning on the name length gap and the absent-character bound, and by
 * trimming the common prefix/suffix before the DP runs on the middles only. */
#define FUZZY_MAX_DIRECTORY_SCAN 4096
/* Names longer than this never take part in fuzzy matching: the edit-distance
 * DP below is O(len^2), so over-long names are bounded out of the search. */
#define FUZZY_NAME_LIMIT 192

typedef struct {
  char name[FUZZY_NAME_LIMIT + 1];
  unsigned long long size;
  uint32_t distance;
  unsigned long long size_gap;
} FuzzyCandidate;

/* rsync's fuzzy distance is a weighted Levenshtein variant in 16.16 fixed point
 * (util1.c fuzzy_distance): a substitution costs UNIT +/- the byte difference
 * and an insertion costs UNIT + the inserted byte, so similar names score low.
 * The search keeps only distances <= 25*UNIT.  Ported verbatim for parity. */
#define FUZZY_DIST_UNIT (1u << 16)
#define FUZZY_DIST_REJECT (0xFFFFu * FUZZY_DIST_UNIT + 1)
#define FUZZY_DIST_LIMIT (25u * FUZZY_DIST_UNIT)

static uint32_t fuzzy_distance(const char* s1, unsigned len1, const char* s2, unsigned len2,
                               uint32_t upperlimit, uint32_t* scratch) {
  if ((len1 > len2 ? len1 - len2 : len2 - len1) * FUZZY_DIST_UNIT > upperlimit)
    return FUZZY_DIST_REJECT;
  if (!len1 || !len2) {
    if (!len1) {
      s1 = s2;
      len1 = len2;
    }
    uint32_t cost = 0;
    for (unsigned i = 0; i < len1; i++)
      cost += (uint8_t)s1[i];
    return (uint32_t)len1 * FUZZY_DIST_UNIT + cost;
  }
  uint32_t* a = scratch;
  for (unsigned i2 = 0; i2 < len2; i2++)
    a[i2] = (i2 + 1) * FUZZY_DIST_UNIT;
  for (unsigned i1 = 0; i1 < len1; i1++) {
    uint32_t diag = i1 * FUZZY_DIST_UNIT;
    uint32_t above = (i1 + 1) * FUZZY_DIST_UNIT;
    for (unsigned i2 = 0; i2 < len2; i2++) {
      uint32_t left = a[i2];
      int32_t cost = (int32_t)(uint8_t)s1[i1] - (int32_t)(uint8_t)s2[i2];
      if (cost != 0)
        cost = cost < 0 ? (int32_t)(FUZZY_DIST_UNIT - (uint32_t)(-cost))
                        : (int32_t)(FUZZY_DIST_UNIT + (uint32_t)cost);
      uint32_t diag_inc = diag + (uint32_t)cost;
      uint32_t left_inc = left + FUZZY_DIST_UNIT + (uint8_t)s1[i1];
      uint32_t above_inc = above + FUZZY_DIST_UNIT + (uint8_t)s2[i2];
      a[i2] = above = left < above ? (left_inc < diag_inc ? left_inc : diag_inc)
                                   : (above_inc < diag_inc ? above_inc : diag_inc);
      diag = left;
    }
  }
  return a[len2 - 1];
}

/* rsync's find_filename_suffix (util1.c): return the last significant filename
 * suffix (its dot included).  Leading dots are not a suffix; a trailing "~" is
 * ignored; .bak/.old/.orig and a "~/<num>" backup marker are skipped. */
static const char* fuzzy_find_suffix(const char* fn, int fn_len, int* len_ptr) {
  const char* suf;
  const char* s;
  bool had_tilde;

  while (fn_len && *fn == '.') {
    fn++;
    fn_len--;
  }
  if (fn_len > 1 && fn[fn_len - 1] == '~') {
    fn_len--;
    had_tilde = true;
  } else {
    had_tilde = false;
  }
  suf = "";
  *len_ptr = 0;
  for (s = fn + fn_len; fn_len > 1;) {
    int s_len;
    while (--s != fn && *s != '.') {
    }
    if (s == fn)
      break;
    s_len = fn_len - (int)(s - fn);
    fn_len = (int)(s - fn);
    if (s_len == 4) {
      if (strcmp(s + 1, "bak") == 0 || strcmp(s + 1, "old") == 0)
        continue;
    } else if (s_len == 5) {
      if (strcmp(s + 1, "orig") == 0)
        continue;
    } else if (s_len > 2 && had_tilde && s[1] == '~' && isdigit((unsigned char)s[2])) {
      continue;
    }
    *len_ptr = s_len;
    suf = s;
    if (s_len == 1)
      break;
    for (s++, s_len--; s_len > 0; s++, s_len--) {
      if (!isdigit((unsigned char)*s))
        return suf;
    }
    s = suf;
  }
  return suf;
}

/* Deterministic ordering of two fuzzy candidates with equal rsync distance:
 * smallest size gap, then the lexical basename (rsync itself takes the last
 * equal-distance candidate in file-list order). */
static bool fuzzy_candidate_better(const FuzzyCandidate* cand, const FuzzyCandidate* best) {
  if (!best->name[0])
    return true;
  if (cand->distance != best->distance)
    return cand->distance < best->distance;
  if (cand->size_gap != best->size_gap)
    return cand->size_gap < best->size_gap;
  return strcmp(cand->name, best->name) < 0;
}

/* Search the destination directory that will contain `check_path` for a similar
 * regular file usable as a --fuzzy delta basis and return an open, confined
 * read descriptor to it (with *out_size set).  Returns -1 (with *out_size 0)
 * when no candidate qualifies, which means the caller performs the normal
 * whole-file transfer.  The basis is signed/applied by streaming its descriptor,
 * so no whole-basis buffer is ever needed and its size is not capped. */
static int fuzzy_basis_find_and_open(const Config* config, const char* check_path,
                                     unsigned long long check_size, time_t check_mtime,
                                     long check_mtime_nsec, unsigned long long* out_size) {
  *out_size = 0;
  if (!config || !config->receive_root_directory || !config->fuzzy || !config->use_delta ||
      !check_path)
    return -1;

  char* full_path = path_cat(config->receive_root_directory, check_path);
  if (!full_path)
    return -1;
  char* leaf = NULL;
  int dir_fd = file_open_secure_parent(full_path, &leaf, false);
  if (dir_fd < 0 || !leaf) {
    free(leaf);
    free(full_path);
    return -1;
  }
  size_t target_len = strlen(leaf);
  /* A target basename longer than FUZZY_NAME_LIMIT can never pass the name gate
     (every candidate name is bounded by the same limit), so skip the scan. */
  if (target_len > FUZZY_NAME_LIMIT) {
    close(dir_fd);
    free(leaf);
    free(full_path);
    return -1;
  }

  int scanfd = dup(dir_fd);
  if (scanfd < 0) {
    close(dir_fd);
    free(leaf);
    free(full_path);
    return -1;
  }
  DIR* dir = fdopendir(scanfd);
  if (!dir) {
    close(scanfd);
    close(dir_fd);
    free(leaf);
    free(full_path);
    return -1;
  }

  /* The weighted-distance scratch row is allocated once per scan (not once per
     candidate). */
  uint32_t* dist_scratch = malloc((FUZZY_NAME_LIMIT + 1) * sizeof(uint32_t));
  if (!dist_scratch) {
    closedir(dir);
    close(dir_fd);
    free(leaf);
    free(full_path);
    return -1;
  }
  int fname_suf_len = 0;
  const char* fname_suf = fuzzy_find_suffix(leaf, (int)target_len, &fname_suf_len);

  FuzzyCandidate best;
  memset(&best, 0, sizeof(best));
  uint32_t lowest_dist = FUZZY_DIST_LIMIT;
  /* rsync's fuzzy search runs an exact size+mtime pass before the name-distance
     pass; such a candidate is almost certainly the same content and wins
     regardless of how dissimilar its name is.  The first one (directory order,
     deterministic) is kept. */
  FuzzyCandidate exact;
  memset(&exact, 0, sizeof(exact));
  const struct dirent* entry;
  size_t scanned = 0;
  /* readdir() yields entries in filesystem-dependent order, so the SET of
     candidates seen is order-dependent; the winner is still deterministic
     because every candidate is compared with the total ordering in
     fuzzy_candidate_better (acceptable for a heuristic). */
  while (scanned < FUZZY_MAX_DIRECTORY_SCAN && (entry = readdir(dir)) != NULL) {
    scanned++;
    const char* name = entry->d_name;
    size_t name_len = strlen(name);
    if (name[0] == '.' || name_len == 0 || name_len > FUZZY_NAME_LIMIT || strcmp(name, leaf) == 0)
      continue;
    struct stat st;
    if (fstatat(dir_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode))
      continue;
    unsigned long long cand_size = (unsigned long long)st.st_size;
    if (cand_size == 0)
      continue;
    long cand_nsec = 0;
#ifdef __linux__
    cand_nsec = st.st_mtim.tv_nsec;
#endif
    if (!exact.name[0] && cand_size == check_size &&
        metadata_mtime_matches(st.st_mtime, cand_nsec, check_mtime, check_mtime_nsec,
                               config->modify_window)) {
      memcpy(exact.name, name, name_len + 1);
      exact.size = cand_size;
      exact.size_gap = 0;
      continue;
    }
    /* rsync's name-distance pass: a weighted Levenshtein distance over the full
       basenames, plus ten times the same distance over the filename suffixes,
       accepted only when it does not exceed the running lowest distance. */
    int name_suf_len = 0;
    const char* name_suf = fuzzy_find_suffix(name, (int)name_len, &name_suf_len);
    uint32_t distance = fuzzy_distance(name, (unsigned)name_len, leaf, (unsigned)target_len,
                                       lowest_dist, dist_scratch);
    if (distance < 0xFFFF0000U)
      distance += fuzzy_distance(name_suf, (unsigned)name_suf_len, fname_suf,
                                 (unsigned)fname_suf_len, 0xFFFF0000U, dist_scratch) *
                  10;
    if (distance > lowest_dist)
      continue;
    lowest_dist = distance;
    FuzzyCandidate cand;
    memcpy(cand.name, name, name_len + 1);
    cand.size = cand_size;
    cand.distance = distance;
    cand.size_gap = cand_size > check_size ? cand_size - check_size : check_size - cand_size;
    if (fuzzy_candidate_better(&cand, &best))
      best = cand;
  }
  closedir(dir);
  free(leaf);
  free(dist_scratch);

  /* Prefer the exact size+mtime candidate over any name-distance winner. */
  if (exact.name[0])
    best = exact;

  int basis_fd = -1;
  if (best.name[0]) {
    /* O_NONBLOCK: a name raced to a FIFO between the fstatat gate and this open
       would otherwise block the receive thread forever on open(2); with it the
       open fails (ENXIO) and the fstat/S_ISREG gate below would reject it too.
       A regular file opened with O_NONBLOCK is unaffected. */
    int fd = openat(dir_fd, best.name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) {
      struct stat st;
      if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
          (unsigned long long)st.st_size == best.size) {
        basis_fd = fd;
      } else {
        close(fd);
      }
    }
  }
  close(dir_fd);
  free(full_path);
  if (basis_fd >= 0)
    *out_size = best.size;
  return basis_fd;
}

/* Receive one whole-file data frame into `file`.  A payload at or below the
 * receiver's streaming bound keeps the historical charged whole-buffer path; a
 * larger one is streamed into a spool temp file (decompressing incrementally)
 * and installed through the File's basis_copy field.  `expected_size` is the
 * logical size from the check frame (0 when unknown, e.g. the non-incremental
 * path). */
static bool receive_file_payload_into(File* file, int fd, const Config* config,
                                      const char* dest_path, unsigned long long expected_size) {
  bool compress =
      config->use_compression && !compression_should_skip_with_suffixes(
                                     file->path, config->skip_compress_suffixes,
                                     config->skip_compress_set ? config->skip_compress_count : -1);
  Data* buffer = NULL;
  char* spool = NULL;
  unsigned long long size = 0;
  if (!file_receive_payload(fd, compress, expected_size, dest_path,
                            protocol_whole_file_receive_limit(), &buffer, &spool, &size)) {
    return false;
  }
  if (spool) {
    Data* reserved = data_create_reserve((size_t)size);
    if (!reserved) {
      unlink(spool);
      free(spool);
      return false;
    }
    data_destroy(file->data);
    file->data = reserved;
    file->basis_copy = spool;
    file->data_spool = true;
  } else {
    data_destroy(file->data);
    file->data = buffer;
  }
  return true;
}

/* Read the remainder of a full-file transfer after the receiver has already
 * sent STATUS_NEXT: receive the metadata frame (when enabled) followed by the
 * data frame, and return an owned File.  Shared by the plain full-transfer path
 * and the --append-verify prefix-mismatch fallback (a clean full transfer
 * instead of a corrupt prefix+tail blend). */
static File* receive_full_file(int fd, const Config* config, const char* path,
                               unsigned long long expected_size) {
  File* file = file_create(path);
  if (!file)
    return NULL;
  if (config->use_metadata) {
    int meta_ok = 1;
    file->metadata = metadata_receive(fd, &meta_ok);
    if (!meta_ok) {
      file_destroy(file);
      return NULL;
    }
  }
  if (!receive_file_xattrs(file, fd, config)) {
    file_destroy(file);
    return NULL;
  }
  char* dest_path = path_cat(config->receive_root_directory, path);
  if (!dest_path) {
    file_destroy(file);
    return NULL;
  }
  bool ok = receive_file_payload_into(file, fd, config, dest_path, expected_size);
  free(dest_path);
  if (!ok) {
    file_destroy(file);
    return NULL;
  }
  return file;
}

/* ---------------------------------------------------------------------------
 * receive_incremental_check() decomposition.
 *
 * The per-file STATUS_CHECK fast path is split into the small helpers below,
 * called in order by a short linear orchestrator (receive_incremental_check_ex).
 * Each helper owns one decision: request validation, secure destination open,
 * metadata-only skip, server-contacting --dry-run no-mutation short-circuit,
 * alternate-basis match, --append tail resume, block delta, --fuzzy basis, and
 * the final "send the whole file" fallback.  Every protocol send/receive and
 * every resource cleanup is preserved exactly; the non-dry-run wire is
 * byte-for-byte unchanged.  receive_incremental_check_ex additionally exposes a
 * `would_transfer` out-param for the dry-run caller; the 3-arg
 * receive_incremental_check wrapper passes NULL.
 * ------------------------------------------------------------------------- */

/* Owned state threaded through the helpers below. */
typedef struct {
  int fd;
  const Config* config;
  char* check_path; /* received destination-relative path */
  char* full_path;  /* receive-root-prefixed destination path */
  unsigned long long check_size;
  long long check_mtime;
  long long check_mtime_nsec;
  uint8_t check_digest[CHECKSUM_MAX_DIGEST_LEN];
  size_t check_digest_len;
  /* Source metadata carried alongside the check frame whenever a basis dir is
     configured (rsync keeps the whole file list; FastSync's sender-driven
     incremental path otherwise never transmits metadata for a SKIPPED file).
     A basis materialization applies these SOURCE attributes instead of the
     basis inode's, matching rsync's "copy then fix attributes". */
  FileMetadata* source_metadata;
  bool dest_exists; /* any destination entry exists (lstat succeeded) */
  bool has_old_file;
  int old_fd;
  struct stat old_st;
  unsigned long long old_size;
  void* old_data; /* snapshot of the existing destination, or NULL */
} IncrementalCheckState;

typedef enum {
  INCREMENTAL_CONTINUE, /* proceed to the next helper */
  INCREMENTAL_ERROR,    /* protocol/validation failure: return NULL */
  INCREMENTAL_SKIP,     /* up to date: *skipped = true, return NULL */
  INCREMENTAL_DRY_RUN,  /* --dry-run resolved: flags set, return NULL */
  INCREMENTAL_FILE,     /* a File* was produced (out_file) */
} IncrementalCheckOutcome;

static void incremental_check_state_init(IncrementalCheckState* state, int fd,
                                         const Config* config) {
  memset(state, 0, sizeof(*state));
  state->fd = fd;
  state->config = config;
  state->old_fd = -1;
}

/* Release every resource the helpers may have acquired.  Idempotent, so it is
   safe on every exit path exactly the way the original inline cleanup was. */
static void incremental_check_state_cleanup(IncrementalCheckState* state) {
  free(state->old_data);
  state->old_data = NULL;
  if (state->old_fd >= 0)
    close(state->old_fd);
  state->old_fd = -1;
  file_metadata_destroy(state->source_metadata);
  state->source_metadata = NULL;
  free(state->full_path);
  state->full_path = NULL;
  free(state->check_path);
  state->check_path = NULL;
}

/* Receive and validate the STATUS_CHECK request frame: path, size, mtime,
   nanosecond mtime, and (when negotiated) the source digest. */
static IncrementalCheckOutcome incremental_check_receive_request(IncrementalCheckState* state) {
  int fd = state->fd;
  const Config* config = state->config;
  char* check_path = receive_wire_str(fd);
  if (check_path == NULL)
    return INCREMENTAL_ERROR;
  state->check_path = check_path;

  if (!receive_n_data(fd, &state->check_size, sizeof(state->check_size)) ||
      !receive_n_data(fd, &state->check_mtime, sizeof(state->check_mtime)))
    return INCREMENTAL_ERROR;
  if (!receive_n_data(fd, &state->check_mtime_nsec, sizeof(state->check_mtime_nsec)) ||
      state->check_mtime_nsec < 0 || state->check_mtime_nsec >= 1000000000LL) {
    send_error_detail(fd, "invalid check mtime nanoseconds");
    return INCREMENTAL_ERROR;
  }
  if ((config->checksum || config->verify_basis)) {
    uint8_t wire_len;
    if (!receive_n_data(fd, &wire_len, sizeof(wire_len)) || wire_len == 0 ||
        wire_len > CHECKSUM_MAX_DIGEST_LEN ||
        wire_len != checksum_digest_len((ChecksumAlgo)config->checksum_algo)) {
      send_error_detail(fd, "invalid check digest length");
      return INCREMENTAL_ERROR;
    }
    state->check_digest_len = wire_len;
    if (!receive_n_data(fd, state->check_digest, state->check_digest_len))
      return INCREMENTAL_ERROR;
  }
  /* The sender transmits the source metadata with every basis-configured check
     so a basis hit can be materialized with the SOURCE's attributes (rsync
     copies/copies-then-fixes; the receiver would otherwise only have the basis
     inode's stat).  The block is symmetric and consumed unconditionally here,
     whether or not this file ends up as a basis hit. */
  if (config_has_basis(config) && config->use_metadata) {
    int meta_ok = 1;
    state->source_metadata = metadata_receive(fd, &meta_ok);
    if (!meta_ok)
      return INCREMENTAL_ERROR;
  }

  /* No file-size refusal: a whole-file payload larger than the historical
     whole-file bound is streamed through a bounded buffer (see
     file_receive_payload).  Only a size that cannot be represented on this
     platform is rejected. */
  if (state->check_size > SIZE_MAX) {
    send_error_detail(fd, "check size is not representable");
    return INCREMENTAL_ERROR;
  }

  if (check_path[0] == '\0' || has_path_traversal(check_path)) {
    char* escaped_path = output_escape(check_path, log_get_8_bit_output());
    log_message(LOG_LEVEL_ERROR, "Invalid received check path: %s",
                escaped_path ? escaped_path : "<allocation failed>");
    free(escaped_path);
    return INCREMENTAL_ERROR;
  }
  return INCREMENTAL_CONTINUE;
}

/* Open the existing destination entry once, confined below the receive root,
   and record its stat. */
static IncrementalCheckOutcome incremental_check_open_destination(IncrementalCheckState* state) {
  char* full_path = path_cat(state->config->receive_root_directory, state->check_path);
  if (!full_path) {
    send_error_detail(state->fd, "could not build destination path");
    return INCREMENTAL_ERROR;
  }
  state->full_path = full_path;

  char* leaf = NULL;
  int parent_fd = file_open_secure_parent(full_path, &leaf, false);
  if (parent_fd >= 0) {
    struct stat dest_st;
    if (fstatat(parent_fd, leaf, &dest_st, AT_SYMLINK_NOFOLLOW) == 0)
      state->dest_exists = true;
    /* O_NONBLOCK: an existing FIFO at the destination must not block this
       openat(); the S_ISREG gate below rejects the non-regular entry. */
    state->old_fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    free(leaf);
    close(parent_fd);
    state->has_old_file = state->old_fd >= 0 && fstat(state->old_fd, &state->old_st) == 0 &&
                          S_ISREG(state->old_st.st_mode);
  }
  if (!state->has_old_file && state->old_fd >= 0) {
    close(state->old_fd);
    state->old_fd = -1;
  }
  state->old_size = state->has_old_file ? (unsigned long long)state->old_st.st_size : 0;
  return INCREMENTAL_CONTINUE;
}

/* Output parity (protocol 2.23.0): when the wire config asked for it, report a
   snapshot of the pre-transfer destination entry BEFORE the ordinary verdict so
   the sender can render rsync-accurate -i/--out-format columns.  A missing
   destination is reported explicitly (existed=false) rather than omitted, so
   the sender can distinguish "new" from "unknown". */
static IncrementalCheckOutcome incremental_check_report_dest_info(IncrementalCheckState* state) {
  if (!state->config->report_dest_info)
    return INCREMENTAL_CONTINUE;
  OutputDestState info;
  memset(&info, 0, sizeof(info));
  info.known = true;
  info.existed = state->has_old_file;
  if (state->has_old_file) {
    info.size = (unsigned long long)state->old_st.st_size;
    info.mtime_sec = (long long)state->old_st.st_mtime;
#ifdef __linux__
    info.mtime_nsec = state->old_st.st_mtim.tv_nsec;
#endif
    info.mode = (uint32_t)state->old_st.st_mode;
    info.uid = (int32_t)state->old_st.st_uid;
    info.gid = (int32_t)state->old_st.st_gid;
  }
  if (!send_status(state->fd, STATUS_DEST_INFO) || !format_dest_state_send(state->fd, &info))
    return INCREMENTAL_ERROR;
  return INCREMENTAL_CONTINUE;
}

/* --ignore-existing short-circuit.  The receiver must answer "skip" (STATUS_OK)
   BEFORE the sender transmits any payload, otherwise the whole file crosses the
   wire only to be discarded at write time.  rsync skips an existing destination
   entry regardless of its content or type, so the reply depends only on the
   lstat existence probe; the ordinary --ignore-existing checks inside
   file_receive remain as defense-in-depth for the frame types that have no
   per-file check (directories/symlinks/specials/hard-links). */
static IncrementalCheckOutcome
incremental_check_ignore_existing(const IncrementalCheckState* state) {
  if (!state->config->ignore_existing || !state->dest_exists)
    return INCREMENTAL_CONTINUE;
  if (!send_status(state->fd, STATUS_OK))
    return INCREMENTAL_ERROR;
  return INCREMENTAL_SKIP;
}

/* Metadata for a materialized basis hit: prefer the SOURCE metadata the sender
   transmitted with the check frame (rsync copies then fixes the destination to
   the source's attributes); fall back to the basis inode's own stat when
   metadata was not negotiated.  Consumes state->source_metadata on success. */
static FileMetadata* basis_take_metadata(IncrementalCheckState* state,
                                         const struct stat* basis_st) {
  if (state->source_metadata) {
    FileMetadata* meta = state->source_metadata;
    state->source_metadata = NULL;
    return meta;
  }
  return file_metadata_create(NULL, basis_st, false, false);
}

/* --link-dest relink of an already up-to-date destination.  rsync hard-links a
   destination entry to a matching basis even when the entry is already correct,
   so a run over an existing tree still maximizes sharing with the basis.  Only a
   link-dest basis triggers this (copy-dest/compare-dest leave an up-to-date
   destination untouched, matching rsync).  The ordinary basis path further down
   handles every not-up-to-date case, so this helper only adds the relink that
   the quick-skip would otherwise short-circuit. */
static IncrementalCheckOutcome incremental_check_link_dest_relink(IncrementalCheckState* state,
                                                                  File** out_file) {
  const Config* config = state->config;
  if (!config_has_basis(config) || config->ignore_times || config->dry_run)
    return INCREMENTAL_CONTINUE;
  if (!state->has_old_file)
    return INCREMENTAL_CONTINUE;
  BasisMatch basis;
  basis_match_find(config, state->check_path, state->check_size, (time_t)state->check_mtime,
                   (long)state->check_mtime_nsec, state->check_digest, state->check_digest_len,
                   true, &basis);
  /* Only a link-dest hit relinks; a copy-dest/compare-dest hit (or a miss) lets
     the up-to-date check below keep the existing destination. */
  if (!basis.hit || basis.type != BASIS_DEST_LINK) {
    basis_match_free(&basis);
    return INCREMENTAL_CONTINUE;
  }
  /* Already the basis inode: nothing to do, leave the destination alone. */
  if (basis.st.st_dev == state->old_st.st_dev && basis.st.st_ino == state->old_st.st_ino) {
    basis_match_free(&basis);
    return INCREMENTAL_CONTINUE;
  }
  File* materialized = file_create(state->check_path);
  if (materialized) {
    data_destroy(materialized->data);
    materialized->data = data_create_reserve((size_t)state->check_size);
    if (!materialized->data) {
      file_destroy(materialized);
      materialized = NULL;
    }
  }
  if (materialized) {
    materialized->metadata = basis_take_metadata(state, &basis.st);
    materialized->skip = true;
    materialized->basis_link = basis.basis_path;
    basis.basis_path = NULL;
    if (!materialized->metadata) {
      file_destroy(materialized);
      materialized = NULL;
    }
  }
  if (materialized) {
    if (!send_status(state->fd, STATUS_OK)) {
      basis_match_free(&basis);
      file_destroy(materialized);
      return INCREMENTAL_ERROR;
    }
    basis_match_free(&basis);
    *out_file = materialized;
    return INCREMENTAL_FILE;
  }
  basis_match_free(&basis);
  return INCREMENTAL_CONTINUE;
}

/* Metadata-only (and, when --checksum forces it, content) up-to-date decision.
   Loads the old contents only when a checksum comparison or delta needs them. */
static IncrementalCheckOutcome incremental_check_quick_skip(IncrementalCheckState* state,
                                                            bool* out_try_delta) {
  int fd = state->fd;
  const Config* config = state->config;
  bool has_old_file = state->has_old_file;
  unsigned long long old_size = state->old_size;
  struct stat st = state->old_st;

  bool size_equal = has_old_file && old_size == state->check_size;
  bool match_by_metadata = false;
  if (size_equal && !config->ignore_times && !config->size_only) {
    long long old_mtime_nsec = 0;
#ifdef __linux__
    old_mtime_nsec = st.st_mtim.tv_nsec;
#endif
    match_by_metadata =
        metadata_mtime_matches(st.st_mtime, old_mtime_nsec, (time_t)state->check_mtime,
                               (long)state->check_mtime_nsec, config->modify_window);
  }

  bool try_delta = config->use_delta && !config->whole_file && has_old_file &&
                   delta_should_attempt(old_size, state->check_size, config->delta_max_file_size);
  bool checksum_needs_read = size_equal && !config->ignore_times && config->checksum;
  /* --dry-run must never read the destination file's CONTENTS: a client could
     otherwise use `--dry-run --checksum` against a read-only module as a
     1-bit content oracle (hash match / mismatch) and force arbitrary reads.
     Decide from metadata alone; when metadata is inconclusive (checksum or
     delta would have required the body) report would-transfer.  The real
     (non-dry-run) behavior below is unchanged. */
  bool need_old_data = !config->dry_run && (checksum_needs_read || try_delta);
  if (config->dry_run)
    try_delta = false;
  *out_try_delta = try_delta;

  if (need_old_data && has_old_file && old_size > 0 && old_size <= MAX_RECEIVE_WHOLE_FILE_SIZE &&
      old_size <= SIZE_MAX) {
    state->old_data = protocol_alloc((size_t)old_size);
    if (state->old_data) {
      size_t got = 0;
      while (got < (size_t)old_size) {
        ssize_t n = read(state->old_fd, (char*)state->old_data + got, (size_t)old_size - got);
        if (n <= 0) {
          free(state->old_data);
          state->old_data = NULL;
          break;
        }
        got += (size_t)n;
      }
    }
  }

  bool match = false;
  if (config->dry_run) {
    /* Metadata-only decision: a size match plus a matching mtime is treated as
       up to date; --checksum/--delta cannot be verified without reading, so an
       otherwise inconclusive comparison is a would-transfer. */
    match = size_equal && !config->ignore_times && (config->size_only || match_by_metadata);
  } else if (checksum_needs_read) {
    uint8_t old_digest[CHECKSUM_MAX_DIGEST_LEN];
    size_t old_len = 0;
    bool hashed = checksum_digest((ChecksumAlgo)config->checksum_algo, config->checksum_seed,
                                  old_size == 0 ? "" : state->old_data, (size_t)old_size,
                                  old_digest, sizeof(old_digest), &old_len);
    match = hashed && old_len == state->check_digest_len && state->check_digest_len > 0 &&
            memcmp(old_digest, state->check_digest, state->check_digest_len) == 0;
  } else if (size_equal && !config->ignore_times) {
    match = config->size_only || match_by_metadata;
  }

  if (match) {
    if (!send_status(fd, STATUS_OK))
      return INCREMENTAL_ERROR;
    return INCREMENTAL_SKIP;
  }
  return INCREMENTAL_CONTINUE;
}

/* Server-contacting --dry-run no-mutation short-circuit.  Runs after the
   quick-skip decision and before any path that could touch the destination.
   When dry_run is set and the file is not already up to date the receiver must
   materialize nothing (no basis link/copy, no append/delta/full transfer) and
   the sender must send no data, so answer STATUS_DRY_RUN_TRANSFER and stop.

   The basis lookup is content-blind: under the default metadata quick-check a
   hit needs no basis bytes and is honored here just as in a real run; under
   --verify-basis a real run hashes the basis against the client-supplied digest,
   which in a dry-run is a 1-bit content oracle, so no basis bytes may be read
   and an otherwise-matching entry is reported as would-transfer.  Everything
   read here (the destination file's metadata, basis candidates' metadata) is
   read-only. */
static IncrementalCheckOutcome incremental_check_dry_run_shortcut(IncrementalCheckState* state,
                                                                  bool* skipped,
                                                                  bool* would_transfer) {
  const Config* config = state->config;
  if (!config->dry_run)
    return INCREMENTAL_CONTINUE;

  bool skip_via_compare = false;
  if (config_has_basis(config) && !config->ignore_times) {
    BasisMatch basis;
    /* hash_content=false: a dry-run must not read or hash the basis file, so
       under --verify-basis no compare-dest hit can be confirmed and an
       otherwise-matching file is reported as would-transfer.  Without
       --verify-basis the metadata quick-check confirms it without touching any
       basis bytes. */
    basis_match_find(config, state->check_path, state->check_size, (time_t)state->check_mtime,
                     (long)state->check_mtime_nsec, state->check_digest, state->check_digest_len,
                     false, &basis);
    if (basis.hit && basis.type == BASIS_DEST_COMPARE && !state->has_old_file)
      skip_via_compare = true;
    basis_match_free(&basis);
  }
  Status reply = skip_via_compare ? STATUS_OK : STATUS_DRY_RUN_TRANSFER;
  if (!send_status(state->fd, reply))
    return INCREMENTAL_ERROR;
  if (skip_via_compare)
    *skipped = true;
  else if (would_transfer)
    *would_transfer = true;
  return INCREMENTAL_DRY_RUN;
}

/* Alternate basis directories (--compare-dest/--copy-dest/--link-dest): a hit
   either suppresses the transfer (compare-dest) or materializes the file from
   the basis without a data frame. */
static IncrementalCheckOutcome incremental_check_try_basis(IncrementalCheckState* state,
                                                           File** out_file) {
  int fd = state->fd;
  const Config* config = state->config;
  if (!config_has_basis(config))
    return INCREMENTAL_CONTINUE;

  BasisMatch basis;
  basis_match_find(config, state->check_path, state->check_size, (time_t)state->check_mtime,
                   (long)state->check_mtime_nsec, state->check_digest, state->check_digest_len,
                   true, &basis);
  if (basis.hit) {
    if (basis.type == BASIS_DEST_COMPARE) {
      basis_match_free(&basis);
      if (!state->has_old_file) {
        if (!send_status(fd, STATUS_OK))
          return INCREMENTAL_ERROR;
        return INCREMENTAL_SKIP;
      }
    } else {
      /* Copy/link installs source their bytes from the basis PATH at install
         time (bounded buffers), so no whole-file content buffer is needed here
         even for an over-limit basis. */
      File* materialized = file_create(state->check_path);
      if (materialized) {
        data_destroy(materialized->data);
        materialized->data = data_create_reserve((size_t)state->check_size);
        if (!materialized->data) {
          file_destroy(materialized);
          materialized = NULL;
        }
      }
      if (materialized) {
        materialized->metadata = basis_take_metadata(state, &basis.st);
        materialized->skip = true; /* receiver must not ack this as a data file */
        if (basis.type == BASIS_DEST_LINK)
          materialized->basis_link = basis.basis_path;
        else
          materialized->basis_copy = basis.basis_path;
        basis.basis_path = NULL;
        if (!materialized->metadata) {
          file_destroy(materialized);
          materialized = NULL;
        }
      }
      if (materialized) {
        if (!send_status(fd, STATUS_OK)) {
          basis_match_free(&basis);
          file_destroy(materialized);
          return INCREMENTAL_ERROR;
        }
        basis_match_free(&basis);
        *out_file = materialized;
        return INCREMENTAL_FILE;
      }
      /* Materialization setup failed: fall through to the normal transfer. */
    }
  }
  basis_match_free(&basis);
  return INCREMENTAL_CONTINUE;
}

/* --append / --append-verify tail resume: when the destination is a SHORTER
   file in an append mode, negotiate the resume offset and receive only the
   tail.  Produces the reconstructed file, or falls through to delta/full. */
static IncrementalCheckOutcome incremental_check_try_append_resume(IncrementalCheckState* state,
                                                                   File** out_file) {
  int fd = state->fd;
  const Config* config = state->config;
  const char* check_path = state->check_path;
  unsigned long long old_size = state->old_size;
  unsigned long long check_size = state->check_size;

  bool append_resume = (config->append || config->append_verify) && state->has_old_file &&
                       append_resume_eligible(old_size, check_size);
  if (!append_resume)
    return INCREMENTAL_CONTINUE;

  /* Ensure the retained prefix (== the whole, shorter destination file) is in
     memory; it is needed both to rebuild the full file and, for
     --append-verify, to checksum it.  A load failure is not fatal: the resume is
     simply not possible and we fall through to the other paths. */
  if (state->old_data == NULL && old_size > 0 && old_size <= MAX_RECEIVE_WHOLE_FILE_SIZE &&
      old_size <= SIZE_MAX) {
    state->old_data = protocol_alloc((size_t)old_size);
    if (state->old_data) {
      size_t got = 0;
      while (got < (size_t)old_size) {
        ssize_t n = read(state->old_fd, (char*)state->old_data + got, (size_t)old_size - got);
        if (n <= 0) {
          free(state->old_data);
          state->old_data = NULL;
          break;
        }
        got += (size_t)n;
      }
    }
  }
  if (state->old_data == NULL && old_size != 0)
    return INCREMENTAL_CONTINUE;

  if (!send_status(fd, STATUS_APPEND) || !send_n_data(fd, &old_size, sizeof(old_size)))
    return INCREMENTAL_ERROR;
  bool verify = config->append_verify;
  bool full_fallback = false;
  if (verify) {
    Status sig_status;
    if (!receive_status(fd, &sig_status))
      return INCREMENTAL_ERROR;
    if (sig_status != STATUS_APPEND_SIG) {
      send_status(fd, STATUS_ERROR);
      return INCREMENTAL_ERROR;
    }
    uint64_t src_prefix_hash;
    if (!receive_n_data(fd, &src_prefix_hash, sizeof(src_prefix_hash)))
      return INCREMENTAL_ERROR;
    /* Compare the retained prefix against the source prefix.  A mismatch must
       never be silently appended to: fall back to a full transfer so the result
       is a byte-identical source copy. */
    uint64_t dst_prefix_hash =
        old_size == 0 ? delta_xxhash64("", 0) : delta_xxhash64(state->old_data, (size_t)old_size);
    if (dst_prefix_hash == src_prefix_hash) {
      if (!send_status(fd, STATUS_APPEND_OK))
        return INCREMENTAL_ERROR;
    } else {
      if (!send_status(fd, STATUS_NEXT))
        return INCREMENTAL_ERROR;
      full_fallback = true;
    }
  }

  if (full_fallback) {
    /* Retained prefix differed: receive the sender's full transfer. */
    free(state->old_data);
    state->old_data = NULL;
    if (state->old_fd >= 0) {
      close(state->old_fd);
      state->old_fd = -1;
    }
    *out_file = receive_full_file(fd, config, check_path, check_size);
    return INCREMENTAL_FILE;
  }

  /* Receive the tail (STATUS_APPEND_DATA + metadata + tail bytes). */
  Status tail_status;
  if (!receive_status(fd, &tail_status))
    return INCREMENTAL_ERROR;
  if (tail_status != STATUS_APPEND_DATA) {
    send_status(fd, STATUS_ERROR);
    return INCREMENTAL_ERROR;
  }
  FileMetadata* meta = NULL;
  FileXattrList* append_xattrs = NULL;
  if (config->use_metadata) {
    int meta_ok = 1;
    meta = metadata_receive(fd, &meta_ok);
    if (!meta_ok) {
      file_metadata_destroy(meta);
      return INCREMENTAL_ERROR;
    }
  }
  if (config->use_xattrs) {
    int xok = 0;
    append_xattrs = xattr_receive(fd, &xok, config->preserve_acls);
    if (!xok) {
      xattr_list_free(append_xattrs);
      file_metadata_destroy(meta);
      return INCREMENTAL_ERROR;
    }
  }
  Data* tail = receive_data_limited(fd, MAX_RECEIVE_WHOLE_FILE_SIZE);
  if (tail == NULL) {
    xattr_list_free(append_xattrs);
    file_metadata_destroy(meta);
    return INCREMENTAL_ERROR;
  }
  if (config->use_compression &&
      !compression_should_skip_with_suffixes(check_path, config->skip_compress_suffixes,
                                             config->skip_compress_set ? config->skip_compress_count
                                                                       : -1)) {
    Data* uncompressed = data_decompress_limited(tail, MAX_RECEIVE_WHOLE_FILE_SIZE);
    ProtocolSession* owner = tail->owner;
    data_destroy(tail);
    if (uncompressed == NULL) {
      xattr_list_free(append_xattrs);
      file_metadata_destroy(meta);
      return INCREMENTAL_ERROR;
    }
    if (!data_charge_session(uncompressed, owner, uncompressed->size)) {
      data_destroy(uncompressed);
      xattr_list_free(append_xattrs);
      file_metadata_destroy(meta);
      return INCREMENTAL_ERROR;
    }
    if (uncompressed->size > MAX_FILE_DATA_SIZE) {
      data_destroy(uncompressed);
      xattr_list_free(append_xattrs);
      file_metadata_destroy(meta);
      return INCREMENTAL_ERROR;
    }
    tail = uncompressed;
  }
  /* The tail must complete the file exactly; anything else is a protocol
     violation (never a truncated or overrun file). */
  unsigned long long expected_tail;
  if (!append_tail_length(old_size, check_size, &expected_tail) ||
      tail->size != (size_t)expected_tail) {
    send_status(fd, STATUS_ERROR);
    data_destroy(tail);
    xattr_list_free(append_xattrs);
    file_metadata_destroy(meta);
    return INCREMENTAL_ERROR;
  }
  size_t full_size = (size_t)check_size;
  void* full = protocol_alloc(full_size ? full_size : 1);
  if (!full) {
    data_destroy(tail);
    xattr_list_free(append_xattrs);
    file_metadata_destroy(meta);
    return INCREMENTAL_ERROR;
  }
  if (old_size > 0 && state->old_data)
    memcpy(full, state->old_data, (size_t)old_size);
  if (tail->size > 0)
    memcpy((char*)full + old_size, tail->data, tail->size);
  data_destroy(tail);
  free(state->old_data);
  state->old_data = NULL;

  File* file = file_create(check_path);
  if (!file) {
    free(full);
    xattr_list_free(append_xattrs);
    file_metadata_destroy(meta);
    return INCREMENTAL_ERROR;
  }
  file->metadata = meta;
  file->xattrs = append_xattrs;
  append_xattrs = NULL;
  data_destroy(file->data);
  file->data = data_create(full, full_size);
  if (!file->data) { /* data_create already freed full on failure */
    file_destroy(file);
    return INCREMENTAL_ERROR;
  }
  *out_file = file;
  return INCREMENTAL_FILE;
}

/* Block delta transfer against the existing destination content. */
static IncrementalCheckOutcome incremental_check_try_delta(IncrementalCheckState* state,
                                                           bool try_delta, File** out_file) {
  if (try_delta && state->old_data != NULL) {
    bool delta_failed = false;
    File* delta_file =
        receive_delta_file(state->fd, state->config, state->check_path, state->old_data,
                           state->old_size, state->check_size, -1, &delta_failed);
    state->old_data = NULL; /* receive_delta_file consumes the snapshot on every path */
    if (delta_file) {
      *out_file = delta_file;
      return INCREMENTAL_FILE;
    }
    if (delta_failed)
      return INCREMENTAL_ERROR;
  }
  free(state->old_data);
  state->old_data = NULL;
  return INCREMENTAL_CONTINUE;
}

/* -y/--fuzzy similar-file delta basis.  Reaching this point means the file
   must be transferred and the destination's own content could not serve as a
   delta basis; try an existing similar-named sibling in the same directory. */
static IncrementalCheckOutcome incremental_check_try_fuzzy(IncrementalCheckState* state,
                                                           File** out_file) {
  const Config* config = state->config;
  if (!config->fuzzy || !config->use_delta)
    return INCREMENTAL_CONTINUE;
  unsigned long long fuzzy_size = 0;
  int fuzzy_fd = fuzzy_basis_find_and_open(config, state->check_path, state->check_size,
                                           (time_t)state->check_mtime,
                                           (long)state->check_mtime_nsec, &fuzzy_size);
  if (fuzzy_fd >= 0) {
    bool fuzzy_failed = false;
    File* fuzzy_file = receive_delta_file(state->fd, config, state->check_path, NULL, fuzzy_size,
                                          state->check_size, fuzzy_fd, &fuzzy_failed);
    close(fuzzy_fd);
    if (fuzzy_file) {
      *out_file = fuzzy_file;
      return INCREMENTAL_FILE;
    }
    if (fuzzy_failed)
      return INCREMENTAL_ERROR;
  }
  return INCREMENTAL_CONTINUE;
}

/* Final fallback: tell the sender to transmit the whole file and receive it. */
static File* incremental_check_receive_full(IncrementalCheckState* state) {
  if (!send_status(state->fd, STATUS_NEXT))
    return NULL;
  if (state->old_fd >= 0) {
    close(state->old_fd);
    state->old_fd = -1;
  }
  return receive_full_file(state->fd, state->config, state->check_path, state->check_size);
}

/* Core implementation.  `would_transfer` (may be NULL) is set true only on the
 * server-contacting --dry-run path, when the file is not up to date and the
 * receiver answered STATUS_DRY_RUN_TRANSFER; the caller then knows no File is
 * returned and nothing was stored. */
File* receive_incremental_check_ex(int fd, const Config* config, bool* skipped,
                                   bool* would_transfer) {
  if (would_transfer)
    *would_transfer = false;
  if (!config || !skipped) {
    send_status(fd, STATUS_ERROR);
    return NULL;
  }
  *skipped = false;

  IncrementalCheckState state;
  incremental_check_state_init(&state, fd, config);

  File* result = NULL;
  bool try_delta = false;
  IncrementalCheckOutcome outcome;

  outcome = incremental_check_receive_request(&state);
  if (outcome == INCREMENTAL_ERROR)
    goto done;

  outcome = incremental_check_open_destination(&state);
  if (outcome == INCREMENTAL_ERROR)
    goto done;

  outcome = incremental_check_report_dest_info(&state);
  if (outcome == INCREMENTAL_ERROR)
    goto done;

  /* --ignore-existing must answer before any data is requested; it takes
     precedence over the metadata up-to-date check below. */
  outcome = incremental_check_ignore_existing(&state);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_SKIP) {
    *skipped = true;
    goto done;
  }

  /* A --link-dest hit relinks even an already up-to-date destination before the
     quick-skip can suppress it (rsync parity). */
  outcome = incremental_check_link_dest_relink(&state, &result);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_FILE)
    goto done;

  outcome = incremental_check_quick_skip(&state, &try_delta);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_SKIP) {
    *skipped = true;
    goto done;
  }

  /* Dry-run resolves here (no mutation) or falls through to the normal path. */
  outcome = incremental_check_dry_run_shortcut(&state, skipped, would_transfer);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome != INCREMENTAL_CONTINUE)
    goto done;

  outcome = incremental_check_try_basis(&state, &result);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_SKIP) {
    *skipped = true;
    goto done;
  }
  if (outcome == INCREMENTAL_FILE)
    goto done;

  outcome = incremental_check_try_append_resume(&state, &result);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_FILE)
    goto done;

  outcome = incremental_check_try_delta(&state, try_delta, &result);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_FILE)
    goto done;

  outcome = incremental_check_try_fuzzy(&state, &result);
  if (outcome == INCREMENTAL_ERROR)
    goto done;
  if (outcome == INCREMENTAL_FILE)
    goto done;

  result = incremental_check_receive_full(&state);

done:
  incremental_check_state_cleanup(&state);
  return result;
}

File* receive_incremental_check(int fd, const Config* config, bool* skipped) {
  return receive_incremental_check_ex(fd, config, skipped, NULL);
}
