#ifndef FILE_H
#define FILE_H

#include "file_send.h"
#include "file_receive.h"
#include "file_types.h"
#include "checksum.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

/* File/FileMetadata lifecycle, local disk helpers, and secure filesystem
   primitives shared by the send/receive pipelines. */

File* file_create(const char* path);
void file_destroy(void* item);
bool file_load_data(File* file);
/* Compute the whole-file content digest of `file` with the negotiated
 * --checksum-choice algorithm and --checksum-seed.  Writes the digest into
 * `out` (capacity `out_capacity`) and its length into `*out_len`.  Returns
 * false on read/allocation failure or when the digest would not fit. */
bool file_checksum(File* file, ChecksumAlgo algo, uint64_t seed, uint8_t* out, size_t out_capacity,
                   size_t* out_len);
size_t file_content_to_buffer(File* file);
FileMetadata* file_metadata_create(const char* path, const struct stat* stats, bool capture_atime,
                                   bool capture_crtime);
void file_metadata_destroy(void* metadata);
/* --open-noatime process-wide sender policy; see file.c. */
void file_set_open_noatime(bool enable);
bool file_get_open_noatime(void);
/* Capture the process umask ONCE, before any threads are created.  Call this at
 * the very top of main() in both entry points so the cached value is read while
 * the process is still single-threaded: reading the umask needs a get+set round
 * trip (umask(0); umask(old)), which would race against receiver threads
 * creating files if it happened during the first write.  Idempotent and safe to
 * call more than once. */
void file_umask_capture(void);
/* Process-wide umask, captured once (thread-safe).  Used to derive the mode of
 * a brand-new destination like rsync: source_mode & 0777 & ~umask.  Falls back
 * to file_umask_capture() (behind pthread_once) if capture was never called. */
unsigned file_process_umask(void);
/* Open `path` read-only for transfer, honouring --open-noatime when set. */
int file_open_for_read(const char* path);
bool file_write_to_disk(const char* path, const void* data, unsigned long long data_size,
                        bool inplace, bool sparse);

/* Symlink trust-boundary helpers (Phase 4, symlink wave; rsync parity).
 * --munge-links is a RECEIVER-side rewrite: rsync prefixes every stored symlink
 * target with this marker, making the link unusable while the referenced
 * directory does not exist.  A SENDER receiving a munged source strips it back
 * off before transmitting (so a munged tree round-trips through the receiver's
 * re-munging). */
#define SYMLINK_MUNGE_PREFIX "/rsyncd-munged/"

char* file_symlink_munge(const char* target);
/* rsync 3.4.1 unsafe_symlink(): true when `target` escapes the transfer tree
 * rooted at `link_path` (the symlink's transfer-relative path incl. its name).
 * Absolute/empty targets and targets climbing above the transfer root (via
 * "..") are unsafe, as are internal "/../" components and trailing "/..". */
bool file_symlink_unsafe(const char* target, const char* link_path);
/* True when a lexical target is relative and contains no ".." component, so it
 * can never escape the receive root once created beneath it. */
bool file_symlink_target_contained(const char* target);
/* Strip a leading SYMLINK_MUNGE_PREFIX from `target` (mutable, in place);
 * returns true when a marker was removed. */
bool file_symlink_unmunge(char* target);
/* Create a symlink at `path` -> `target`, confined below the authorized root
 * (O_NOFOLLOW parent walk, symlinkat; the target is never followed).  The link
 * value is copied verbatim (rsync -l); only the placement path is confined.
 * Returns false when a directory already occupies `path`. */
bool file_symlink_at_secure(const char* path, const char* target);
/* --keep-dirlinks (-K) receiver process-wide policy: allow an in-root existing
 * symlink-to-directory to be followed as a directory. */
void file_set_keep_dirlinks(bool enable);

/* --trust-sender receiver process-wide policy (Phase 5).  When set, the
 * receiver trusts that the sender already produced a clean file list and skips
 * its own redundant up-front re-validation of incoming paths (the empty/".."
 * rejection and the escaping-symlink-target containment).  The low-level
 * fd-relative confinement primitives below are deliberately NOT disabled by
 * this flag, so a hostile sender still cannot escape the authorized root. */
void file_set_trust_sender(bool enable);
bool file_get_trust_sender(void);

/* Secure path/filesystem primitives (symlink-safe, O_NOFOLLOW, root-confined). */
bool file_path_exists_secure(const char* path);
bool file_stat_secure(const char* path, struct stat* st);
bool file_destination_is_newer_secure(const char* path, const FileMetadata* metadata);
int file_open_secure_parent(const char* path, char** leaf_out, bool create_dirs);
/* Protocol 2.28.0 variant: also increments *dirs_created for every missing
 * parent directory this walk creates that lies strictly below `count_floor`
 * (a receive-root-relative path, or NULL to count all of them). */
int file_open_secure_parent_counted(const char* path, char** leaf_out, bool create_dirs,
                                    unsigned* dirs_created, const char* count_floor);
bool file_ensure_directory_secure(const char* path);
bool file_directory_exists_secure(const char* path);
bool file_rename_secure(const char* old_path, const char* new_path);
/* Remove the whole directory tree at `path` (confined, symlink-safe).  Used by
   --force to clear a non-empty destination directory that blocks an incoming
   regular file.  See the .c for the exact success semantics. */
bool file_remove_tree_secure(const char* path);
/* Open a private 0700 directory (creating it on demand) that must live below
   the authorized root.  Used for the --delay-updates staging directory. */
int file_open_private_dir(const char* dir_path);

/* Open an existing --temp-dir scratch directory as-is (absolute or relative;
   no creation, no root confinement), matching rsync's --temp-dir handling. */
int file_open_temp_dir(const char* dir_path);

/* The file_to_disk_secure* variants write a temporary copy in the destination
   directory and atomically rename it over `path`.  temp_dir is a scratch
   directory (an absolute path, or one the caller already resolved against the
   destination root): when it is non-NULL the temporary copy is instead created
   there (with a name unique across the whole scratch directory) and atomically
   renamed into the destination directory once fully written and fsynced.  When
   that rename/link fails with EXDEV (the scratch dir is on another filesystem)
   the write falls back to a non-atomic copy directly in the destination
   directory, matching rsync.  Pass NULL for the same-directory behavior.
   --inplace writes never use temp_dir. */
bool file_to_disk_secure(const char* path, const void* data, unsigned long long data_size,
                         bool inplace, bool sparse, bool preallocate, const FileMetadata* metadata,
                         FileAttrPolicy policy, const char* temp_dir);
bool file_to_disk_secure_with_fsync(const char* path, const void* data,
                                    unsigned long long data_size, bool inplace, bool sparse,
                                    bool preallocate, const FileMetadata* metadata,
                                    FileAttrPolicy policy, bool use_fsync, const char* temp_dir);
/* With update enabled, an existing newer destination is left untouched.  The
   check is descriptor-based for inplace writes; atomic replacement still has
   an unavoidable final rename race without filesystem locking. */
bool file_to_disk_secure_update(const char* path, const void* data, unsigned long long data_size,
                                bool inplace, bool sparse, bool preallocate,
                                const FileMetadata* metadata, FileAttrPolicy policy,
                                const char* temp_dir);
bool file_to_disk_secure_no_replace(const char* path, const void* data,
                                    unsigned long long data_size, bool sparse, bool preallocate,
                                    const FileMetadata* metadata, FileAttrPolicy policy,
                                    const char* temp_dir);
/* Receiver write-path variant that also applies per-file xattrs (-X/-A) and the
 * --fake-super stat xattr fd-relative before the final rename.  `update` /
 * `no_replace` / `use_fsync` mirror the plain wrappers above; `keep_partial`
 * enables --partial best-effort retention of a failed write's temp. */
bool file_to_disk_secure_attrs(const char* path, const void* data, unsigned long long data_size,
                               bool inplace, bool sparse, bool preallocate,
                               const FileMetadata* metadata, FileAttrPolicy policy, bool update,
                               bool no_replace, bool use_fsync, const FileXattrList* xattrs,
                               bool fake_super, bool keep_partial, const char* temp_dir);
/* Atomic --link-dest install: replace `path` with a hard link to `basis_path`
   (via a temp name + rename); fall back to a byte-identical local copy from
   `data` when the link is impossible (EXDEV/EPERM/unsupported filesystem).
   `metadata` is applied only on the copy fallback.  `preallocate` applies to
   that copy fallback only (a hard-linked file shares the basis inode and is
   never re-allocated). */
bool file_to_disk_secure_link(const char* path, const char* basis_path, const void* data,
                              unsigned long long data_size, bool preallocate,
                              const FileMetadata* metadata, FileAttrPolicy policy, bool use_fsync,
                              const char* temp_dir);
/* Like file_to_disk_secure_link, but the byte-copy fallback also applies the
 * per-file xattrs (-X/-A) and --fake-super stat xattr (fd-relative).  On a
 * successful hard link no attributes are applied (the shared inode already
 * carries the basis's). */
bool file_to_disk_secure_link_attrs(const char* path, const char* basis_path, const void* data,
                                    unsigned long long data_size, bool preallocate,
                                    const FileMetadata* metadata, FileAttrPolicy policy,
                                    bool use_fsync, const FileXattrList* xattrs, bool fake_super,
                                    const char* temp_dir);
/* Protocol 2.28.0 receiver-stat variants: like the two above but additionally
 * report through `dirs_created` (when non-NULL) how many parent directories the
 * confined secure walk had to create that lie strictly below `count_floor` (a
 * receive-root-relative prefix, or NULL for all).  Used to reproduce rsync's
 * `Number of created files` directory count on a fresh destination. */
bool file_to_disk_secure_attrs_counted(const char* path, const void* data,
                                       unsigned long long data_size, bool inplace, bool sparse,
                                       bool preallocate, const FileMetadata* metadata,
                                       FileAttrPolicy policy, bool update, bool no_replace,
                                       bool use_fsync, const FileXattrList* xattrs, bool fake_super,
                                       bool keep_partial, const char* temp_dir,
                                       unsigned* dirs_created, const char* count_floor);
bool file_to_disk_secure_link_attrs_counted(const char* path, const char* basis_path,
                                            const void* data, unsigned long long data_size,
                                            bool preallocate, const FileMetadata* metadata,
                                            FileAttrPolicy policy, bool use_fsync,
                                            const FileXattrList* xattrs, bool fake_super,
                                            const char* temp_dir, unsigned* dirs_created,
                                            const char* count_floor);
/* The logical transfer root expressed receive-root-relative, or NULL when the
 * wire paths carry no mirror scaffolding above it.  Caller frees non-NULL. */
char* file_transfer_root_floor(const Config* config);

#endif
