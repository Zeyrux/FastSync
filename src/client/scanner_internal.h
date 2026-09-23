#ifndef SCANNER_INTERNAL_H
#define SCANNER_INTERNAL_H

/* Internal declarations shared between the scanner translation units
 * (scanner_filter.c, scanner.c, scanner_parallel.c).  Nothing here is part of
 * the public scanner façade (scanner.h); every symbol stays internal to the
 * client module. */

#include "array_list.h"
#include "file.h"
#include "scanner.h"
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

typedef struct {
  char* path;
  int depth;
  FilterNode* context; /* inherited per-directory filter context */
} DirEntry;

/* How rsync's readlink_stat()/generator resolves one source symlink. */
typedef enum {
  LINK_ACTION_SKIP,           /* not transferred (no link option) */
  LINK_ACTION_SKIP_PROTECTED, /* ignored as unsafe by --safe-links; rsync keeps
                                 it in the transfer, so its destination mirror
                                 must be protected from --delete */
  LINK_ACTION_DEREF,          /* follow the referent (--copy-links, an unsafe
                                 target under --copy-unsafe-links, or -k dir) */
  LINK_ACTION_CARRY,          /* transmit the link itself (-l) */
} LinkAction;

typedef struct {
  char* path;
  struct stat stats;
  bool is_directory;
  /* True when the entry should be carried through as a SYMLINK (is_symlink)
     rather than a dereferenced file/directory.  When true, `link_target` holds
     the owned target string to transmit (sender-munged under --munge-links);
     ownership transfers to the File built from this entry. */
  bool is_symlink;
  char* link_target;
  /* True when the entry was pruned by a user selection rule (--filter/-C/per-dir
     rules or the --exclude/--include layer) rather than skipped for another
     reason (unreadable, symlink policy, not applicable). */
  bool excluded;
  /* True when the entry was skipped specifically by --max-size/--min-size.
     Size pruning protects the destination mirror even under --delete-excluded,
     so it is recorded into a separate sink from `excluded`. */
  bool size_excluded;
  /* True when a symlink selected for dereferencing (-L/--copy-links or an
     unsafe target under --copy-unsafe-links) had no usable referent (a broken
     link or a stat() failure).  rsync still reports this as a partial transfer
     (exit 23) even though the entry is skipped, so the scanner records it as a
     non-fatal I/O error. */
  bool referent_error;
} ScannerEntry;

typedef enum {
  SCANNER_SPECIAL_REGULAR,  /* ordinary file: transfer content */
  SCANNER_SPECIAL_RECREATE, /* is_special node to recreate on the receiver */
  SCANNER_SPECIAL_SKIP,     /* non-regular entry not requested: skip */
} ScannerSpecial;

/* scanner_filter.c */
void filter_node_destroy(void* item);
FilterNode* filter_node_alloc(FilterNode* parent, FilterRuleList* own);
void dir_entry_destroy(void* item);
DirEntry* dir_entry_create(const char* path, int depth, FilterNode* context);
LinkAction scanner_link_action(const ScannerOptions* options, const char* path,
                               const char* link_rel, char* target, size_t target_size);
File* scanner_build_dir_file(const char* path, const struct stat* stats,
                             const ScannerOptions* options);
char* child_rel_path(const char* parent_rel, const char* name);
char* scanner_prefix_send_path(const char* prefix, const char* rel);
bool entry_passes_selection(const FileListSet* file_list, const FilterRuleList* base,
                            const FilterNode* node, const char* rel, const char* leaf, bool is_dir,
                            bool per_dir_filters, bool exclude_filter_files, bool* protect_out);
void scanner_capture_xattrs(const DirectoryScanner* scanner, File* file);
void scanner_assign_hardlink(DirectoryScanner* scanner, HardLinkTable* table, File* file,
                             const struct stat* stats);
ScannerSpecial scanner_prepare_special(bool preserve_devices, bool preserve_specials,
                                       bool copy_devices, File* file, const struct stat* stats);
bool excluded_sink_append(ArrayList* list, mtx_t* mtx, const char* rel);
void scanner_note_nonreg(const ScannerOptions* options, const char* fs_path);
void scanner_note_mount(const ScannerOptions* options, const char* fs_path);
void scanner_note_filter(const ScannerOptions* options, const char* name);
void scanner_dir_count_count(const ScannerOptions* options);
void scanner_dir_count_uncount(const ScannerOptions* options);
void scanner_record_excluded(DirectoryScanner* scanner, const char* fs_path);
void scanner_record_size_skipped(DirectoryScanner* scanner, const char* fs_path);
bool scanner_record_synced_dir(const ScannerOptions* options, const char* fs_path, const char* rel,
                               bool relative_mode);
FilterRuleList* read_dir_filters(const ScannerOptions* options, const char* dir_path,
                                 const char* rel, bool* any_exists, char* err, size_t err_size);
int open_directory_filter_context(DirectoryScanner* scanner, const FilterNode* inherited);
int scanner_inspect_entry(const ScannerOptions* options, const char* containing_dir,
                          const char* link_rel, const char* name, ScannerEntry* entry);

/* scanner.c */
bool scanner_capture_dir_time(ArrayList* dir_entries, mtx_t* mutex, const char* root_path,
                              const char* fs_path, bool relative_mode, const char* relative_prefix,
                              bool preserve_atimes, bool preserve_crtimes, bool preserve_xattrs,
                              bool preserve_acls, bool no_implied_dirs,
                              const FileListSet* file_list);

#endif
