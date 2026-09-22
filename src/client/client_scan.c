#include "client_send_internal.h"
#include "array_list.h"
#include "charset.h"
#include "config.h"
#include "delete_plan.h"
#include "file.h"
#include "file_list.h"
#include "filter.h"
#include "hardlink.h"
#include "log.h"
#include "scanner.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Build the scanner options for one scan. Returns false and logs on failure. */
bool prepare_scanner(const Config* config, int num_threads, PreparedScanner* out) {
  if (!out)
    return false;
  out->base_filters = NULL;
  out->hardlinks = NULL;
  out->relative_prefix = NULL;
  memset(&out->options, 0, sizeof(out->options));

  int rule_count = config->filters ? config->filters->size : 0;
  const char** texts = NULL;
  if (rule_count > 0) {
    texts = malloc((size_t)rule_count * sizeof(char*));
    if (!texts) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed for filter rules");
      return false;
    }
    for (int i = 0; i < rule_count; i++)
      texts[i] = (const char*)config->filters->items[i];
  }
  if (rule_count > 0 || config->cvs_exclude) {
    char err[160];
    out->base_filters = filter_base_build(texts, rule_count, config->cvs_exclude,
                                          config->delete_excluded, err, sizeof(err));
    free(texts);
    if (!out->base_filters) {
      log_message(LOG_LEVEL_ERROR, "invalid filter rule: %s", err);
      return false;
    }
  } else {
    free(texts);
  }

  ScannerOptions* options = &out->options;
  options->use_metadata = config->use_metadata;
  options->preserve_atimes = config->preserve_atimes;
  options->preserve_crtimes = config->preserve_crtimes;
  options->preserve_xattrs = config->preserve_xattrs;
  options->preserve_acls = config->preserve_acls;
  options->chunk_size = config->chunk_size;
  /* --exclude/--include are compiled, in command-line order, into the SAME
   * ordered filter rule list as --filter/-f (see config_add_selection_rule), so
   * the legacy per-kind arrays are deliberately NOT passed to the scanner:
   * doing so would re-apply them with the old "excludes first, then includes as
   * a mandatory whitelist" precedence and defeat rsync's first-match-wins
   * ordering.  The arrays remain populated purely for the Config API surface. */
  options->exclude_patterns = NULL;
  options->exclude_count = 0;
  options->include_patterns = NULL;
  options->include_count = 0;
  options->max_size = config->max_size;
  options->min_size = config->min_size;
  options->max_depth = config->max_depth;
  options->num_threads = num_threads;
  options->follow_symlinks = config->follow_symlinks;
  options->copy_links = config->copy_links;
  options->safe_links = config->safe_links;
  options->copy_unsafe_links = config->copy_unsafe_links;
  options->copy_dirlinks = config->copy_dirlinks;
  options->munge_links = config->munge_links;
  options->checksum = config->checksum;
  options->one_file_system = config->one_file_system;
  options->preserve_devices = config->preserve_devices;
  options->preserve_specials = config->preserve_specials;
  options->copy_devices = config->copy_devices;
  options->file_list = (const FileListSet*)config->files_from_set;
  options->base_filters = out->base_filters;
  options->per_dir_filters = config->per_dir_filter;
  options->delete_excluded = config->delete_excluded;
  options->exclude_per_dir_filter_files = config->per_dir_filter_count >= 2;
  options->dirs = config->dirs;
  options->relative = config->relative;
  /* A real recursive transfer recreates empty source directories (rsync
     parity); low-level scanner users leave this off. */
  options->emit_empty_dirs = true;
  /* --no-implied-dirs only has meaning with -R (rsync): without it the option
     is a documented no-op, so the scanner must not suppress directory
     metadata. */
  options->no_implied_dirs = config->no_implied_dirs && config->relative;
  /* -R/--relative outside --files-from reconstructs every destination path from
   * the source spec (rsync's '/./' cut point).  With --files-from the listed
   * entry already supplies the bare relative path, so no prefix is built. */
  if (config->relative && config->files_from_set == NULL && config->send_directory) {
    out->relative_prefix = scanner_relative_prefix(config->send_directory);
    if (!out->relative_prefix) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed building --relative path prefix");
      filter_rule_list_free(out->base_filters);
      out->base_filters = NULL;
      return false;
    }
    options->relative_prefix = out->relative_prefix;
  }
  options->prune_empty_dirs = config->prune_empty_dirs;
  options->ignore_io_errors = config->ignore_errors;
  options->ignore_missing_args = config->ignore_missing_args || config->delete_missing_args;
  options->note_nonreg = (config->info_level & LOG_INFO_NONREG) != 0 && !config->quiet;
  options->note_mount = (config->info_level & LOG_INFO_MOUNT) != 0 && !config->quiet;
  options->send_directory = config->send_directory;
  options->eight_bit_output = config->eight_bit_output;
  options->excluded_paths = NULL;
  options->excluded_mutex = NULL;
  options->size_skipped_paths = NULL;
  options->synced_dirs = NULL;
  options->hardlinks = NULL;
  /* Set by the real send paths; NULL for the metadata-only scans (progress
     pre-count, batch) that must not perturb the sender's --stats counter. */
  options->dir_count = NULL;
  /* P7 Wave D: capture source directory metadata when a directory attribute is
     requested (-p for modes, -t for times unless -O omits them).  Whether they
     are APPLIED is decided receiver-side. */
  options->capture_dir_times = dir_metadata_should_capture(config);
  options->dir_entries = NULL;
  options->dir_entries_mutex = NULL;
  if (config->preserve_hard_links) {
    out->hardlinks = hardlink_table_create();
    if (!out->hardlinks) {
      filter_rule_list_free(out->base_filters);
      out->base_filters = NULL;
      return false;
    }
    options->hardlinks = out->hardlinks;
  }
  return true;
}

void prepared_scanner_destroy(PreparedScanner* prepared) {
  if (!prepared)
    return;
  filter_rule_list_free(prepared->base_filters);
  prepared->base_filters = NULL;
  hardlink_table_destroy(prepared->hardlinks);
  prepared->hardlinks = NULL;
  free(prepared->relative_prefix);
  prepared->relative_prefix = NULL;
}

/* -R/--relative implied directories: rsync transmits the metadata of the
 * parent directories implied by the source path (every prefix component above
 * the source root) so the receiver applies their attributes to the created
 * parents.  FastSync's scan only covers the source root and below, so append
 * one metadata-only directory entry per implied ancestor.  --no-implied-dirs
 * suppresses this exactly like rsync.  A missing ancestor is never fatal. */
bool append_implied_dir_times(const Config* config, ArrayList* dir_entries) {
  if (!dir_entries || !config->relative || config->files_from_set != NULL ||
      config->no_implied_dirs || !config->send_directory)
    return true;
  char* prefix = scanner_relative_prefix(config->send_directory);
  if (!prefix)
    return true;
  int ncomp = 0;
  for (const char* s = prefix; *s;) {
    while (*s == '/')
      s++;
    if (!*s)
      break;
    while (*s && *s != '/')
      s++;
    ncomp++;
  }
  if (ncomp <= 1) {
    free(prefix);
    return true;
  }
  char* fs = str_dup(config->send_directory);
  if (!fs) {
    free(prefix);
    return true;
  }
  size_t flen = strlen(fs);
  while (flen > 1 && fs[flen - 1] == '/')
    fs[--flen] = '\0';
  bool ok = true;
  /* Walk the source path upwards one component at a time (fs is truncated in
     place, so each step targets the next implied ancestor). */
  for (int depth = ncomp - 2; depth >= 0 && ok; depth--) {
    char* slash = strrchr(fs, '/');
    if (!slash || slash == fs)
      break;
    *slash = '\0';
    char* p = prefix;
    int c = 0;
    while (c <= depth) {
      while (*p == '/')
        p++;
      while (*p && *p != '/')
        p++;
      c++;
    }
    char saved = *p;
    *p = '\0';
    struct stat st;
    if (stat(fs, &st) == 0 && S_ISDIR(st.st_mode)) {
      File* file = file_create(fs);
      if (!file) {
        ok = false;
      } else {
        file->is_dir = true;
        file->metadata =
            file_metadata_create(fs, &st, config->preserve_atimes, config->preserve_crtimes);
        file->send_path = str_dup(prefix);
        if (!file->metadata || !file->send_path || !array_list_add(dir_entries, file)) {
          file_destroy(file);
          ok = false;
        }
      }
    }
    *p = saved;
  }
  free(fs);
  free(prefix);
  return ok;
}

/* The delete-walk root scope for a full (non---files-from) transfer: rsync
 * confines --delete to the directories it actually transferred.  A plain
 * recursive run mirrors the source under the receive root, so "." (the whole
 * tree) is correct; an -R run transfers only the reconstructed prefix subtree,
 * so the walk is scoped to that prefix instead.  Returns a malloc'd wire path
 * (or "."), or NULL on allocation failure. */
char* delete_scope_root_marker(const Config* config) {
  if (config->relative && config->files_from_set == NULL && config->send_directory) {
    char* prefix = scanner_relative_prefix(config->send_directory);
    if (!prefix)
      return NULL;
    if (prefix[0] != '\0')
      return prefix;
    free(prefix);
  }
  return str_dup(".");
}

/* The -R destination prefix that confines a per-directory delete walk, or NULL
 * when the whole receive root is in scope.  The marker was installed into
 * `synced_dirs` by delete_scope_root_marker(); for a plain recursive transfer
 * it is "." (whole root) and for --files-from the list is not a single prefix. */
const char* delete_plan_walk_root(const Config* config, const ArrayList* synced_dirs) {
  if (!config || config->files_from_set != NULL || !config->relative || !config->send_directory)
    return NULL;
  if (!synced_dirs || synced_dirs->size != 1)
    return NULL;
  const char* marker = (const char*)synced_dirs->items[0];
  if (marker[0] == '\0' || strcmp(marker, ".") == 0)
    return NULL;
  return marker;
}

/* The destination-relative mirror path for a missing --files-from entry: where
   a PRESENT entry with the same name would have been written.  With -R that is
   the entry's bare relative path (the bare wire path the receiver uses);
   otherwise it is the full source mirror below the destination root
   (`send_directory` joined to the entry, leading '/' stripped), exactly the
   path the manifest records for a present sibling.  Returns an owned string, or
   NULL on allocation failure. */
static char* files_from_missing_dest_path(const Config* config, const char* entry) {
  if (config->relative)
    return str_dup(entry);
  char* joined = path_cat(config->send_directory, entry);
  if (!joined)
    return NULL;
  const char* rel = *joined == '/' ? joined + 1 : joined;
  char* dup = str_dup(rel);
  free(joined);
  return dup;
}

/* --files-from semantics: every listed entry must resolve under the source
 * root, otherwise rsync reports a hard error instead of silently transferring
 * nothing. An entry of "." (the whole tree) and listed-but-empty directories
 * are valid.  An empty list is valid too: rsync transfers nothing and exits 0.
 * With --ignore-missing-args
 * (implied by --delete-missing-args) a listed-but-missing entry is instead
 * skipped: nothing is transferred for it, it never enters the keep-set and the
 * run succeeds for the rest (an all-missing non-empty list succeeds
 * transferring nothing, matching rsync).  With --delete-missing-args
 * `missing_dest` (when non-NULL) collects the entry's destination-relative
 * mirror for the receiver's exact-deletion request.  Runs before any
 * transfer so the failure/skip is surfaced uniformly in the single-threaded,
 * -m, dry-run and --list-only paths. */
bool files_from_list_check(const Config* config, ArrayList* missing_dest, int* skipped_out) {
  *skipped_out = 0;
  const FileListSet* set = (const FileListSet*)config->files_from_set;
  if (!set)
    return true;
  if (!config->send_directory) {
    log_message(LOG_LEVEL_ERROR, "--files-from requires a source directory");
    return false;
  }
  if (set->count == 0) {
    /* rsync treats an empty --files-from list as "nothing to transfer" and
       exits 0 (the source directory is still a valid source arg), so this is
       not an error.  Nothing passes the (empty) allow-set, so no file is sent
       and no keep-set entry is produced. */
    return true;
  }
  bool ignore = config->ignore_missing_args || config->delete_missing_args;
  for (int i = 0; i < set->count; i++) {
    const char* entry = set->entries[i];
    if (entry[0] == '\0')
      continue; /* "." == list the whole tree */
    char* full = path_cat(config->send_directory, entry);
    if (!full) {
      log_message(LOG_LEVEL_ERROR, "memory allocation failed while validating --files-from");
      return false;
    }
    struct stat st;
    if (lstat(full, &st) != 0) {
      free(full);
      if (ignore) {
        (*skipped_out)++;
        char* escaped_entry = output_escape(entry, log_get_8_bit_output());
        log_info_message(LOG_INFO_MISC, "skipping missing --files-from entry '%s'",
                         escaped_entry ? escaped_entry : "<allocation failed>");
        free(escaped_entry);
        if (config->delete_missing_args && missing_dest) {
          char* mirror = files_from_missing_dest_path(config, entry);
          if (!mirror || !array_list_add(missing_dest, mirror)) {
            free(mirror);
            log_message(LOG_LEVEL_ERROR, "memory allocation failed while validating --files-from");
            return false;
          }
        }
        continue;
      }
      char* escaped_entry = output_escape(entry, log_get_8_bit_output());
      char* escaped_src = output_escape(config->send_directory, log_get_8_bit_output());
      log_message(LOG_LEVEL_ERROR, "--files-from entry '%s' not found in source '%s'",
                  escaped_entry ? escaped_entry : "<allocation failed>",
                  escaped_src ? escaped_src : "<allocation failed>");
      free(escaped_entry);
      free(escaped_src);
      return false;
    }
    free(full);
  }
  if (*skipped_out > 0) {
    if (config->delete_missing_args) {
      /* --list-only never deletes and a --dry-run only shows intent, so the
         summary must not claim a real deletion happened in those modes. */
      if (config->list_only)
        log_message(LOG_LEVEL_WARNING,
                    "--delete-missing-args: %d missing --files-from entr%s skipped (--list-only "
                    "never deletes)",
                    *skipped_out, *skipped_out == 1 ? "y" : "ies");
      else if (config->dry_run)
        log_message(LOG_LEVEL_WARNING,
                    "--delete-missing-args: %d missing --files-from entr%s would be deleted from "
                    "the destination (dry run)",
                    *skipped_out, *skipped_out == 1 ? "y" : "ies");
      else
        log_message(
            LOG_LEVEL_WARNING,
            "--delete-missing-args: %d missing --files-from entr%s will be deleted from the "
            "destination",
            *skipped_out, *skipped_out == 1 ? "y" : "ies");
    } else if (config->ignore_missing_args)
      log_message(LOG_LEVEL_WARNING,
                  "--ignore-missing-args: ignored %d missing --files-from entr%s", *skipped_out,
                  *skipped_out == 1 ? "y" : "ies");
  }
  return true;
}

/* Walk the whole source tree once collecting only destination-relative wire
   paths, loading and sending nothing.  --delete-before/--delete-during need the
   complete keep-set manifest before the first data byte, so it is built by a
   dedicated pre-scan pass and transmitted early; the data pass then re-scans
   with a fresh scanner.  --delete-before additionally replays this very scan as
   its data pass (rsync's single file list), so `chunks_out` (optional) retains
   the scanned Chunk objects for the caller to send instead of destroying them;
   the caller owns the list and must give it a chunk_destroy destructor.  A
   source I/O error is fatal unless the options carry --ignore-errors, in which
   case the scan continues past the unreadable directory and *io_error_out
   reports it (the caller still performs the deletion but reports the run as
   errored). */
bool scan_paths_only(const Config* config, const ScannerOptions* options, ArrayList* manifest,
                     DeletePlanSender* plans, bool* io_error_out,
                     unsigned long long* non_dir_count_out, ArrayList* chunks_out,
                     bool emit_nonreg) {
  if (io_error_out)
    *io_error_out = false;
  if (non_dir_count_out)
    *non_dir_count_out = 0;
  ScannerOptions local = *options;
  /* The pre-scan is normally a paths-only pass with no client output: it must
     not emit --info=nonreg lines because the data pass re-scans and emits them
     once.  When the caller replays this scan as the data pass (--delete-before)
     there is no later scan, so it opts in and the lines are emitted here. */
  local.note_nonreg = emit_nonreg && options->note_nonreg;
  DirectoryScanner* scanner = directory_scanner_create_with_options(config->send_directory, &local);
  if (!scanner)
    return false;
  bool ok = true;
  Chunk* chunk;
  while ((chunk = directory_scanner_next(scanner)) != NULL) {
    if (non_dir_count_out) {
      for (int i = 0; i < chunk->element_count; i++) {
        const File* f = chunk->items[i];
        if (f && !f->is_dir)
          (*non_dir_count_out)++;
      }
    }
    if (manifest && !add_chunk_to_manifest(manifest, chunk)) {
      ok = false;
      chunk_destroy(chunk);
      break;
    }
    if (plans) {
      for (int i = 0; i < chunk->element_count; i++) {
        File* f = chunk->items[i];
        if (!f)
          continue;
        const char* path = file_wire_path(f);
        if (!delete_plan_sender_add(plans, path, f->is_dir)) {
          ok = false;
          break;
        }
      }
      if (!ok) {
        chunk_destroy(chunk);
        break;
      }
    }
    if (chunks_out) {
      /* Retain the chunk for the caller's data pass; ownership moves with it. */
      if (!array_list_add(chunks_out, chunk)) {
        ok = false;
        chunk_destroy(chunk);
        break;
      }
    } else {
      chunk_destroy(chunk);
    }
  }
  if (ok) {
    /* Keep every traversed source directory, including empty ones, so a plan
       no longer removes the destination directory itself.  Their own plans are
       emitted after the data stream (no file frame triggers them). */
    if (plans && options->plan_dirs) {
      for (int i = 0; i < options->plan_dirs->size; i++) {
        if (!delete_plan_sender_add(plans, (const char*)options->plan_dirs->items[i], true)) {
          ok = false;
          break;
        }
      }
    }
  }
  if (ok && directory_scanner_failed(scanner))
    ok = false;
  if (io_error_out)
    *io_error_out = directory_scanner_had_io_error(scanner);
  directory_scanner_destroy(scanner);
  return ok;
}
