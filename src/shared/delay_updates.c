#include "delay_updates.h"

#include "config.h"
#include "file.h"
#include "log.h"
#include "utils.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

DelayUpdatesContext* delay_updates_context_create(const char* root_directory) {
  if (!root_directory)
    return NULL;
  DelayUpdatesContext* context = calloc(1, sizeof(DelayUpdatesContext));
  if (!context)
    return NULL;
  context->root_directory = str_dup(root_directory);
  if (!context->root_directory) {
    free(context);
    return NULL;
  }
  context->staging_root = path_cat(root_directory, DELAY_UPDATES_STAGING_DIR);
  if (!context->staging_root) {
    free(context->root_directory);
    free(context);
    return NULL;
  }
  context->entries = NULL;
  context->count = 0;
  context->capacity = 0;
  context->prepared = false;
  if (mtx_init(&context->mutex, mtx_plain) != thrd_success) {
    free(context->staging_root);
    free(context->root_directory);
    free(context);
    return NULL;
  }
  return context;
}

void delay_updates_context_destroy(DelayUpdatesContext* context) {
  if (!context)
    return;
  mtx_destroy(&context->mutex);
  free(context->staging_root);
  free(context->root_directory);
  for (size_t i = 0; i < context->count; i++) {
    free(context->entries[i].staged_path);
    free(context->entries[i].final_path);
    free(context->entries[i].file_path);
  }
  free(context->entries);
  free(context);
}

/* Recursively delete every entry inside an open directory (never following
   symlinks).  The directory itself is left in place.  Mirrors the fd-relative
   walk used by the delete code so a symlink planted inside the staging tree
   can never redirect removal outside of it. */
static bool delay_wipe_dir_fd(int dirfd) {
  int scanfd = dup(dirfd);
  if (scanfd < 0)
    return false;
  DIR* dir = fdopendir(scanfd);
  if (!dir) {
    close(scanfd);
    return false;
  }
  bool operation_ok = true;
  const struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    struct stat st;
    if (fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno != ENOENT)
        operation_ok = false;
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      int childfd = openat(dirfd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      bool child_removed = false;
      if (childfd >= 0) {
        child_removed = delay_wipe_dir_fd(childfd);
        close(childfd);
      } else if (errno != ENOENT) {
        operation_ok = false;
      }
      if (child_removed && unlinkat(dirfd, entry->d_name, AT_REMOVEDIR) != 0 && errno != ENOENT)
        operation_ok = false;
    } else {
      if (unlinkat(dirfd, entry->d_name, 0) != 0 && errno != ENOENT)
        operation_ok = false;
    }
  }
  closedir(dir);
  return operation_ok;
}

bool delay_updates_prepare(DelayUpdatesContext* context) {
  if (!context)
    return false;
  if (context->prepared)
    return true;
  int fd = file_open_private_dir(context->staging_root);
  if (fd < 0) {
    int saved_errno = errno;
    char* escaped = output_escape(context->staging_root, false);
    log_message(LOG_LEVEL_ERROR, "could not create --delay-updates staging directory '%s': %s",
                escaped ? escaped : "<allocation failed>", strerror(saved_errno));
    free(escaped);
    return false;
  }
  bool ok = delay_wipe_dir_fd(fd);
  if (close(fd) != 0)
    ok = false;
  if (!ok) {
    log_message(LOG_LEVEL_ERROR, "could not clear stale --delay-updates staging files under '%s'",
                context->staging_root);
    return false;
  }
  context->prepared = true;
  return true;
}

bool delay_updates_record(DelayUpdatesContext* context, const char* staged_path,
                          const char* final_path, const char* file_path) {
  if (!context || !staged_path || !final_path || !file_path)
    return false;
  char* staged_copy = str_dup(staged_path);
  char* final_copy = str_dup(final_path);
  char* file_copy = str_dup(file_path);
  if (!staged_copy || !final_copy || !file_copy) {
    free(staged_copy);
    free(final_copy);
    free(file_copy);
    return false;
  }
  mtx_lock(&context->mutex);
  bool ok = true;
  if (context->count == context->capacity) {
    size_t new_capacity = context->capacity == 0 ? 64 : context->capacity * 2;
    if (new_capacity < context->capacity) {
      ok = false;
    } else {
      StagedFileEntry* grown = realloc(context->entries, new_capacity * sizeof(StagedFileEntry));
      if (!grown) {
        ok = false;
      } else {
        context->entries = grown;
        context->capacity = new_capacity;
      }
    }
  }
  if (ok) {
    context->entries[context->count].staged_path = staged_copy;
    context->entries[context->count].final_path = final_copy;
    context->entries[context->count].file_path = file_copy;
    context->count++;
  }
  mtx_unlock(&context->mutex);
  if (!ok) {
    free(staged_copy);
    free(final_copy);
    free(file_copy);
  }
  return ok;
}

/* Move an existing final destination file aside before the staged replacement
   is installed.  Deferred from stage time so the final destination is not
   modified until publication.  Mirrors the immediate-mode backup logic. */
static bool delay_publish_backup(DelayUpdatesContext* context, const Config* config,
                                 const StagedFileEntry* entry) {
  bool backup_enabled = config && config->backup && !config->ignore_existing;
  if (!backup_enabled)
    return true;
  const char* backup_suffix = (config && config->suffix) ? config->suffix : "~";
  struct stat backup_stat;
  if (!file_stat_secure(entry->final_path, &backup_stat))
    return true; /* nothing to back up */

  char* backup_path = NULL;
  if (config->backup_dir) {
    char* confined_backup = path_cat(context->root_directory, config->backup_dir);
    if (!confined_backup)
      return false;
    backup_path = path_cat(confined_backup, entry->file_path);
    free(confined_backup);
  } else {
    size_t path_len = strlen(entry->final_path);
    size_t suffix_len = strlen(backup_suffix);
    if (path_len > SIZE_MAX - suffix_len - 1)
      return false;
    backup_path = malloc(path_len + suffix_len + 1);
    if (backup_path) {
      memcpy(backup_path, entry->final_path, path_len);
      memcpy(backup_path + path_len, backup_suffix, suffix_len + 1);
    }
  }
  if (!backup_path)
    return false;
  char* parent_copy = str_dup(backup_path);
  if (!parent_copy || !file_ensure_directory_secure(dirname(parent_copy))) {
    free(parent_copy);
    free(backup_path);
    return false;
  }
  free(parent_copy);
  bool ok = file_rename_secure(entry->final_path, backup_path);
  free(backup_path);
  return ok;
}

static bool delay_publish_entry(DelayUpdatesContext* context, const Config* config,
                                const StagedFileEntry* entry) {
  if (!delay_publish_backup(context, config, entry))
    return false;
  if (!file_rename_secure(entry->staged_path, entry->final_path)) {
    if (errno == EXDEV) {
      char* escaped = output_escape(entry->final_path, false);
      log_message(LOG_LEVEL_ERROR,
                  "staging directory is on a different filesystem than the destination; cannot "
                  "atomically install file (EXDEV): %s",
                  escaped ? escaped : "<allocation failed>");
      free(escaped);
    } else {
      char* escaped = output_escape(entry->final_path, false);
      log_message(LOG_LEVEL_ERROR, "could not install staged file '%s': %s",
                  escaped ? escaped : "<allocation failed>", strerror(errno));
      free(escaped);
    }
    return false;
  }
  return true;
}

bool delay_updates_publish(DelayUpdatesContext* context, const Config* config) {
  if (!context)
    return false;
  mtx_lock(&context->mutex);
  bool ok = true;
  for (size_t i = 0; i < context->count; i++) {
    if (!delay_publish_entry(context, config, &context->entries[i])) {
      ok = false;
      break;
    }
  }
  mtx_unlock(&context->mutex);

  /* Renaming files out of the staging tree leaves the mirrored directories
     behind, and a mid-publish failure leaves the remaining staged files.
     Remove whatever is left so a later run starts from a clean staging area
     and no staged content can linger after a failed publish. */
  int fd = open(context->staging_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd >= 0) {
    delay_wipe_dir_fd(fd);
    close(fd);
    rmdir(context->staging_root);
  }
  return ok;
}

void delay_updates_cleanup(DelayUpdatesContext* context) {
  if (!context)
    return;
  int fd = open(context->staging_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return;
  delay_wipe_dir_fd(fd);
  close(fd);
  rmdir(context->staging_root);
}
