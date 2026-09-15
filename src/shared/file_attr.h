#ifndef FILE_ATTR_H
#define FILE_ATTR_H

#include "config.h"
#include <stdbool.h>
#include <sys/stat.h>

/*
 * Per-attribute receiver policy for applying a transmitted FileMetadata.  This
 * is the split-out replacement for the former single use_metadata bundle: each
 * flag is applied independently, matching rsync's -p/-t/-o/-g/-E/-U semantics.
 * `use_metadata` remains the transport/presence gate (whether the metadata frame
 * travelled at all); this struct decides which attributes are ACTUALLY applied.
 *
 * It lives in its own header (rather than metadata.h) because xattr.h's
 * fake_super_restore_fd() takes one and metadata.h <-> file_types.h form an
 * include cycle that must not be entered from xattr.h.
 *
 * The mode leg is: perms wins over executability; an exec-bits-only change is
 * made only when perms is off; when neither is set the receiver deliberately
 * sets no source mode.  file.c then substitutes the pre-existing destination
 * mode for a brand-new destination with metadata it uses the sanitized
 * source-mode-&-umask base (S_IWGRP|S_IWOTH cleared), and the fixed 0644
 * default only when no metadata is available at all, so a no--p overwrite
 * does not lose the destination's perms.
 */
typedef struct FileAttrPolicy {
  bool perms;         /* config->preserve_perms: apply the source mode bits */
  bool times;         /* config->preserve_times: apply the source mtime */
  bool atimes;        /* config->preserve_atimes (-U): apply the source atime */
  bool executability; /* config->use_executability (-E): exec-bits-only mode */
} FileAttrPolicy;

/* Build the per-attribute policy from a connection's Config.  A NULL config
 * yields the all-off policy (no attribute application). */
FileAttrPolicy file_attr_policy_from_config(const Config* config);

#endif
