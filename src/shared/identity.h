#ifndef IDENTITY_H
#define IDENTITY_H

#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Identity mapping: --numeric-ids / --usermap / --groupmap / --chown.
 *
 * FastSync transmits uid/gid numerically (int32 on the wire) and, by design,
 * NEVER applies client-supplied ownership unless a user explicitly opts in with
 * an identity flag below.  This module is the controlled, opt-in,
 * privilege-gated path for applying ownership on the receiver: the wire config
 * is snapshotted once per connection via identity_set_active() and applied
 * through an fd-relative fchown() in the receiver's metadata-restore path.
 *
 * Because only numeric ids cross the wire, name-based values are resolved to
 * numbers at CLI parse time using the CLIENT (sender) machine's databases.  On
 * a shared-account source/destination this reproduces rsync's semantics; a
 * genuinely different destination database is a documented divergence (see
 * RSYNC_COMPAT.md).
 */

/* Parse one --usermap= / --groupmap= value (comma-separated FROM:TO rules,
 * first match wins) into config->usermap / config->groupmap.  is_group selects
 * the group tables and name databases.  Returns 0 on success, -1 on a
 * malformed spec or an unresolvable name (never a silent no-op). */
int identity_parse_map(Config* config, const char* value, bool is_group);

/* Parse --chown=USER:GROUP.  Supports USER:GROUP, USER (owner only), :GROUP
 * (group only), '*' (current/root as appropriate) and numeric ids.  Returns 0
 * on success, -1 on a malformed spec / unresolvable name. */
int identity_parse_chown(Config* config, const char* value);

/* Parse --copy-as=USER[:GROUP] (P7 Wave E).  USER is resolved with the same
 * user-database rules as --chown (a name, @N/bare N numeric id, or '*' meaning
 * the client's current euid); when ':GROUP' is present the group is resolved
 * with the group database ('*' meaning the client's egid).  When the group is
 * omitted, the user's primary gid is used (getpwuid(uid)->pw_gid); if the
 * resolved user is a numeric id with no local passwd entry, gid falls back to
 * uid.  On success sets copy_as_set/copy_as_uid/copy_as_gid and forces
 * metadata transmission (ownership application needs the metadata path).
 * Returns 0 on success, -1 on a malformed / empty / unresolvable spec (never a
 * silent no-op). */
int identity_parse_copy_as(Config* config, const char* value);

/* True when a --copy-as request is active AND this (receiving) process is not
 * privileged enough to honor it (euid != 0).  This is the up-front refusal
 * predicate; the server rejects the whole transfer at the config handshake
 * rather than silently ignoring the requested ownership. */
bool identity_copy_as_refused(void);

/* Receiver-side snapshot of the negotiated identity config.  The server calls
 * identity_set_active() once per connection (before any file write) using the
 * config received over the wire; the snapshot is a deep copy so the caller may
 * free its Config immediately.  identity_clear_active() releases it. */
void identity_set_active(const Config* config);
void identity_clear_active(void);

/* True when any ownership-affecting identity option is present in the active
 * snapshot.  Ownership stays OFF ("do not apply") for every transfer that
 * requests none of them, preserving FastSync's existing behavior. */
bool identity_active_enabled(void);

/* Apply the negotiated ownership to an already-written file descriptor.
 * source_uid/source_gid are the transmitted numeric ids.  Resolution order:
 * a matching usermap/groupmap rule, then --chown, then --numeric-ids (raw),
 * then a best-effort name lookup on the receiver's own databases (skipped when
 * the transmitted id has no name on this system).  Only calls fchown() when the
 * result differs from the current value; EPERM/EACCES are logged and ignored,
 * never fatal (rsync parity: the transfer must not abort). */
void identity_apply_ownership(int fd, int32_t source_uid, int32_t source_gid);

/* P7 Wave D: the no-follow (symlink) counterpart.  Resolves the same
 * usermap/groupmap/chown/numeric-ids policy but applies it with
 * fchownat(..., AT_SYMLINK_NOFOLLOW) so a symlink's own ownership is changed
 * without ever dereferencing it.  A no-op unless an identity flag is active. */
void identity_apply_ownership_link(int parent_fd, const char* leaf, int32_t source_uid,
                                   int32_t source_gid);

/* Receiver-side wire validation of the resolved identity fields. */
bool identity_wire_valid(const Config* config);

#endif