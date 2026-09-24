#ifndef IDENTITY_H
#define IDENTITY_H

#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Maximum length of a receiver-resolved identity name in a FROM:TO map's TO
 * field.  Bounded so a malicious/huge name can never cross the wire (see
 * identity_wire_map_valid). */
#define IDENTITY_MAX_NAME_LEN 255

/*
 * Identity mapping: --numeric-ids / --usermap / --groupmap / --chown / --copy-as.
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
 * the group tables and name databases.  A FROM name wildcard (containing `*`,
 * `?` or `[...]`, but not the bare `*`) is expanded against the SENDER's
 * account database at parse time into one or more numeric id/range rules
 * (contiguous ids collapse to a range) sharing the same TO, because only
 * numeric ids cross the wire; the expansion is capped at MAX_IDENTITY_MAP and a
 * wildcard matching no account is an error.  Returns 0 on success, -1 on a
 * malformed spec, an unresolvable name, an unmatched wildcard, or a map that
 * would exceed MAX_IDENTITY_MAP (never a silent no-op). */
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

/* True when a --copy-as request is active but the receiver is not permitted to
 * perform the privileged ownership application it needs.  This is the up-front
 * refusal predicate: the server rejects the whole transfer at the config
 * handshake rather than silently ignoring the requested ownership.  It is a
 * pure function of the config mode and the current effective uid (it does NOT
 * read the active snapshot, so it is valid at the pre-STATUS_OK gate, before
 * identity_set_active() has run).  `super_mode` is the EFFECTIVE mode after any
 * server-side policy veto. */
bool identity_copy_as_refused(const Config* config);

/* True when the CURRENT per-connection snapshot has a --copy-as active (i.e.
 * identity_set_active() has run against a config with copy_as_set).  The
 * --fake-super owner replay consults this so a copy-as run never lets the
 * recorded source owner overwrite the forced target owner.  Reads the active
 * snapshot, so call identity_set_active() first (the receiver does, before any
 * write). */
bool identity_copy_as_active(void);

/* Receiver-side snapshot of the negotiated identity config.  The server calls
 * identity_set_active() once per connection (before any file write) using the
 * config received over the wire; the snapshot is a deep copy so the caller may
 * free its Config immediately.  identity_clear_active() releases it.
 *
 * Returns true on success.  On an allocation failure while deep-copying a
 * requested usermap/groupmap it logs a LOG_LEVEL_ERROR, leaves the snapshot
 * cleared (never a partial/wrong policy) and returns false; the caller must
 * refuse the connection. */
bool identity_set_active(const Config* config);
void identity_clear_active(void);

/* True when any ownership-affecting identity option is present in the active
 * snapshot.  Ownership stays OFF ("do not apply") for every transfer that
 * requests none of them, preserving FastSync's existing behavior.  --super /
 * --no-super alone does NOT enable ownership; an explicit identity flag
 * (--numeric-ids / --chown / --usermap / --groupmap / --copy-as) or a
 * preserve-source -o/--owner / -g/--group request is required. */
bool identity_active_enabled(void);

/* Per-side predicates over the ACTIVE per-connection snapshot (call
 * identity_set_active() first).  They mirror the owner_requested /
 * group_requested conditions inside identity_resolve_targets() exactly, so
 * callers that must apply only one side (e.g. the --fake-super owner replay)
 * can pass (uid_t)-1 / (gid_t)-1 for the side that was NOT requested and leave
 * it untouched.  The owner side is requested by --copy-as, --chown USER,
 * --numeric-ids, -o/--owner, or a non-empty --usermap; the group side by
 * --copy-as, --chown :GROUP, --numeric-ids, -g/--group, or a non-empty
 * --groupmap. */
bool identity_owner_requested(void);
bool identity_group_requested(void);

/* Pure, config-only predicate: true when the client requested ANY client-chosen
 * ownership or super-user activity (--numeric-ids, --chown, --usermap/--groupmap,
 * --copy-as, --fake-super, an explicit --super, or a preserve-source -o/-g).
 * General awareness only; the daemon module gate uses the narrower
 * identity_explicit_ownership_requested() below.  Never reads the snapshot. */
bool identity_ownership_requested(const Config* config);

/* Pure, config-only predicate for the narrow set that lets the CLIENT choose an
 * arbitrary owner/group: --numeric-ids, --chown, --usermap/--groupmap,
 * --copy-as, --fake-super, or an explicit --super.  Deliberately EXCLUDES a
 * plain -o/--owner / -g/--group (or -a) preserve-source request, which the
 * daemon gate handles by forcing super-user ownership activity off rather than
 * refusing the whole transfer.  Never reads the snapshot. */
bool identity_explicit_ownership_requested(const Config* config);

/* Apply the negotiated ownership to an already-written file descriptor.
 * source_uid/source_gid are the transmitted numeric ids.  Resolution order:
 * --copy-as (highest priority, forces both ids), then a matching
 * usermap/groupmap rule, then --chown, then --numeric-ids (raw), then a
 * best-effort name lookup on the receiver's own databases (skipped when the
 * transmitted id has no name on this system).  Only calls fchown() when the
 * result differs from the current value.
 *
 * Returns false ONLY when an active --copy-as ownership application failed: its
 * forced ownership is REQUIRED, so the caller must treat the entry as failed
 * rather than reporting success with the wrong owner.  For every other identity
 * policy an fchown EPERM/EACCES is logged and ignored and true is returned
 * (rsync parity: the transfer must not abort).  A no-op when no identity policy
 * is active returns true. */
bool identity_apply_ownership(int fd, int32_t source_uid, int32_t source_gid);

/* Resolve the ownership that --fake-super should RECORD in the reserved xattr
 * (rather than chown for real).  A requested side (--copy-as / usermap /
 * --chown / -o / -g, with --numeric-ids as the raw-id modifier) yields the
 * resolved target; a side that was not requested keeps the transmitted source
 * id.  Must be called after identity_set_active(). */
void identity_resolve_storage_ids(int32_t source_uid, int32_t source_gid, uint32_t* out_uid,
                                  uint32_t* out_gid);

/* P7 Wave D: the no-follow (symlink) counterpart.  Resolves the same
 * usermap/groupmap/chown/numeric-ids/copy-as policy but applies it with
 * fchownat(..., AT_SYMLINK_NOFOLLOW) so a symlink's own ownership is changed
 * without ever dereferencing it.  A no-op unless an identity flag is active.
 * The return value follows identity_apply_ownership(): false only when an
 * active --copy-as application failed. */
bool identity_apply_ownership_link(int parent_fd, const char* leaf, int32_t source_uid,
                                   int32_t source_gid);

/* Receiver-side wire validation of the resolved identity fields. */
bool identity_wire_valid(const Config* config);

/* P7 Wave E receiver-side permission gate for super-user activities (ownership
 * application and char/block device-node creation).  `privilege_super_permitted`
 * consults the per-connection snapshot (call identity_set_active() first);
 * `privilege_super_mode_permitted` is the pure mode predicate and is what
 * callers holding a Config use (the config-frame gate, file_receive).  Both
 * return false only for SUPER_MODE_OFF; SUPER_MODE_ON and SUPER_MODE_AUTO (the
 * default) permit a confined attempt, matching FastSync's historical
 * best-effort behavior where an unprivileged attempt is refused by the kernel
 * and skipped.  Neither EVER elevates privileges. */
bool privilege_super_permitted(void);
bool privilege_super_mode_permitted(SuperMode mode);

#endif