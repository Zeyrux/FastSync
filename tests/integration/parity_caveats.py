"""Data-driven allowlist for the differential rsync-parity gate.

Every entry maps a case id (see ``test_differential_parity.py``) to the aspects
that are *known* to differ from ``rsync 3.4.1`` and the documented reason.  A
differential mismatch in an aspect that is **not** listed here fails the gate.

Aspect keys
-----------
``tree``    destination tree differs (paths, file hashes, symlink targets,
            modes, hardlink grouping)
``stdout``  normalized output for ``-i`` / ``--stats`` / ``--out-format``
``extra``   a case-specific assertion differs (basis/inode checks, ...)
``rc``      exit status differs

Burn-down
---------
If a case is listed here but now matches rsync, the gate emits a loud
``pytest`` warning naming the stale entry: delete the entry (and, when the
underlying row in ``RSYNC_COMPAT.md`` is now parity, update that row).  Set
``FASTSYNC_PARITY_STRICT=1`` to turn stale entries into failures in CI.

Keep the values concise but cite the governing row so the entry can be
re-triaged when the row moves.
"""

# case id -> {aspect: "reason (ref: RSYNC_COMPAT.md ...)"}
CAVEATS = {
    # A source subtree whose only files are all filtered out (here, by
    # --min-size) is left behind as an empty directory by rsync but not by
    # FastSync: the recursive scanner keeps directory entries record-only, so
    # `sub/deep` is only implicit through the (skipped) file.  This is the
    # documented recursive-empty-directory residual, not a payload/selection
    # bug.
    "min_size": {
        "tree": "recursive transfer does not create a source directory that "
                "becomes empty after --min-size filtering (FastSync directory "
                "entries are record-only). ref: RSYNC_COMPAT.md `-d/--dirs` "
                "row and completion-wave residual ('recursive transfers still "
                "do not create empty directories').",
    },
    # FastSync's recursive scanner keeps directory entries record-only, so a
    # plain `-d`/recursive source whose only role for a directory is that entry
    # (empty dir, or a dir emptied by filtering) is not created on the
    # destination.  rsync creates it.  `--dirs`/`--files-from`-listed
    # directories DO cross as explicit entries (covered by the passing
    # `empty_dirs_files_from` / `files_from` cases).
    "empty_dirs_recursive": {
        "tree": "recursive transfer does not create empty source directories. "
                "ref: RSYNC_COMPAT.md `-d/--dirs` row and completion-wave "
                "residual ('recursive transfers still do not create empty "
                "directories').",
    },
    # A plain `-d` invocation: FastSync's `--source-dir` treats the argument as
    # the directory entry itself (creates the empty source-root mirror), while
    # rsync's `src/` trailing-slash form lists the immediate contents.
    "dirs_plain": {
        "tree": "plain -d semantics: FastSync creates the source-root directory "
                "entry (its documented --dirs files-from behavior) instead of "
                "rsync's one-level contents listing for a `src/` argument. "
                "ref: RSYNC_COMPAT.md `-d/--dirs` row (⚠️).",
    },
    # --max-delete stops the extras walk part-way and exits 25 in both
    # implementations; which of the remaining extras survives depends on
    # deletion order, which neither tool specifies.  The exit code and the
    # number of survivors match (asserted implicitly by the harness's rc
    # comparison and the one-for-one diff below).
    "max_delete": {
        "tree": "which destination extras survive a partial --max-delete abort "
                "is deletion-order dependent and unspecified; rc=25 and the "
                "number of survivors match rsync. ref: RSYNC_COMPAT.md "
                "`--max-delete=NUM` row.",
    },
}

# Accepted aspect names (guards against typos in this file).
ASPECTS = ("tree", "stdout", "extra", "rc")


def caveat_for(case_id: str) -> dict:
    return CAVEATS.get(case_id, {})
