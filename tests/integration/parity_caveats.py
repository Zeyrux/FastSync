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
