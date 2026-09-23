"""Differential rsync-parity gate.

Runs real ``rsync 3.4.1`` and FastSync over the same corpora and flags, then
compares the destination trees and the normalized output of the
output-oriented flags.  This is the executable counterpart of
``RSYNC_COMPAT.md``: the fast subset (``-m parity_ci``) guards the ✅ surface on
every pull request, and the full set (``-m parity``) burns the documented
⚠️/❌ residuals down.

Known, documented differences live in ``parity_caveats.py``; anything else
fails with a readable tree/stdout diff.  A stale allowlist entry is reported
loudly (and fails when ``FASTSYNC_PARITY_STRICT=1``).

Run locally::

    python3 -m pytest tests/integration/test_differential_parity.py -n 4 --dist=load -m parity_ci
    python3 -m pytest tests/integration/test_differential_parity.py -n 4 --dist=load -m parity
"""
import os
import re
import shutil
import sys
import warnings

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    ServerManager,
    TEST_DATA_DIR,
    clean_dir,
    get_dest_received_dir,
)
from parity_caveats import ASPECTS, caveat_for  # noqa: E402
import parity_harness as H  # noqa: E402

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")

# `--allow-super` matches the rest of the integration suite; `--allow-delete`
# is needed only by the delete cases.
SUPER = ("--allow-super",)
DELETE = ("--allow-super", "--allow-delete")
_OLD_MTIME = 1_500_000_000

parity = pytest.mark.parity
parity_ci = pytest.mark.parity_ci


@pytest.fixture(scope="session")
def parity_server_factory():
    """Lazily start one server per distinct extra-argument set, per xdist worker."""
    servers = {}

    def get(extra):
        key = tuple(extra)
        if key not in servers:
            s = ServerManager()
            s.start(extra_args=list(extra))
            servers[key] = s
        return servers[key]

    yield get
    for s in servers.values():
        s.stop()


def _pin(path, mtime):
    os.utime(path, (mtime, mtime))


def _mk(path, data, mtime=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    if mtime is not None:
        _pin(path, mtime)


# --- destination seeds ------------------------------------------------------

def seed_extras(_src, rroot, froot):
    for root in (rroot, froot):
        _mk(os.path.join(root, "extra.txt"), b"extra\n")
        _mk(os.path.join(root, "extradir", "z.txt"), b"z\n")


def seed_update(_src, rroot, froot):
    for root in (rroot, froot):
        p = os.path.join(root, "a.txt")
        _mk(p, b"destination is newer and longer\n", 2_000_000_000)


def seed_ignore_existing(_src, rroot, froot):
    for root in (rroot, froot):
        _mk(os.path.join(root, "a.txt"), b"destination-kept\n", _OLD_MTIME)


def seed_append(_src, rroot, froot):
    for root in (rroot, froot):
        _mk(os.path.join(root, "a.txt"), b"hello ", _OLD_MTIME)


def seed_backup(_src, rroot, froot):
    for root in (rroot, froot):
        _mk(os.path.join(root, "a.txt"), b"OLD-CONTENT\n", _OLD_MTIME)


def seed_size_only(_src, rroot, froot):
    for root in (rroot, froot):
        _mk(os.path.join(root, "a.txt"), b"XXXXXXXXXXX\n", _OLD_MTIME)


def seed_delete_excluded(_src, rroot, froot):
    for root in (rroot, froot):
        _mk(os.path.join(root, "drop.log"), b"stale log\n", _OLD_MTIME)
        _mk(os.path.join(root, "extra.txt"), b"extra\n", _OLD_MTIME)
        _mk(os.path.join(root, "keep.txt"), b"keep\n", _OLD_MTIME)


def seed_filter_protect(_src, rroot, froot):
    """Destination-only entries, including nested ones, for the receiver-side
    `protect` rule: the `.log` extras must survive --delete, the rest go."""
    for root in (rroot, froot):
        _mk(os.path.join(root, "extra.log"), b"dest-only log\n", _OLD_MTIME)
        _mk(os.path.join(root, "other.txt"), b"dest-only other\n", _OLD_MTIME)
        _mk(os.path.join(root, "sub", "extra2.log"), b"nested dest-only log\n", _OLD_MTIME)
        _mk(os.path.join(root, "sub", "other2.txt"), b"nested dest-only other\n", _OLD_MTIME)


def seed_max_delete(_src, rroot, froot):
    for root in (rroot, froot):
        _mk(os.path.join(root, "extra1.txt"), b"e1\n", _OLD_MTIME)
        _mk(os.path.join(root, "extra2.txt"), b"e2\n", _OLD_MTIME)


def fuzzy_basis_seed(_src, rroot, froot):
    """Seed a same-suffix sibling whose name is one edit from the source and
    whose content matches it, with a DIFFERENT mtime so rsync's exact
    size+mtime pass cannot fire: both tools must select it via the
    name-distance pass.  Where the two tools' basis choices coincide the
    block-level results are identical when the block size is pinned."""
    for root in (rroot, froot):
        _mk(os.path.join(root, "report_v1.txt"), H.FUZZY_PAYLOAD, _OLD_MTIME)


def max_delete_count_check(_src, rroot, froot, _rs, _fs):
    """The exact survivor set is order-dependent; the count must still match."""
    r = H.snapshot(rroot)
    f = H.snapshot(froot)
    if len(r) != len(f):
        return [f"survivor count differs: rsync={len(r)} fastsync={len(f)}"]
    return []


# --- case table -------------------------------------------------------------

_CASES = [
    # --- core archive / recursion -----------------------------------------
    H.Case("archive", "basic", ["-a"], ci=True, ref="-a/--archive"),
    H.Case("recursive", "basic", ["-r"], ci=True, ref="-r/--recursive"),
    H.Case("unicode_names", "unicode", ["-a"], ci=True, ref="-a unicode names"),
    H.Case("links_archive", "links", ["-a"], ci=True, ref="-l/--links"),
    H.Case("copy_links", "links", ["-aL"], ref="-L/--copy-links"),
    H.Case("hardlinks", "hardlinks", ["-a", "-H"], compare_hardlinks=True,
           ci=True, ref="-H/--hard-links"),
    H.Case("hardlinks_without_H", "hardlinks", ["-a"], compare_hardlinks=True,
           ref="hardlinks without -H"),
    H.Case("sparse", "sparse", ["-a", "-S"], ref="-S/--sparse"),

    # --- compression / checksums ------------------------------------------
    H.Case("compress_zstd", "basic", ["-a", "-z"], ci=True, ref="-z/--compress"),
    H.Case("checksum", "basic", ["-a", "-c"], ref="-c/--checksum"),
    H.Case("checksum_choice_xxh64", "basic",
           ["-a", "-c", "--checksum-choice=xxh64"], ref="--checksum-choice"),

    # --- selection --------------------------------------------------------
    H.Case("exclude", "filters", ["-a", "--exclude=*.log"], ci=True,
           ref="--exclude"),
    H.Case("include_exclude", "filters",
           ["-a", "--include=*.txt", "--exclude=*"], ci=True,
           ref="--include/--exclude ordering"),
    H.Case("filter_rules", "filters",
           ["-a", "-f", "- *.log", "-f", "+ *.txt", "-f", "- *"],
           ref="--filter/-f grammar"),
    H.Case("max_size", "basic", ["-a", "--max-size=1000"], ref="--max-size"),
    H.Case("min_size", "basic", ["-a", "--min-size=1000"], ref="--min-size"),

    # --- output-oriented --------------------------------------------------
    H.Case("stats", "basic", ["-a", "--stats"], stdout=H.STDOUT_STATS,
           ci=True, ref="--stats"),
    H.Case("itemize", "links", ["-a", "-i"], stdout=H.STDOUT_ITEMIZE,
           ci=True, ref="-i/--itemize-changes"),
    H.Case("out_format_n_l", "basic", ["-a", "--out-format=%n %l"],
           stdout=H.STDOUT_OUTFMT, ref="--out-format %n %l"),
    H.Case("out_format_i_n", "basic", ["-a", "--out-format=%i %n"],
           stdout=H.STDOUT_OUTFMT, ref="--out-format %i %n"),
    H.Case("progress", "multidir", ["-a", "--progress"], stdout=H.STDOUT_PROGRESS,
           ci=True, ref="--progress multi-directory file list"),
    H.Case("progress_threads", "multidir", ["-a", "--progress"],
           fastsync_flags=["-a", "--progress", "--threads"],
           stdout=H.STDOUT_PROGRESS, ci=True,
           ref="--progress multi-directory file list (--threads)"),

    # --- transfer modifications -------------------------------------------
    H.Case("update", "basic", ["-a", "--update"], seed=seed_update,
           ref="-u/--update"),
    H.Case("ignore_existing", "basic", ["-a", "--ignore-existing"],
           seed=seed_ignore_existing, ci=True, ref="--ignore-existing"),
    H.Case("size_only", "basic",
           ["-a", "--size-only"], fastsync_flags=["-a", "--incremental", "--size-only"],
           seed=seed_size_only, ref="--size-only"),
    H.Case("append", "basic", ["-a", "--append"], seed=seed_append,
           ref="--append"),
    H.Case("append_verify", "basic", ["-a", "--append-verify"], seed=seed_append,
           ref="--append-verify"),
    H.Case("backup", "basic", ["-a", "--backup"], seed=seed_backup,
           ref="--backup"),
    H.Case("chmod", "basic", ["-a", "--chmod=Fu+rwx"], compare_modes=True,
           ci=True, ref="--chmod"),

    # --- delta / similar-file basis (--fuzzy) -----------------------------
    # Basis choices coincide here (same-suffix sibling, name distance one edit,
    # content identical); with the block size pinned both tools report the same
    # Matched/Literal/transferred counters.  The residual (FastSync's narrower
    # delta size window) is covered by TestFuzzy in test_parity_quickwins.py.
    H.Case("fuzzy_basis", "fuzzy",
           ["-a", "--no-whole-file", "--fuzzy", "--stats", "-B8192"],
           fastsync_flags=["-a", "--incremental", "--delta", "--fuzzy",
                           "--stats", "--delta-block=8192"],
           seed=fuzzy_basis_seed, stdout=H.STDOUT_STATS, ci=True,
           ref="-y/--fuzzy similar-file basis"),

    # --- deletion ---------------------------------------------------------
    H.Case("delete", "basic", ["-a", "--delete"], seed=seed_extras,
           server_args=DELETE, ci=True, ref="--delete"),
    H.Case("delete_before", "basic", ["-a", "--delete-before"], seed=seed_extras,
           server_args=DELETE, ref="--delete-before"),
    H.Case("delete_during", "basic", ["-a", "--delete-during"], seed=seed_extras,
           server_args=DELETE, ref="--delete-during"),
    H.Case("delete_delay", "basic", ["-a", "--delete-delay"], seed=seed_extras,
           server_args=DELETE, ref="--delete-delay"),
    H.Case("delete_after", "basic", ["-a", "--delete-after"], seed=seed_extras,
           server_args=DELETE, ref="--delete-after"),
    H.Case("delete_commit", "basic", ["-a", "--delete-after"], seed=seed_extras,
           fastsync_flags=["-a", "--delete-commit"], server_args=DELETE,
           ref="FastSync-only --delete-commit == rsync --delete-after"),
    H.Case("delete_excluded", "filters",
           ["-a", "--delete", "--delete-excluded", "--exclude=*.log"],
           seed=seed_delete_excluded, server_args=DELETE, ref="--delete-excluded"),
    H.Case("exclude_protect_dest_only", "filters",
           ["-a", "--delete", "--exclude=*.log"],
           seed=seed_delete_excluded, server_args=DELETE, ci=True,
           ref="--delete protects a destination-only excluded entry like rsync"),
    H.Case("max_delete", "basic", ["-a", "--delete", "--max-delete=1"],
           seed=seed_max_delete, server_args=DELETE,
           extra_check=max_delete_count_check, compare_tree=False,
           ref="--max-delete"),
    H.Case("filter_protect", "filters",
           ["-a", "--delete", "--filter=P *.log"],
           seed=seed_filter_protect, server_args=DELETE, ci=True,
           ref="--filter P/--protect receiver-side delete protection (default during)"),
    H.Case("filter_protect_during", "filters",
           ["-a", "--delete-during", "--filter=P *.log"],
           seed=seed_filter_protect, server_args=DELETE, ci=True,
           ref="--filter P/--protect under --delete-during"),
    H.Case("filter_protect_delay", "filters",
           ["-a", "--delete-delay", "--filter=P *.log"],
           seed=seed_filter_protect, server_args=DELETE, ci=True,
           ref="--filter P/--protect under --delete-delay"),
    H.Case("filter_protect_after", "filters",
           ["-a", "--delete-after", "--filter=P *.log"],
           seed=seed_filter_protect, server_args=DELETE, ci=True,
           ref="--filter P/--protect under the whole-tree --delete-after commit"),

    # --- relative / dirs --------------------------------------------------
    H.Case("relative_general", "basic", ["-a", "-R"], layout=H.MIRROR_ABS,
           compare_modes=True, ref="-R/--relative"),
    H.Case("relative_no_implied_dirs", "basic",
           ["-a", "-R", "--no-implied-dirs"], layout=H.MIRROR_ABS,
           compare_modes=True, ref="--no-implied-dirs"),
    H.Case("files_from", "relative", ["--dirs", "-R"],
           files_from=("dir1", "sub/x.txt"), layout=H.RELATIVE, ci=True,
           ref="-d/--dirs + --files-from"),
    H.Case("dirs_plain", "basic", ["-d"], fs_src_suffix="/",
           ref="-d/--dirs (plain)"),
    H.Case("empty_dirs_recursive", "empty_dir", ["-a"],
           ref="recursive empty-directory residual"),
    H.Case("empty_dirs_files_from", "empty_dir", ["--dirs", "-R"],
           files_from=("emptydir",), layout=H.RELATIVE, ci=True,
           ref="-d/--dirs explicit empty directory"),

    # --- codecs -----------------------------------------------------------
    H.Case("iconv_identity", "basic", ["-a", "--iconv=UTF-8,UTF-8"],
           ref="--iconv identity"),
    H.Case("iconv_convert", "iconv",
           ["-a", "--iconv=ISO-8859-1,UTF-8"],
           server_args=("--allow-super", "--iconv=UTF-8"),
           ref="--iconv conversion (receiver declares its own charset)"),
    # rsync's spec is LOCAL,REMOTE and the destination end's charset is REMOTE
    # on a push, so a default server writes the wire (UTF-8) names verbatim.
    H.Case("iconv_default_server", "iconv",
           ["-a", "--iconv=ISO-8859-1,UTF-8"],
           ref="--iconv push direction (default receiver charset = REMOTE)"),

    # --- partial ----------------------------------------------------------
    H.Case("partial_complete", "basic", ["-a", "--partial"], ref="--partial"),
]

# Cases that must always be tolerated (documented ⚠️/❌ residuals) get an
# allowlist entry; the table below stays the exact ✅ surface.
ALL_CASES = _CASES


def _params():
    out = []
    for case in ALL_CASES:
        marks = [parity]
        if case.ci:
            marks.append(parity_ci)
        out.append(pytest.param(case, id=case.id, marks=marks))
    return out


def _aspects_to_check(result):
    return {
        "tree": result["tree"],
        "stdout": result["stdout"],
        "extra": result["extra"],
    }


def _assert_no_unexpected(case_id, mismatches, caveat, ref=""):
    unexpected = {a: v for a, v in mismatches.items() if v and a not in caveat}
    if unexpected:
        lines = [f"differential parity mismatch for case {case_id!r}:"]
        lines.append(f"  ref: {ref or 'see RSYNC_COMPAT.md'}")
        for aspect, detail in unexpected.items():
            lines.append(f"  --- {aspect} ---")
            lines.extend("  " + str(d) for d in detail)
        lines.append("If this is a documented residual, add it to "
                     "tests/integration/parity_caveats.py with a RSYNC_COMPAT.md "
                     "reference.  Do not allowlist an undocumented divergence.")
        pytest.fail("\n".join(lines))

    stale = [a for a in ASPECTS
             if a in caveat and a != "rc" and not mismatches.get(a)]
    if stale:
        msg = (f"stale parity allowlist entry for case {case_id!r}, aspect(s) "
               f"{stale}: FastSync now matches rsync. Remove it from "
               f"parity_caveats.py (and update RSYNC_COMPAT.md if the row moved).")
        if os.environ.get("FASTSYNC_PARITY_STRICT") == "1":
            pytest.fail(msg)
        warnings.warn(msg, stacklevel=2)


@requires_rsync
@pytest.mark.parametrize("case", _params())
def test_differential_case(case, parity_server_factory):
    server = parity_server_factory(case.server_args)
    result = H.execute_case(case, server)
    caveat = caveat_for(case.id)

    mismatches = _aspects_to_check(result)
    if result["rsync_rc"] != result["fastsync_rc"]:
        mismatches["rc"] = [
            f"rsync rc={result['rsync_rc']} fastsync rc={result['fastsync_rc']} "
            f"(rsync stderr: {result['rsync_stderr'][:200]!r}, "
            f"fastsync stderr: {result['fastsync_stderr'][:200]!r})"]
    _assert_no_unexpected(case.id, mismatches, caveat, ref=case.ref)


# ---------------------------------------------------------------------------
# Multi-run and setup-heavy scenarios (kept as explicit tests)
# ---------------------------------------------------------------------------

def _result_aspects(result):
    return _aspects_to_check(result)


_STANDALONE_REFS = {
    "incremental_modified": "-i/--itemize-changes + incremental second run",
    "compare_dest": "--compare-dest",
    "copy_dest": "--copy-dest",
    "link_dest": "--link-dest",
    "link_dest_stats": "--link-dest + --stats",
    "verify_basis": "--verify-basis (FastSync-only)",
    "verify_basis_default": "--verify-basis (default quick-check vs rsync)",
    "added_and_deleted": "--delete across two runs",
    "added_and_deleted_seed": "--delete across two runs",
    "one_file_system": "-x/--one-file-system",
}


def _run_and_check(case_id, result, ref=""):
    mismatches = _result_aspects(result)
    if result["rsync_rc"] != result["fastsync_rc"]:
        mismatches["rc"] = [
            f"rsync rc={result['rsync_rc']} fastsync rc={result['fastsync_rc']} "
            f"(rsync stderr: {result['rsync_stderr'][:200]!r}, "
            f"fastsync stderr: {result['fastsync_stderr'][:200]!r})"]
    _assert_no_unexpected(case_id, mismatches, caveat_for(case_id),
                          ref=ref or _STANDALONE_REFS.get(case_id, ""))


@requires_rsync
@parity
def test_incremental_modified_file(parity_server_factory):
    """A second run sends only the modified file; destinations stay identical."""
    case_id = "incremental_modified"
    src = os.path.join(TEST_DATA_DIR, "parity_inc_src")
    rdst = os.path.join(TEST_DATA_DIR, "parity_inc_rdst")
    fdst = os.path.join(TEST_DATA_DIR, "parity_inc_fdst")
    H.CORPORA["basic"](src)
    server = parity_server_factory(SUPER)

    # Seed both destinations with the initial content.
    H.run_differential(src, rdst, fdst, ["-a"], ["-a"], server,
                       extra_check=lambda *a: [])
    with open(os.path.join(src, "a.txt"), "wb") as fh:
        fh.write(b"hello world, now modified and longer\n")
    _pin(os.path.join(src, "a.txt"), 1_650_000_000)

    result = H.run_differential(
        src, rdst, fdst, ["-a", "-i"], ["-a", "-i", "--incremental"], server,
        stdout=H.STDOUT_ITEMIZE)
    _run_and_check(case_id, result)


def _seed_basis(rel_entries):
    def seed(src, rroot, froot):
        for root in (rroot, froot):
            os.makedirs(root, exist_ok=True)
            for rel, data in rel_entries.items():
                _mk(os.path.join(root, rel), data)
    return seed


@requires_rsync
@parity
def test_compare_dest_skips_basis(parity_server_factory):
    """--compare-dest: a file present in the basis is not copied."""
    case_id = "compare_dest"
    src = os.path.join(TEST_DATA_DIR, "parity_cmpd_src")
    rdst = os.path.join(TEST_DATA_DIR, "parity_cmpd_rdst")
    fdst = os.path.join(TEST_DATA_DIR, "parity_cmpd_fdst")
    clean_dir(src)
    _mk(os.path.join(src, "f.txt"), b"basis-content\n")
    _pin(os.path.join(src, "f.txt"), _OLD_MTIME)
    server = parity_server_factory(SUPER)
    rel = os.path.abspath(src).lstrip(os.sep)

    # rsync resolves --compare-dest relative to the destination dir; FastSync
    # resolves it under the receive root and appends the mirrored source path.
    # Both rely on rsync's size+mtime quick-check, so the basis mtime is pinned
    # to the source's to keep the match deterministic across a second boundary.
    def seed(_src, rroot, froot):
        _mk(os.path.join(rroot, "basis", "f.txt"), b"basis-content\n", _OLD_MTIME)
        _mk(os.path.join(fdst, "basis", rel, "f.txt"), b"basis-content\n", _OLD_MTIME)

    def extra(_src, rroot, froot, _rs, _fs):
        out = []
        for label, root in (("rsync", rroot), ("fastsync", froot)):
            if os.path.exists(os.path.join(root, "f.txt")):
                out.append(f"{label} copied a file that is present in the "
                           f"compare basis")
        return out

    result = H.run_differential(
        src, rdst, fdst,
        ["-a", "--compare-dest=basis"],
        ["-a", f"--compare-dest={os.path.join(fdst, 'basis')}", "--incremental"],
        server, seed=seed, ignore_paths=("basis",), extra_check=extra)
    _run_and_check(case_id, result)


@requires_rsync
@parity
def test_link_dest_hardlinks_basis(parity_server_factory):
    """--link-dest: an unchanged file is hard-linked to the basis, not copied."""
    case_id = "link_dest"
    src = os.path.join(TEST_DATA_DIR, "parity_linkd_src")
    rdst = os.path.join(TEST_DATA_DIR, "parity_linkd_rdst")
    fdst = os.path.join(TEST_DATA_DIR, "parity_linkd_fdst")
    clean_dir(src)
    _mk(os.path.join(src, "f.txt"), b"link-basis-content\n")
    _pin(os.path.join(src, "f.txt"), _OLD_MTIME)
    server = parity_server_factory(SUPER)
    rel = os.path.abspath(src).lstrip(os.sep)

    def seed(_src, rroot, froot):
        _mk(os.path.join(rroot, "basis", "f.txt"), b"link-basis-content\n", _OLD_MTIME)
        _mk(os.path.join(fdst, "basis", rel, "f.txt"), b"link-basis-content\n", _OLD_MTIME)

    def extra(_src, rroot, froot, _rs, _fs):
        r_basis = os.stat(os.path.join(rroot, "basis", "f.txt")).st_ino
        f_basis = os.stat(os.path.join(fdst, "basis", rel, "f.txt")).st_ino
        out = []
        for label, root, basis in (("rsync", rroot, r_basis),
                                   ("fastsync", froot, f_basis)):
            target = os.path.join(root, "f.txt")
            if not os.path.exists(target):
                out.append(f"{label}: f.txt missing")
            elif os.stat(target).st_ino != basis:
                out.append(f"{label}: f.txt is not hard-linked to the basis")
        return out

    result = H.run_differential(
        src, rdst, fdst,
        ["-a", "--link-dest=basis"],
        ["-a", f"--link-dest={os.path.join(fdst, 'basis')}", "--incremental"],
        server, seed=seed, ignore_paths=("basis",), extra_check=extra)
    _run_and_check(case_id, result)


@requires_rsync
@parity
def test_link_dest_stats_matches_rsync(parity_server_factory):
    """A basis hit must not be counted as created or literal data: rsync reports
    zero for both, so FastSync's receiver tallies must too (regression for the
    basis materialization over-report)."""
    case_id = "link_dest_stats"
    src = os.path.join(TEST_DATA_DIR, "parity_linkds_src")
    rdst = os.path.join(TEST_DATA_DIR, "parity_linkds_rdst")
    fdst = os.path.join(TEST_DATA_DIR, "parity_linkds_fdst")
    clean_dir(src)
    _mk(os.path.join(src, "f.txt"), b"link-basis-content\n")
    _pin(os.path.join(src, "f.txt"), _OLD_MTIME)
    server = parity_server_factory(SUPER)
    rel = os.path.abspath(src).lstrip(os.sep)

    def seed(_src, rroot, froot):
        _mk(os.path.join(rroot, "basis", "f.txt"), b"link-basis-content\n", _OLD_MTIME)
        _mk(os.path.join(fdst, "basis", rel, "f.txt"), b"link-basis-content\n", _OLD_MTIME)

    result = H.run_differential(
        src, rdst, fdst,
        ["-a", "--link-dest=basis", "--stats"],
        ["-a", f"--link-dest={os.path.join(fdst, 'basis')}", "--incremental", "--stats"],
        server, seed=seed, ignore_paths=("basis",), stdout=H.STDOUT_STATS)
    _run_and_check(case_id, result, ref="--link-dest + --stats")


@requires_rsync
@parity
def test_copy_dest_copies_basis(parity_server_factory):
    """--copy-dest: a basis match is materialized as an independent copy with the
    source's attributes, matching rsync (copy then fix attributes)."""
    case_id = "copy_dest"
    src = os.path.join(TEST_DATA_DIR, "parity_copyd_src")
    rdst = os.path.join(TEST_DATA_DIR, "parity_copyd_rdst")
    fdst = os.path.join(TEST_DATA_DIR, "parity_copyd_fdst")
    clean_dir(src)
    _mk(os.path.join(src, "f.txt"), b"copy-basis-content\n")
    _pin(os.path.join(src, "f.txt"), 1_600_000_000)
    os.chmod(os.path.join(src, "f.txt"), 0o755)
    server = parity_server_factory(SUPER)
    rel = os.path.abspath(src).lstrip(os.sep)

    def seed(_src, rroot, froot):
        # Basis content matches the source; give the basis a different mode so a
        # wrong "keep basis attributes" implementation is visible.
        _mk(os.path.join(rroot, "basis", "f.txt"), b"copy-basis-content\n",
            1_600_000_000)
        os.chmod(os.path.join(rroot, "basis", "f.txt"), 0o644)
        _mk(os.path.join(fdst, "basis", rel, "f.txt"), b"copy-basis-content\n",
            1_600_000_000)
        os.chmod(os.path.join(fdst, "basis", rel, "f.txt"), 0o644)

    def extra(_src, rroot, froot, _rs, _fs):
        out = []
        bases = {"rsync": os.path.join(rroot, "basis", "f.txt"),
                 "fastsync": os.path.join(fdst, "basis", rel, "f.txt")}
        for label, root in (("rsync", rroot), ("fastsync", froot)):
            target = os.path.join(root, "f.txt")
            if not os.path.exists(target):
                out.append(f"{label}: f.txt missing")
                continue
            if os.stat(target).st_ino == os.stat(bases[label]).st_ino:
                out.append(f"{label}: f.txt is hard-linked, not copied")
            if (os.stat(target).st_mode & 0o777) != 0o755:
                out.append(f"{label}: f.txt mode "
                           f"{oct(os.stat(target).st_mode & 0o777)} != 0o755")
        return out

    result = H.run_differential(
        src, rdst, fdst,
        ["-a", "--copy-dest=basis"],
        ["-a", f"--copy-dest={os.path.join(fdst, 'basis')}", "--incremental"],
        server, seed=seed, ignore_paths=("basis",), extra_check=extra,
        compare_modes=True)
    _run_and_check(case_id, result)


@requires_rsync
@parity
def test_verify_basis_restores_strict_content(parity_server_factory):
    """Default matches rsync's metadata quick-check; FastSync-only
    `--verify-basis` restores strict content equality and transfers the source
    when a same-size/different-content basis would otherwise be trusted."""
    case_id = "verify_basis"
    src = os.path.join(TEST_DATA_DIR, "parity_vbasis_src")
    rdst = os.path.join(TEST_DATA_DIR, "parity_vbasis_rdst")
    fdst = os.path.join(TEST_DATA_DIR, "parity_vbasis_fdst")
    clean_dir(src)
    _mk(os.path.join(src, "f.txt"), b"AAAA\n")
    _pin(os.path.join(src, "f.txt"), _OLD_MTIME)
    server = parity_server_factory(SUPER)
    rel = os.path.abspath(src).lstrip(os.sep)

    def seed(_src, rroot, froot):
        # Same size and mtime as the source, different bytes: a metadata
        # quick-check trusts it; --verify-basis must not.
        for root, basis_rel in ((rroot, os.path.join("basis", "f.txt")),
                                (fdst, os.path.join("basis", rel, "f.txt"))):
            _mk(os.path.join(root, basis_rel), b"BBBB\n", _OLD_MTIME)

    # Default: both tools trust the basis (rsync's quick check), so the
    # destination carries the basis bytes and the trees match.
    result = H.run_differential(
        src, rdst, fdst,
        ["-a", "--link-dest=basis"],
        ["-a", f"--link-dest={os.path.join(fdst, 'basis')}", "--incremental"],
        server, seed=seed, ignore_paths=("basis",))
    _run_and_check(case_id + "_default", result)

    # --verify-basis (FastSync only): the digest mismatch rejects the basis and
    # the source is transferred, so the destination is the source bytes.  rsync
    # has no such flag; assert the FastSync outcome directly against the source.
    fdst2 = os.path.join(TEST_DATA_DIR, "parity_vbasis_fdst2")
    clean_dir(fdst2)
    for root, basis_rel in ((fdst2, os.path.join("basis", rel, "f.txt")),):
        _mk(os.path.join(root, basis_rel), b"BBBB\n", _OLD_MTIME)
    result, _ = H.run_fastsync(src, fdst2,
                               ["-a", f"--link-dest={os.path.join(fdst2, 'basis')}",
                                "--incremental", "--verify-basis"], server.port)
    assert result.returncode == 0, (result.stderr or result.stdout)[:300]
    target = os.path.join(get_dest_received_dir(fdst2, src), "f.txt")
    with open(target, "rb") as fh:
        assert fh.read() == b"AAAA\n", \
            "--verify-basis must reject the same-size/different-content basis"


@requires_rsync
@parity
def test_added_and_deleted_between_runs(parity_server_factory):
    """A source deletion and addition sync correctly under --delete."""
    case_id = "added_and_deleted"
    src = os.path.join(TEST_DATA_DIR, "parity_addel_src")
    rdst = os.path.join(TEST_DATA_DIR, "parity_addel_rdst")
    fdst = os.path.join(TEST_DATA_DIR, "parity_addel_fdst")
    server = parity_server_factory(DELETE)
    H.CORPORA["basic"](src)

    seed = seed_extras
    result = H.run_differential(
        src, rdst, fdst, ["-a", "--delete"], ["-a", "--delete"], server,
        seed=seed)
    _run_and_check(case_id + "_seed", result)

    os.remove(os.path.join(src, "a.txt"))
    _mk(os.path.join(src, "added.txt"), b"added between runs\n")
    result = H.run_differential(
        src, rdst, fdst, ["-a", "--delete", "-i"],
        ["-a", "--delete", "-i", "--incremental"], server,
        stdout=H.STDOUT_ITEMIZE)
    _run_and_check(case_id, result)


def _seed_dest_tree(src, root):
    """Copy `src`'s tree into `root` (the transfer mirror), preserving symlinks
    and directory mtimes, so a second differential run starts from an existing
    destination exactly like a seeded rsync run."""
    os.makedirs(root, exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(src):
        rel = os.path.relpath(dirpath, src)
        for name in dirnames:
            s = os.path.join(dirpath, name)
            d = os.path.join(root, rel, name) if rel != "." else os.path.join(root, name)
            if os.path.islink(s):
                continue
            os.makedirs(d, exist_ok=True)
        for name in filenames:
            s = os.path.join(dirpath, name)
            d = os.path.join(root, rel, name) if rel != "." else os.path.join(root, name)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            if os.path.islink(s):
                if os.path.lexists(d):
                    os.remove(d)
                os.symlink(os.readlink(s), d)
            else:
                shutil.copy2(s, d)
        if rel != ".":
            os.utime(os.path.join(root, rel), None)
    os.utime(root, None)


# A full rsync itemize code (11 columns) followed by the name.  H._ITEMIZE_RE
# only matches created (`+`) entries, so the changed-attribute codes this test
# asserts need their own matcher.
_ITEMIZE_LINE_RE = re.compile(r"^[<>ch.*][fdLDS].{9} ")


def _itemize_dir_link_lines(text):
    """The itemize lines for directory and symlink entries, excluding the
    transfer-root `./` line (FastSync emits it unconditionally; a documented
    residual)."""
    out = []
    for line in (text or "").splitlines():
        line = line.rstrip()
        if not line or not _ITEMIZE_LINE_RE.match(line):
            continue
        name = line.rsplit(" ", 1)[-1]
        if name == "./":
            continue
        if name.endswith("/") or " -> " in line:
            out.append(line)
    return sorted(out)


@requires_rsync
@parity
def test_itemize_rerun_dirs_symlinks_matches_rsync(parity_server_factory):
    """#314: a re-run reports directory/symlink destination state like rsync.

    On an unchanged tree FastSync emits no per-directory `cd+++++++++` (or
    symlink) lines, and after a changed directory mtime / symlink target it
    renders rsync's `.d..t......` / `cLc........` instead of `cd`/`cL`."""
    case_id = "itemize_rerun_dirs_symlinks"
    src = os.path.join(TEST_DATA_DIR, "parity_itemds_src")
    rdst = os.path.join(TEST_DATA_DIR, "parity_itemds_rdst")
    fdst = os.path.join(TEST_DATA_DIR, "parity_itemds_fdst")
    clean_dir(src)
    _mk(os.path.join(src, "sub", "b.txt"), b"nested\n")
    os.makedirs(os.path.join(src, "emptydir"), exist_ok=True)
    os.symlink("a.txt", os.path.join(src, "link"))
    _mk(os.path.join(src, "a.txt"), b"top\n")
    clean_dir(rdst)
    clean_dir(fdst)
    server = parity_server_factory(SUPER)
    rroot = rdst
    froot = get_dest_received_dir(fdst, src)
    _seed_dest_tree(src, rroot)
    _seed_dest_tree(src, froot)

    # Unchanged re-run: no directory or symlink itemize lines from either tool.
    rs = H.run_rsync(src, rdst, ["-a", "-i"])
    fs, _ = H.run_fastsync(src, fdst, ["-a", "-i", "--incremental"], server.port)
    assert rs.returncode == 0, rs.stderr
    assert fs.returncode == 0, fs.stderr
    assert _itemize_dir_link_lines(rs.stdout) == []
    fast_unchanged = _itemize_dir_link_lines(fs.stdout)
    assert fast_unchanged == [], f"unchanged re-run itemized dirs/links: {fast_unchanged}"

    # Change the directory mtime and the symlink target, then re-run.
    _pin(os.path.join(src, "sub"), _OLD_MTIME)
    os.remove(os.path.join(src, "link"))
    os.symlink("b.txt", os.path.join(src, "link"))
    rs = H.run_rsync(src, rdst, ["-a", "-i"])
    fs, _ = H.run_fastsync(src, fdst, ["-a", "-i", "--incremental"], server.port)
    assert rs.returncode == 0, rs.stderr
    assert fs.returncode == 0, fs.stderr
    expected = _itemize_dir_link_lines(rs.stdout)
    actual = _itemize_dir_link_lines(fs.stdout)
    assert actual == expected, f"rsync={rs.stdout!r} fastsync={fs.stdout!r}"
    assert any(line.endswith(" sub/") and line.startswith(".d..t") for line in actual), actual
    assert any(line.startswith("cLc") and " -> b.txt" in line for line in actual), actual


def _deleted_breakdown_line(text):
    for line in (text or "").splitlines():
        if line.startswith("Number of deleted files:"):
            return " ".join(line.split())
    return ""


@requires_rsync
@parity
def test_stats_deleted_breakdown_matches_rsync(parity_server_factory):
    """#316: `--stats` renders rsync's per-type `Number of deleted files`
    breakdown for removed regular files, directories, symlinks and a special."""
    case_id = "stats_deleted_breakdown"
    src = os.path.join(TEST_DATA_DIR, "parity_delbd_src")
    rdst = os.path.join(TEST_DATA_DIR, "parity_delbd_rdst")
    fdst = os.path.join(TEST_DATA_DIR, "parity_delbd_fdst")
    clean_dir(src)
    _mk(os.path.join(src, "keep.txt"), b"keep\n")
    server = parity_server_factory(DELETE)

    def seed(_src, rroot, froot):
        for root in (rroot, froot):
            _mk(os.path.join(root, "extra1.txt"), b"e1\n", _OLD_MTIME)
            _mk(os.path.join(root, "extradir", "inside.txt"), b"e2\n", _OLD_MTIME)
            os.makedirs(os.path.join(root, "extradir"), exist_ok=True)
            link = os.path.join(root, "extralink")
            if not os.path.lexists(link):
                os.symlink("keep.txt", link)
            fifo = os.path.join(root, "extrafifo")
            if not os.path.exists(fifo):
                os.mkfifo(fifo)

    def extra(_src, _rroot, _froot, rs, fs):
        rs_line = _deleted_breakdown_line(rs.stdout)
        fs_line = _deleted_breakdown_line(fs.stdout)
        if not rs_line:
            return ["rsync printed no deleted-files line"]
        if rs_line != fs_line:
            return [f"deleted breakdown rsync={rs_line!r} fastsync={fs_line!r}"]
        if "reg:" not in rs_line or "dir:" not in rs_line or \
                "link:" not in rs_line or "special:" not in rs_line:
            return [f"breakdown missing a category: {rs_line!r}"]
        return []

    result = H.run_differential(
        src, rdst, fdst, ["-a", "--delete", "--stats"],
        ["-a", "--delete", "--stats", "--incremental"], server,
        seed=seed, extra_check=extra)
    _run_and_check(case_id, result, ref="--stats deleted per-type breakdown")


@requires_rsync
@parity
def test_one_file_system(parity_server_factory):
    """-x emits the mount-point directory but not its contents."""
    case_id = "one_file_system"
    local = os.stat(".")
    shm = "/dev/shm"
    if not os.path.isdir(shm):
        pytest.skip("/dev/shm not available")
    if os.stat(shm).st_dev == local.st_dev:
        pytest.skip("no cross-device filesystem available")

    src = os.path.join(TEST_DATA_DIR, "parity_ofs_src")
    rdst = os.path.join(TEST_DATA_DIR, "parity_ofs_rdst")
    fdst = os.path.join(TEST_DATA_DIR, "parity_ofs_fdst")
    clean_dir(src)
    _mk(os.path.join(src, "keep.txt"), b"keep\n")
    probe = os.path.join(shm, f"fastsync_ofs_{os.getpid()}")
    shutil.rmtree(probe, ignore_errors=True)
    os.makedirs(probe)
    _mk(os.path.join(probe, "inside.txt"), b"cross\n")
    try:
        os.symlink(probe, os.path.join(src, "nested_link"))
        server = parity_server_factory(SUPER)
        result = H.run_differential(
            src, rdst, fdst,
            ["-a", "--copy-links", "-x"],
            ["-a", "--copy-links", "-x"], server)
        _run_and_check(case_id, result)
    finally:
        shutil.rmtree(probe, ignore_errors=True)


@requires_rsync
@parity
def test_parity_caveats_reference_known_cases():
    """Every allowlist entry must name a real case id and aspect."""
    from parity_caveats import CAVEATS
    known = {c.id for c in ALL_CASES} | {
        "incremental_modified", "compare_dest", "link_dest",
        "added_and_deleted", "added_and_deleted_seed", "one_file_system",
    }
    problems = []
    for case_id, entry in CAVEATS.items():
        if case_id not in known:
            problems.append(f"unknown case id in parity_caveats.py: {case_id!r}")
        for aspect in entry:
            if aspect not in ASPECTS:
                problems.append(
                    f"{case_id!r}: unknown aspect {aspect!r} (expected {ASPECTS})")
    assert not problems, "\n".join(problems)
