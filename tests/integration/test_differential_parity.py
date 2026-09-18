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
import shutil
import sys
import warnings

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    ServerManager,
    TEST_DATA_DIR,
    clean_dir,
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


def seed_max_delete(_src, rroot, froot):
    for root in (rroot, froot):
        _mk(os.path.join(root, "extra1.txt"), b"e1\n", _OLD_MTIME)
        _mk(os.path.join(root, "extra2.txt"), b"e2\n", _OLD_MTIME)


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
    H.Case("delete_excluded", "filters",
           ["-a", "--delete", "--delete-excluded", "--exclude=*.log"],
           seed=seed_delete_excluded, server_args=DELETE, ref="--delete-excluded"),
    H.Case("max_delete", "basic", ["-a", "--delete", "--max-delete=1"],
           seed=seed_max_delete, server_args=DELETE,
           extra_check=max_delete_count_check, ref="--max-delete"),

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
    "link_dest": "--link-dest",
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
    server = parity_server_factory(SUPER)
    rel = os.path.abspath(src).lstrip(os.sep)

    # rsync resolves --compare-dest relative to the destination dir; FastSync
    # resolves it under the receive root and appends the mirrored source path.
    def seed(_src, rroot, froot):
        _mk(os.path.join(rroot, "basis", "f.txt"), b"basis-content\n")
        _mk(os.path.join(fdst, "basis", rel, "f.txt"), b"basis-content\n")

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
    server = parity_server_factory(SUPER)
    rel = os.path.abspath(src).lstrip(os.sep)

    def seed(_src, rroot, froot):
        _mk(os.path.join(rroot, "basis", "f.txt"), b"link-basis-content\n")
        _mk(os.path.join(fdst, "basis", rel, "f.txt"), b"link-basis-content\n")

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
