"""Differential rsync-parity harness.

Runs the SAME transfer with real ``rsync`` and with FastSync over separate
destinations and compares the resulting trees and (optionally) normalized
stdout.  ``test_differential_parity.py`` drives this module with a table of
cases; ``parity_caveats.py`` is the data-driven allowlist of documented
residuals.

Design notes
------------
FastSync mirrors the *absolute* source path below its receive root, while
rsync copies the source contents directly into the destination.  ``Case.layout``
tells the harness which pair of directory roots to compare:

* ``MIRROR``     -- rsync ``DEST/`` vs FastSync ``DEST/<abs-src>/`` (the common
  case; matches ``common.get_dest_received_dir``).
* ``MIRROR_ABS`` -- ``rsync -R`` without a cut lays the full absolute path
  under the destination, so rsync ``DEST/<abs-src>/`` is compared against the
  same FastSync mirror path.
* ``RELATIVE``   -- ``rsync -R --files-from`` lays bare relative paths under the
  destination and FastSync does the same, so both destination roots compare
  directly.

Only ``tests/integration/common.py`` is used to reach the build products and the
server manager; the harness never duplicates that plumbing.
"""
import difflib
import hashlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402  (path bootstrap above)
    TEST_DATA_DIR,
    clean_dir,
    get_dest_received_dir,
    run_client,
)

RSYNC = shutil.which("rsync")

# Comparison layouts (see module docstring).
MIRROR = "mirror"
MIRROR_ABS = "mirror_abs"
RELATIVE = "relative"

# stdout comparators.
STDOUT_NONE = None
STDOUT_ITEMIZE = "itemize"
STDOUT_OUTFMT = "outfmt"
STDOUT_STATS = "stats"

# rsync --stats lines that are protocol-independent and must match exactly.
# `Number of files` and `Number of created files` carry rsync's per-type
# breakdown; protocol 2.28.0 reports the receiver-created split over
# STATUS_STATS.  Deliberately excluded: Total bytes sent/received (protocol
# framing differs, see the `--stats` row in RSYNC_COMPAT.md).
STATS_KEYS = (
    "Number of files",
    "Number of created files",
    "Number of deleted files",
    "Number of regular files transferred",
    "Total file size",
    "Total transferred file size",
    "Literal data",
    "Matched data",
    "File list size",
)

_ITEMIZE_RE = re.compile(r"^(<|>|c|h|\.|\*)[fdLDS][.+\-][.+\-][.+\-][.+\-]")


@dataclass
class Case:
    """One differential scenario: a corpus, a flag set, and how to compare."""

    id: str
    corpus: str
    flags: List[str]
    fastsync_flags: Optional[List[str]] = None
    layout: str = MIRROR
    server_args: Tuple[str, ...] = ("--allow-super",)
    seed: Optional[Callable] = None
    stdout: Optional[str] = STDOUT_NONE
    compare_modes: bool = False
    compare_hardlinks: bool = False
    ignore_paths: Tuple[str, ...] = ()
    extra_check: Optional[Callable] = None
    files_from: Optional[Tuple[str, ...]] = None
    # rsync receives ``src + "/"``; FastSync mirrors the path it is given, so a
    # trailing-slash-sensitive case must hand FastSync the same form.
    fs_src_suffix: str = ""
    # Some cases have an unspecified result (e.g. which extras survive a
    # partial --max-delete abort): assert the case-specific invariants via
    # extra_check and skip the exact-tree comparison.
    compare_tree: bool = True
    ci: bool = False
    ref: str = ""

    def fs_flags(self) -> List[str]:
        return list(self.flags if self.fastsync_flags is None else self.fastsync_flags)


# ---------------------------------------------------------------------------
# Corpora
# ---------------------------------------------------------------------------

# Deterministic mtimes so quick-check decisions are reproducible.
_SRC_MTIME = 1_600_000_000


def _write(path: str, data: bytes, mode: Optional[int] = None) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    os.utime(path, (_SRC_MTIME, _SRC_MTIME))
    if mode is not None:
        os.chmod(path, mode)


def _set_mode(path: str, mode: int) -> None:
    os.chmod(path, mode)


def corpus_basic(root: str) -> None:
    """Regular files + nested dirs (dirs are implied by their files)."""
    clean_dir(root)
    _write(os.path.join(root, "a.txt"), b"hello world\n")
    _write(os.path.join(root, "sub", "b.bin"),
           bytes((i * 7) & 0xFF for i in range(5000)))
    _write(os.path.join(root, "sub", "deep", "c.txt"), "w\u00f6rld\n".encode())


def corpus_unicode(root: str) -> None:
    clean_dir(root)
    _write(os.path.join(root, "uni \u00f1\u6587.txt"), b"unicode\n")
    _write(os.path.join(root, "sub", "sp ace \u00e9.dat"), b"spaced\n")
    _set_mode(os.path.join(root, "sub"), 0o750)


def corpus_links(root: str) -> None:
    corpus_basic(root)
    os.symlink("a.txt", os.path.join(root, "rel_link"))
    os.symlink("/etc/hostname", os.path.join(root, "abs_link"))
    os.symlink("nowhere/target", os.path.join(root, "broken_link"))


def corpus_hardlinks(root: str) -> None:
    clean_dir(root)
    _write(os.path.join(root, "h1.txt"), b"hardlinked payload\n")
    os.link(os.path.join(root, "h1.txt"), os.path.join(root, "h2.txt"))
    _write(os.path.join(root, "other.txt"), b"other\n")


def corpus_sparse(root: str) -> None:
    clean_dir(root)
    _write(os.path.join(root, "small.txt"), b"small\n")
    sparse = os.path.join(root, "sparse.bin")
    with open(sparse, "wb") as fh:
        fh.seek(1024 * 1024 - 1)
        fh.write(b"\0")
    os.utime(sparse, (_SRC_MTIME, _SRC_MTIME))


def corpus_filters(root: str) -> None:
    clean_dir(root)
    _write(os.path.join(root, "keep.txt"), b"keep\n")
    _write(os.path.join(root, "drop.log"), b"log\n")
    _write(os.path.join(root, "sub", "keep2.txt"), b"keep2\n")
    _write(os.path.join(root, "sub", "drop2.log"), b"log2\n")
    _write(os.path.join(root, "sub", "data.bin"), b"bin\n")


def corpus_empty_dir(root: str) -> None:
    clean_dir(root)
    _write(os.path.join(root, "keep.txt"), b"keep\n")
    os.makedirs(os.path.join(root, "emptydir"), exist_ok=True)
    os.utime(os.path.join(root, "emptydir"), (_SRC_MTIME, _SRC_MTIME))
    _write(os.path.join(root, "nonempty", "f.txt"), b"f\n")


def corpus_relative(root: str) -> None:
    """Tree for the -R/--files-from cases."""
    clean_dir(root)
    _write(os.path.join(root, "a.txt"), b"a\n")
    _write(os.path.join(root, "b.txt"), b"b\n")
    _write(os.path.join(root, "sub", "x.txt"), b"x\n")
    _write(os.path.join(root, "sub", "y.txt"), b"y\n")
    os.makedirs(os.path.join(root, "dir1"), exist_ok=True)
    os.utime(os.path.join(root, "dir1"), (_SRC_MTIME, _SRC_MTIME))
    _write(os.path.join(root, "dir1", "keep.txt"), b"keep\n")


def corpus_iconv(root: str) -> None:
    """Latin-1 (ISO-8859-1) encoded filenames, matching the --iconv direction."""
    clean_dir(root)
    for rel, data in ((b"caf\xe9.txt", b"caf\xe9\n"),
                      (os.path.join(b"sub", b"\xfcber.txt"), b"\xfcber\n")):
        full = os.path.join(os.fsencode(root), rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)
        os.utime(full, (_SRC_MTIME, _SRC_MTIME))


CORPORA: Dict[str, Callable[[str], None]] = {
    "basic": corpus_basic,
    "unicode": corpus_unicode,
    "links": corpus_links,
    "hardlinks": corpus_hardlinks,
    "sparse": corpus_sparse,
    "filters": corpus_filters,
    "empty_dir": corpus_empty_dir,
    "relative": corpus_relative,
    "iconv": corpus_iconv,
}


# ---------------------------------------------------------------------------
# Tree snapshotting / comparison
# ---------------------------------------------------------------------------

def snapshot(root: str, compare_modes: bool = False) -> Dict[str, tuple]:
    """Map relative path -> descriptor for every entry below ``root``.

    Files hash their contents with SHA-256 (structural comparison, so differing
    quick-check metadata cannot mask a payload difference).  Symlinks record
    their target.  Empty directories are included (as ``("dir", ...)``) so the
    recursive-empty-directory residual is observable.
    """
    out: Dict[str, tuple] = {}
    if not os.path.isdir(root):
        return out

    def describe(path: str) -> Optional[tuple]:
        st = os.lstat(path)
        if os.path.islink(path):
            return ("link", os.readlink(path))
        if os.path.isdir(path):
            mode = oct(st.st_mode & 0o7777) if compare_modes else None
            return ("dir", mode)
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        mode = oct(st.st_mode & 0o7777) if compare_modes else None
        return ("file", h.hexdigest()[:16], mode)

    # The comparison root itself is not part of the tree diff: a no-transfer
    # result legitimately leaves FastSync's mirror directory absent while rsync
    # leaves an existing (empty) destination root.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(dirnames):
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                out[rel] = ("link", os.readlink(p))
                dirnames.remove(name)
            else:
                out[rel] = describe(p)
        for name in sorted(filenames):
            p = os.path.join(dirpath, name)
            out[os.path.relpath(p, root)] = describe(p)
    return out


def _hardlink_groups(root: str) -> Dict[str, str]:
    """Assign a stable group letter to each inode shared by >1 regular file."""
    inodes: Dict[tuple, List[str]] = {}
    for dirpath, _dirs, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                continue
            st = os.lstat(p)
            if st.st_nlink > 1:
                inodes.setdefault((st.st_dev, st.st_ino), []).append(
                    os.path.relpath(p, root))
    groups: Dict[str, str] = {}
    for i, (_key, members) in enumerate(sorted(inodes.items())):
        for rel in members:
            groups[rel] = chr(ord("A") + i)
    return groups


def _drop_ignored(tree: Dict[str, tuple], ignore_paths) -> Dict[str, tuple]:
    if not ignore_paths:
        return tree
    out = {}
    for rel, desc in tree.items():
        if any(rel == ig or rel.startswith(ig.rstrip("/") + "/") for ig in ignore_paths):
            continue
        out[rel] = desc
    return out


def tree_diff(rsync_root: str, fs_root: str, case: Case) -> List[str]:
    """Return a list of human-readable differences (empty when identical)."""
    rtree = _drop_ignored(snapshot(rsync_root, case.compare_modes), case.ignore_paths)
    ftree = _drop_ignored(snapshot(fs_root, case.compare_modes), case.ignore_paths)
    if case.compare_hardlinks:
        rgroups = _hardlink_groups(rsync_root)
        fgroups = _hardlink_groups(fs_root)
    else:
        rgroups = fgroups = {}
    diffs: List[str] = []
    for rel in sorted(set(rtree) | set(ftree)):
        r = rtree.get(rel)
        f = ftree.get(rel)
        if r == f:
            continue
        if r is None:
            diffs.append(f"+ fastsync-only: {rel!r} {f}")
        elif f is None:
            diffs.append(f"- rsync-only:    {rel!r} {r}")
        else:
            diffs.append(f"~ differs:       {rel!r} rsync={r} fastsync={f}")
    if case.compare_hardlinks:
        for rel in sorted(set(rgroups) | set(fgroups)):
            if rgroups.get(rel) != fgroups.get(rel):
                diffs.append(
                    f"~ hardlink group: {rel!r} rsync={rgroups.get(rel)} "
                    f"fastsync={fgroups.get(rel)}")
    return diffs


# ---------------------------------------------------------------------------
# stdout normalization
# ---------------------------------------------------------------------------

def _parse_bytes(text: str) -> str:
    m = re.match(r"([\d,]+)", text.strip())
    return m.group(1).replace(",", "") if m else text.strip()


def normalize_stdout(text: str, mode: Optional[str]) -> object:
    if mode == STDOUT_ITEMIZE:
        lines = []
        for line in (text or "").splitlines():
            line = line.rstrip()
            if not line:
                continue
            if line.startswith("*deleting"):
                lines.append(line)
                continue
            if not _ITEMIZE_RE.match(line):
                continue
            # Directories are not transfer entries in FastSync's recursive
            # scanner, so rsync's `cd+++++++++ name/` lines have no counterpart
            # (documented recursive-empty-dir residual).  Compare file/link
            # itemization only.
            if line.rsplit(" ", 1)[-1].endswith("/"):
                continue
            lines.append(line)
        return sorted(lines)
    if mode == STDOUT_OUTFMT:
        lines = []
        for line in (text or "").splitlines():
            line = line.rstrip()
            if not line:
                continue
            # Directory entries are emitted by rsync but not by FastSync's
            # recursive scanner (documented residual).  Tokens are either
            # `%n %l` (path first) or `%i %n` (path last); drop a line when
            # either end-token is a directory path.
            first = line.split(" ", 1)[0]
            last = line.rsplit(" ", 1)[-1]
            if first.endswith("/") or last.endswith("/"):
                continue
            lines.append(line)
        return sorted(lines)
    if mode == STDOUT_STATS:
        found = {}
        for line in (text or "").splitlines():
            for key in STATS_KEYS:
                if line.startswith(key + ":"):
                    found[key] = _parse_bytes(line.split(":", 1)[1])
        return found
    # raw
    return sorted(l.rstrip() for l in (text or "").splitlines() if l.strip())


def stdout_diff(rsync_out: str, fs_out: str, mode: Optional[str]) -> List[str]:
    r = normalize_stdout(rsync_out, mode)
    f = normalize_stdout(fs_out, mode)
    if r == f:
        return []
    if mode == STDOUT_STATS:
        return [f"stats rsync={r}", f"stats fastsync={f}"]
    return list(difflib.unified_diff(
        [str(x) for x in r], [str(x) for x in f],
        fromfile="rsync", tofile="fastsync", lineterm=""))


# ---------------------------------------------------------------------------
# Running one case
# ---------------------------------------------------------------------------

def run_rsync(src: str, rdst: str, flags: List[str]) -> subprocess.CompletedProcess:
    args = [RSYNC] + list(flags) + [src + "/", rdst + "/"]
    return subprocess.run(
        args, capture_output=True, text=True,
        env=dict(os.environ, LC_ALL="C"), timeout=180)


def run_fastsync(src: str, fdst: str, flags: List[str], port: int):
    return run_client(src, fdst, flags=list(flags), port=port)


def run_differential(  # noqa: PLR0913 (explicit scenario parameters)
    src: str,
    rdst: str,
    fdst: str,
    rs_flags: List[str],
    fs_flags: List[str],
    server,
    layout: str = MIRROR,
    seed: Optional[Callable] = None,
    stdout: Optional[str] = STDOUT_NONE,
    compare_modes: bool = False,
    compare_hardlinks: bool = False,
    ignore_paths: Tuple[str, ...] = (),
    extra_check: Optional[Callable] = None,
    files_from: Optional[Tuple[str, ...]] = None,
    fs_src_suffix: str = "",
    compare_tree: bool = True,
) -> Dict[str, object]:
    """Run one rsync/FastSync pair and return the diff aspects.

    Returned dict keys: ``rsync_rc``, ``fastsync_rc``, ``rsync_stderr``,
    ``fastsync_stderr``, ``tree``, ``stdout``, ``extra``.
    """
    clean_dir(rdst)
    clean_dir(fdst)
    abs_src = os.path.abspath(src)
    rel = abs_src.lstrip(os.sep)
    if layout == RELATIVE:
        rroot, froot = rdst, fdst
    elif layout == MIRROR_ABS:
        rroot, froot = os.path.join(rdst, rel), get_dest_received_dir(fdst, src)
    else:
        rroot, froot = rdst, get_dest_received_dir(fdst, src)
    # rsync's destination root always exists (clean_dir created it).  FastSync's
    # logical transfer root is the mirror path below the destination argument,
    # so pre-create it too: `Number of created files` counts the root only when
    # it is genuinely absent, and the two tools must start from the same state.
    os.makedirs(froot, exist_ok=True)
    if seed:
        seed(src, rroot, froot)

    rs_flags = list(rs_flags)
    fs_flags = list(fs_flags)
    if files_from is not None:
        list_path = os.path.join(TEST_DATA_DIR, "parity_" +
                                 os.path.basename(src) + ".list")
        write_list(list_path, files_from)
        rs_flags.append(f"--files-from={list_path}")
        fs_flags.append(f"--files-from={list_path}")

    rs = run_rsync(src, rdst, rs_flags)
    fs_result, _ = run_fastsync(src + fs_src_suffix, fdst, fs_flags, server.port)

    class _View:
        """Adapter so tree_diff/extra_check keep the Case-shaped interface."""

        def __init__(self) -> None:
            self.compare_modes = compare_modes
            self.compare_hardlinks = compare_hardlinks
            self.ignore_paths = ignore_paths

    result = {
        "rsync_rc": rs.returncode,
        "fastsync_rc": fs_result.returncode,
        "rsync_stderr": rs.stderr,
        "fastsync_stderr": fs_result.stderr or fs_result.stdout,
        "tree": tree_diff(rroot, froot, _View()) if compare_tree else [],
        "stdout": [],
        "extra": [],
    }
    if stdout is not None:
        result["stdout"] = stdout_diff(rs.stdout, fs_result.stdout, stdout)
    if extra_check:
        result["extra"] = list(extra_check(src, rroot, froot, rs, fs_result) or [])
    return result


def execute_case(case: Case, server) -> Dict[str, object]:
    """Run a table-driven case and return the diff aspects."""
    tag = case.id
    src = os.path.join(TEST_DATA_DIR, f"parity_{tag}_src")
    rdst = os.path.join(TEST_DATA_DIR, f"parity_{tag}_rdst")
    fdst = os.path.join(TEST_DATA_DIR, f"parity_{tag}_fdst")
    CORPORA[case.corpus](src)
    return run_differential(
        src, rdst, fdst,
        case.flags, case.fs_flags(), server,
        layout=case.layout, seed=case.seed, stdout=case.stdout,
        compare_modes=case.compare_modes, compare_hardlinks=case.compare_hardlinks,
        ignore_paths=case.ignore_paths, extra_check=case.extra_check,
        files_from=case.files_from, fs_src_suffix=case.fs_src_suffix,
        compare_tree=case.compare_tree,
    )


def write_list(path: str, entries) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(e + "\n")
    return path
