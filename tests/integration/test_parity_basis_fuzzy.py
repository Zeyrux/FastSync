"""Differential rsync-parity coverage for two residuals closed on this branch.

* A4 -- ``--compare-dest``/``--copy-dest``/``--link-dest`` relative-DIR
  resolution: rsync resolves a relative DIR against the destination directory
  and appends the file's TRANSFER-RELATIVE name.  FastSync's default transfer
  mirrors the absolute source path below its receive root, so a naive relative
  DIR used to probe a different tree.  These tests seed the basis at rsync's
  spelling and assert FastSync finds it (byte-exact / hard-linked / sparse),
  matching real rsync 3.4.1.

* A5 -- ``-y``/``--fuzzy`` candidate eligibility: rsync's ``find_fuzzy`` has no
  delta-size gate, so it reuses an oversized (>10x) or sub-16-KiB sibling;
  FastSync used to decline both.  These tests assert FastSync now uses the same
  sibling as rsync (observable as ``Matched data``) with a byte-exact result.

Every test skips cleanly when rsync is absent.
"""
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    TEST_DATA_DIR,
    clean_dir,
    get_dest_received_dir,
    run_client,
)

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")

OLD_MTIME = 1_500_000_000


def _write(path, content, mtime=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([RSYNC] + args, capture_output=True, text=True, env=env, timeout=120)


def _stat_bytes(text, label):
    for line in text.splitlines():
        if line.startswith(label + ":"):
            return int(line.split(":", 1)[1].strip().split()[0].replace(",", ""))
    return None


class TestRelativeBasisDirResolution:
    """A4: a relative basis DIR must resolve to the same tree as rsync's."""

    _FILES = {
        "root.txt": b"root-basis-content\n",
        "sub/nested.txt": b"nested-basis-content\n",
    }

    def _seed_source(self, source):
        clean_dir(source)
        for rel, data in self._FILES.items():
            _write(os.path.join(source, rel), data, OLD_MTIME)
        return self._FILES

    @requires_rsync
    @pytest.mark.parametrize("flag", ["--compare-dest", "--link-dest"])
    def test_relative_dir_resolves_like_rsync(self, shared_server, flag):
        tag = flag.lstrip("-")
        source = os.path.join(TEST_DATA_DIR, f"relbasis_{tag}_src")
        rdst = os.path.join(TEST_DATA_DIR, f"relbasis_{tag}_rdst")
        fdst = os.path.join(TEST_DATA_DIR, f"relbasis_{tag}_fdst")
        self._seed_source(source)

        # rsync: relative DIR -> dest/basis/<transfer-relative name>.
        clean_dir(rdst)
        for rel, data in self._FILES.items():
            _write(os.path.join(rdst, "basis", rel), data, OLD_MTIME)
        rs = _rsync(["-a", f"{flag}=basis", source + "/", rdst + "/"])
        assert rs.returncode == 0, rs.stderr

        # FastSync: the SAME relative spelling seeded at the SAME
        # transfer-relative location under its destination root.
        clean_dir(fdst)
        for rel, data in self._FILES.items():
            _write(os.path.join(fdst, "basis", rel), data, OLD_MTIME)
        result, _ = run_client(source, fdst,
                               flags=["-a", f"{flag}=basis", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        received = get_dest_received_dir(fdst, source)

        for rel, data in self._FILES.items():
            rfile = os.path.join(rdst, rel)
            ffile = os.path.join(received, rel)
            basis = os.path.join(fdst, "basis", rel)
            if flag == "--compare-dest":
                # compare-dest never copies: both destinations stay sparse.
                assert not os.path.exists(rfile), f"rsync copied {rel}"
                assert not os.path.exists(ffile), (
                    f"FastSync did not resolve the relative basis DIR at {basis!r} "
                    f"(expected {rel!r} to stay sparse like rsync)")
            else:
                # link-dest hard-links; a basis miss would transfer a new file.
                assert os.path.exists(ffile), f"FastSync lost {rel}"
                assert _read(ffile) == data
                assert os.stat(ffile).st_ino == os.stat(basis).st_ino, (
                    f"FastSync did not hard-link {rel!r} to the relative basis at "
                    f"{basis!r} (basis not resolved like rsync)")

    @requires_rsync
    def test_relative_dir_copy_dest_content(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "relbasis_copy_src")
        fdst = os.path.join(TEST_DATA_DIR, "relbasis_copy_fdst")
        self._seed_source(source)
        clean_dir(fdst)
        for rel, data in self._FILES.items():
            _write(os.path.join(fdst, "basis", rel), data, OLD_MTIME)
        result, _ = run_client(source, fdst,
                               flags=["-a", "--copy-dest=basis", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        received = get_dest_received_dir(fdst, source)
        for rel, data in self._FILES.items():
            ffile = os.path.join(received, rel)
            assert os.path.exists(ffile), f"copy-dest did not materialize {rel}"
            assert _read(ffile) == data
            assert os.stat(ffile).st_ino != os.stat(os.path.join(fdst, "basis", rel)).st_ino


class TestFuzzyEligibilityWindow:
    """A5: --fuzzy candidate eligibility must match rsync's uncapped window."""

    BASE = b"the quick brown fox jumps over the lazy dog\n" * 4000

    def _run_pair(self, shared_server, tag, payload, sibling):
        source = os.path.join(TEST_DATA_DIR, f"fzw_{tag}_src")
        dest = os.path.join(TEST_DATA_DIR, f"fzw_{tag}_dst")
        rdst = os.path.join(TEST_DATA_DIR, f"fzw_{tag}_rdst")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(rdst)
        _write(os.path.join(source, "report_v2.txt"), payload)
        for root in (rdst, get_dest_received_dir(dest, source)):
            _write(os.path.join(root, "report_v1.txt"), sibling)

        rs = _rsync(["-a", "--no-whole-file", "--fuzzy", "--stats",
                     source + "/", rdst + "/"])
        assert rs.returncode == 0, rs.stderr
        result, _ = run_client(
            source, dest,
            flags=["-a", "--incremental", "--delta", "--fuzzy", "--stats"],
            port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]

        # The reconstructed file is byte-exact in every case.
        assert _read(os.path.join(get_dest_received_dir(dest, source),
                                  "report_v2.txt")) == payload
        return rs, result

    @requires_rsync
    def test_oversized_sibling_eligible_like_rsync(self, shared_server):
        """A sibling 20x the source is used by rsync; FastSync must too (its old
        10x delta-size gate declined it)."""
        n = 65536
        payload = (self.BASE * ((n // len(self.BASE)) + 1))[:n]
        sibling = (self.BASE * 200)[: n * 20]
        rs, result = self._run_pair(shared_server, "big", payload, sibling)
        assert _stat_bytes(rs.stdout, "Matched data") > 0, \
            "rsync should use a >10x fuzzy basis"
        assert _stat_bytes(result.stdout, "Matched data") > 0, (
            "FastSync's fuzzy eligibility must accept a >10x sibling like rsync "
            f"(Matched data={_stat_bytes(result.stdout, 'Matched data')})")

    @requires_rsync
    def test_small_source_sibling_eligible_like_rsync(self, shared_server):
        """A sub-16-KiB source with an identical sibling is used by rsync;
        FastSync's old 16 KiB delta minimum declined it."""
        n = 8192
        payload = (self.BASE * ((n // len(self.BASE)) + 1))[:n]
        rs, result = self._run_pair(shared_server, "small", payload, payload)
        assert _stat_bytes(rs.stdout, "Matched data") > 0, \
            "rsync applies --fuzzy below 16 KiB"
        assert _stat_bytes(result.stdout, "Matched data") > 0, (
            "FastSync's fuzzy eligibility must accept a sub-16-KiB source like "
            f"rsync (Matched data={_stat_bytes(result.stdout, 'Matched data')})")
