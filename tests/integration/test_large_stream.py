"""#318: whole-file streaming above the receiver's 256 MiB ceiling.

The receiver's historical whole-file bound (``MAX_RECEIVE_WHOLE_FILE_SIZE``,
256 MiB) refused any single-file payload above it.  The transfer engine now
streams such a payload (and the basis read/verify/hash) through a bounded buffer
and spools it to a temp file, so arbitrarily large single files transfer without
being materialized in memory.

To exercise the streaming path deterministically and quickly, these tests lower
the receiver bound with the test-only ``FASTSYNC_MAX_WHOLE_FILE_SIZE`` hook (it
can only lower, never raise, the protocol ceiling) and transfer a file a few
times larger than the lowered bound.  A real >256 MiB transfer is covered once,
unmarked, so it runs in the full suite but not the fast PR gate.
"""
import hashlib
import os
import random
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    ServerManager,
    TEST_DATA_DIR,
    clean_dir,
    get_dest_received_dir,
    run_client,
)

LOW_BOUND = 1024 * 1024
FILE_SIZE = 3 * 1024 * 1024
OLD_MTIME = 1_500_000_000


@pytest.fixture(scope="module")
def small_bound_server():
    """A server whose whole-file streaming bound is 1 MiB."""
    server = ServerManager()
    server.start(extra_args=["--allow-super"],
                 env={"FASTSYNC_MAX_WHOLE_FILE_SIZE": str(LOW_BOUND)})
    yield server
    server.stop()


def _payload(n):
    rng = random.Random(0xC0FFEE)
    return rng.randbytes(n)


def _write(path, data, mtime=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def _resolved(dest, source, rel):
    return os.path.join(get_dest_received_dir(dest, source), rel)


def _no_spool_leftovers(dest):
    leftovers = []
    for root, _dirs, files in os.walk(dest):
        leftovers += [os.path.join(root, f) for f in files if ".fastsync-spool." in f]
    return leftovers


class TestStreamedWholeFile:
    """A file above the (lowered) bound transfers correctly in every mode."""

    @pytest.mark.parametrize(
        "flags",
        [
            ["-a"],
            ["-a", "--incremental"],
            ["-a", "-z"],
            ["-a", "--incremental", "-z"],
            ["-a", "--threads", "--incremental"],
            ["-a", "--inplace"],
            ["-a", "--partial"],
        ],
    )
    def test_above_bound_transfers(self, small_bound_server, flags):
        tag = "_".join(f.strip("-") for f in flags) or "default"
        source = os.path.join(TEST_DATA_DIR, f"stream_src_{tag}")
        dest = os.path.join(TEST_DATA_DIR, f"stream_dst_{tag}")
        clean_dir(source)
        clean_dir(dest)
        data = _payload(FILE_SIZE)
        _write(os.path.join(source, "big.bin"), data, OLD_MTIME)
        if "--inplace" in flags:
            # --inplace only matters when the destination already exists.
            _write(_resolved(dest, source, "big.bin"), b"stale", OLD_MTIME)

        result, _ = run_client(source, dest, flags=flags, port=small_bound_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]

        got = os.path.join(get_dest_received_dir(dest, source), "big.bin")
        assert os.path.exists(got), "streamed file was not written"
        with open(got, "rb") as fh:
            assert fh.read() == data, "streamed file content mismatch"
        assert _no_spool_leftovers(dest) == [], "a spool temp file leaked"


class TestStreamedBasis:
    """A basis above the bound is streamed, not refused (compare/copy/link)."""

    def _seed(self, dest, source, data):
        clean_dir(source)
        clean_dir(dest)
        _write(os.path.join(source, "big.bin"), data, OLD_MTIME)
        # FastSync resolves a relative basis DIR against the destination and
        # appends the transfer-relative name.
        _write(os.path.join(dest, "basis", "big.bin"), data, OLD_MTIME)

    def test_compare_dest_above_bound(self, small_bound_server):
        source = os.path.join(TEST_DATA_DIR, "sbasis_cmp_src")
        dest = os.path.join(TEST_DATA_DIR, "sbasis_cmp_dst")
        data = _payload(FILE_SIZE)
        self._seed(dest, source, data)
        result, _ = run_client(source, dest,
                               flags=["-a", "--compare-dest=basis", "--incremental"],
                               port=small_bound_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]
        # compare-dest never copies: an already-present destination stays sparse.
        assert not os.path.exists(_resolved(dest, source, "big.bin"))

    def test_copy_dest_above_bound(self, small_bound_server):
        source = os.path.join(TEST_DATA_DIR, "sbasis_cpy_src")
        dest = os.path.join(TEST_DATA_DIR, "sbasis_cpy_dst")
        data = _payload(FILE_SIZE)
        self._seed(dest, source, data)
        result, _ = run_client(source, dest,
                               flags=["-a", "--copy-dest=basis", "--incremental"],
                               port=small_bound_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]
        got = _resolved(dest, source, "big.bin")
        assert os.path.exists(got)
        with open(got, "rb") as fh:
            assert fh.read() == data
        assert os.stat(got).st_ino != os.stat(os.path.join(dest, "basis", "big.bin")).st_ino
        assert _no_spool_leftovers(dest) == []

    def test_link_dest_above_bound(self, small_bound_server):
        source = os.path.join(TEST_DATA_DIR, "sbasis_lnk_src")
        dest = os.path.join(TEST_DATA_DIR, "sbasis_lnk_dst")
        data = _payload(FILE_SIZE)
        self._seed(dest, source, data)
        result, _ = run_client(source, dest,
                               flags=["-a", "--link-dest=basis", "--incremental"],
                               port=small_bound_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]
        got = _resolved(dest, source, "big.bin")
        assert os.path.exists(got)
        with open(got, "rb") as fh:
            assert fh.read() == data
        assert os.stat(got).st_ino == os.stat(os.path.join(dest, "basis", "big.bin")).st_ino


class TestFuzzyAboveBound:
    """-y/--fuzzy reuses a basis above the bound by streaming its signature."""

    def test_fuzzy_oversized_sibling(self, small_bound_server):
        source = os.path.join(TEST_DATA_DIR, "sfuzzy_src")
        dest = os.path.join(TEST_DATA_DIR, "sfuzzy_dst")
        clean_dir(source)
        clean_dir(dest)
        base = _payload(FILE_SIZE)
        sibling = bytearray(base)
        sibling[FILE_SIZE // 2:FILE_SIZE // 2 + 4096] = bytes(
            (b + 1) % 256 for b in sibling[FILE_SIZE // 2:FILE_SIZE // 2 + 4096])
        _write(os.path.join(source, "report_v2.txt"), base)
        _write(os.path.join(get_dest_received_dir(dest, source), "report_v1.txt"), bytes(sibling))
        result, _ = run_client(
            source, dest,
            flags=["-a", "--incremental", "--delta", "--fuzzy", "--stats"],
            port=small_bound_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]
        got = _resolved(dest, source, "report_v2.txt")
        with open(got, "rb") as fh:
            assert fh.read() == base, "fuzzy reconstruction mismatch"
        assert _no_spool_leftovers(dest) == []


class TestRealLargeFile:
    """A real >256 MiB transfer, run only in the full (non-PR-gate) suite."""

    def test_real_300mib_transfer(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "real_large_src")
        dest = os.path.join(TEST_DATA_DIR, "real_large_dst")
        clean_dir(source)
        clean_dir(dest)
        n = 300 * 1024 * 1024
        # Deterministic, compressible pattern written in bounded chunks.
        chunk = bytes(range(256)) * 4096
        digest = hashlib.sha256()
        with open(os.path.join(source, "big.bin"), "wb") as fh:
            written = 0
            while written < n:
                piece = chunk[: min(len(chunk), n - written)]
                fh.write(piece)
                digest.update(piece)
                written += len(piece)

        result, _ = run_client(source, dest, flags=["-a", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]
        got = os.path.join(get_dest_received_dir(dest, source), "big.bin")
        assert os.path.getsize(got) == n
        got_digest = hashlib.sha256()
        with open(got, "rb") as fh:
            while True:
                block = fh.read(1 << 20)
                if not block:
                    break
                got_digest.update(block)
        assert got_digest.hexdigest() == digest.hexdigest()
        shutil.rmtree(source, ignore_errors=True)
        shutil.rmtree(dest, ignore_errors=True)
