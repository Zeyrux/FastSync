"""Differential coverage for ``--delete-delay`` + ``--max-delete`` with a
refilled deferred directory.

FastSync snapshots a directory's extras at plan time (``defer_add``) but charges
``--max-delete`` only when a path is actually removed, and its deferred commit
re-scans a queued directory and removes content created after the plan -- the
same rules as rsync.  These tests run both tools on the same fixture and assert
both sides remove the late content (recursively) and bound the deletion with
``--max-delete`` identically.

They are not part of the fast PR gate because the rsync side needs a wide
real-time injection window (a throttled transfer), while the FastSync side uses
the existing byte-deterministic slicing proxy.

The refilled directory sits at the transfer ROOT, whose delete plan is always
processed before any subdirectory's, so the budget is deterministically charged
to the refilled entry; the second extra lives under ``b`` and is skipped.
"""
import os
import shutil
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    TEST_DATA_DIR,
    ServerManager,
    clean_dir,
    get_dest_received_dir,
    run_client,
)
from test_delete_timing_parity import _SlicingProxy  # noqa: E402

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")

BIG_BYTES = 8 * 1024 * 1024
MID_TRANSFER_BYTES = 256 * 1024
PROXY_THROTTLE = 0.001
# rsync is driven locally, so the refill is injected on a wall-clock delay while
# a throttled ~8 s transfer is in flight.  1.5 s is safely after rsync's plan
# scan (t=0) and well before the deferred commit at the end.
RSYNC_BWLIMIT = 1024  # 1 MiB/s
RSYNC_INJECT_DELAY = 1.5


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)


def _seed_source(tag):
    source = os.path.join(TEST_DATA_DIR, f"ddb_{tag}_src")
    clean_dir(source)
    _write(os.path.join(source, "a", "keep.bin"), b"B" * BIG_BYTES)
    _write(os.path.join(source, "b", "keep.txt"), b"keep\n")
    return source


def _seed_fastsync(tag):
    """FastSync mirrors the absolute source path under its receive root, so the
    extras live below ``received``."""
    source = _seed_source(tag)
    dest = os.path.join(TEST_DATA_DIR, f"ddb_{tag}_dst")
    clean_dir(dest)
    received = get_dest_received_dir(dest, source)
    os.makedirs(os.path.join(received, "xdir"), exist_ok=True)
    os.makedirs(os.path.join(received, "b", "ydir"), exist_ok=True)
    return source, dest, received


def _seed_rsync(tag):
    """rsync mirrors the source contents directly into the destination, so the
    extras are flat under ``rsync_dst``."""
    source = _seed_source(tag)
    rsync_dst = os.path.join(TEST_DATA_DIR, f"ddb_{tag}_dst")
    clean_dir(rsync_dst)
    os.makedirs(os.path.join(rsync_dst, "xdir"), exist_ok=True)
    os.makedirs(os.path.join(rsync_dst, "b", "ydir"), exist_ok=True)
    return source, rsync_dst


def _deleted_count(text):
    for line in text.splitlines():
        if line.startswith("Number of deleted files:"):
            return int(line.split(":", 1)[1].split()[0])
    return None


def _rsync(args, timeout=120):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([RSYNC] + args, capture_output=True, text=True, env=env, timeout=timeout)


class TestDeleteDelayRefilledDirVsRsync:
    """Both tools charge --max-delete on actual removals and recurse."""

    def _fastsync_refilled(self, tag, max_delete=None):
        """Run FastSync with the refill injected deterministically by the proxy
        hook (fired once the receiver has processed the plan frames)."""
        source, dest, received = _seed_fastsync(tag)
        late = os.path.join(received, "xdir", "new.txt")

        def hook():
            _write(late, b"created mid-transfer\n")

        flags = ["--delete-delay", "--incremental", "--ignore-times", "--stats"]
        if max_delete is not None:
            flags.append(f"--max-delete={max_delete}")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            proxy = _SlicingProxy(server.port, hook=hook, hook_after=MID_TRANSFER_BYTES,
                                  throttle=PROXY_THROTTLE, wait_for_reply=True)
            result, _ = run_client(source, dest, flags=flags, port=proxy.port)
            proxy.finish()
        assert proxy.hook_called.is_set(), "refill hook never fired"
        return result, received, late

    @requires_rsync
    def test_max_delete_budget_bound_matches(self):
        # --- FastSync: the one actual removal is the late file; dirs survive ---
        result, received, late = self._fastsync_refilled("budget_fs", max_delete=1)
        assert result.returncode == 25, (result.stderr or result.stdout)[:300]
        assert _deleted_count(result.stdout) == 1, result.stdout
        assert not os.path.exists(late), "FastSync kept the late content of a queued dir"
        assert os.path.isdir(os.path.join(received, "xdir"))
        assert os.path.isdir(os.path.join(received, "b", "ydir")), (
            "FastSync did not bound the deletion with --max-delete=1"
        )

        # --- rsync: same budget rule and recursive removal ---
        source, rsync_dst = _seed_rsync("budget_rsync")

        def inject():
            time.sleep(RSYNC_INJECT_DELAY)
            _write(os.path.join(rsync_dst, "xdir", "new.txt"), b"created mid-transfer\n")

        t = threading.Thread(target=inject)
        t.start()
        rsync_result = _rsync(
            ["-a", "--delete-delay", "--max-delete=1", "--stats",
             f"--bwlimit={RSYNC_BWLIMIT}", source + "/", rsync_dst + "/"]
        )
        t.join()
        assert rsync_result.returncode == 25, rsync_result.stderr
        assert _deleted_count(rsync_result.stdout) == _deleted_count(result.stdout)
        assert not os.path.exists(os.path.join(rsync_dst, "xdir", "new.txt")), (
            "rsync kept late content inside a queued directory"
        )
        assert os.path.isdir(os.path.join(rsync_dst, "b", "ydir")), (
            "rsync did not bound the deletion with --max-delete=1"
        )
        assert os.path.isdir(os.path.join(received, "b", "ydir"))

    @requires_rsync
    def test_refilled_extra_dir_recursive_removal_matches(self):
        """Without --max-delete both tools remove the refilled extra directory
        (and its late content)."""
        result, received, late = self._fastsync_refilled("recur_fs")
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        assert not os.path.exists(late), "FastSync kept the refilled directory's late content"
        assert not os.path.isdir(os.path.join(received, "xdir"))

        source, rsync_dst = _seed_rsync("recur_rsync")

        def inject():
            time.sleep(RSYNC_INJECT_DELAY)
            _write(os.path.join(rsync_dst, "xdir", "new.txt"), b"created mid-transfer\n")

        t = threading.Thread(target=inject)
        t.start()
        rsync_result = _rsync(
            ["-a", "--delete-delay", "--stats", f"--bwlimit={RSYNC_BWLIMIT}",
             source + "/", rsync_dst + "/"]
        )
        t.join()
        assert rsync_result.returncode == 0, rsync_result.stderr
        assert not os.path.exists(os.path.join(rsync_dst, "xdir")), (
            "rsync did not recursively remove the refilled extra directory"
        )
