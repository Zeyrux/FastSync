"""Differential coverage for the delete-timing ABORT BOUNDARY (A9/A10).

rsync's generator runs ahead of its throttled sender, so on a mid-transfer abort
it has already removed every extra it planned.  FastSync now transmits the
COMPLETE per-directory plan set before the first data frame, so an abort has the
same effect.  Before that change FastSync only removed the extras of the
directories its (slower) data stream had reached, and ``-d/--dirs`` used an
end-of-transfer commit that removed nothing on abort.

These tests abort both tools mid-transfer and assert the destination extras
removed match real ``rsync 3.4.1``.  The rsync side is driven locally with
``--bwlimit`` and a small timing window (its generator's delete list is computed
long before the throttled payload finishes); the FastSync side uses the
byte-deterministic slicing proxy from ``test_delete_timing_parity``.
"""
import os
import shutil
import subprocess
import sys
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

# Exceeds the 10 MiB scanner chunk, so the next directory lands in a later chunk
# (still unreached when the proxy cuts the stream).
BIG_BYTES = 16 * 1024 * 1024
# Cut well past the (small) config + delete-plan frames and into the big payload,
# so the receiver has provably processed every plan before the abort.
MID_TRANSFER_BYTES = 256 * 1024
PROXY_THROTTLE = 0.001
# Throttle rsync's sender so the generator has deleted long before the payload
# finishes, then interrupt it mid-transfer.
RSYNC_BWLIMIT = 512  # KiB/s -> ~32 s for 16 MiB
RSYNC_ABORT_DELAY = 1.5


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)


def _rsync_aborted(args, delay=RSYNC_ABORT_DELAY):
    """Start rsync, let its generator run, then interrupt it mid-transfer."""
    env = dict(os.environ, LC_ALL="C")
    proc = subprocess.Popen([RSYNC] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env)
    time.sleep(delay)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    return proc


class TestDeleteDuringAbortBoundary:
    """A9: on an abort, every planned removal has already been applied."""

    def _seed_recursive(self, tag):
        source = os.path.join(TEST_DATA_DIR, f"dab_{tag}_src")
        clean_dir(source)
        # ``a/keep.bin`` sorts first, so the client streams it (and the proxy
        # cuts) before the data pass ever reaches ``z/deep``.
        _write(os.path.join(source, "a", "keep.bin"), b"B" * BIG_BYTES)
        _write(os.path.join(source, "z", "deep", "keep.txt"), b"keep\n")
        return source

    @requires_rsync
    def test_recursive_abort_removes_all_planned_extras(self):
        # ---- FastSync: abort mid ``a/keep.bin``; ``z/deep`` is never reached.
        source = self._seed_recursive("rec_fs")
        dest = os.path.join(TEST_DATA_DIR, "dab_rec_fs_dst")
        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        os.makedirs(os.path.join(received, "a"), exist_ok=True)
        _write(os.path.join(received, "a", "a_extra"), b"stale\n")
        os.makedirs(os.path.join(received, "z", "deep"), exist_ok=True)
        _write(os.path.join(received, "z", "deep", "old_extra"), b"stale\n")

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            proxy = _SlicingProxy(server.port, forward_limit=MID_TRANSFER_BYTES,
                                  throttle=PROXY_THROTTLE)
            result, _ = run_client(source, dest, flags=["--delete-during"], port=proxy.port)
            proxy.finish()
        assert result.returncode != 0, "truncated transfer reported success"
        assert not os.path.exists(os.path.join(received, "a", "a_extra"))
        assert not os.path.exists(os.path.join(received, "z", "deep", "old_extra")), (
            "FastSync left an extra in a directory it never reached before the abort"
        )

        # ---- rsync 3.4.1: same tree, same abort, same delete outcome.
        source = self._seed_recursive("rec_rs")
        rsync_dst = os.path.join(TEST_DATA_DIR, "dab_rec_rs_dst")
        clean_dir(rsync_dst)
        os.makedirs(os.path.join(rsync_dst, "a"), exist_ok=True)
        _write(os.path.join(rsync_dst, "a", "a_extra"), b"stale\n")
        os.makedirs(os.path.join(rsync_dst, "z", "deep"), exist_ok=True)
        _write(os.path.join(rsync_dst, "z", "deep", "old_extra"), b"stale\n")

        proc = _rsync_aborted(["-a", "--delete-during", f"--bwlimit={RSYNC_BWLIMIT}",
                               source + "/", rsync_dst + "/"])
        assert proc.returncode != 0, "rsync was not actually interrupted"
        assert not os.path.exists(os.path.join(rsync_dst, "a", "a_extra"))
        assert not os.path.exists(os.path.join(rsync_dst, "z", "deep", "old_extra")), (
            "rsync's generator did not delete ahead of its sender"
        )


class TestDirsDeleteAbortBoundary:
    """A10: ``-d/--dirs`` uses per-directory plans like rsync.

    The listed directory's direct extras are removed by the up-front plan while
    a kept but untraversed subdirectory (and its destination content) is
    shielded.
    """

    def _seed_dirs(self, tag):
        source = os.path.join(TEST_DATA_DIR, f"ddb_{tag}_src")
        clean_dir(source)
        _write(os.path.join(source, "big.bin"), b"B" * BIG_BYTES)
        _write(os.path.join(source, "subdir", "keep.txt"), b"inner\n")
        return source

    @pytest.mark.parametrize("fs_flag,rs_flag", [("--delete-during", "--delete-during"),
                                                 ("--delete", "--delete")])
    @requires_rsync
    def test_dirs_abort_removes_direct_extras_only(self, fs_flag, rs_flag):
        label = f"{fs_flag.lstrip('-')}_{rs_flag.lstrip('-')}"
        # ---- FastSync: ``-d`` lists the immediate children; big.bin streams and
        # the abort lands mid-payload.
        source = self._seed_dirs(f"dirs_{label}_fs")
        dest = os.path.join(TEST_DATA_DIR, f"ddb_{label}_fs_dst")
        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        _write(os.path.join(received, "old_extra"), b"stale\n")
        os.makedirs(os.path.join(received, "subdir"), exist_ok=True)
        _write(os.path.join(received, "subdir", "stale.txt"), b"stale inner\n")

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            proxy = _SlicingProxy(server.port, forward_limit=MID_TRANSFER_BYTES,
                                  throttle=PROXY_THROTTLE)
            result, _ = run_client(source + "/", dest, flags=["-d", fs_flag], port=proxy.port)
            proxy.finish()
        assert result.returncode != 0, f"{fs_flag}: truncated transfer reported success"
        assert not os.path.exists(os.path.join(received, "old_extra")), (
            f"{fs_flag}: the listed directory's direct extra survived the abort"
        )
        assert os.path.exists(os.path.join(received, "subdir", "stale.txt")), (
            f"{fs_flag}: descended into a kept, untraversed subdirectory"
        )

        # ---- rsync 3.4.1: same shape and same abort.
        source = self._seed_dirs(f"dirs_{label}_rs")
        rsync_dst = os.path.join(TEST_DATA_DIR, f"ddb_{label}_rs_dst")
        clean_dir(rsync_dst)
        _write(os.path.join(rsync_dst, "old_extra"), b"stale\n")
        os.makedirs(os.path.join(rsync_dst, "subdir"), exist_ok=True)
        _write(os.path.join(rsync_dst, "subdir", "stale.txt"), b"stale inner\n")

        proc = _rsync_aborted(["-d", rs_flag, f"--bwlimit={RSYNC_BWLIMIT}",
                               source + "/", rsync_dst + "/"])
        assert proc.returncode != 0, "rsync was not actually interrupted"
        assert not os.path.exists(os.path.join(rsync_dst, "old_extra")), (
            f"rsync {rs_flag}: the listed directory's direct extra survived the abort"
        )
        assert os.path.exists(os.path.join(rsync_dst, "subdir", "stale.txt")), (
            f"rsync {rs_flag}: descended into a kept, untraversed subdirectory"
        )


def _tree(root):
    out = []
    for dirpath, dirs, files in os.walk(root):
        for name in dirs:
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
        for name in files:
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
    return sorted(out)


class TestDirsDeleteFinalStateParity:
    """A10 completed run: ``-d DIR/ --delete`` (during default) and
    ``--delete-during`` match rsync's final tree, including a kept but
    untraversed subdirectory whose destination content survives."""

    @pytest.mark.parametrize("flag", ["--delete", "--delete-during"])
    @requires_rsync
    def test_dirs_final_state_matches_rsync(self, flag):
        source = os.path.join(TEST_DATA_DIR, f"ddf_{flag.lstrip('-')}_src")
        clean_dir(source)
        _write(os.path.join(source, "keep.txt"), b"new keep\n")
        _write(os.path.join(source, "subdir", "inner.txt"), b"inner\n")

        def seed_dest(root):
            clean_dir(root)
            _write(os.path.join(root, "keep.txt"), b"old keep\n")
            _write(os.path.join(root, "extra.txt"), b"extra\n")
            _write(os.path.join(root, "extrasub", "ex.txt"), b"extra sub\n")
            _write(os.path.join(root, "subdir", "stale.txt"), b"stale inner\n")

        rsync_dst = os.path.join(TEST_DATA_DIR, f"ddf_{flag.lstrip('-')}_rs_dst")
        seed_dest(rsync_dst)
        env = dict(os.environ, LC_ALL="C")
        rsync_result = subprocess.run(
            [RSYNC, "-d", flag, source + "/", rsync_dst + "/"],
            capture_output=True, text=True, env=env, timeout=120)
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_tree = _tree(rsync_dst)

        dest = os.path.join(TEST_DATA_DIR, f"ddf_{flag.lstrip('-')}_fs_dst")
        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        seed_dest(received)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source + "/", dest, flags=["-d", flag], port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        fastsync_tree = _tree(received)
        assert fastsync_tree == rsync_tree, (
            f"-d {flag}: fastsync tree {fastsync_tree} != rsync tree {rsync_tree}")


class TestOneFileSystemDeleteParity:
    """A9 side effect: the per-directory plan is now emitted only for directories
    whose children were enumerated, so a ``-x`` mount-point directory that is
    emitted but never traversed is shielded -- its destination content survives,
    exactly as rsync keeps a non-descended mount point under ``--delete``."""

    @requires_rsync
    def test_mountpoint_content_survives_delete(self):
        local = os.stat(".")
        shm = "/dev/shm"
        if not os.path.isdir(shm) or os.stat(shm).st_dev == local.st_dev:
            pytest.skip("no cross-device filesystem available")
        probe = os.path.join(shm, f"fastsync_dofs_{os.getpid()}")
        clean_dir(probe)
        _write(os.path.join(probe, "inside.txt"), b"cross\n")
        try:
            source = os.path.join(TEST_DATA_DIR, "dofs_src")
            clean_dir(source)
            _write(os.path.join(source, "keep.txt"), b"keep\n")
            os.symlink(probe, os.path.join(source, "nested_link"))

            def seed_dest(root):
                clean_dir(root)
                _write(os.path.join(root, "keep.txt"), b"old\n")
                _write(os.path.join(root, "nested_link", "stale.txt"), b"stale\n")

            rsync_dst = os.path.join(TEST_DATA_DIR, "dofs_rs_dst")
            seed_dest(rsync_dst)
            env = dict(os.environ, LC_ALL="C")
            rsync_result = subprocess.run(
                [RSYNC, "-a", "--copy-links", "-x", "--delete-during",
                 source + "/", rsync_dst + "/"],
                capture_output=True, text=True, env=env, timeout=120)
            assert rsync_result.returncode == 0, rsync_result.stderr
            assert os.path.exists(os.path.join(rsync_dst, "nested_link", "stale.txt")), (
                "rsync unexpectedly descended into the mount point")

            dest = os.path.join(TEST_DATA_DIR, "dofs_fs_dst")
            clean_dir(dest)
            received = get_dest_received_dir(dest, source)
            seed_dest(received)
            with ServerManager() as server:
                server.start(extra_args=["--allow-delete"])
                result, _ = run_client(source, dest,
                                       flags=["-a", "--copy-links", "-x", "--delete-during"],
                                       port=server.port)
            assert result.returncode == 0, (result.stderr or result.stdout)[:300]
            assert os.path.exists(os.path.join(received, "nested_link", "stale.txt")), (
                "FastSync descended into a non-traversed mount point under --delete")
        finally:
            clean_dir(probe)

