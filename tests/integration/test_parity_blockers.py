"""Differential/regression coverage for the parity-completion review blockers.

Each test pins a fix against real ``rsync 3.4.1`` where a deterministic
comparison exists; the differential tests skip cleanly when rsync is absent.
"""
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    TEST_DATA_DIR,
    ServerManager,
    clean_dir,
    get_dest_received_dir,
    run_client,
)

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)


def _tree(root):
    """Sorted relative paths of every entry below root (files and dirs)."""
    out = []
    for dirpath, dirs, files in os.walk(root):
        for name in dirs:
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
        for name in files:
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
    return sorted(out)


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([RSYNC] + args, capture_output=True, text=True, env=env, timeout=120)


class TestRelativePerDirDeleteScope:
    """Blocker #1: -R --delete-during/--delete-delay must not delete destination
    content outside the transferred prefix (rsync keeps sibling directories)."""

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("timing", ["--delete-during", "--delete-delay"])
    def test_prefix_scoped_delete_matches_rsync(self, timing):
        source = os.path.join(TEST_DATA_DIR, "delblk_src")
        clean_dir(source)
        _write(os.path.join(source, "foo", "a.txt"), b"payload\n")
        spec = source + "/./foo"

        def seed(root):
            clean_dir(root)
            _write(os.path.join(root, "foo", "extra.txt"), b"stale\n")
            _write(os.path.join(root, "unrelated", "keep.txt"), b"keep\n")

        rdst = os.path.join(TEST_DATA_DIR, "delblk_rdst")
        dest = os.path.join(TEST_DATA_DIR, "delblk_dst")
        seed(rdst)
        seed(dest)
        r = _rsync(["-aR", timing, spec, rdst + "/"])
        assert r.returncode == 0, r.stderr
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(spec, dest, flags=["-a", "-R", timing], port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        # The prefix's parent-directory sibling survives on both sides.
        assert os.path.isfile(os.path.join(dest, "unrelated", "keep.txt"))
        assert os.path.isfile(os.path.join(rdst, "unrelated", "keep.txt"))
        # The in-scope extra is removed on both sides.
        assert not os.path.exists(os.path.join(dest, "foo", "extra.txt"))
        assert not os.path.exists(os.path.join(rdst, "foo", "extra.txt"))
        assert _tree(dest) == _tree(rdst)
