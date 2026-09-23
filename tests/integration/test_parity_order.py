"""Differential rsync-parity coverage for FastSync's transfer/delete ORDER.

rsync walks a source tree in its sorted flist order: within each directory the
non-directories come first (ascending name), then the subdirectories (ascending
name), each subdirectory immediately followed by its own subtree (depth-first).
The sequential scanner now reproduces that order, which makes both the
``--info=name`` stream and the ``--delete-during`` deletion sequence match real
``rsync 3.4.1`` exactly.  ``--threads`` has no rsync analogue and is unordered.

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
    ServerManager,
    clean_dir,
    get_dest_received_dir,
    run_client,
)

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")

MTIME = 1_500_000_000

_TREE = {
    "a.txt": b"a\n",
    "b.txt": b"b\n",
    "z.txt": b"z\n",
    "a_dir/f.txt": b"f\n",
    "a_dir/deep/g.txt": b"g\n",
    "m_dir/h.txt": b"h\n",
    "Z_dir/i.txt": b"i\n",
}


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    os.utime(path, (MTIME, MTIME))


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([RSYNC] + args, capture_output=True, text=True, env=env, timeout=120)


def _deleting(text):
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("*deleting") or stripped.startswith("deleting"):
            out.append(stripped.split()[-1])
    return out


class TestTransferOrderParity:
    @requires_rsync
    def test_info_name_file_order_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "order_name_src")
        clean_dir(source)
        for rel, data in _TREE.items():
            _write(os.path.join(source, rel), data)

        rdst = os.path.join(TEST_DATA_DIR, "order_name_rdst")
        clean_dir(rdst)
        rs = _rsync(["-a", "--info=name", source + "/", rdst + "/"])
        assert rs.returncode == 0, rs.stderr
        # rsync also names the directories (trailing '/'); FastSync names the
        # transferred entries.  Compare the file/symlink sequence, which is what
        # the traversal order determines.
        rsync_files = [l for l in rs.stdout.splitlines() if l.strip() and not l.endswith("/")]

        fdst = os.path.join(TEST_DATA_DIR, "order_name_fdst")
        clean_dir(fdst)
        result, _ = run_client(source, fdst, flags=["-a", "--info=name"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        fsync_files = [
            l for l in result.stdout.splitlines()
            if l.strip() and l.strip() != "./" and not l.startswith("sending")
        ]
        assert fsync_files == rsync_files, (
            f"transfer order differs\nrsync={rsync_files}\nfastsync={fsync_files}")


class TestDeleteOrderParity:
    _EXTRA = {
        "a_extra.txt": b"a\n",
        "z_extra.txt": b"z\n",
        "a_extra_dir/f": b"f\n",
        "z_extra_dir/f": b"f\n",
        "a_extra_dir/sub/g": b"g\n",
    }

    def _seed_source(self):
        source = os.path.join(TEST_DATA_DIR, "order_del_src")
        clean_dir(source)
        _write(os.path.join(source, "keep.txt"), b"k\n")
        _write(os.path.join(source, "keepdir", "x.txt"), b"x\n")
        _write(os.path.join(source, "keep2", "y.txt"), b"y\n")
        return source

    def _assert_order(self, timing, dry_run=False):
        source = self._seed_source()
        rdst = os.path.join(TEST_DATA_DIR, f"order_{timing}_rdst")
        clean_dir(rdst)
        for rel, data in self._EXTRA.items():
            _write(os.path.join(rdst, rel), data)
        rs_flags = ["-a", "-n"] if dry_run else ["-a"]
        rs = _rsync(rs_flags + [timing, "--info=del", source + "/", rdst + "/"])
        assert rs.returncode == 0, rs.stderr

        fdst = os.path.join(TEST_DATA_DIR, f"order_{timing}_fdst")
        clean_dir(fdst)
        received = get_dest_received_dir(fdst, source)
        for rel, data in self._EXTRA.items():
            _write(os.path.join(received, rel), data)
        fs_flags = ["-a", "-n"] if dry_run else ["-a"]
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, fdst, flags=fs_flags + [timing, "--info=del"],
                                   port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]

        rsync_order = _deleting(rs.stdout)
        fsync_order = _deleting(result.stdout)
        assert sorted(fsync_order) == sorted(rsync_order), (
            f"{timing} deleted set differs\nrsync={rsync_order}\nfastsync={fsync_order}")
        assert fsync_order == rsync_order, (
            f"{timing} deletion order differs\nrsync={rsync_order}\nfastsync={fsync_order}")

    @requires_rsync
    def test_delete_during_deletion_order_matches_rsync(self):
        self._assert_order("--delete-during")

    @requires_rsync
    def test_delete_delay_deletion_order_matches_rsync(self):
        self._assert_order("--delete-delay")

    @requires_rsync
    def test_dry_run_delete_order_matches_rsync(self):
        self._assert_order("--delete", dry_run=True)

    @requires_rsync
    def test_partial_max_delete_survivor_order_matches_rsync(self):
        """With the exact removal order matching rsync, a --max-delete cap stops
        after the same entries, so the survivor set is identical too."""
        source = os.path.join(TEST_DATA_DIR, "order_maxdel_src")
        clean_dir(source)
        _write(os.path.join(source, "keep.txt"), b"k\n")
        extra = {f"e{i}.txt": b"x\n" for i in range(6)}
        extra["ed/f"] = b"f\n"
        extra["ed/g"] = b"g\n"

        rdst = os.path.join(TEST_DATA_DIR, "order_maxdel_rdst")
        clean_dir(rdst)
        for rel, data in extra.items():
            _write(os.path.join(rdst, rel), data)
        rs = _rsync(["-a", "--delete-during", "--max-delete=3", "--info=del",
                     source + "/", rdst + "/"])
        assert rs.returncode in (0, 25), (rs.returncode, rs.stderr)

        fdst = os.path.join(TEST_DATA_DIR, "order_maxdel_fdst")
        clean_dir(fdst)
        received = get_dest_received_dir(fdst, source)
        for rel, data in extra.items():
            _write(os.path.join(received, rel), data)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, fdst,
                                   flags=["-a", "--delete-during", "--max-delete=3", "--info=del"],
                                   port=server.port)
        assert result.returncode in (0, 25), (result.returncode, result.stderr[:300])
        assert _deleting(result.stdout) == _deleting(rs.stdout), (
            f"partial --max-delete survivor order differs\n"
            f"rsync={_deleting(rs.stdout)}\nfastsync={_deleting(result.stdout)}")
