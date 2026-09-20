"""Differential parity for `--info=mount` and `--info=stats` (no-wire).

Both behaviours are compared against real rsync 3.4.1:

* `--info=mount` prints rsync's ``[sender] skipping mount-point dir NAME`` line
  when ``-xx`` drops a mount-point directory.  Plain ``-x`` keeps the empty
  directory and stays silent, exactly like rsync.
* `--info=stats` requests the same transfer-statistics block as `--stats`
  (rsync spells the full block ``--info=stats2``/``--stats``).

The tests are skipped when rsync is unavailable.
"""
import os
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import TEST_DATA_DIR, run_client, clean_dir, get_dest_received_dir

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([RSYNC] + args, capture_output=True, text=True, env=env, timeout=120)


def _cross_device_mount_tree(source):
    """Build a source whose ``nested_link`` is a symlink onto a tmpfs directory.

    ``--copy-links`` dereferences it so ``-x`` sees a mount-point directory on a
    different device.  Returns the probe path to remove, or skips the test when
    no cross-device filesystem is available.
    """
    local = os.stat(".")
    shm = "/dev/shm"
    try:
        shm_stat = os.stat(shm)
    except OSError:
        pytest.skip("/dev/shm not available")
    if shm_stat.st_dev == local.st_dev:
        pytest.skip("no cross-device filesystem available")

    clean_dir(source)
    with open(os.path.join(source, "keep.txt"), "wb") as fh:
        fh.write(b"keep\n")
    probe = os.path.join(shm, f"fastsync_info_mount_{os.getpid()}")
    shutil.rmtree(probe, ignore_errors=True)
    os.makedirs(probe)
    with open(os.path.join(probe, "inside.txt"), "wb") as fh:
        fh.write(b"cross\n")
    try:
        os.symlink(probe, os.path.join(source, "nested_link"))
    except OSError:
        shutil.rmtree(probe, ignore_errors=True)
        pytest.skip("cannot create symlink")
    return probe


@requires_rsync
@pytest.mark.ci
def test_info_mount_xx_matches_rsync(shared_server):
    """`-xx --info=mount` drops the mount-point dir and prints rsync's line."""
    source = os.path.join(TEST_DATA_DIR, "info_mount_src")
    dest = os.path.join(TEST_DATA_DIR, "info_mount_dst")
    rdst = os.path.join(TEST_DATA_DIR, "info_mount_rdst")
    probe = _cross_device_mount_tree(source)
    clean_dir(dest)
    clean_dir(rdst)
    flags = ["-a", "--copy-links", "-xx", "--info=mount"]
    try:
        rsync_result = _rsync(flags + [source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]

        expected = "[sender] skipping mount-point dir nested_link"
        assert expected in rsync_result.stdout, rsync_result.stdout
        assert expected in result.stdout, (result.stdout, result.stderr)

        received = get_dest_received_dir(dest, source)
        assert os.path.exists(os.path.join(received, "keep.txt"))
        # -xx omits the mount-point directory entirely.
        assert not os.path.exists(os.path.join(received, "nested_link"))
        assert not os.path.exists(os.path.join(rdst, "nested_link"))
    finally:
        shutil.rmtree(probe, ignore_errors=True)


@requires_rsync
@pytest.mark.ci
def test_info_mount_single_x_is_silent(shared_server):
    """Plain `-x` keeps the empty mount-point directory and prints no line."""
    source = os.path.join(TEST_DATA_DIR, "info_mount1_src")
    dest = os.path.join(TEST_DATA_DIR, "info_mount1_dst")
    rdst = os.path.join(TEST_DATA_DIR, "info_mount1_rdst")
    probe = _cross_device_mount_tree(source)
    clean_dir(dest)
    clean_dir(rdst)
    flags = ["-a", "--copy-links", "-x", "--info=mount"]
    try:
        rsync_result = _rsync(flags + [source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]

        assert "skipping mount-point dir" not in rsync_result.stdout
        assert "skipping mount-point dir" not in result.stdout

        received = get_dest_received_dir(dest, source)
        assert os.path.isdir(os.path.join(received, "nested_link"))
        assert not os.path.exists(os.path.join(received, "nested_link", "inside.txt"))
        assert os.path.isdir(os.path.join(rdst, "nested_link"))
        assert not os.path.exists(os.path.join(rdst, "nested_link", "inside.txt"))
    finally:
        shutil.rmtree(probe, ignore_errors=True)


def _make_stats_tree(root):
    clean_dir(root)
    os.makedirs(os.path.join(root, "sub"))
    with open(os.path.join(root, "a.txt"), "wb") as fh:
        fh.write(b"alpha\n")
    with open(os.path.join(root, "sub", "b.txt"), "wb") as fh:
        fh.write(b"beta\n")


def _pick_stats(text):
    keys = ("Number of files", "Number of regular files transferred", "Total file size",
            "Total transferred file size", "Literal data", "Matched data")
    out = {}
    for line in text.splitlines():
        for key in keys:
            if line.startswith(key + ":"):
                out[key] = line
    return out


@requires_rsync
@pytest.mark.ci
def test_info_stats_emits_full_stats_block(shared_server):
    """`--info=stats` is the same full block as `--stats` and matches rsync."""
    source = os.path.join(TEST_DATA_DIR, "info_stats_src")
    dest = os.path.join(TEST_DATA_DIR, "info_stats_dst")
    rdst = os.path.join(TEST_DATA_DIR, "info_stats_rdst")
    dest2 = os.path.join(TEST_DATA_DIR, "info_stats_dst2")
    _make_stats_tree(source)
    for path in (dest, rdst, dest2):
        clean_dir(path)
        os.makedirs(get_dest_received_dir(path, source), exist_ok=True)

    rsync_result = _rsync(["-a", "--stats", source + "/", rdst + "/"])
    assert rsync_result.returncode == 0, rsync_result.stderr

    info_result, _ = run_client(source, dest, flags=["-a", "--info=stats"],
                                port=shared_server.port)
    assert info_result.returncode == 0, (info_result.stderr or info_result.stdout)[:300]
    stats_result, _ = run_client(source, dest2, flags=["-a", "--stats"],
                                 port=shared_server.port)
    assert stats_result.returncode == 0, (stats_result.stderr or stats_result.stdout)[:300]

    # --info=stats must print the same block as --stats...
    assert _pick_stats(info_result.stdout) == _pick_stats(stats_result.stdout), (
        f"info={info_result.stdout} stats={stats_result.stdout}")
    # ...and the protocol-independent counters must match real rsync.
    assert _pick_stats(info_result.stdout) == _pick_stats(rsync_result.stdout), (
        f"rsync={_pick_stats(rsync_result.stdout)} fastsync={_pick_stats(info_result.stdout)}")
    assert re.search(r"^Number of files: \d+ \(reg: 2, dir: 2\)$", info_result.stdout,
                     re.MULTILINE), info_result.stdout
