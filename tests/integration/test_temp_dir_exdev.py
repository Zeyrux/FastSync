"""End-to-end coverage for the `--temp-dir` EXDEV (cross-filesystem) fallback.

`file_to_disk_secure_impl` installs a completed temp file with `renameat(2)`;
when the scratch dir lives on a different filesystem the rename fails with
`EXDEV` and the engine retries with no scratch dir, writing the file directly in
the destination directory (a non-atomic copy), matching rsync.

The daemon receiver confines `--temp-dir` to the authorized receive root, so a
genuine cross-fs scratch there would require an in-root mount point.  Bind/tmpfs
mounting is not permitted in the CI container (no `CAP_SYS_ADMIN`, and
unprivileged user namespaces are disabled), so this test reaches the exact same
code path through the local `--read-batch` apply instead: it has no
authorized-root confinement, so a relative `--temp-dir` that is a symlink to a
tmpfs (`/dev/shm`) is accepted and the final install then crosses filesystems.
"""
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import CLIENT_CMD, get_dest_received_dir

TMPFS = "/dev/shm"


def _run(args):
    return subprocess.run(CLIENT_CMD + args, capture_output=True, text=True, timeout=180)


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def test_read_batch_temp_dir_cross_filesystem_fallback(tmp_path):
    if not os.path.isdir(TMPFS):
        pytest.skip("no /dev/shm tmpfs available to force a cross-filesystem install")

    source = tmp_path / "src"
    dest = tmp_path / "dst"
    source.mkdir()
    dest.mkdir()
    files = {
        "payload.bin": bytes(range(256)) * 64,
        "sub/nested.txt": b"nested exdev fallback\n" * 8,
    }
    for rel, data in files.items():
        full = source / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(data)

    batch = tmp_path / "tree.batch"
    r = _run(["--only-write-batch", str(batch), str(source)])
    assert r.returncode == 0, (r.stdout, r.stderr)

    # A cross-filesystem scratch dir, reached through a relative --temp-dir
    # symlink (the local batch apply performs no authorized-root confinement).
    scratch = os.path.join(TMPFS, "fastsync_exdev_%d" % os.getpid())
    shutil.rmtree(scratch, ignore_errors=True)
    os.makedirs(scratch)
    os.symlink(scratch, dest / "scratch")
    try:
        assert os.stat(scratch).st_dev != os.stat(dest).st_dev, (
            "scratch and destination share a filesystem; EXDEV cannot be exercised"
        )
        r = _run(["--read-batch", str(batch), str(dest), "--temp-dir=scratch"])
        assert r.returncode == 0, (r.stdout, r.stderr)
        # The engine must report the non-atomic cross-fs fallback rather than
        # silently claiming an atomic install.
        assert "different filesystem" in (r.stdout + r.stderr), (r.stdout, r.stderr)
        # The tree is still byte-exact and the scratch dir is left clean.
        received = get_dest_received_dir(str(dest), str(source))
        for rel, data in files.items():
            assert _read(os.path.join(received, rel)) == data, f"content mismatch for {rel}"
        assert os.listdir(scratch) == [], "cross-fs temp file was not cleaned up"
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
