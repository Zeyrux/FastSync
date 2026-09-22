"""Parity coverage for an absolute ``--temp-dir`` that lies inside the receive root.

FastSync confines the ``--temp-dir`` scratch directory to the receive root.  It
previously rejected *every* absolute path; it now canonicalizes an absolute path
with ``realpath(3)`` and accepts it when it resolves inside the canonical receive
root (the destination is identical, so this is a pure parity win), while an
absolute path that escapes the root stays rejected with a clear error.

Two paths exercise the same receiver-side resolution:

* the local ``--read-batch`` apply (no network; the batch destination is the
  receive root), and
* a real TCP transfer against the shared server (the destination root is the
  client-supplied absolute path).

The out-of-root case asserts the run fails without writing a single scratch
file, so the confinement invariant is preserved.
"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import CLIENT_CMD, TEST_DATA_DIR, clean_dir, get_dest_received_dir, run_client

FILES = {
    "top.txt": b"top level\n",
    "sub/nested.txt": b"nested file\n" * 16,
}


def _run(args):
    return subprocess.run(CLIENT_CMD + args, capture_output=True, text=True, timeout=180)


def _seed_source(root):
    clean_dir(root)
    for rel, data in FILES.items():
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)


def _make_batch(tmp, source):
    batch = os.path.join(tmp, "tree.batch")
    result = _run(["--only-write-batch", batch, source])
    assert result.returncode == 0, (result.stdout, result.stderr)
    return batch


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


@pytest.mark.ci
def test_read_batch_absolute_temp_dir_inside_root_accepted(tmp_path):
    source = os.path.join(tmp_path, "src")
    dest = os.path.join(tmp_path, "dst")
    _seed_source(source)
    clean_dir(dest)
    scratch = os.path.join(dest, "scratch")
    os.makedirs(scratch)

    batch = _make_batch(str(tmp_path), source)
    result = _run(["--read-batch", batch, dest, "--temp-dir", scratch])
    assert result.returncode == 0, (result.stdout, result.stderr)

    received = get_dest_received_dir(dest, source)
    for rel, data in FILES.items():
        assert _read(os.path.join(received, rel)) == data, f"content mismatch for {rel}"
    assert os.listdir(scratch) == [], "scratch dir was not left clean"


@pytest.mark.ci
def test_read_batch_absolute_temp_dir_outside_root_rejected(tmp_path):
    source = os.path.join(tmp_path, "src")
    dest = os.path.join(tmp_path, "dst")
    _seed_source(source)
    clean_dir(dest)
    outside = os.path.join(tmp_path, "outside")
    os.makedirs(outside)

    batch = _make_batch(str(tmp_path), source)
    result = _run(["--read-batch", batch, dest, "--temp-dir", outside])
    assert result.returncode != 0, "an absolute temp dir outside the receive root must be rejected"
    assert os.listdir(outside) == [], "receiver wrote into an unconfined temp dir"
    assert "temp-dir" in (result.stdout + result.stderr), (result.stdout, result.stderr)


def test_tcp_absolute_temp_dir_inside_root_accepted(shared_server):
    source = os.path.join(TEST_DATA_DIR, "tempdir_abs_in_src")
    dest = os.path.join(TEST_DATA_DIR, "tempdir_abs_in_dst")
    _seed_source(source)
    clean_dir(dest)
    scratch = os.path.join(dest, "scratch")
    os.makedirs(scratch)

    result, _ = run_client(source, dest, flags=["--temp-dir", scratch], port=shared_server.port)
    assert result.returncode == 0, (result.stdout, result.stderr)[:300]
    received = get_dest_received_dir(dest, source)
    for rel, data in FILES.items():
        assert _read(os.path.join(received, rel)) == data, f"content mismatch for {rel}"
    assert os.listdir(scratch) == [], "scratch dir was not left clean"


def test_tcp_absolute_temp_dir_outside_root_rejected(shared_server):
    source = os.path.join(TEST_DATA_DIR, "tempdir_abs_out_src")
    dest = os.path.join(TEST_DATA_DIR, "tempdir_abs_out_dst")
    _seed_source(source)
    clean_dir(dest)
    outside = os.path.join(TEST_DATA_DIR, "tempdir_abs_out_scratch")
    clean_dir(outside)

    result, _ = run_client(source, dest, flags=["--temp-dir", outside], port=shared_server.port)
    assert result.returncode != 0, "an absolute temp dir outside the receive root must be rejected"
    assert os.listdir(outside) == [], "receiver wrote into an unconfined temp dir"
