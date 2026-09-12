"""Residual-batch (client-only) driver tests.

--write-batch / --only-write-batch emit a self-contained batch file of a whole
source tree; --read-batch applies one locally.  None of these cross the wire (no
PROTOCOL_VERSION bump, no config-frame field, no server flag): only --write-batch
also performs a live transfer and so needs a server.
"""
import os
import shutil
import subprocess
import sys
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    TEST_DATA_DIR,
    run_client,
    generate_test_files,
    verify_transfer,
    clean_dir,
    get_dest_received_dir,
    CLIENT_CMD,
)

SOURCE_DIR = os.path.join(TEST_DATA_DIR, "batch_source")
DEST1 = os.path.join(TEST_DATA_DIR, "batch_dest1")
DEST2 = os.path.join(TEST_DATA_DIR, "batch_dest2")
BATCH_FILE = os.path.join(TEST_DATA_DIR, "batch.bin")

BATCH_MAGIC = b"FSTRESBATCH"


@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    generate_test_files(SOURCE_DIR, full=False)
    clean_dir(DEST1)
    clean_dir(DEST2)
    yield
    shutil.rmtree(SOURCE_DIR, ignore_errors=True)
    shutil.rmtree(DEST1, ignore_errors=True)
    shutil.rmtree(DEST2, ignore_errors=True)
    for p in (BATCH_FILE,):
        if os.path.exists(p):
            os.unlink(p)


def _run(args):
    return CLIENT_CMD + args


def test_write_batch_no_server():
    """--only-write-batch emits a batch from the source with no destination and
    no server connection."""
    if os.path.exists(BATCH_FILE):
        os.unlink(BATCH_FILE)
    cmd = _run(["--only-write-batch", BATCH_FILE, SOURCE_DIR])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, (result.stdout, result.stderr)
    with open(BATCH_FILE, "rb") as f:
        assert f.read(len(BATCH_MAGIC)) == BATCH_MAGIC
    # No destination was touched (nothing was created next to the batch).
    assert not os.path.exists(os.path.join(DEST1, "small.txt"))


def test_read_batch_roundtrip_no_source():
    """--read-batch applies an emitted batch to a fresh destination with no
    source and no server; the tree is byte-identical to the source."""
    received = get_dest_received_dir(DEST2, SOURCE_DIR)
    clean_dir(DEST2)
    cmd = _run(["--read-batch", BATCH_FILE, DEST2])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, (result.stdout, result.stderr)
    mismatches, missing = verify_transfer(SOURCE_DIR, received)
    assert not missing, f"Missing: {missing[:5]}"
    assert not mismatches, f"Mismatch: {mismatches[:5]}"


def test_write_batch_with_transfer(shared_server):
    """--write-batch runs a live transfer to a server AND emits the batch file."""
    if os.path.exists(BATCH_FILE):
        os.unlink(BATCH_FILE)
    clean_dir(DEST1)
    result, _ = run_client(
        SOURCE_DIR, DEST1,
        flags=["--write-batch", BATCH_FILE], port=shared_server.port)
    assert result.returncode == 0, (result.stdout, result.stderr)
    with open(BATCH_FILE, "rb") as f:
        assert f.read(len(BATCH_MAGIC)) == BATCH_MAGIC
    received = get_dest_received_dir(DEST1, SOURCE_DIR)
    mismatches, missing = verify_transfer(SOURCE_DIR, received)
    assert not missing, f"Missing: {missing[:5]}"
    assert not mismatches, f"Mismatch: {mismatches[:5]}"


def test_read_batch_requires_destination():
    """--read-batch with no positional destination fails cleanly."""
    cmd = _run(["--read-batch", BATCH_FILE])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode != 0


def test_only_write_batch_requires_source():
    """--only-write-batch with no source fails cleanly."""
    cmd = _run(["--only-write-batch", BATCH_FILE])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode != 0


def test_batch_modes_conflict():
    """The three batch flags are mutually exclusive."""
    combos = [
        ["--write-batch", BATCH_FILE, "--only-write-batch", BATCH_FILE],
        ["--write-batch", BATCH_FILE, "--read-batch", BATCH_FILE],
        ["--only-write-batch", BATCH_FILE, "--read-batch", BATCH_FILE],
    ]
    for flags in combos:
        cmd = _run(["--source-dir", SOURCE_DIR, "--dest-dir", DEST1] + flags)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        assert result.returncode != 0, \
            f"expected conflict failure for {flags}: {result.stderr}"