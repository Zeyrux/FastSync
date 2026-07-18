"""SSH transport tests."""
import os
import shutil
import subprocess
import sys
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    PROJECT_ROOT, BUILD_DIR, TEST_DATA_DIR,
    CLIENT_CMD, generate_test_files, verify_transfer, clean_dir, make_result,
)

SOURCE_DIR = os.path.join(TEST_DATA_DIR, "ssh_source")
DEST_DIR = os.path.join(TEST_DATA_DIR, "ssh_dest")
SSH_AVAILABLE = False


def _check_ssh():
    global SSH_AVAILABLE
    try:
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
             "localhost", "which", "fastsync-server"],
            capture_output=True, timeout=10,
        )
        if r.returncode == 0:
            SSH_AVAILABLE = True
            return

        # Try to install server binary into PATH
        server_path = os.path.join(BUILD_DIR, "server")
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "localhost", 'echo "$PATH"'],
            capture_output=True, timeout=10, text=True,
        )
        if r.returncode != 0:
            return
        for d in r.stdout.strip().split(":"):
            d = d.strip()
            if not d or "wrappers" in d:
                continue
            test = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "localhost",
                 f'test -w "{d}" && ln -sf {server_path} "{d}/fastsync-server" && which fastsync-server'],
                capture_output=True, timeout=10,
            )
            if test.returncode == 0:
                SSH_AVAILABLE = True
                return
    except FileNotFoundError:
        pass


@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    _check_ssh()
    if SSH_AVAILABLE:
        generate_test_files(SOURCE_DIR, full=False)
        clean_dir(DEST_DIR)
    yield
    shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)


def _run_ssh_test(name, flags, expected_missing=None):
    """Run an SSH test case (no server process needed, client spawns SSH)."""
    ssh_dest = f"localhost:{DEST_DIR}"
    clean_dir(DEST_DIR)
    cmd = CLIENT_CMD + [SOURCE_DIR, ssh_dest, "--save-to-disk"] + flags
    start = __import__("time").monotonic()
    result = subprocess.run(cmd, text=True, capture_output=True)
    duration = __import__("time").monotonic() - start

    if result.returncode != 0:
        return make_result(name, False, duration, f"Exit {result.returncode}: {(result.stderr or result.stdout)[:100]}")

    mismatches, missing = verify_transfer(SOURCE_DIR, DEST_DIR)
    if expected_missing:
        missing = [m for m in missing if m not in expected_missing]
    if missing:
        return make_result(name, False, duration, f"Missing: {', '.join(missing[:5])}")
    if mismatches:
        return make_result(name, False, duration, f"Mismatch: {', '.join(mismatches[:3])}")
    return make_result(name, True, duration)


@pytest.mark.skipif(not SSH_AVAILABLE, reason="SSH to localhost not available")
class TestSSHStandard:
    def test_standard(self):
        r = _run_ssh_test("SSH (localhost)", [])
        assert r["status"] == "Success", r["error"]

    def test_multithreading(self):
        r = _run_ssh_test("SSH Multithreading (-m)", ["-m"])
        assert r["status"] == "Success", r["error"]

    def test_compression(self):
        r = _run_ssh_test("SSH Compression (-c)", ["-c"])
        assert r["status"] == "Success", r["error"]

    def test_chunk_serialization(self):
        r = _run_ssh_test("SSH Chunk Serialization (-s)", ["-s"])
        assert r["status"] == "Success", r["error"]

    def test_compression_chunk(self):
        r = _run_ssh_test("SSH Compression + Chunk (-c -s)", ["-c", "-s"])
        assert r["status"] == "Success", r["error"]

    def test_multithread_compression(self):
        r = _run_ssh_test("SSH Multithread + Compression (-m -c)", ["-m", "-c"])
        assert r["status"] == "Success", r["error"]

    def test_multithread_chunk(self):
        r = _run_ssh_test("SSH Multithread + Chunk (-m -s)", ["-m", "-s"])
        assert r["status"] == "Success", r["error"]

    def test_all_flags(self):
        r = _run_ssh_test("SSH All Flags (-m -c -s)", ["-m", "-c", "-s"])
        assert r["status"] == "Success", r["error"]


@pytest.mark.skipif(not SSH_AVAILABLE, reason="SSH to localhost not available")
class TestSSHFeatures:
    def test_archive(self):
        r = _run_ssh_test("SSH Archive (-a)", ["-a"])
        assert r["status"] == "Success", r["error"]

    def test_exclude(self):
        r = _run_ssh_test("SSH Exclude (--exclude small.txt)",
                          ["--exclude", "small.txt"],
                          expected_missing=["small.txt"])
        assert r["status"] == "Success", r["error"]
