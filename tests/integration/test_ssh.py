"""SSH transport tests."""
import os
import shutil
import subprocess
import sys
import pytest
import shlex
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(__file__))
from common import (PROJECT_ROOT, BUILD_DIR, TEST_DATA_DIR, CLIENT_CMD,
                    generate_test_files, verify_transfer, clean_dir, make_result,
                    get_dest_received_dir)

SOURCE_DIR = os.path.join(TEST_DATA_DIR, "ssh_source")
DEST_DIR = os.path.join(TEST_DATA_DIR, "ssh_dest")
SSH_AVAILABLE = False
SSH_SKIP_REASON = "SSH localhost probe was not run"
SSH_PROBE_DIR = None


def _check_ssh():
    global SSH_AVAILABLE, SSH_SKIP_REASON, SSH_PROBE_DIR
    server_path = os.path.join(BUILD_DIR, "server")
    if not os.path.isfile(server_path):
        SSH_SKIP_REASON = f"current server binary is missing: {server_path}"
        return
    try:
        SSH_PROBE_DIR = tempfile.mkdtemp(prefix="fastsync-ssh-probe-")
        probe_server = os.path.join(SSH_PROBE_DIR, "fastsync-server")
        os.symlink(server_path, probe_server)
        command = f"{shlex.quote(probe_server)} --help"
        path = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                               "localhost", "sh", "-c", command],
                              capture_output=True, timeout=10, text=True)
        if path.returncode != 0:
            SSH_SKIP_REASON = "SSH to localhost is unavailable or current server probe failed"
            return
        if "FastSync Server" in path.stdout:
            SSH_AVAILABLE = True
            return
        SSH_SKIP_REASON = "SSH probe did not execute the current server binary"
    except FileNotFoundError:
        SSH_SKIP_REASON = "ssh executable is unavailable"
    except (OSError, subprocess.TimeoutExpired) as exc:
        SSH_SKIP_REASON = f"SSH setup failed: {exc}"
    finally:
        if SSH_PROBE_DIR:
            shutil.rmtree(SSH_PROBE_DIR, ignore_errors=True)
            SSH_PROBE_DIR = None


_check_ssh()


@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    if SSH_AVAILABLE:
        generate_test_files(SOURCE_DIR, full=False)
        clean_dir(DEST_DIR)
    yield
    shutil.rmtree(SOURCE_DIR, ignore_errors=True)
    shutil.rmtree(DEST_DIR, ignore_errors=True)


def _run_ssh_test(name, flags, expected_missing=None):
    ssh_dest = f"localhost:{DEST_DIR}"
    clean_dir(DEST_DIR)
    cmd = CLIENT_CMD + [SOURCE_DIR, ssh_dest, "--save-to-disk",
                        "--fastsync-server-path", os.path.join(BUILD_DIR, "server")] + flags
    start = __import__("time").monotonic()
    result = subprocess.run(cmd, text=True, capture_output=True)
    duration = __import__("time").monotonic() - start
    if result.returncode != 0:
        return make_result(name, False, duration,
                           f"Exit {result.returncode}: {(result.stderr or result.stdout)[:100]}")
    mismatches, missing = verify_transfer(SOURCE_DIR, get_dest_received_dir(DEST_DIR, SOURCE_DIR))
    if expected_missing:
        missing = [m for m in missing if m not in expected_missing]
    if missing:
        return make_result(name, False, duration, f"Missing: {', '.join(missing[:5])}")
    if mismatches:
        return make_result(name, False, duration, f"Mismatch: {', '.join(mismatches[:3])}")
    return make_result(name, True, duration)


class TestSSHStandard:
    @pytest.fixture(autouse=True)
    def require_ssh(self):
        if not SSH_AVAILABLE:
            pytest.skip(SSH_SKIP_REASON)

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


class TestSSHFeatures:
    @pytest.fixture(autouse=True)
    def require_ssh(self):
        if not SSH_AVAILABLE:
            pytest.skip(SSH_SKIP_REASON)

    def test_archive(self):
        r = _run_ssh_test("SSH Archive (-a)", ["-a"])
        assert r["status"] == "Success", r["error"]

    def test_exclude(self):
        r = _run_ssh_test("SSH Exclude (--exclude small.txt)",
                          ["--exclude", "small.txt"], expected_missing=["small.txt"])
        assert r["status"] == "Success", r["error"]

    def test_preallocate(self):
        r = _run_ssh_test("SSH Preallocate (--preallocate)", ["--preallocate"])
        assert r["status"] == "Success", r["error"]

    def test_trust_sender(self):
        r = _run_ssh_test("SSH Trust Sender (--trust-sender)", ["--trust-sender"])
        assert r["status"] == "Success", r["error"]

    def test_remote_option_reaches_server(self):
        """--remote-option=OPT appends OPT to the remote server command line and
        the server honors it.  Over SSH the server is launched without
        --allow-delete, so a bare --delete is inert (nothing is removed).  If
        --remote-option=--allow-delete really reaches the remote server, the
        receiver's deletion policy becomes permissive and the stale destination
        file IS removed.  Asserting the file is gone is therefore a positive
        proof the forwarded option was honored by the server."""
        src = SOURCE_DIR
        if os.path.exists(src):
            shutil.rmtree(src)
        os.makedirs(src)
        with open(os.path.join(src, "keep.txt"), "w") as f:
            f.write("kept\n")
        with open(os.path.join(src, "stale.txt"), "w") as f:
            f.write("stale\n")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)

        # Initial push so the destination mirrors the source.
        clean_dir(DEST_DIR)
        ssh_dest = f"localhost:{DEST_DIR}"
        base = CLIENT_CMD + [src, ssh_dest, "--save-to-disk",
                             "--fastsync-server-path", os.path.join(BUILD_DIR, "server")]
        first = subprocess.run(base, text=True, capture_output=True)
        assert first.returncode == 0, f"initial push failed: {(first.stderr or first.stdout)[:200]}"
        assert os.path.exists(os.path.join(received, "stale.txt"))

        # Remove stale.txt from the source and re-push with --delete +
        # --remote-option=--allow-delete.  Forwarding --allow-delete to the
        # server is what makes the deletion actually happen.
        os.remove(os.path.join(src, "stale.txt"))
        second = subprocess.run(base + ["--delete", "--remote-option=--allow-delete"],
                                text=True, capture_output=True)
        assert second.returncode == 0, \
            f"second push failed: {(second.stderr or second.stdout)[:200]}"
        assert not os.path.exists(os.path.join(received, "stale.txt")), (
            "stale.txt still present: --allow-delete (forwarded via "
            "--remote-option) did not reach the remote server"
        )
        assert os.path.exists(os.path.join(received, "keep.txt"))
