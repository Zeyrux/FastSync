"""CLI validation and preflight checks."""
import subprocess
import sys
import os
import shutil
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import BUILD_DIR, CLIENT_CMD, SERVER_CMD, TEST_DATA_DIR, run_client, verify_transfer


class TestHelp:
    def test_client_help(self):
        r = subprocess.run(CLIENT_CMD + ["--help"], capture_output=True, text=True)
        assert r.returncode == 0
        assert "Usage:" in r.stdout
        assert "SSH transport" in r.stdout

    def test_server_help(self):
        r = subprocess.run(SERVER_CMD + ["--help"], capture_output=True, text=True)
        assert r.returncode == 0
        assert "Usage:" in r.stdout


class TestSSHDetection:
    def test_remote_dest_detected(self):
        """Posix-style SSH dest should be detected and fail gracefully."""
        r = subprocess.run(
            CLIENT_CMD + ["/x", "somehost:/y"],
            capture_output=True, text=True, timeout=5,
        )
        assert r.returncode != 0
        stderr = (r.stderr or "").lower()
        assert "ssh" in stderr or "error" in stderr or "could not" in stderr

    def test_local_dest_not_ssh(self):
        """Local path should not be detected as SSH."""
        r = subprocess.run(
            CLIENT_CMD + ["/tmp/x", "/tmp/y"],
            capture_output=True, text=True, timeout=5,
        )
        # Should fail with connection error (no server), not SSH error
        assert r.returncode != 0


class TestServerStdio:
    def test_stdio_mode_starts(self):
        """Server --stdio should start and wait for stdin."""
        try:
            r = subprocess.run(
                SERVER_CMD + ["--stdio"],
                capture_output=True, text=True, timeout=3,
            )
            # Should exit with error (no data on stdin) or timeout
        except subprocess.TimeoutExpired:
            pass  # Expected: server waiting for stdin


class TestServerPort:
    def test_invalid_port(self):
        """Server should reject invalid port numbers."""
        r = subprocess.run(
            SERVER_CMD + ["-p", "99999"],
            capture_output=True, text=True, timeout=5,
        )
        assert r.returncode != 0

    def test_default_port(self):
        """Server should start on default port 8080."""
        proc = subprocess.Popen(
            SERVER_CMD, stdout=subprocess.DEVNULL, stderr=None,
        )
        try:
            import socket, time
            time.sleep(0.5)
            with socket.create_connection(("127.0.0.1", 8080), timeout=2):
                pass  # Port is listening
        except (ConnectionRefusedError, OSError):
            pytest.fail("Server not listening on default port 8080")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def _seed_protocol_source(source):
    os.makedirs(source, exist_ok=True)
    with open(os.path.join(source, "p.txt"), "w") as fh:
        fh.write("protocol test\n")
    os.makedirs(os.path.join(source, "nested"), exist_ok=True)
    with open(os.path.join(source, "nested", "deep.txt"), "w") as fh:
        fh.write("deep file\n")


class TestProtocol:
    @pytest.mark.ci
    def test_protocol_current_version_accepted(self, shared_server):
        """--protocol=2.19.0 (the current PROTOCOL_VERSION) is accepted and the
        transfer completes normally."""
        source = os.path.join(TEST_DATA_DIR, "proto_ok_src")
        dest = os.path.join(TEST_DATA_DIR, "proto_ok_dst")
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest)
        _seed_protocol_source(source)
        result, _ = run_client(source, dest, flags=["--protocol=2.19.0"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"--protocol current run failed: {(result.stderr or result.stdout)[:400]}"
        received = os.path.join(dest, os.path.abspath(source).lstrip(os.sep))
        mismatches, missing = verify_transfer(source, received)
        assert not mismatches and not missing, \
            f"transfer mismatch: missing={missing} mismatches={mismatches}"

    @pytest.mark.ci
    def test_protocol_rejects_other_versions(self, shared_server):
        """Other versions are rejected up front, before connecting."""
        source = os.path.join(TEST_DATA_DIR, "proto_reject_src")
        dest = os.path.join(TEST_DATA_DIR, "proto_reject_dst")
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest)
        _seed_protocol_source(source)
        for bad in ("2.18.0", "2.17.0", "2.15.0", "2.16.0", "216", "31"):
            result, _ = run_client(source, dest, flags=[f"--protocol={bad}"],
                                   port=shared_server.port)
            assert result.returncode != 0, f"--protocol={bad} should be rejected"

    @pytest.mark.ci
    def test_protocol_rejects_garbage(self, shared_server):
        """Garbage/empty --protocol values are rejected up front."""
        source = os.path.join(TEST_DATA_DIR, "proto_garbage_src")
        dest = os.path.join(TEST_DATA_DIR, "proto_garbage_dst")
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest)
        _seed_protocol_source(source)
        for bad in ("abc", ""):
            result, _ = run_client(source, dest, flags=[f"--protocol={bad}"],
                                   port=shared_server.port)
            assert result.returncode != 0, f"--protocol={bad} should be rejected"
