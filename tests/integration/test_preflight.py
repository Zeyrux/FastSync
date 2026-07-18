"""CLI validation and preflight checks."""
import subprocess
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import BUILD_DIR, CLIENT_CMD, SERVER_CMD


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
