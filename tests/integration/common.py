import filecmp
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
SERVER_CMD = [os.path.join(BUILD_DIR, "server")]
CLIENT_CMD = [os.path.join(BUILD_DIR, "client")]
TEST_DATA_DIR = os.path.join(PROJECT_ROOT, "test_data")


class ServerManager:
    """Manages a long-lived server process. Reuses across test cases."""

    def __init__(self):
        self._proc = None
        self._port = None

    def start(self, extra_args=None):
        self.stop()
        self._port = _find_free_port()
        cmd = SERVER_CMD + ["-p", str(self._port)]
        if extra_args:
            cmd += extra_args
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _wait_for_port(self._port, timeout=5)

    def stop(self):
        if self._proc:
            _wait_proc(self._proc)
            self._proc = None

    @property
    def port(self):
        return self._port

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def __del__(self):
        self.stop()


def run_client(source_dir, dest_dir, flags=None, port=None, extra_args=None):
    """Run the client and return (result, duration)."""
    cmd = CLIENT_CMD + ["--source-dir", source_dir, "--dest-dir", dest_dir, "--save-to-disk"]
    if port:
        cmd += ["--server-port", str(port)]
    if flags:
        cmd += flags
    if extra_args:
        cmd += extra_args
    start = time.monotonic()
    result = subprocess.run(cmd, text=True, capture_output=True)
    duration = time.monotonic() - start
    return result, duration


def run_client_posix(source_dir, dest_dir, flags=None, port=None):
    """Run the client with positional args (rsync-style)."""
    cmd = CLIENT_CMD + [source_dir, dest_dir, "--save-to-disk"]
    if port:
        cmd += ["--server-port", str(port)]
    if flags:
        cmd += flags
    start = time.monotonic()
    result = subprocess.run(cmd, text=True, capture_output=True)
    duration = time.monotonic() - start
    return result, duration


def generate_test_files(source_dir, full=False):
    """Generate structured test data. Returns total bytes written."""
    if os.path.exists(source_dir):
        shutil.rmtree(source_dir)
    os.makedirs(source_dir)

    target_total = 25 * 1024 * 1024 if full else 0
    written = 0

    files = {
        "small.txt": b"hello world\n",
        "medium.txt": b"the quick brown fox jumps over the lazy dog\n" * 5000,
        "binary.bin": bytes(range(256)) * 1000,
        "nested/subdir/deep.txt": b"deeply nested file\n",
        "nested/another.txt": b"another nested file\n" * 50,
    }
    for rel_path, content in files.items():
        full_path = os.path.join(source_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(content)
        written += len(content)

    if full:
        os.makedirs(os.path.join(source_dir, "bulk"), exist_ok=True)
        i = 0
        while written < target_total:
            chunk_size = min(5 * 1024 * 1024, target_total - written)
            with open(os.path.join(source_dir, f"bulk/file_{i}.dat"), "wb") as f:
                f.write(random.randbytes(chunk_size))
            written += chunk_size
            i += 1

    return written


def verify_transfer(source_dir, received_dir):
    """Verify all files from source exist in received_dir and match. Returns (mismatches, missing)."""
    source_dir = os.path.abspath(source_dir)
    received_dir = os.path.abspath(received_dir)
    if not os.path.exists(received_dir):
        return [], ["no received files found"]
    mismatches, missing = [], []
    for root, dirs, files in os.walk(source_dir):
        for f in files:
            src_path = os.path.join(root, f)
            rel = os.path.relpath(src_path, source_dir)
            dst_path = os.path.join(received_dir, rel)
            if not os.path.exists(dst_path):
                missing.append(rel)
            elif not filecmp.cmp(src_path, dst_path, shallow=False):
                mismatches.append(rel)
    return mismatches, missing


def clean_dir(path):
    """Remove and recreate a directory."""
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)


def make_result(name, success, duration=None, error=""):
    """Create a standardized result dict."""
    return {
        "name": name,
        "status": "Success" if success else "Failed",
        "time": f"{duration:.4f}s" if duration is not None else "N/A",
        "error": error,
    }


def get_dest_received_dir(dest_dir, source_dir):
    """Get the path where received files land inside dest_dir."""
    return os.path.join(dest_dir, os.path.abspath(source_dir).lstrip(os.sep))


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _wait_for_port(port, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)
    raise RuntimeError(f"Server port {port} not ready after {timeout}s")


def _wait_proc(proc, timeout=5):
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
