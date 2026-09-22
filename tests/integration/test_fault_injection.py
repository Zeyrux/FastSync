"""Fault injection: the server must survive truncated / corrupted protocol
frames and abrupt mid-frame disconnects, and keep serving later connections.

These tests deliberately speak raw bytes to a real server process:

  * malformed frames before/inside the config handshake (oversized length
    headers, truncated string bodies, outright garbage),
  * a captured *valid* config frame replayed so the connection reaches the
    operation loop, followed by a partial ``STATUS_MANIFEST`` frame that is cut
    mid-body and dropped, and
  * a real client run relayed through a proxy that truncates the stream at a
    range of byte offsets and resets both ends.

After every fault the server process is asserted alive and a subsequent
ordinary transfer must complete and verify, proving the accept loop and
per-connection children recovered cleanly.  All interactions are bounded by
short socket timeouts (no sleeps).
"""
import os
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    ServerManager,
    TEST_DATA_DIR,
    get_dest_received_dir,
    run_client,
    verify_transfer,
)

PROTOCOL_VERSION = b"2.29.0"
STATUS_MANIFEST = 5
STATUS_OK = 0

SOURCE_DIR = os.path.join(TEST_DATA_DIR, "fault_src")
DEST_DIR = os.path.join(TEST_DATA_DIR, "fault_dst")


@pytest.fixture(scope="module")
def fault_server():
    """A dedicated server so the aliveness assertions observe exactly the
    process these faults were sent to."""
    server = ServerManager()
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="module", autouse=True)
def _seed_source():
    if os.path.exists(SOURCE_DIR):
        shutil.rmtree(SOURCE_DIR)
    os.makedirs(os.path.join(SOURCE_DIR, "nested"))
    # The receiver rejects a destination root that does not exist, and the
    # capture fixture can run before any test that creates it, so create it
    # here (test order/distribution must not matter).
    os.makedirs(DEST_DIR, exist_ok=True)
    with open(os.path.join(SOURCE_DIR, "hello.txt"), "wb") as fh:
        fh.write(b"fault injection payload\n" * 64)
    with open(os.path.join(SOURCE_DIR, "nested", "deep.bin"), "wb") as fh:
        fh.write(bytes(range(256)) * 16)
    yield
    shutil.rmtree(SOURCE_DIR, ignore_errors=True)
    shutil.rmtree(DEST_DIR, ignore_errors=True)


def _assert_alive(server):
    assert server._proc is not None, "server process missing"
    assert server._proc.poll() is None, (
        f"server exited with {server._proc.returncode} after fault injection"
    )


def _recover(server, label):
    """Run one ordinary transfer and verify it end-to-end."""
    shutil.rmtree(DEST_DIR, ignore_errors=True)
    os.makedirs(DEST_DIR)
    result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=server.port)
    assert result.returncode == 0, (
        f"{label}: recovery transfer failed rc={result.returncode}: "
        f"{(result.stderr or result.stdout)[:200]}"
    )
    received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
    mismatches, missing = verify_transfer(SOURCE_DIR, received)
    assert not missing, f"{label}: recovery missing {missing}"
    assert not mismatches, f"{label}: recovery mismatch {mismatches}"


def _abrupt_close(sock):
    """Force an RST instead of a graceful FIN, the nastier mid-frame drop."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _raw_connect(server):
    sock = socket.create_connection(("127.0.0.1", server.port), timeout=5)
    sock.settimeout(5)
    return sock


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# --- faults before/inside the config handshake -----------------------------

CONFIG_HANDSHAKE_FAULTS = {
    "empty": b"",
    # Length header claims a 1 EiB string body that never arrives.
    "oversized_length": struct.pack("<Q", 1 << 60),
    # A truncated 8-byte length header (only 3 bytes of it are sent).
    "truncated_length_header": b"\x10\x00\x00",
    # A valid version string followed by a string-length header whose body is
    # deliberately truncated (mid-config-frame disconnect).
    "truncated_config_body": struct.pack("<Q", len(PROTOCOL_VERSION)) + PROTOCOL_VERSION
    + struct.pack("<Q", 4096)
    + b"partial",
    # Pure garbage that is not a valid frame at any offset.
    "garbage": b"\xff" * 32,
}


class TestConfigHandshakeFaults:
    def test_truncated_and_corrupt_config_frames(self, fault_server):
        for name, payload in CONFIG_HANDSHAKE_FAULTS.items():
            sock = _raw_connect(fault_server)
            if payload:
                sock.sendall(payload)
            _abrupt_close(sock)
            _assert_alive(fault_server)
        _recover(fault_server, "config handshake faults")


# --- capture a valid config frame, then truncate a STATUS_MANIFEST ----------


class _CaptureProxy:
    """Relay one client<->server connection and record the client's config
    frame (all client bytes forwarded before the server's first reply)."""

    def __init__(self, target_port):
        self.target = ("127.0.0.1", target_port)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(20)
        self.port = self.listener.getsockname()[1]
        self.config_frame = None

    def run(self, cmd):
        def serve():
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            try:
                backend = socket.create_connection(self.target, timeout=10)
            except OSError:
                client.close()
                return
            client.settimeout(20)
            backend.settimeout(20)
            buf_c = bytearray()
            seen_server = False
            try:
                while True:
                    ready, _, _ = select.select([client, backend], [], [], 20)
                    if not ready:
                        break
                    done = False
                    for sock in ready:
                        data = sock.recv(65536)
                        if not data:
                            done = True
                            continue
                        if sock is client:
                            buf_c += data
                            backend.sendall(data)
                        else:
                            if not seen_server:
                                seen_server = True
                                self.config_frame = bytes(buf_c)
                            client.sendall(data)
                    if done:
                        break
            except OSError:
                pass
            finally:
                client.close()
                backend.close()

        thread = threading.Thread(target=serve)
        thread.start()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        thread.join(20)
        return result

    def close(self):
        try:
            self.listener.close()
        except OSError:
            pass


@pytest.fixture(scope="module")
def captured_config(fault_server):
    """Capture the config frame of one real client run through a relay."""
    proxy = _CaptureProxy(fault_server.port)
    cmd = [
        os.path.join(os.path.dirname(__file__), "..", "..", "build", "client"),
        "--source-dir",
        SOURCE_DIR,
        "--dest-dir",
        DEST_DIR,
        "--save-to-disk",
        "--server-port",
        str(proxy.port),
    ]
    try:
        result = proxy.run(cmd)
        assert result.returncode == 0, (
            f"capture run failed rc={result.returncode}: "
            f"{(result.stderr or result.stdout)[:200]}"
        )
        assert proxy.config_frame, "failed to capture the client config frame"
        yield proxy.config_frame
    finally:
        proxy.close()


class TestTruncatedStatusFrame:
    def test_partial_manifest_frame_then_drop(self, fault_server, captured_config):
        sock = _raw_connect(fault_server)
        sock.sendall(captured_config)
        ack = _recv_exact(sock, 4)
        assert ack is not None, "server closed before the config ack"
        (status,) = struct.unpack("<i", ack)
        assert status == STATUS_OK, f"expected STATUS_OK, got {status}"

        # STATUS_MANIFEST, then only half of the keep-count int, then an RST.
        sock.sendall(struct.pack("<i", STATUS_MANIFEST) + b"\x02\x00")
        _abrupt_close(sock)

        _assert_alive(fault_server)
        _recover(fault_server, "truncated manifest frame")

    def test_manifest_count_without_sections(self, fault_server, captured_config):
        """A syntactically valid STATUS_MANIFEST whose bodies never arrive."""
        sock = _raw_connect(fault_server)
        sock.sendall(captured_config)
        assert _recv_exact(sock, 4) is not None

        sock.sendall(struct.pack("<i", STATUS_MANIFEST) + struct.pack("<i", 3))
        # Announce three keeps but send none; then drop.
        _abrupt_close(sock)

        _assert_alive(fault_server)
        _recover(fault_server, "manifest body truncation")


# --- abrupt truncation of a real transfer ----------------------------------


class _TruncatingProxy:
    """Forward at most ``max_client_bytes`` from client to server, then reset
    both ends mid-stream.  Runs one client command (which is expected to fail)."""

    def __init__(self, target_port, max_client_bytes):
        self.target = ("127.0.0.1", target_port)
        self.max_client_bytes = max_client_bytes
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(20)
        self.port = self.listener.getsockname()[1]

    def run(self, cmd):
        def serve():
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            try:
                backend = socket.create_connection(self.target, timeout=10)
            except OSError:
                client.close()
                return
            # A short receive timeout bounds the case where the client has
            # nothing left to send and is waiting on the server: the proxy then
            # cuts the stream anyway instead of stalling the test.
            client.settimeout(2)
            backend.settimeout(20)
            forwarded = 0
            try:
                while forwarded < self.max_client_bytes:
                    data = client.recv(65536)
                    if not data:
                        break
                    room = self.max_client_bytes - forwarded
                    take = data[:room]
                    backend.sendall(take)
                    forwarded += len(take)
                    if forwarded >= self.max_client_bytes:
                        break
            except (OSError, socket.timeout):
                pass
            for sock in (client, backend):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        finally:
            thread.join(20)
        self.listener.close()


class TestAbruptMidTransferDisconnect:
    def test_client_stream_cut_at_offsets(self, fault_server, captured_config):
        """Cut the real client stream at offsets anchored to the config frame's
        actual size: mid-config, right after the config, and into the operation
        stream -- each followed by an RST of both ends."""
        config_len = len(captured_config)
        cuts = sorted({max(1, config_len // 2), max(1, config_len - 1), config_len + 8,
                       config_len + 256})
        for cut in cuts:
            proxy = _TruncatingProxy(fault_server.port, cut)
            cmd = [
                os.path.join(os.path.dirname(__file__), "..", "..", "build", "client"),
                "--source-dir",
                SOURCE_DIR,
                "--dest-dir",
                DEST_DIR,
                "--save-to-disk",
                "--server-port",
                str(proxy.port),
            ]
            # The client is expected to fail; what matters is the server survives.
            proxy.run(cmd)
            _assert_alive(fault_server)
        _recover(fault_server, "abrupt mid-transfer disconnects")
