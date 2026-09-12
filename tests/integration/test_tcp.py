"""TCP transport correctness tests."""
import os
import shutil
import sys
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    PROJECT_ROOT, BUILD_DIR, TEST_DATA_DIR,
    run_client, run_client_posix,
    generate_test_files, verify_transfer, clean_dir, make_result,
    get_dest_received_dir, CLIENT_CMD,
)

SOURCE_DIR = os.path.join(TEST_DATA_DIR, "tcp_source")
DEST_DIR = os.path.join(TEST_DATA_DIR, "tcp_dest")


@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    generate_test_files(SOURCE_DIR, full=False)
    clean_dir(DEST_DIR)
    yield
    shutil.rmtree(SOURCE_DIR, ignore_errors=True)
    shutil.rmtree(DEST_DIR, ignore_errors=True)


def _run_tcp_test(name, port, flags, use_metadata=True, posix=False):
    """Run a single TCP test case against a shared server."""
    clean_dir(DEST_DIR)
    if posix:
        result, dur = run_client_posix(SOURCE_DIR, DEST_DIR,
                                       flags=(["--preserve"] if use_metadata else []) + flags,
                                       port=port)
    else:
        result, dur = run_client(SOURCE_DIR, DEST_DIR,
                                 flags=(["--preserve"] if use_metadata else []) + flags,
                                 port=port)

    if result.returncode != 0:
        return make_result(name, False, dur, f"Exit {result.returncode}: {(result.stderr or result.stdout)[:100]}")

    received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
    mismatches, missing = verify_transfer(SOURCE_DIR, received)
    if missing:
        return make_result(name, False, dur, f"Missing: {', '.join(missing[:5])}")
    if mismatches:
        return make_result(name, False, dur, f"Mismatch: {', '.join(mismatches[:3])}")
    return make_result(name, True, dur)


class TestTCPStandard:
    @pytest.mark.ci
    def test_standard(self, shared_server):
        r = _run_tcp_test("Standard", shared_server.port, [])
        assert r["status"] == "Success", r["error"]

    @pytest.mark.ci
    def test_posix_args(self, shared_server):
        r = _run_tcp_test("Posix Args", shared_server.port, [], posix=True)
        assert r["status"] == "Success", r["error"]

    def test_no_metadata(self, shared_server):
        r = _run_tcp_test("Standard (no metadata)", shared_server.port, [], use_metadata=False)
        assert r["status"] == "Success", r["error"]


class TestTCPFlags:
    @pytest.mark.ci
    def test_multithreading(self, shared_server):
        r = _run_tcp_test("Multithreading (--threads)", shared_server.port, ["--threads"])
        assert r["status"] == "Success", r["error"]

    @pytest.mark.ci
    def test_compression(self, shared_server):
        r = _run_tcp_test("Compression (-z)", shared_server.port, ["-z"])
        assert r["status"] == "Success", r["error"]

    def test_compression_threads(self, shared_server):
        r = _run_tcp_test("Compression threads (-z --compress-threads=2)", shared_server.port,
                          ["-z", "--compress-threads=2"])
        assert r["status"] == "Success", r["error"]

    def test_chunk_serialization(self, shared_server):
        r = _run_tcp_test("Chunk Serialization (--chunk-serialization)", shared_server.port, ["--chunk-serialization"])
        assert r["status"] == "Success", r["error"]

    def test_compression_chunk(self, shared_server):
        r = _run_tcp_test("Compression + Chunk (-z --chunk-serialization)", shared_server.port, ["-z", "--chunk-serialization"])
        assert r["status"] == "Success", r["error"]

    def test_multithread_compression(self, shared_server):
        r = _run_tcp_test("Multithreading + Compression (--threads -z)", shared_server.port, ["--threads", "-z"])
        assert r["status"] == "Success", r["error"]

    def test_multithread_chunk(self, shared_server):
        r = _run_tcp_test("Multithreading + Chunk (--threads --chunk-serialization)", shared_server.port, ["--threads", "--chunk-serialization"])
        assert r["status"] == "Success", r["error"]

    def test_all_flags(self, shared_server):
        r = _run_tcp_test("Multithread + Compression + Chunk (--threads -z --chunk-serialization)", shared_server.port, ["--threads", "-z", "--chunk-serialization"])
        assert r["status"] == "Success", r["error"]

    def test_sendfile(self, shared_server):
        r = _run_tcp_test("Sendfile (--sendfile)", shared_server.port, ["--sendfile"])
        assert r["status"] == "Success", r["error"]

    def test_sendfile_multithread(self, shared_server):
        r = _run_tcp_test("Sendfile + Multithreading (--sendfile --threads)", shared_server.port, ["--sendfile", "--threads"])
        assert r["status"] == "Success", r["error"]


class TestTCPSocketOptions:
    """--sockopts, -4/-6 and --address: rsync-compatible socket/bind options.

    These are purely local (client-side) socket concerns that never cross the
    wire, so each is exercised by a normal transfer succeeding end-to-end."""

    @pytest.mark.ci
    def test_sockopts_apply(self, shared_server):
        r = _run_tcp_test("Sockopts (TCP_NODELAY=1,SO_KEEPALIVE=1)", shared_server.port,
                          ["--sockopts=TCP_NODELAY=1,SO_KEEPALIVE=1"])
        assert r["status"] == "Success", r["error"]

    def test_sockopts_buffer_sizes(self, shared_server):
        r = _run_tcp_test("Sockopts buffer sizes (SO_RCVBUF/SO_SNDBUF)", shared_server.port,
                          ["--sockopts=SO_RCVBUF=131072,SO_SNDBUF=131072"])
        assert r["status"] == "Success", r["error"]

    def test_ipv4_forced(self, shared_server):
        r = _run_tcp_test("Force IPv4 (-4)", shared_server.port, ["-4"])
        assert r["status"] == "Success", r["error"]

    @pytest.mark.skipif(shutil.which("ip") is None,
                        reason="requires ip tooling to enumerate a usable local address")
    def test_address_source_bind(self, shared_server):
        r = _run_tcp_test("Source bind (--address=127.0.0.1)", shared_server.port,
                          ["--address", "127.0.0.1"])
        assert r["status"] == "Success", r["error"]


class TestTCPChunkSize:
    def test_custom_chunk_size(self, shared_server):
        r = _run_tcp_test("Chunk size 5MB", shared_server.port, ["--chunk-size", "5242880"])
        assert r["status"] == "Success", r["error"]

    def test_small_chunk_size(self, shared_server):
        r = _run_tcp_test("Chunk size 1KB", shared_server.port, ["--chunk-size", "1024"])
        assert r["status"] == "Success", r["error"]
