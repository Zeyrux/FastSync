"""TCP transport correctness tests."""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    PROJECT_ROOT, BUILD_DIR, TEST_DATA_DIR,
    ServerManager, run_client, run_client_posix,
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
    import shutil
    shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)


def _run_tcp_test(name, flags, use_metadata=True, posix=False):
    """Run a single TCP test case with a fresh server."""
    clean_dir(DEST_DIR)
    with ServerManager() as server:
        if posix:
            result, dur = run_client_posix(SOURCE_DIR, DEST_DIR,
                                           flags=(["-M"] if use_metadata else []) + flags,
                                           port=server.port)
        else:
            result, dur = run_client(SOURCE_DIR, DEST_DIR,
                                     flags=(["-M"] if use_metadata else []) + flags,
                                     port=server.port)

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
    def test_standard(self):
        r = _run_tcp_test("Standard", [])
        assert r["status"] == "Success", r["error"]

    def test_posix_args(self):
        r = _run_tcp_test("Posix Args", [], posix=True)
        assert r["status"] == "Success", r["error"]

    def test_no_metadata(self):
        r = _run_tcp_test("Standard (no metadata)", [], use_metadata=False)
        assert r["status"] == "Success", r["error"]


class TestTCPFlags:
    def test_multithreading(self):
        r = _run_tcp_test("Multithreading (-m)", ["-m"])
        assert r["status"] == "Success", r["error"]

    def test_compression(self):
        r = _run_tcp_test("Compression (-c)", ["-c"])
        assert r["status"] == "Success", r["error"]

    def test_chunk_serialization(self):
        r = _run_tcp_test("Chunk Serialization (-s)", ["-s"])
        assert r["status"] == "Success", r["error"]

    def test_compression_chunk(self):
        r = _run_tcp_test("Compression + Chunk (-c -s)", ["-c", "-s"])
        assert r["status"] == "Success", r["error"]

    def test_multithread_compression(self):
        r = _run_tcp_test("Multithreading + Compression (-m -c)", ["-m", "-c"])
        assert r["status"] == "Success", r["error"]

    def test_multithread_chunk(self):
        r = _run_tcp_test("Multithreading + Chunk (-m -s)", ["-m", "-s"])
        assert r["status"] == "Success", r["error"]

    def test_all_flags(self):
        r = _run_tcp_test("Multithread + Compression + Chunk (-m -c -s)", ["-m", "-c", "-s"])
        assert r["status"] == "Success", r["error"]

    def test_sendfile(self):
        r = _run_tcp_test("Sendfile (-f)", ["-f"])
        assert r["status"] == "Success", r["error"]

    def test_sendfile_multithread(self):
        r = _run_tcp_test("Sendfile + Multithreading (-f -m)", ["-f", "-m"])
        assert r["status"] == "Success", r["error"]


class TestTCPChunkSize:
    def test_custom_chunk_size(self):
        r = _run_tcp_test("Chunk size 5MB", ["--chunk-size", "5242880"])
        assert r["status"] == "Success", r["error"]

    def test_small_chunk_size(self):
        r = _run_tcp_test("Chunk size 1KB", ["--chunk-size", "1024"])
        assert r["status"] == "Success", r["error"]
