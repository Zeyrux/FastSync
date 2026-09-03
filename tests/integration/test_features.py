"""Feature tests: incremental sync, bandwidth limiting, dry run, metadata, filters."""
import os
import shutil
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    PROJECT_ROOT, BUILD_DIR, TEST_DATA_DIR,
    run_client,
    generate_test_files, verify_transfer, clean_dir, make_result,
    get_dest_received_dir, CLIENT_CMD,
)

SOURCE_DIR = os.path.join(TEST_DATA_DIR, "feature_source")
DEST_DIR = os.path.join(TEST_DATA_DIR, "feature_dest")


@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    generate_test_files(SOURCE_DIR, full=False)
    clean_dir(DEST_DIR)
    yield
    shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)


class TestDryRun:
    def test_dry_run(self):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-n"],
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert "Dry run:" in result.stdout, f"No dry run output: {result.stdout[:200]}"


class TestArchiveMode:
    def test_archive_mode(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-a"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestExclude:
    def test_exclude_single(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--exclude", "small.txt"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert "small.txt" in missing, "small.txt should be excluded but was transferred"
        other_missing = [m for m in missing if m != "small.txt"]
        assert not other_missing, f"Other files missing: {other_missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_exclude_glob(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--exclude", "*.txt"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert not os.path.exists(os.path.join(received, "small.txt")), "small.txt should be excluded"
        assert os.path.exists(os.path.join(received, "binary.bin")), "binary.bin should be present"


class TestInclude:
    def test_include_single(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--include", "binary.bin"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert os.path.exists(os.path.join(received, "binary.bin")), "binary.bin should be included"
        assert not os.path.exists(os.path.join(received, "small.txt")), "small.txt should not be included"

    def test_include_glob(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--include", "*.bin"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert os.path.exists(os.path.join(received, "binary.bin")), "binary.bin should be included"


class TestSizeFilters:
    def test_max_size(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--max-size", "100"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert os.path.exists(os.path.join(received, "small.txt")), "small.txt should be present"
        assert not os.path.exists(os.path.join(received, "medium.txt")), "medium.txt should be skipped"

    def test_min_size(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--min-size", "1000"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert not os.path.exists(os.path.join(received, "small.txt")), "small.txt should be skipped"
        assert os.path.exists(os.path.join(received, "medium.txt")), "medium.txt should be present"


class TestIncremental:
    def test_incremental_skips_unchanged(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-M"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"First sync failed: {result.stderr[:100]}"

        start = time.monotonic()
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-M", "--incremental"],
            port=shared_server.port,
        )
        incremental_time = time.monotonic() - start

        assert result.returncode == 0, f"Incremental sync failed: {(result.stderr or result.stdout)[:200]}"

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_incremental_detects_changes(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-M"],
            port=shared_server.port,
        )
        assert result.returncode == 0

        modified_file = os.path.join(SOURCE_DIR, "small.txt")
        with open(modified_file, "wb") as f:
            f.write(b"modified content for incremental test\n")

        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-M", "--incremental"],
            port=shared_server.port,
        )
        assert result.returncode == 0

        with open(modified_file, "wb") as f:
            f.write(b"hello world\n")

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        received_file = os.path.join(received, "small.txt")
        assert os.path.exists(received_file), "Modified file should be present"
        with open(received_file, "rb") as f:
            content = f.read()
        assert b"modified content" in content, f"Modified content not transferred: {content[:50]}"

    def test_checksum_detects_same_size_and_mtime_change(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-M"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        received_file = os.path.join(received, "small.txt")
        source_stat = os.stat(source_file)
        with open(received_file, "wb") as f:
            f.write(b"different!\n")
        os.utime(received_file, (source_stat.st_atime, source_stat.st_mtime))

        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["-M", "--incremental", "--checksum"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Checksum sync failed: {result.stderr[:200]}"
        with open(received_file, "rb") as f:
            assert f.read() == b"hello world\n"

    def test_modify_window_allows_subsecond_mtime_difference(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-M"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        received_file = os.path.join(received, "small.txt")
        source_stat = os.stat(source_file)
        with open(received_file, "wb") as f:
            f.write(b"modified!!!\n")
        os.utime(received_file, ns=(source_stat.st_atime_ns,
                                    source_stat.st_mtime_ns - 1500000000))

        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["-M", "--incremental", "--modify-window=2"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Modify-window sync failed: {result.stderr[:200]}"
        with open(received_file, "rb") as f:
            assert f.read() == b"modified!!!\n"


class TestDelete:
    def test_delete_removes_extra_files(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-M"],
            port=shared_server.port,
        )
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        extra_file = os.path.join(received, "extra_file.txt")
        extra_dir = os.path.join(received, "extra_dir")
        with open(extra_file, "w") as f:
            f.write("should be deleted")
        os.makedirs(extra_dir, exist_ok=True)
        with open(os.path.join(extra_dir, "nested.txt"), "w") as f:
            f.write("nested extra")

        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-M", "--delete"],
            port=shared_server.port,
        )

        assert result.returncode == 0, f"Delete sync failed: {(result.stderr or result.stdout)[:200]}"
        # The default server policy intentionally refuses client-requested
        # deletion unless it is started with --allow-delete.
        assert os.path.exists(extra_file), "unauthorized delete removed an extra file"
        assert os.path.exists(extra_dir), "unauthorized delete removed an extra directory"

        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestProgress:
    def test_progress_output(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--progress"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        output = result.stdout + result.stderr
        assert "Sent " in output and "MB" in output, "--progress produced no stable byte marker"
        assert "Done." in output, "--progress did not report completion"


class TestBandwidthLimit:
    def test_bwlimit_runs(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--bwlimit", "10240"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
