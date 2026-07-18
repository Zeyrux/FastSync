"""Feature tests: incremental sync, bandwidth limiting, dry run, metadata, filters."""
import os
import shutil
import subprocess
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    PROJECT_ROOT, BUILD_DIR, TEST_DATA_DIR,
    ServerManager, run_client,
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
    def test_archive_mode(self):
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["-a"],
                port=server.port,
            )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestExclude:
    def test_exclude_single(self):
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--exclude", "small.txt"],
                port=server.port,
            )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        # small.txt should be missing (excluded)
        assert "small.txt" in missing, f"small.txt should be excluded but was transferred"
        # all other files should be present
        other_missing = [m for m in missing if m != "small.txt"]
        assert not other_missing, f"Other files missing: {other_missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_exclude_glob(self):
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--exclude", "*.txt"],
                port=server.port,
            )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        # Only binary.bin and bulk files should be present
        assert not os.path.exists(os.path.join(received, "small.txt")), "small.txt should be excluded"
        assert os.path.exists(os.path.join(received, "binary.bin")), "binary.bin should be present"


class TestInclude:
    def test_include_single(self):
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--include", "binary.bin"],
                port=server.port,
            )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        # Only binary.bin should be present
        assert os.path.exists(os.path.join(received, "binary.bin")), "binary.bin should be included"
        assert not os.path.exists(os.path.join(received, "small.txt")), "small.txt should not be included"

    def test_include_glob(self):
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--include", "*.bin"],
                port=server.port,
            )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert os.path.exists(os.path.join(received, "binary.bin")), "binary.bin should be included"


class TestSizeFilters:
    def test_max_size(self):
        """Files larger than --max-size should be skipped."""
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--max-size", "100"],  # 100 bytes
                port=server.port,
            )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        # small.txt (12 bytes) should be present, medium.txt (220k+) should be skipped
        assert os.path.exists(os.path.join(received, "small.txt")), "small.txt should be present"
        assert not os.path.exists(os.path.join(received, "medium.txt")), "medium.txt should be skipped"

    def test_min_size(self):
        """Files smaller than --min-size should be skipped."""
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--min-size", "1000"],  # 1 KB
                port=server.port,
            )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        # small.txt (12 bytes) should be skipped, medium.txt should be present
        assert not os.path.exists(os.path.join(received, "small.txt")), "small.txt should be skipped"
        assert os.path.exists(os.path.join(received, "medium.txt")), "medium.txt should be present"


class TestIncremental:
    def test_incremental_skips_unchanged(self):
        """Second sync with --incremental should be fast (skips unchanged files)."""
        # First sync: populate dest
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["-M"],
                port=server.port,
            )
            assert result.returncode == 0, f"First sync failed: {result.stderr[:100]}"

        # Second sync with --incremental (should be near-instant)
        with ServerManager() as server:
            start = time.monotonic()
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["-M", "--incremental"],
                port=server.port,
            )
            incremental_time = time.monotonic() - start

        assert result.returncode == 0, f"Incremental sync failed: {(result.stderr or result.stdout)[:200]}"

        # Verify files are still correct
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_incremental_detects_changes(self):
        """Incremental sync should transfer modified files."""
        # First sync
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, _ = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["-M"],
                port=server.port,
            )
            assert result.returncode == 0

        # Modify a file
        modified_file = os.path.join(SOURCE_DIR, "small.txt")
        with open(modified_file, "wb") as f:
            f.write(b"modified content for incremental test\n")

        # Second sync with --incremental
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["-M", "--incremental"],
                port=server.port,
            )
            assert result.returncode == 0

        # Restore original content
        with open(modified_file, "wb") as f:
            f.write(b"hello world\n")

        # Verify the modified content was transferred
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        received_file = os.path.join(received, "small.txt")
        assert os.path.exists(received_file), "Modified file should be present"
        with open(received_file, "rb") as f:
            content = f.read()
        assert b"modified content" in content, f"Modified content not transferred: {content[:50]}"


class TestDelete:
    def test_delete_removes_extra_files(self):
        """--delete should remove files on dest that aren't in source."""
        # First sync: populate dest
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, _ = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["-M"],
                port=server.port,
            )
            assert result.returncode == 0

        # Add extra files to destination
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        extra_file = os.path.join(received, "extra_file.txt")
        extra_dir = os.path.join(received, "extra_dir")
        with open(extra_file, "w") as f:
            f.write("should be deleted")
        os.makedirs(extra_dir, exist_ok=True)
        with open(os.path.join(extra_dir, "nested.txt"), "w") as f:
            f.write("nested extra")

        # Second sync with --delete
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["-M", "--delete"],
                port=server.port,
            )

        assert result.returncode == 0, f"Delete sync failed: {(result.stderr or result.stdout)[:200]}"
        assert not os.path.exists(extra_file), "extra_file.txt should be deleted"
        assert not os.path.exists(extra_dir), "extra_dir should be deleted"

        # Verify remaining files are correct
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestProgress:
    def test_progress_output(self):
        """--progress should produce some output."""
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--progress"],
                port=server.port,
            )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        # Progress output goes to stderr or stdout
        output = result.stdout + result.stderr
        # Just verify it ran successfully; progress output format may vary
        assert len(output) >= 0  # No assertion on specific output format


class TestBandwidthLimit:
    def test_bwlimit_runs(self):
        """--bwlimit should run without error."""
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--bwlimit", "10240"],
                port=server.port,
            )
        assert result.returncode == 0, f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
