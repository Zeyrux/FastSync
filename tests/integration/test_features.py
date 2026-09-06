"""Feature tests: incremental sync, bandwidth limiting, dry run, metadata, filters."""
import filecmp
import os
import shutil
import subprocess
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
    def test_human_readable_dry_run(self):
        result, dur = run_client(SOURCE_DIR, DEST_DIR, flags=["-h", "--dry-run"])
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert "Total:" in result.stdout
        assert "KB" in result.stdout

    def test_dry_run(self):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-n"],
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert "Dry run:" in result.stdout, f"No dry run output: {result.stdout[:200]}"

    def test_quiet_suppresses_dry_run_output(self):
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-q", "-n", "--progress", "--stats"],
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert result.stdout == ""
        assert result.stderr == ""

    def test_quiet_preserves_errors(self):
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--quiet", "--server-port", "1"],
        )
        assert result.returncode != 0
        assert result.stderr != ""

    @pytest.mark.parametrize("flags", [["-q", "-v"], ["-v", "-q"]])
    def test_quiet_successful_transfer_and_verbose_order(self, shared_server, flags):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=flags,
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert result.stdout == ""
        assert result.stderr == ""
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestRemoveSourceFiles:
    def test_removes_only_transferred_regular_files(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_source")
        dest = os.path.join(TEST_DATA_DIR, "remove_dest")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "one.txt"), "wb") as f:
            f.write(b"one")
        with open(os.path.join(source, "two.txt"), "wb") as f:
            f.write(b"two")
        os.makedirs(os.path.join(source, "directory"))
        os.symlink("one.txt", os.path.join(source, "link.txt"))

        result, _ = run_client(source, dest, flags=["--remove-source-files", "-m"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Remove-source sync failed: {result.stderr[:200]}"
        assert not os.path.exists(os.path.join(source, "one.txt"))
        assert not os.path.exists(os.path.join(source, "two.txt"))
        assert os.path.isdir(os.path.join(source, "directory"))
        assert os.path.islink(os.path.join(source, "link.txt"))

    def test_single_threaded_removes_transferred_file(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_single_source")
        dest = os.path.join(TEST_DATA_DIR, "remove_single_dest")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"single threaded")

        result, _ = run_client(source, dest, flags=["--remove-source-files"],
                               port=shared_server.port)
        assert result.returncode == 0
        assert not os.path.exists(source_file)

    def test_dry_run_preserves_source_files(self):
        source = os.path.join(TEST_DATA_DIR, "remove_dry_source")
        dest = os.path.join(TEST_DATA_DIR, "remove_dry_dest")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"keep")

        result, _ = run_client(source, dest, flags=["--remove-source-files", "--dry-run"])
        assert result.returncode == 0
        assert os.path.isfile(source_file)

    def test_failed_connection_preserves_source_files(self):
        source = os.path.join(TEST_DATA_DIR, "remove_failed_source")
        dest = os.path.join(TEST_DATA_DIR, "remove_failed_dest")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"keep after failure")

        result, _ = run_client(source, dest, flags=["--remove-source-files"], port=1)
        assert result.returncode != 0
        assert os.path.isfile(source_file)

    def test_incremental_skip_preserves_source_file(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_skipped_source")
        dest = os.path.join(TEST_DATA_DIR, "remove_skipped_dest")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"keep after skip")

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0
        result, _ = run_client(source, dest,
                               flags=["--remove-source-files", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0
        assert os.path.isfile(source_file)


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

    def test_archive_implied_options_can_be_negated(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--archive", "--no-compress", "--no-m", "--no-preserve"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestExecutability:
    def test_preserves_only_executable_bits(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "executability_source")
        dest = os.path.join(TEST_DATA_DIR, "executability_dest")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "tool.sh")
        with open(source_file, "w") as f:
            f.write("#!/bin/sh\necho test\n")
        os.chmod(source_file, 0o751)

        result, _ = run_client(source, dest, flags=["-E"], port=shared_server.port)
        assert result.returncode == 0, f"Executability sync failed: {result.stderr[:200]}"
        received_file = os.path.join(get_dest_received_dir(dest, source), "tool.sh")
        received_mode = os.stat(received_file).st_mode
        assert received_mode & 0o111 == 0o111
        assert received_mode & 0o600 == 0o600
        assert received_mode & 0o077 == 0o011


class TestChmod:
    def test_chmod_applies_to_transferred_files(self, shared_server):
        clean_dir(DEST_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        os.chmod(source_file, 0o777)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--chmod=u=rw,go=r"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert (os.stat(os.path.join(received, "small.txt")).st_mode & 0o777) == 0o644


class TestCompressionChoice:
    def test_zstd_choice_compresses(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--zc", "zstd"],
                               port=shared_server.port)
        assert result.returncode == 0, f"zstd sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_none_choice_disables_compression(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-z", "--compress-choice", "none"],
                               port=shared_server.port)
        assert result.returncode == 0, f"none sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestSkipCompress:
    def test_skip_compress_case_insensitive(self, shared_server):
        clean_dir(DEST_DIR)
        with open(os.path.join(SOURCE_DIR, "skip-case.TXT"), "wb") as f:
            f.write((b"skip compression case test\n" * 100))
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-c", "--skip-compress=.txt"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Skip-compress sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        with open(os.path.join(received, "skip-case.TXT"), "rb") as f:
            assert f.read() == b"skip compression case test\n" * 100

    def test_skip_compress_empty_list(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-c", "--skip-compress="],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Empty skip-compress sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_skip_compress_incremental_full_fallback(self, shared_server):
        clean_dir(DEST_DIR)
        path = os.path.join(SOURCE_DIR, "incremental-skip.TXT")
        with open(path, "wb") as f:
            f.write(b"original skipped content\n")
        flags = ["-c", "-M", "--skip-compress=.txt"]
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"Initial sync failed: {(result.stderr or result.stdout)[:200]}"
        with open(path, "wb") as f:
            f.write(b"updated skipped content\n")
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=flags + ["--incremental"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Incremental sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        with open(os.path.join(received, "incremental-skip.TXT"), "rb") as f:
            assert f.read() == b"updated skipped content\n"

    def test_skip_compress_rejects_chunk_serialization(self, shared_server):
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-c", "-s", "--skip-compress=.txt"],
            port=shared_server.port,
        )
        assert result.returncode != 0
        assert "cannot be combined" in (result.stderr or result.stdout)


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

    def test_size_only_skips_same_size_with_different_mtime(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-M"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        received_file = os.path.join(received, "small.txt")
        with open(received_file, "wb") as f:
            f.write(b"different!!\n")
        os.utime(received_file, (time.time() - 3600, time.time() - 3600))

        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-M", "--incremental", "--size-only"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Size-only sync failed: {result.stderr[:200]}"
        with open(received_file, "rb") as f:
            assert f.read() == b"different!!\n"

    def test_ignore_times_transfers_same_size_and_mtime(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-M"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        received_file = os.path.join(received, "small.txt")
        source_stat = os.stat(source_file)
        with open(received_file, "wb") as f:
            f.write(b"stale data!\n")
        os.utime(received_file, (source_stat.st_atime, source_stat.st_mtime))

        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["-M", "--incremental", "--ignore-times"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Ignore-times sync failed: {result.stderr[:200]}"
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

    def test_whole_file_disables_delta_and_keeps_compression(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-M"], port=shared_server.port)
        assert result.returncode == 0

        source_file = os.path.join(SOURCE_DIR, "medium.txt")
        with open(source_file, "wb") as f:
            f.write(b"whole-file replacement\n" * 5000)

        result, _ = run_client(
            SOURCE_DIR,
            DEST_DIR,
            flags=["-M", "--incremental", "--delta", "-W", "-c"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Whole-file sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestUpdate:
    def test_update_skips_older_destination_and_allows_equal_or_newer_source(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        received_file = os.path.join(received, "small.txt")
        source_stat = os.stat(source_file)

        with open(received_file, "wb") as f:
            f.write(b"newer destination\n")
        os.utime(received_file, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns + 10_000_000_000))
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
        assert result.returncode == 0
        with open(received_file, "rb") as f:
            assert f.read() == b"newer destination\n"

        os.utime(received_file, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
        assert result.returncode == 0
        with open(received_file, "rb") as f:
            assert f.read() == b"hello world\n"

    def test_update_skips_unreadable_newer_destination(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
        assert result.returncode == 0

        received_file = os.path.join(get_dest_received_dir(DEST_DIR, SOURCE_DIR), "small.txt")
        source_stat = os.stat(os.path.join(SOURCE_DIR, "small.txt"))
        with open(received_file, "wb") as f:
            f.write(b"protected destination\n")
        os.utime(received_file, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns + 10_000_000_000))
        original_mode = os.stat(received_file).st_mode
        try:
            os.chmod(received_file, 0)
            result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
            assert result.returncode == 0
            os.chmod(received_file, original_mode)
            with open(received_file, "rb") as f:
                assert f.read() == b"protected destination\n"
        finally:
            os.chmod(received_file, original_mode)

        with open(received_file, "wb") as f:
            f.write(b"older destination\n")
        os.utime(received_file, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns - 10_000_000_000))
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
        assert result.returncode == 0
        with open(received_file, "rb") as f:
            assert f.read() == b"hello world\n"


class TestExisting:
    def test_existing_updates_existing_and_skips_new(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-M"], port=shared_server.port)
        assert result.returncode == 0, f"Initial sync failed: {(result.stderr or result.stdout)[:200]}"

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        new_source_file = os.path.join(SOURCE_DIR, "new-existing-test.txt")
        with open(source_file, "wb") as f:
            f.write(b"updated existing content\n")
        with open(new_source_file, "wb") as f:
            f.write(b"this file must not be created\n")

        try:
            result, _ = run_client(SOURCE_DIR, DEST_DIR,
                                   flags=["-M", "--existing"], port=shared_server.port)
            assert result.returncode == 0, f"--existing sync failed: {(result.stderr or result.stdout)[:200]}"

            with open(os.path.join(received, "small.txt"), "rb") as f:
                assert f.read() == b"updated existing content\n"
            assert not os.path.exists(os.path.join(received, "new-existing-test.txt"))
        finally:
            os.unlink(new_source_file)
            with open(source_file, "wb") as f:
                f.write(b"hello world\n")


class TestIgnoreExisting:
    def test_ignore_existing_preserves_existing_and_transfers_new(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        existing_file = os.path.join(received, "small.txt")
        with open(existing_file, "wb") as f:
            f.write(b"destination content\n")
        new_source = os.path.join(SOURCE_DIR, "new.txt")
        try:
            with open(new_source, "wb") as f:
                f.write(b"new file\n")

            result, _ = run_client(SOURCE_DIR, DEST_DIR,
                                   flags=["--ignore-existing"], port=shared_server.port)
            assert result.returncode == 0, f"Sync failed: {(result.stderr or result.stdout)[:200]}"
            with open(existing_file, "rb") as f:
                assert f.read() == b"destination content\n"
            with open(os.path.join(received, "new.txt"), "rb") as f:
                assert f.read() == b"new file\n"
        finally:
            if os.path.lexists(new_source):
                os.unlink(new_source)


class TestIgnoreExisting:
    def test_ignore_existing_preserves_existing_and_transfers_new(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        existing_file = os.path.join(received, "small.txt")
        with open(existing_file, "wb") as f:
            f.write(b"destination content\n")
        new_source = os.path.join(SOURCE_DIR, "new.txt")
        try:
            with open(new_source, "wb") as f:
                f.write(b"new file\n")

            result, _ = run_client(SOURCE_DIR, DEST_DIR,
                                   flags=["--ignore-existing"], port=shared_server.port)
            assert result.returncode == 0, f"Sync failed: {(result.stderr or result.stdout)[:200]}"
            with open(existing_file, "rb") as f:
                assert f.read() == b"destination content\n"
            with open(os.path.join(received, "new.txt"), "rb") as f:
                assert f.read() == b"new file\n"
        finally:
            if os.path.lexists(new_source):
                os.unlink(new_source)


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

    def test_human_readable_stats(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-h", "--stats"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert "Stats:" in result.stderr
        assert "KB" in result.stderr

    def test_human_readable_progress_multithreaded(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-m", "-h", "--progress"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        output = result.stdout + result.stderr
        assert "Sent " in output
        assert "KB" in output
        assert "Done." in output


class TestInfo:
    def test_info_copy_reports_transfers(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--info=copy"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Info sync failed: {(result.stderr or result.stdout)[:200]}"
        output = result.stdout + result.stderr
        assert "[INFO]" in output and "Transferring" in output

    def test_info_stats_reports_multithreaded_transfer(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-m", "--info=stats"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Info stats sync failed: {(result.stderr or result.stdout)[:200]}"
        output = result.stdout + result.stderr
        assert "[INFO]" in output and "Transfer summary:" in output

    def test_info_rejects_unknown_flag(self):
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--info=unknown"],
        )
        assert result.returncode != 0
        assert "unsupported --info flag" in result.stderr

    @pytest.mark.parametrize("flags", [
        ["--info=none", "--verbose"],
        ["--verbose", "--info=none"],
    ])
    def test_info_none_suppresses_verbose_info(self, shared_server, flags):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"Info sync failed: {(result.stderr or result.stdout)[:200]}"
        output = result.stdout + result.stderr
        assert "[INFO]" not in output
        assert "Transferring" not in output
        assert "Transfer summary:" not in output


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


def _read_file(path):
    with open(path, "rb") as fh:
        return fh.read()


class TestRemoveSourceFilesSkips:
    """--remove-source-files must not delete sources the receiver skipped
    (rsync reference behavior)."""

    def test_existing_first_sync_keeps_new_source(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_rsf_existing_src")
        dest = os.path.join(TEST_DATA_DIR, "remove_rsf_existing_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "only.txt"), "wb") as f:
            f.write(b"keep me")

        result, _ = run_client(source, dest, flags=["--remove-source-files", "--existing"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Sync failed: {result.stderr[:200]}"
        # The file exists only on the source side, so --existing makes the
        # receiver skip it; the source must therefore not be removed.
        assert os.path.isfile(os.path.join(source, "only.txt"))
        received = get_dest_received_dir(dest, source)
        assert not os.path.exists(os.path.join(received, "only.txt"))

    def test_ignore_existing_keeps_skipped_source(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_rsf_ignore_src")
        dest = os.path.join(TEST_DATA_DIR, "remove_rsf_ignore_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"payload")

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0

        result, _ = run_client(source, dest, flags=["--remove-source-files", "--ignore-existing"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Sync failed: {result.stderr[:200]}"
        # Destination already has the file, so the second run is a receiver
        # skip; the source file must survive.
        assert os.path.isfile(source_file)
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "file.txt")) == b"payload"

    def test_update_newer_destination_keeps_source(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_rsf_update_src")
        dest = os.path.join(TEST_DATA_DIR, "remove_rsf_update_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"source payload")

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(dest, source)
        received_file = os.path.join(received, "file.txt")
        with open(received_file, "wb") as f:
            f.write(b"newer destination payload")
        os.utime(received_file, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))

        result, _ = run_client(source, dest, flags=["--remove-source-files", "--update"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Sync failed: {result.stderr[:200]}"
        # --update skips a destination that is newer than the source, so the
        # source must not be removed.
        assert os.path.isfile(source_file)
        assert _read_file(received_file) == b"newer destination payload"

    def test_multithreaded_ignore_existing_keeps_skipped_source(self, shared_server):
        """The multithreaded writer path must also report per-file outcomes so a
        --remove-source-files sender does not delete skipped sources."""
        source = os.path.join(TEST_DATA_DIR, "remove_rsf_mt_ignore_src")
        dest = os.path.join(TEST_DATA_DIR, "remove_rsf_mt_ignore_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"payload")

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0

        result, _ = run_client(source, dest,
                               flags=["--remove-source-files", "--ignore-existing", "-m"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Sync failed: {result.stderr[:200]}"
        # Destination already has the file, so the receiver (writer thread)
        # skips it; the source must survive.
        assert os.path.isfile(source_file)
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "file.txt")) == b"payload"


class TestBackup:
    def _sync(self, source, dest, flags, port):
        return run_client(source, dest, flags=flags, port=port)

    def test_plain_backup_keeps_previous_version(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "backup_src")
        dest = os.path.join(TEST_DATA_DIR, "backup_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "f.txt")
        with open(source_file, "wb") as f:
            f.write(b"AAAA")

        result, _ = self._sync(source, dest, ["--backup"], shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"

        with open(source_file, "wb") as f:
            f.write(b"BBBB")
        result, _ = self._sync(source, dest, ["--backup"], shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"

        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "f.txt")) == b"BBBB"
        # rsync default suffix "~" keeps the overwritten version.
        assert _read_file(os.path.join(received, "f.txt~")) == b"AAAA"

    def test_backup_custom_suffix(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "backup_suffix_src")
        dest = os.path.join(TEST_DATA_DIR, "backup_suffix_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "f.txt")
        with open(source_file, "wb") as f:
            f.write(b"AAAA")

        flags = ["--backup", "--suffix", ".bak"]
        result, _ = self._sync(source, dest, flags, shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"
        with open(source_file, "wb") as f:
            f.write(b"BBBB")
        result, _ = self._sync(source, dest, flags, shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"

        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "f.txt")) == b"BBBB"
        assert _read_file(os.path.join(received, "f.txt.bak")) == b"AAAA"

    def test_backup_dir_stores_backups_separately(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "backup_dir_src")
        dest = os.path.join(TEST_DATA_DIR, "backup_dir_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "f.txt")
        with open(source_file, "wb") as f:
            f.write(b"AAAA")

        flags = ["--backup", "--backup-dir", "backups"]
        result, _ = self._sync(source, dest, flags, shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"
        with open(source_file, "wb") as f:
            f.write(b"BBBB")
        result, _ = self._sync(source, dest, flags, shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"

        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "f.txt")) == b"BBBB"
        backup = os.path.join(dest, "backups", os.path.relpath(source_file, os.path.sep))
        assert _read_file(backup) == b"AAAA"


class TestPartialDir:
    def test_completed_transfer_installed_in_destination(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "partial_src")
        dest = os.path.join(TEST_DATA_DIR, "partial_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "f.txt")
        with open(source_file, "wb") as f:
            f.write(b"partial payload")

        result, _ = run_client(source, dest, flags=["--partial", "--partial-dir", ".partial"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Partial sync failed: {result.stderr[:200]}"

        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "f.txt")) == b"partial payload"
        # A completed transfer must not remain under the partial directory.
        partial = os.path.join(dest, ".partial", os.path.relpath(source_file, os.path.sep))
        assert not os.path.exists(partial)


class TestLargeFile:
    def test_transfer_100mb_file(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "large_src")
        dest = os.path.join(TEST_DATA_DIR, "large_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "big.bin")
        chunk = os.urandom(1024 * 1024)
        with open(source_file, "wb") as f:
            for _ in range(100):
                f.write(chunk)

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, f"Large-file sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        assert filecmp.cmp(source_file, os.path.join(received, "big.bin"), shallow=False)


class TestOneFileSystem:
    def _make_tree(self, source):
        clean_dir(source)
        os.makedirs(os.path.join(source, "nested", "deeper"))
        with open(os.path.join(source, "root.txt"), "wb") as f:
            f.write(b"root")
        with open(os.path.join(source, "nested", "inner.txt"), "wb") as f:
            f.write(b"inner")
        with open(os.path.join(source, "nested", "deeper", "deep.txt"), "wb") as f:
            f.write(b"deep")

    def _assert_full_tree_transferred(self, source, dest, port, flags):
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=flags, port=port)
        assert result.returncode == 0, f"Sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_x_transfer_matches_plain_over_single_filesystem(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "ofs_src")
        self._make_tree(source)
        self._assert_full_tree_transferred(source, os.path.join(TEST_DATA_DIR, "ofs_dst"),
                                           shared_server.port, ["-x"])

    def test_x_multithreaded_transfer_matches_plain_over_single_filesystem(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "ofs_m_src")
        self._make_tree(source)
        self._assert_full_tree_transferred(source, os.path.join(TEST_DATA_DIR, "ofs_m_dst"),
                                           shared_server.port, ["-m", "--one-file-system"])

    def test_x_skips_other_device_mountpoint(self, shared_server):
        if os.geteuid() != 0 or shutil.which("mount") is None or shutil.which("umount") is None:
            pytest.skip("cross-device test requires root and mount(8)")
        source = os.path.join(TEST_DATA_DIR, "ofs_mnt_src")
        dest = os.path.join(TEST_DATA_DIR, "ofs_mnt_dst")
        dest_plain = os.path.join(TEST_DATA_DIR, "ofs_mnt_plain_dst")
        mountpoint = os.path.join(source, "external")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(dest_plain)
        os.makedirs(mountpoint)
        os.makedirs(os.path.join(source, "nested"))
        with open(os.path.join(source, "root.txt"), "wb") as f:
            f.write(b"root")
        with open(os.path.join(source, "nested", "inner.txt"), "wb") as f:
            f.write(b"inner")
        mounted = False
        unmount_error = ""
        try:
            mount = subprocess.run(["mount", "-t", "tmpfs", "tmpfs", mountpoint],
                                   capture_output=True, text=True)
            if mount.returncode != 0:
                pytest.skip(f"cannot mount tmpfs: {mount.stderr.strip()}")
            mounted = True
            with open(os.path.join(mountpoint, "away.txt"), "wb") as f:
                f.write(b"cross device")
            result, _ = run_client(source, dest, flags=["-x"], port=shared_server.port)
            assert result.returncode == 0, f"-x sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            assert os.path.isfile(os.path.join(received, "root.txt"))
            assert os.path.isfile(os.path.join(received, "nested", "inner.txt"))
            assert not os.path.exists(os.path.join(received, "external", "away.txt")), \
                "-x must not cross into the mounted filesystem"
            result, _ = run_client(source, dest_plain, port=shared_server.port)
            assert result.returncode == 0, f"plain sync failed: {result.stderr[:200]}"
            received_plain = get_dest_received_dir(dest_plain, source)
            assert os.path.isfile(os.path.join(received_plain, "external", "away.txt")), \
                "without -x the mounted subtree must be transferred"
        finally:
            if mounted:
                umount = subprocess.run(["umount", mountpoint], capture_output=True, text=True)
                if umount.returncode != 0:
                    unmount_error = umount.stderr.strip()
        if unmount_error:
            pytest.fail(f"test mountpoint {mountpoint} still mounted after umount: {unmount_error}")
