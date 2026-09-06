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
    get_dest_received_dir, CLIENT_CMD, ServerManager,
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


def _walk_tmp_files(root):
    """Recursively list *.tmp* leftovers under root (empty if root missing)."""
    leftovers = []
    if not os.path.isdir(root):
        return leftovers
    for base, _, files in os.walk(root):
        for name in files:
            if ".tmp." in name:
                leftovers.append(os.path.join(base, name))
    return leftovers


class TestTempDir:
    """--temp-dir=DIR puts the receiver's temporary working copies in a scratch
    directory below the destination root and atomically renames each completed
    file into its final destination.  Files sharing a basename across
    directories exercise the flat scratch namespace."""

    def _make_source(self, name):
        source = os.path.join(TEST_DATA_DIR, name)
        clean_dir(source)
        entries = {
            "top.txt": b"top level\n",
            "sub/file.txt": b"nested file\n" * 20,
            "other/file.txt": b"other nested file\n",
            "sub/deep.bin": bytes(range(256)) * 8,
        }
        for rel, content in entries.items():
            full = os.path.join(source, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(content)
        return source

    def _assert_clean_scratch(self, scratch):
        assert os.path.isdir(scratch), f"scratch dir {scratch} was not created"
        leftovers = _walk_tmp_files(scratch)
        assert leftovers == [], f"leftover temp files in scratch dir: {leftovers}"

    @pytest.mark.parametrize("mt", [False, True])
    def test_temp_dir_scratch(self, shared_server, mt):
        source = self._make_source("tempdir_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_dst")
        clean_dir(dest)
        flags = ["--temp-dir=scratch"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"temp-dir sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        self._assert_clean_scratch(os.path.join(dest, "scratch"))

    def test_default_behavior_has_no_scratch_dir(self, shared_server):
        source = self._make_source("tempdir_default_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_default_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, f"Default sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        assert not os.path.exists(os.path.join(dest, "scratch"))

    def test_temp_dir_ignored_with_inplace(self, shared_server):
        """--inplace writes directly into the destination; --temp-dir must not
        redirect those writes into a scratch dir."""
        source = self._make_source("tempdir_inplace_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_inplace_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest,
                               flags=["--inplace", "--temp-dir=scratch"],
                               port=shared_server.port)
        assert result.returncode == 0, f"inplace+temp-dir sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        assert not os.path.exists(os.path.join(dest, "scratch")), \
            "--inplace wrote through the scratch dir"

    def test_temp_dir_ignored_with_partial_dir(self, shared_server):
        """--partial --partial-dir already stages in a separate directory;
        --temp-dir must not be used on top of it."""
        source = self._make_source("tempdir_partial_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_partial_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest,
                               flags=["--partial", "--partial-dir", ".partial",
                                      "--temp-dir=scratch"],
                               port=shared_server.port)
        assert result.returncode == 0, f"partial+temp-dir sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        partial = os.path.join(dest, ".partial",
                               os.path.relpath(os.path.join(source, "top.txt"), os.path.sep))
        assert not os.path.exists(partial), "completed file remained under the partial dir"
        assert not os.path.exists(os.path.join(dest, "scratch")), \
            "--partial-dir wrote through the scratch dir"

    def test_temp_dir_escape_rejected(self, shared_server):
        source = self._make_source("tempdir_escape_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_escape_dst")
        clean_dir(dest)
        # "../escape" would resolve one level above the destination root.
        outside = os.path.join(TEST_DATA_DIR, "escape")
        assert not os.path.lexists(outside)

        result, _ = run_client(source, dest, flags=["--temp-dir=../escape"],
                               port=shared_server.port)
        assert result.returncode != 0, "relative escaping --temp-dir was not rejected"
        assert not os.path.lexists(outside), "file created outside the destination root"

        clean_dir(dest)
        abs_escape = os.path.join(TEST_DATA_DIR, "abs_escape_probe")
        assert not os.path.lexists(abs_escape)
        result, _ = run_client(source, dest, flags=["--temp-dir", abs_escape],
                               port=shared_server.port)
        assert result.returncode != 0, "absolute --temp-dir was not rejected"
        assert not os.path.lexists(abs_escape), "file created outside the destination root"


def _source_files():
    """All source paths (absolute) that a transfer would send right now."""
    return [
        os.path.join(root, name)
        for root, _dirs, names in os.walk(SOURCE_DIR)
        for name in names
    ]


class TestListOnly:
    """--list-only prints every transfer candidate and changes nothing."""

    def test_list_only_prints_each_file_and_does_not_transfer(self):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--list-only"])
        assert result.returncode == 0, f"list-only failed: {result.stderr[:200]}"
        for full_path in _source_files():
            assert full_path in result.stdout, f"list-only omitted {full_path}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert not os.path.exists(received), "list-only wrote to the destination"

    def test_list_only_with_dry_run_does_not_error(self):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--list-only", "--dry-run"])
        assert result.returncode == 0, f"list-only -n failed: {result.stderr[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert not os.path.exists(received)

    def test_list_only_multithreaded(self):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--list-only", "-m"])
        assert result.returncode == 0, f"list-only -m failed: {result.stderr[:200]}"
        for full_path in _source_files():
            assert full_path in result.stdout, f"list-only -m omitted {full_path}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert not os.path.exists(received), "list-only -m wrote to the destination"


class TestItemizeChanges:
    """-i/--itemize-changes prints rsync-style lines only for files sent."""

    def test_first_run_prints_sent_lines(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["-M", "-i"], port=shared_server.port)
        assert result.returncode == 0, f"itemize sync failed: {result.stderr[:200]}"
        sent_lines = {">f+++++++++ " + p for p in _source_files()}
        assert sent_lines <= set(result.stdout.splitlines()), (
            f"missing itemize lines; got {result.stdout[:500]}"
        )

    def test_incremental_second_run_prints_no_line_for_unchanged(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-M"], port=shared_server.port)
        assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["-M", "-i", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, f"incremental itemize failed: {result.stderr[:200]}"
        itemized = [line for line in result.stdout.splitlines() if line and line[0] in ">.<c"]
        assert itemized == [], f"unchanged files were itemized: {itemized[:5]}"

    def test_multithreaded_emits_same_itemize_lines(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["-M", "-i", "-m"], port=shared_server.port)
        assert result.returncode == 0, f"itemize -m sync failed: {result.stderr[:200]}"
        sent_lines = {">f+++++++++ " + p for p in _source_files()}
        assert sent_lines <= set(result.stdout.splitlines()), (
            f"missing itemize lines in -m mode; got {result.stdout[:500]}"
        )

    def test_dry_run_with_itemize_does_not_error(self):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-i", "--dry-run"])
        assert result.returncode == 0, f"dry-run -i failed: {result.stderr[:200]}"

    def test_changed_file_on_second_incremental_run_prints_exactly_one_line(self, shared_server):
        """A changed file itemizes exactly once on an incremental rerun while
        unchanged files print nothing (no double emission)."""
        source = os.path.join(TEST_DATA_DIR, "itemize_change_src")
        dest = os.path.join(TEST_DATA_DIR, "itemize_change_dst")
        clean_dir(source)
        clean_dir(dest)
        changed = os.path.join(source, "changed.txt")
        untouched = os.path.join(source, "untouched.txt")
        with open(changed, "wb") as fh:
            fh.write(b"original\n")
        with open(untouched, "wb") as fh:
            fh.write(b"stable\n")

        result, _ = run_client(source, dest, flags=["-M"], port=shared_server.port)
        assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"

        with open(changed, "wb") as fh:
            fh.write(b"edited payload\n")

        result, _ = run_client(source, dest,
                               flags=["-M", "-i", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, f"incremental itemize failed: {result.stderr[:200]}"
        itemized = [line for line in result.stdout.splitlines() if line.startswith(">f")]
        assert itemized == [">f+++++++++ " + changed], (
            f"expected exactly one itemize line for {changed}, got {itemized}"
        )
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "changed.txt")) == b"edited payload\n"
        assert _read_file(os.path.join(received, "untouched.txt")) == b"stable\n"


class TestOutFormat:
    """--out-format prints a line per transferred file using the template."""

    def test_out_format_path_and_size(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--out-format=%f %l"], port=shared_server.port)
        assert result.returncode == 0, f"out-format sync failed: {result.stderr[:200]}"
        expected = {f"{p} {os.path.getsize(p)}" for p in _source_files()}
        got = set(result.stdout.splitlines())
        assert expected <= got, f"out-format lines missing: expected {len(expected)} got {len(got)}"

    def test_out_format_multithreaded_matches_single(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--out-format=%f %l", "-m"], port=shared_server.port)
        assert result.returncode == 0, f"out-format -m sync failed: {result.stderr[:200]}"
        expected = {f"{p} {os.path.getsize(p)}" for p in _source_files()}
        got = set(result.stdout.splitlines())
        assert expected <= got, f"out-format -m lines missing: {result.stdout[:500]}"


class TestLogFileFormat:
    """--log-file plus --log-file-format writes per-file lines to the log."""

    def test_log_file_format_writes_transferred_files(self, shared_server):
        clean_dir(DEST_DIR)
        log_path = os.path.join(TEST_DATA_DIR, "itemize_transfer.log")
        if os.path.exists(log_path):
            os.unlink(log_path)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--log-file", log_path, "--log-file-format=%f %l"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"log-file sync failed: {result.stderr[:200]}"
        assert os.path.exists(log_path), "--log-file created no log"
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        expected = {f"{p} {os.path.getsize(p)}" for p in _source_files()}
        for line in expected:
            assert line in content, f"log file missing {line!r}"

    def test_log_file_format_multithreaded_writes_transferred_files(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "itemize_log_mt_src")
        dest = os.path.join(TEST_DATA_DIR, "itemize_log_mt_dst")
        clean_dir(source)
        clean_dir(dest)
        files = {"a.txt": b"alpha\n", "b.txt": b"beta\n"}
        for rel, data in files.items():
            with open(os.path.join(source, rel), "wb") as fh:
                fh.write(data)
        log_path = os.path.join(TEST_DATA_DIR, "itemize_mt.log")
        if os.path.exists(log_path):
            os.unlink(log_path)
        result, _ = run_client(
            source,
            dest,
            flags=["--log-file", log_path, "--log-file-format=%f %l", "-m"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"log-file -m sync failed: {result.stderr[:200]}"
        assert os.path.exists(log_path), "--log-file created no log"
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        expected = {f"{os.path.join(source, rel)} {len(data)}" for rel, data in files.items()}
        for line in expected:
            assert line in content, f"log file (-m) missing {line!r}"


class TestDelayUpdates:
    """--delay-updates stages every updated file under a private 0700 staging
    directory inside the receive root and atomically publishes all of them only
    after the whole transfer succeeds."""

    STAGING = ".fastsync-stage"

    def _make_source(self, name):
        source = os.path.join(TEST_DATA_DIR, name)
        clean_dir(source)
        entries = {
            "top.txt": b"top level\n",
            "sub/deep.txt": b"deeply nested file\n",
            "sub/another.txt": b"another nested file\n" * 20,
            "binary.bin": bytes(range(256)) * 4,
        }
        for rel, content in entries.items():
            full = os.path.join(source, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(content)
        return source

    @pytest.mark.parametrize("mt", [False, True])
    def test_delay_updates_matches_plain_transfer(self, shared_server, mt):
        source = self._make_source("delay_match_src")
        plain_dest = os.path.join(TEST_DATA_DIR, "delay_match_plain_dst")
        delay_dest = os.path.join(TEST_DATA_DIR, "delay_match_delay_dst")
        clean_dir(plain_dest)
        clean_dir(delay_dest)

        result, _ = run_client(source, plain_dest, port=shared_server.port)
        assert result.returncode == 0, f"plain sync failed: {result.stderr[:200]}"
        flags = ["--delay-updates"] + (["-m"] if mt else [])
        result, _ = run_client(source, delay_dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"delay-updates sync failed: {result.stderr[:200]}"

        plain_received = get_dest_received_dir(plain_dest, source)
        delay_received = get_dest_received_dir(delay_dest, source)
        mismatches, missing = verify_transfer(source, delay_received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        for root, _dirs, files in os.walk(delay_received):
            for name in files:
                rel = os.path.relpath(os.path.join(root, name), delay_received)
                assert filecmp.cmp(os.path.join(plain_received, rel),
                                   os.path.join(delay_received, rel), shallow=False), rel
        assert not os.path.isdir(os.path.join(delay_dest, self.STAGING)), \
            "staging directory left behind after a successful delayed transfer"

    @pytest.mark.parametrize("mt", [False, True])
    def test_delay_updates_incremental_rerun_no_leftovers(self, shared_server, mt):
        source = self._make_source("delay_rerun_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_rerun_dst")
        clean_dir(dest)
        flags = ["--delay-updates", "-M", "--incremental"] + (["-m"] if mt else [])

        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"first delayed sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing and not mismatches
        assert not os.path.isdir(os.path.join(dest, self.STAGING))

        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"second delayed sync failed: {result.stderr[:200]}"
        assert not os.path.isdir(os.path.join(dest, self.STAGING)), \
            "fully-skipped delayed run left a staging directory"

    @pytest.mark.parametrize("mt", [False, True])
    def test_remove_source_files_with_delay_updates(self, shared_server, mt):
        source = self._make_source("delay_rsf_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_rsf_dst")
        clean_dir(dest)
        flags = ["--remove-source-files", "--delay-updates"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"delayed remove-source sync failed: {result.stderr[:200]}"

        # Sources are removed only after the receiver published every file.
        for root, _dirs, files in os.walk(source):
            assert files == [], f"source files survived delayed remove-source-files: {files}"
        received = get_dest_received_dir(dest, source)
        assert os.path.isfile(os.path.join(received, "top.txt"))
        assert os.path.isfile(os.path.join(received, "sub", "deep.txt"))
        assert not os.path.isdir(os.path.join(dest, self.STAGING))

    @pytest.mark.parametrize("mt", [False, True])
    def test_delete_with_delay_updates(self, mt):
        """--delete runs before publication, so the delete walker must not treat
        the staging directory as a set of extras: a changed file must still be
        published after genuine extras are removed.  Uses its own server started
        with --allow-delete (the shared session server refuses deletion)."""
        source = os.path.join(TEST_DATA_DIR, "delay_delete_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_delete_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "f.txt"), "wb") as fh:
            fh.write(b"AAAA")
        with open(os.path.join(source, "extra.txt"), "wb") as fh:
            fh.write(b"seed extra")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            assert _read_file(os.path.join(received, "extra.txt")) == b"seed extra"

            # Second source state: f.txt changed, extra.txt removed from source.
            with open(os.path.join(source, "f.txt"), "wb") as fh:
                fh.write(b"BBBB")
            os.remove(os.path.join(source, "extra.txt"))

            flags = ["--delete", "--delay-updates"] + (["-m"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"delete+delay-updates sync failed: {result.stderr[:200]}"
            assert _read_file(os.path.join(received, "f.txt")) == b"BBBB", \
                "changed file was not published after deletion"
            assert not os.path.exists(os.path.join(received, "extra.txt")), \
                "genuine extra file was not deleted"
            assert not os.path.isdir(os.path.join(dest, self.STAGING))

    def test_delay_updates_rejects_reserved_backup_dir(self):
        """--backup-dir equal to the internal staging name must be rejected so
        an old backup can never be silently installed as the "new" file."""
        source = self._make_source("delay_reserved_bak_src")
        for variant, suffix in (("bare", ""), ("slash", "/")):
            dest = os.path.join(TEST_DATA_DIR, f"delay_reserved_bak_{variant}_dst")
            clean_dir(dest)
            flags = ["--delay-updates", "--backup", "--backup-dir",
                     ".fastsync-stage" + suffix]
            result, _ = run_client(source, dest, flags=flags, port=None)
            assert result.returncode != 0, \
                f"reserved --backup-dir '{suffix}' was accepted"
            assert not os.path.isdir(os.path.join(dest, self.STAGING)), \
                "staging directory created by a rejected run"

    @pytest.mark.parametrize("remove_source_files", [False, True])
    @pytest.mark.parametrize("mt", [False, True])
    def test_mid_publish_failure_keeps_published_no_rollback(self, shared_server, mt,
                                                             remove_source_files):
        """A stage->publish rename failing part way through publication must
        fail the whole transfer, keep the already-published top-level file (no
        rollback), leave the not-yet-published nested file absent, and clean up
        the staging area.  A regular file is planted where the final "sub"
        directory must be created, so the nested rename fails (mkdir over a
        file is impossible even for root) while the top-level file, which is
        always staged first, publishes.  With --remove-source-files the sender
        must keep every source because no success/outcome frame is ever sent."""
        source = os.path.join(TEST_DATA_DIR, "delay_mid_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_mid_dst")
        clean_dir(source)
        clean_dir(dest)
        top_path = os.path.join(source, "top.txt")
        deep_path = os.path.join(source, "sub", "deep.txt")
        with open(top_path, "wb") as fh:
            fh.write(b"top payload\n")
        os.makedirs(os.path.dirname(deep_path))
        with open(deep_path, "wb") as fh:
            fh.write(b"deep payload\n")

        received = get_dest_received_dir(dest, source)
        os.makedirs(received)
        with open(os.path.join(received, "sub"), "wb") as fh:
            fh.write(b"blocks the nested destination directory")

        flags = ["--delay-updates"] + (["-m"] if mt else [])
        if remove_source_files:
            flags += ["--remove-source-files"]
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode != 0, "blocked nested publish did not fail"

        # The top-level file was published before the nested rename failed and
        # is intentionally NOT rolled back.
        assert _read_file(os.path.join(received, "top.txt")) == b"top payload\n"
        # The nested file was never published.
        assert not os.path.lexists(os.path.join(received, "sub", "deep.txt")), \
            "nested file appeared despite a failed publish"
        assert not os.path.isdir(os.path.join(dest, self.STAGING)), \
            "staging leftovers after a failed mid-publish"
        # Sources survive: no success frame was sent, so a remove-source-files
        # sender must not delete anything.
        assert os.path.isfile(top_path)
        assert os.path.isfile(deep_path)

    @pytest.mark.parametrize("mt", [False, True])
    def test_remove_source_files_keeps_receiver_skipped_source(self, shared_server, mt):
        """With --delay-updates + --ignore-existing a receiver-skipped source
        must survive (its outcome is sent only after publication) while a
        freshly delivered file is published and its source removed."""
        source = os.path.join(TEST_DATA_DIR, "delay_rsf_skip_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_rsf_skip_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"existing on dest")
        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"

        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"changed on source")
        with open(os.path.join(source, "deliver.txt"), "wb") as fh:
            fh.write(b"new file")
        flags = ["--remove-source-files", "--ignore-existing", "--delay-updates"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"delayed skip sync failed: {result.stderr[:200]}"
        # keep.txt already existed at the destination: receiver skip -> source stays.
        assert os.path.isfile(os.path.join(source, "keep.txt")), \
            "receiver-skipped source was removed despite --ignore-existing"
        # deliver.txt was new: staged, published, and its source removed.
        assert not os.path.isfile(os.path.join(source, "deliver.txt")), \
            "published source was not removed"
        received = get_dest_received_dir(dest, source)
        assert not os.path.isdir(os.path.join(dest, self.STAGING))

    def test_delay_updates_rejects_inplace(self):
        source = self._make_source("delay_inplace_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_inplace_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["--delay-updates", "--inplace"])
        assert result.returncode != 0, "--inplace with --delay-updates was accepted"
        assert not os.path.isdir(os.path.join(dest, self.STAGING))

class TestFilesFrom:
    """--files-from transfers exactly the listed files; a listed directory
    transfers its whole subtree. The manifest (and thus --delete) derives from
    what was actually sent."""


def _make_relative_source(name):
    """A small tree used by the -R/--dirs/--no-implied-dirs tests."""
    source = os.path.join(TEST_DATA_DIR, name)
    clean_dir(source)
    entries = {
        "top.txt": b"top\n",
        "a/b.txt": b"nested\n",
        "sub/x.txt": b"x\n",
        "sub/y.txt": b"y\n",
        "dir1/keep.txt": b"dir content\n",
    }
    for rel, content in entries.items():
        full = os.path.join(source, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(content)
    return source


def _write_rel_list(rel_text):
    path = os.path.join(TEST_DATA_DIR, "rel_list.txt")
    with open(path, "wb") as fh:
        fh.write(rel_text)
    return path


class TestRelativeFilesFrom:
    """-R/--relative with --files-from keeps each listed entry's bare relative
    destination path below the destination root instead of mirroring the full
    source path.  Without -R the layout is unchanged (full source mirror)."""

    @pytest.mark.parametrize("mt", [False, True])
    def test_relative_files_from_keeps_relative_layout(self, shared_server, mt):
        source = _make_relative_source("rel_src")
        dest = os.path.join(TEST_DATA_DIR, "rel_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"top.txt\nsub/x.txt\n")
        flags = ["--files-from", lst, "-R"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"-R files-from sync failed: {result.stderr[:200]}"
        assert _read_file(os.path.join(dest, "sub", "x.txt")) == b"x\n", \
            "listed file must land at <dest>/sub/x.txt"
        assert _read_file(os.path.join(dest, "top.txt")) == b"top\n", \
            "top-level listed file must land at <dest>/top.txt"
        assert not os.path.exists(os.path.join(dest, "sub", "y.txt"))
        # The source-root mirror must not be reproduced under -R.
        assert not os.path.exists(get_dest_received_dir(dest, source)), \
            "-R must not mirror the full source path"

    @pytest.mark.parametrize("mt", [False, True])
    def test_relative_without_files_from_has_no_effect(self, shared_server, mt):
        """-R alone (no --files-from) must leave the normal full-source mirror
        layout untouched."""
        source = _make_relative_source("rel_only_src")
        dest = os.path.join(TEST_DATA_DIR, "rel_only_dst")
        clean_dir(dest)
        flags = ["-R"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"-R alone sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing and not mismatches

    @pytest.mark.parametrize("mt", [False, True])
    def test_without_relative_layout_unchanged(self, shared_server, mt):
        source = _make_relative_source("rel_noR_src")
        dest = os.path.join(TEST_DATA_DIR, "rel_noR_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"sub/x.txt\n")
        flags = ["--files-from", lst] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"files-from sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "sub", "x.txt")) == b"x\n", \
            "without -R the full source mirror layout is preserved"
        assert not os.path.exists(os.path.join(dest, "sub")), \
            "bare relative layout must not appear without -R"

    def test_relative_delete_manifest_stays_consistent(self):
        """--delete derives from the sent (-R) relative paths, so a later
        subset run removes unlisted relative entries but keeps listed ones."""
        source = _make_relative_source("rel_del_src")
        dest = os.path.join(TEST_DATA_DIR, "rel_del_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            lst = _write_rel_list(b"sub/x.txt\nsub/y.txt\n")
            result, _ = run_client(source, dest, flags=["--files-from", lst, "-R"],
                                   port=server.port)
            assert result.returncode == 0, f"seed -R sync failed: {result.stderr[:200]}"
            assert os.path.isfile(os.path.join(dest, "sub", "y.txt"))

            subset = _write_rel_list(b"sub/x.txt\n")
            result, _ = run_client(source, dest,
                                   flags=["--files-from", subset, "-R", "--delete"],
                                   port=server.port)
            assert result.returncode == 0, f"-R delete sync failed: {result.stderr[:200]}"
            assert os.path.isfile(os.path.join(dest, "sub", "x.txt")), "listed file was deleted"
            assert not os.path.exists(os.path.join(dest, "sub", "y.txt")), \
                "unlisted relative file was not deleted"


class TestNoImpliedDirs:
    """--no-implied-dirs (only meaningful with -R + --files-from) refuses to
    place a listed file whose parent directory is not itself listed."""

    def _make(self):
        return _make_relative_source("noimplied_src")

    @pytest.mark.parametrize("mt", [False, True])
    def test_implied_dir_only_fails_entry(self, shared_server, mt):
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "noimplied_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"a/b.txt\n")  # "a" itself is not listed
        flags = ["--files-from", lst, "-R", "--no-implied-dirs"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode != 0, "implied parent directory was not rejected"
        assert "--no-implied-dirs" in (result.stderr or result.stdout)
        assert not os.path.exists(os.path.join(dest, "a", "b.txt"))

    @pytest.mark.parametrize("mt", [False, True])
    def test_listed_dir_allows_file(self, shared_server, mt):
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "noimplied_ok_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"a\na/b.txt\n")
        flags = ["--files-from", lst, "-R", "--no-implied-dirs"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"listed dir + file sync failed: {result.stderr[:200]}"
        assert _read_file(os.path.join(dest, "a", "b.txt")) == b"nested\n"

    @pytest.mark.parametrize("mt", [False, True])
    def test_no_implied_dirs_without_relative_changes_nothing(self, shared_server, mt):
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "noimplied_noR_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"a/b.txt\n")
        flags = ["--files-from", lst, "--no-implied-dirs"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, "--no-implied-dirs without -R changed behavior"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "a", "b.txt")) == b"nested\n"


class TestDirs:
    """-d/--dirs (and the --old-dirs/--old-d aliases) transfer directory entries
    without recursing into their contents."""

    def _make(self):
        return _make_relative_source("dirs_src")

    def _assert_only_empty_mirror(self, dest, source):
        mirror = get_dest_received_dir(dest, source)
        assert os.path.isdir(mirror), "source-root mirror directory was not created"
        files = []
        for root, _dirs, names in os.walk(mirror):
            files.extend(os.path.relpath(os.path.join(root, n), mirror) for n in names)
        assert files == [], f"--dirs descended into contents: {files}"

    @pytest.mark.parametrize("flag", ["--dirs", "-d", "--old-dirs", "--old-d"])
    @pytest.mark.parametrize("mt", [False, True])
    def test_dirs_transfers_empty_dir_only(self, shared_server, flag, mt):
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_dst")
        clean_dir(dest)
        flags = [flag] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"{flag} sync failed: {result.stderr[:200]}"
        self._assert_only_empty_mirror(dest, source)

    @pytest.mark.parametrize("mt", [False, True])
    def test_dirs_with_files_from(self, shared_server, mt):
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_ff_dst")
        clean_dir(dest)
        # A listed directory is created empty; a listed file is transferred.
        lst = _write_rel_list(b"dir1\nsub/x.txt\n")
        flags = ["--files-from", lst, "--dirs", "-R"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"dirs files-from sync failed: {result.stderr[:200]}"
        assert os.path.isdir(os.path.join(dest, "dir1")), "listed dir was not created"
        assert not os.path.exists(os.path.join(dest, "dir1", "keep.txt")), \
            "--dirs must not descend into a listed directory"
        assert _read_file(os.path.join(dest, "sub", "x.txt")) == b"x\n", \
            "listed file content was not transferred"
        assert not os.path.exists(os.path.join(dest, "sub", "y.txt")), \
            "unlisted file appeared"

    @pytest.mark.parametrize("mt", [False, True])
    def test_dirs_with_files_from_mirror_layout(self, shared_server, mt):
        """Without -R the dirs+files-from entries still mirror the source path."""
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_ff_noR_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"dir1\n")
        flags = ["--files-from", lst, "--dirs"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"dirs files-from no-R sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        assert os.path.isdir(os.path.join(received, "dir1")), "mirrored dir entry not created"
        assert not os.path.exists(os.path.join(received, "dir1", "keep.txt")), \
            "--dirs must not descend into a listed directory"
        assert not os.path.exists(os.path.join(received, "sub")), \
            "unlisted subtree appeared"

    @pytest.mark.parametrize("mt", [False, True])
    def test_dirs_chunk_serialization(self, shared_server, mt):
        """--dirs entries survive the chunk-serialization wire path (type
        marker round-trips); a listed dir lands empty and a listed file lands
        with content, with no protocol desync under -s -m."""
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_s_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"dir1\nsub/x.txt\n")
        flags = ["--files-from", lst, "--dirs", "-R", "-s"] + (["-m"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"dirs -s sync failed: {result.stderr[:200]}"
        assert os.path.isdir(os.path.join(dest, "dir1")), "listed dir was not created"
        assert not os.path.exists(os.path.join(dest, "dir1", "keep.txt")), \
            "--dirs must not descend into a listed directory"
        assert _read_file(os.path.join(dest, "sub", "x.txt")) == b"x\n", \
            "listed file content was not transferred"

    def test_dirs_delete_keeps_transferred_empty_dir(self):
        """Directory entries appear in the delete manifest, so the empty dir a
        --dirs run just created is not pruned as an extra by --delete."""
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_del_dst")
        clean_dir(dest)
        extra = os.path.join(dest, "extra.txt")
        with open(extra, "wb") as fh:
            fh.write(b"delete me")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["--dirs", "--delete"],
                                   port=server.port)
            assert result.returncode == 0, f"--dirs --delete sync failed: {result.stderr[:200]}"
            assert not os.path.exists(extra), "--delete did not remove the extra file"
            mirror = get_dest_received_dir(dest, source)
            assert os.path.isdir(mirror), "transferred empty dir was pruned as an extra"
            files = []
            for root, _dirs, names in os.walk(mirror):
                files.extend(os.path.relpath(os.path.join(root, n), mirror) for n in names)
            assert files == [], f"--dirs descended into contents: {files}"

    def test_dirs_listed_dir_colliding_with_file_fails(self, shared_server):
        """A listed directory that already exists as a regular file at the
        destination fails the transfer cleanly instead of clobbering the file."""
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_coll_dst")
        clean_dir(dest)
        blocker = os.path.join(dest, "dir1")
        with open(blocker, "wb") as fh:
            fh.write(b"blocking file")
        lst = _write_rel_list(b"dir1\n")
        result, _ = run_client(source, dest, flags=["--files-from", lst, "--dirs", "-R"],
                               port=shared_server.port)
        assert result.returncode != 0, "dir entry over an existing file did not fail"
        assert os.path.isfile(blocker), "blocking regular file was clobbered"


class TestMkpath:
    """--mkpath tells the server to create the destination root directory (and
    missing leading components) when it does not exist yet; without it a missing
    destination root fails the transfer."""

    @pytest.mark.parametrize("mt", [False, True])
    def test_missing_root_fails_without_mkpath(self, mt):
        source = _make_relative_source("mkpath_fail_src")
        dest = os.path.join(TEST_DATA_DIR, "mkpath_missing_dst")
        shutil.rmtree(dest, ignore_errors=True)
        with ServerManager() as server:
            server.start()
            flags = ["-m"] if mt else []
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode != 0, "missing destination root did not fail without --mkpath"
            assert not os.path.exists(dest), "missing root was created without --mkpath"

    @pytest.mark.parametrize("mt", [False, True])
    def test_mkpath_creates_missing_root(self, mt):
        source = _make_relative_source("mkpath_ok_src")
        dest = os.path.join(TEST_DATA_DIR, "deep", "mkpath_dst")
        shutil.rmtree(os.path.join(TEST_DATA_DIR, "deep"), ignore_errors=True)
        with ServerManager() as server:
            server.start()
            flags = ["--mkpath"] + (["-m"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, f"--mkpath sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            assert _read_file(os.path.join(received, "sub", "x.txt")) == b"x\n", \
                "file not transferred into the --mkpath-created root"

    @pytest.mark.parametrize("mkpath", [False, True])
    def test_existing_dest_with_trailing_slash(self, shared_server, mkpath):
        """A destination root written with a trailing slash must keep working:
        an existing root is accepted both with and without --mkpath."""
        source = _make_relative_source("mkpath_trail_src")
        dest = os.path.join(TEST_DATA_DIR, "mkpath_trail_dst")
        clean_dir(dest)
        dest_slash = dest + "/"
        flags = ["--mkpath"] if mkpath else []
        result, _ = run_client(source, dest_slash, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"trailing-slash dest sync (mkpath={mkpath}) failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "sub", "x.txt")) == b"x\n", \
            "file not transferred into the trailing-slash destination root"

    @pytest.mark.parametrize("mkpath", [False, True])
    def test_dest_equal_authorized_root(self, mkpath):
        """A destination that is exactly the server's authorized root works
        without --mkpath, and with --mkpath creates no stray <root>/<basename>
        nested directory."""
        root = os.path.join(TEST_DATA_DIR, "mkpath_eq_root")
        clean_dir(root)
        source = _make_relative_source("mkpath_eq_src")
        with ServerManager() as server:
            server.start(extra_args=["--destination-root", root])
            flags = ["--mkpath"] if mkpath else []
            result, _ = run_client(source, root, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"dest==authorized-root sync (mkpath={mkpath}) failed: {result.stderr[:200]}"
            received = get_dest_received_dir(root, source)
            assert _read_file(os.path.join(received, "sub", "x.txt")) == b"x\n", \
                "file not transferred when the dest equals the authorized root"
            basename = os.path.basename(root.rstrip(os.sep))
            assert not os.path.exists(os.path.join(root, basename)), \
                "--mkpath created a spurious nested <root>/<basename> directory"


class TestFilters:
    """--filter/-C/-F rule layer: excludes prune, ordering is first-match-wins,
    the default with no matching rule is include, and legacy --exclude remains
    an independent layer."""


class TestDeleteTiming:
    """rsync deletion-timing family.  --delete-before/--delete-during transmit
    the keep-set manifest BEFORE any file data (the receiver deletes extras and
    acks first); --delete/--delete-after/--delete-delay commit deletions only
    after the whole transfer succeeded.  Every timing flag implies --delete."""

    def _seed(self, tag):
        source = os.path.join(TEST_DATA_DIR, f"deltiming_{tag}_src")
        clean_dir(source)
        entries = {
            "top.txt": b"top level\n",
            "sub/deep.txt": b"deeply nested file\n",
        }
        for rel, content in entries.items():
            full = os.path.join(source, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(content)
        return source

    @pytest.mark.parametrize("flag", ["--delete-before", "--delete-during", "--del",
                                      "--delete-after", "--delete-delay"])
    @pytest.mark.parametrize("mt", [False, True])
    def test_flag_removes_extras_on_success(self, flag, mt):
        """Every timing flag is accepted, implies --delete, and on a successful
        transfer removes the destination extras exactly like plain --delete."""
        source = self._seed("ok")
        dest = os.path.join(TEST_DATA_DIR, "deltiming_ok_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            extra = os.path.join(received, "extra.txt")
            with open(extra, "wb") as fh:
                fh.write(b"should be deleted")

            flags = [flag] + (["-m"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"{flag} sync failed: {(result.stderr or result.stdout)[:300]}"
            assert not os.path.exists(extra), f"{flag} did not remove the extra file"
            mismatches, missing = verify_transfer(source, received)
            assert not missing, f"{flag} missing files: {missing}"
            assert not mismatches, f"{flag} mismatched files: {mismatches}"

    @pytest.mark.parametrize("flag", ["--delete-before", "--delete-during", "--del"])
    @pytest.mark.parametrize("mt", [False, True])
    def test_early_flags_delete_before_data(self, flag, mt):
        """--delete-before/--delete-during remove extras (and a file blocking a
        destination directory) BEFORE data is applied, so a nested write that
        would fail while the blocker still exists succeeds."""
        source = self._seed("early")
        dest = os.path.join(TEST_DATA_DIR, "deltiming_early_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            extra = os.path.join(received, "extra.txt")
            with open(extra, "wb") as fh:
                fh.write(b"extra file")
            blocker = os.path.join(received, "sub")
            shutil.rmtree(blocker)
            with open(blocker, "wb") as fh:
                fh.write(b"blocks the nested destination directory")

            flags = [flag] + (["-m"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"{flag} (early delete) did not remove the blocker in time: " \
                f"{(result.stderr or result.stdout)[:300]}"
            assert not os.path.exists(extra), f"{flag} did not delete the extra before data"
            assert _read_file(os.path.join(received, "sub", "deep.txt")) == b"deeply nested file\n", \
                f"{flag}: nested file was not written after the early deletion"

    @pytest.mark.parametrize("flag", ["--delete", "--delete-after", "--delete-delay"])
    def test_late_flags_commit_only_after_success(self, flag):
        """Plain --delete/--delete-after/--delete-delay defer deletion until the
        whole transfer succeeds: a mid-transfer write failure must leave every
        extra in place (commit-style safety)."""
        source = self._seed("late")
        dest = os.path.join(TEST_DATA_DIR, "deltiming_late_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            extra = os.path.join(received, "extra.txt")
            with open(extra, "wb") as fh:
                fh.write(b"extra file")
            blocker = os.path.join(received, "sub")
            shutil.rmtree(blocker)
            with open(blocker, "wb") as fh:
                fh.write(b"blocks the nested destination directory")

            result, _ = run_client(source, dest, flags=[flag], port=server.port)
            assert result.returncode != 0, \
                f"{flag} unexpectedly succeeded (deletion must be deferred)"
            assert os.path.exists(extra), \
                f"{flag} removed an extra although the transfer failed"
            assert os.path.isfile(blocker), \
                f"{flag} deleted the blocker although the transfer failed"

    def test_early_flag_respected_when_server_refuses_delete(self, shared_server):
        """With an --allow-delete-less server the client's early timing still
        completes (no deadlock on the pre-delete ack) and simply never deletes,
        exactly like the plain server policy."""
        source = self._seed("refused")
        dest = os.path.join(TEST_DATA_DIR, "deltiming_refused_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        extra = os.path.join(received, "extra.txt")
        with open(extra, "wb") as fh:
            fh.write(b"extra file")
        result, _ = run_client(source, dest, flags=["--delete-before"], port=shared_server.port)
        assert result.returncode == 0, \
            f"--delete-before against a refuse-delete server failed: {result.stderr[:300]}"
        assert os.path.exists(extra), "unauthorized delete removed an extra file"
