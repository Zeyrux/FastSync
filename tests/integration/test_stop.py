"""--stop-after / --stop-at deadline-stop integration tests.

These cover the client-only sender stop conditions: --stop-after=MINS stops
after N elapsed minutes, --stop-at=HH:MM[:SS] or now+N[smhd] stops at an
absolute (or relative) wall-clock time.  A reached deadline ends the transfer
elegantly at the next chunk/file boundary -- whatever was already transferred is
kept, the completion tail still runs, and the exit code is 0 (like rsync's
clean "stopped early" behavior).  Malformed values are rejected up front.
"""
import os
import shutil
import time

import pytest

from common import (
    TEST_DATA_DIR,
    run_client,
    clean_dir,
    get_dest_received_dir,
    verify_transfer,
)


def _make(self_prefix):
    source = os.path.join(TEST_DATA_DIR, f"stop_{self_prefix}_src")
    dest = os.path.join(TEST_DATA_DIR, f"stop_{self_prefix}_dst")
    clean_dir(source)
    shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest)
    return source, dest


def _received_files(root):
    """All files under `root`, relative paths."""
    if not os.path.isdir(root):
        return []
    return [
        os.path.relpath(os.path.join(dirpath, name), root)
        for dirpath, _, names in os.walk(root)
        for name in names
    ]


def _seed_source(source):
    """Create a handful of regular and nested files."""
    files = {
        "small.txt": b"hello world\n",
        "medium.txt": b"the quick brown fox jumps over the lazy dog\n" * 400,
        "binary.bin": bytes(range(256)) * 100,
        "nested/deep.txt": b"deeply nested file\n",
        "nested/another.txt": b"another nested file\n" * 40,
    }
    for rel, content in files.items():
        path = os.path.join(source, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(content)


class TestStopAfter:
    @pytest.mark.ci
    def test_stop_after_within_window(self, shared_server):
        """A --stop-after set well past the run's duration lets it finish fully."""
        source, dest = _make("within")
        _seed_source(source)
        result, _ = run_client(source, dest, flags=["--stop-after=60"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"--stop-after full run failed: {(result.stderr or result.stdout)[:400]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not mismatches and not missing, \
            f"full transfer mismatch: missing={missing} mismatches={mismatches}"

    @pytest.mark.ci
    def test_stop_after_rejects_nonpositive(self, shared_server):
        """0 and negative minutes are invalid (must be a positive integer)."""
        source, dest = _make("reject")
        _seed_source(source)
        for bad in ("0", "-1"):
            result, _ = run_client(source, dest, flags=[f"--stop-after={bad}"],
                                   port=shared_server.port)
            assert result.returncode != 0, f"--stop-after={bad} should be rejected"


class TestStopAt:
    @pytest.mark.ci
    def test_stop_at_past(self, shared_server):
        """A --stop-at already in the past stops the transfer immediately but
        cleanly (exit 0, nothing transferred)."""
        source, dest = _make("past")
        _seed_source(source)
        now = time.localtime()
        if now.tm_hour * 60 + now.tm_min >= 1:
            past = time.localtime(time.time() - 120)
            stop_value = f"{past.tm_hour:02d}:{past.tm_min:02d}"
        else:
            stop_value = "now+0s"  # first minute of the day: use "immediately now"
        result, _ = run_client(source, dest, flags=[f"--stop-at={stop_value}"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"--stop-at past run failed (rc {result.returncode}): " \
            f"{(result.stderr or result.stdout)[:400]}"
        received = get_dest_received_dir(dest, source)
        assert _received_files(received) == [], \
            f"expected nothing transferred, got {_received_files(received)}"

    @pytest.mark.ci
    def test_stop_at_now_plus_stops_immediately(self, shared_server):
        """now+0s resolves to the current instant, so the transfer stops at once."""
        source, dest = _make("nowplus")
        _seed_source(source)
        result, _ = run_client(source, dest, flags=["--stop-at=now+0s"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"--stop-at=now+0s should stop cleanly: " \
            f"{(result.stderr or result.stdout)[:400]}"
        received = get_dest_received_dir(dest, source)
        assert _received_files(received) == [], \
            f"expected nothing transferred, got {_received_files(received)}"

    @pytest.mark.ci
    def test_stop_rejects_garbage(self, shared_server):
        """Malformed --stop-at/--stop-after values are rejected up front."""
        source, dest = _make("garbage")
        _seed_source(source)
        for flag in ("--stop-after=abc", "--stop-at=12:99", "--stop-at=12",
                     "--stop-at=now+5x", "--stop-at=now-5s"):
            result, _ = run_client(source, dest, flags=[flag],
                                   port=shared_server.port)
            assert result.returncode != 0, f"{flag} should be rejected"