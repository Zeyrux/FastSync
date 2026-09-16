"""Differential/regression coverage for the parity-completion review blockers.

Each test pins a fix against real ``rsync 3.4.1`` where a deterministic
comparison exists; the differential tests skip cleanly when rsync is absent.
"""
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    TEST_DATA_DIR,
    ServerManager,
    clean_dir,
    get_dest_received_dir,
    run_client,
)

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)


def _tree(root):
    """Sorted relative paths of every entry below root (files and dirs)."""
    out = []
    for dirpath, dirs, files in os.walk(root):
        for name in dirs:
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
        for name in files:
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
    return sorted(out)


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([RSYNC] + args, capture_output=True, text=True, env=env, timeout=120)


class TestRelativePerDirDeleteScope:
    """Blocker #1: -R --delete-during/--delete-delay must not delete destination
    content outside the transferred prefix (rsync keeps sibling directories)."""

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("timing", ["--delete-during", "--delete-delay"])
    def test_prefix_scoped_delete_matches_rsync(self, timing):
        source = os.path.join(TEST_DATA_DIR, "delblk_src")
        clean_dir(source)
        _write(os.path.join(source, "foo", "a.txt"), b"payload\n")
        spec = source + "/./foo"

        def seed(root):
            clean_dir(root)
            _write(os.path.join(root, "foo", "extra.txt"), b"stale\n")
            _write(os.path.join(root, "unrelated", "keep.txt"), b"keep\n")

        rdst = os.path.join(TEST_DATA_DIR, "delblk_rdst")
        dest = os.path.join(TEST_DATA_DIR, "delblk_dst")
        seed(rdst)
        seed(dest)
        r = _rsync(["-aR", timing, spec, rdst + "/"])
        assert r.returncode == 0, r.stderr
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(spec, dest, flags=["-a", "-R", timing], port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
#The prefix's parent-directory sibling survives on both sides.
        assert os.path.isfile(os.path.join(dest, "unrelated", "keep.txt"))
        assert os.path.isfile(os.path.join(rdst, "unrelated", "keep.txt"))
#The in - scope extra is removed on both sides.
        assert not os.path.exists(os.path.join(dest, "foo", "extra.txt"))
        assert not os.path.exists(os.path.join(rdst, "foo", "extra.txt"))
        assert _tree(dest) == _tree(rdst)


def _stats_value(text, label):
    for line in text.splitlines():
        if line.startswith(label + ":"):
            return int(line.split(":", 1)[1].strip().split()[0].replace(",", ""))
    return None


def _seed_delta_pair(tag):
    """Source file plus a same-size/basis destination file whose mtime differs,
    and an extra destination file to be deleted."""
    source = os.path.join(TEST_DATA_DIR, f"stats_{tag}_src")
    dest = os.path.join(TEST_DATA_DIR, f"stats_{tag}_dst")
    rdst = os.path.join(TEST_DATA_DIR, f"stats_{tag}_rdst")
    clean_dir(source)
    clean_dir(dest)
    clean_dir(rdst)
    payload = (b"0123456789abcdef" * 16384)[:200000]
    _write(os.path.join(source, "f.bin"), payload)
#Destination basis : same length, one byte changed, deliberately older.
    basis = bytearray(payload)
    basis[100000] ^= 0xFF
    received = get_dest_received_dir(dest, source)
    for root in (rdst, received):
        _write(os.path.join(root, "f.bin"), bytes(basis))
        _write(os.path.join(root, "extra.txt"), b"delete me\n")
        old = 1000000
        os.utime(os.path.join(root, "f.bin"), (old, old))
    return source, dest, rdst


class TestReceiverWireStats:
    """Blocker #3/#4: the receiver must populate the STATUS_STATS counters
    (matched data, deleted files) on both the single-threaded and -m paths."""

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("threads", [False, True])
    def test_stats_reports_matched_and_deleted(self, threads):
        source, dest, rdst = _seed_delta_pair(f"mt{int(threads)}")
        rsync_result = _rsync(["-a", "--stats", "--delete", "--no-whole-file", source + "/",
                               rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        assert _stats_value(rsync_result.stdout, "Matched data") > 0
        assert _stats_value(rsync_result.stdout, "Number of deleted files") == 1

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            flags = ["-a", "--stats", "--delete", "--delta", "--incremental"]
            if threads:
                flags.append("--threads")
            result, _ = run_client(source, dest, flags=flags, port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        assert _stats_value(result.stdout, "Matched data") > 0, result.stdout
        assert _stats_value(result.stdout, "Number of deleted files") == 1, result.stdout

    @requires_rsync
    @pytest.mark.ci
    def test_threads_dry_run_delete_lines_match_rsync(self):
        """-n --delete --threads must emit transfer-relative `*deleting` lines."""
        source = os.path.join(TEST_DATA_DIR, "stats_drydel_src")
        dest = os.path.join(TEST_DATA_DIR, "stats_drydel_dst")
        rdst = os.path.join(TEST_DATA_DIR, "stats_drydel_rdst")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(rdst)
        _write(os.path.join(source, "a.txt"), b"a\n")
        for root in (rdst, get_dest_received_dir(dest, source)):
            _write(os.path.join(root, "extra.txt"), b"x\n")
            _write(os.path.join(root, "sub", "y.txt"), b"y\n")
        rsync_result = _rsync(["-a", "-n", "--delete", "-i", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_del = sorted(
            line for line in rsync_result.stdout.splitlines() if line.startswith("*deleting")
        )
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest,
                                   flags=["-a", "-n", "--delete", "-i", "--threads"],
                                   port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        fast_del = sorted(
            line for line in result.stdout.splitlines() if line.startswith("*deleting")
        )
        assert fast_del and fast_del == rsync_del, f"rsync={rsync_del}\nfastsync={fast_del}"


class TestRelativeFilesFromProtect:
    """Blocker #9: a -R + --files-from receiver-protect rule must record the bare
    relative wire path so the protected destination mirror survives --delete."""

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_hidden_protected_mirror_survives_delete(self, mt):
        source = os.path.join(TEST_DATA_DIR, "rfprot_src")
        dest = os.path.join(TEST_DATA_DIR, "rfprot_dst")
        clean_dir(source)
        clean_dir(dest)
#Root - level entry exercises the parallel root scanner; the nested one
#exercises the sequential worker scanner.
        _write(os.path.join(source, "root_secret.tmp"), b"root\n")
        _write(os.path.join(source, "sub", "nested_secret.tmp"), b"nested\n")
        _write(os.path.join(source, "sub", "keep.txt"), b"keep\n")
        listfile = os.path.join(TEST_DATA_DIR, "rfprot.list")
        with open(listfile, "w") as fh:
            fh.write(".\n")
#H hides from the sender, P protects the receiver mirror from-- delete.
        filters = ["--filter=H root_secret.tmp", "--filter=P root_secret.tmp",
                   "--filter=H sub/nested_secret.tmp", "--filter=P sub/nested_secret.tmp"]
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            seed = ["--files-from", listfile, "-R"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=seed, port=server.port)
            assert result.returncode == 0, (result.stderr or result.stdout)[:300]
            assert os.path.isfile(os.path.join(dest, "root_secret.tmp"))
            assert os.path.isfile(os.path.join(dest, "sub", "nested_secret.tmp"))
            _write(os.path.join(dest, "extra.txt"), b"extra\n")
            _write(os.path.join(dest, "sub", "extra.txt"), b"extra\n")
            flags = seed + ["--delete"] + filters
            result, _ = run_client(source, dest, flags=flags, port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        assert os.path.isfile(os.path.join(dest, "root_secret.tmp")), \
            "root-level protected mirror was deleted"
        assert os.path.isfile(os.path.join(dest, "sub", "nested_secret.tmp")), \
            "nested protected mirror was deleted"
        assert not os.path.exists(os.path.join(dest, "extra.txt"))
        assert not os.path.exists(os.path.join(dest, "sub", "extra.txt"))


class TestInvalidPerDirFilter:
    """Blocker #8: a per-directory filter file that fails to parse must fail the
    scan even when an earlier merge file in the same directory existed."""

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_invalid_dir_filter_fails_scan(self, mt):
        source = os.path.join(TEST_DATA_DIR, "badfilter_src")
        dest = os.path.join(TEST_DATA_DIR, "badfilter_dst")
        clean_dir(source)
        clean_dir(dest)
#A valid.rsync - filter makes any_exists true for the directory; the
#invalid.rules must not then be silently ignored.
        _write(os.path.join(source, ".rsync-filter"), b"- *.bak\n")
        _write(os.path.join(source, ".rules"), b"protect\n")
        _write(os.path.join(source, "a.txt"), b"a\n")
        flags = ["-a", "-F", "--filter=: .rules"]
        if mt:
            flags.append("--threads")
        with ServerManager() as server:
            result, _ = run_client(source, dest, flags=flags, port=server.port)
        assert result.returncode != 0, "invalid per-directory filter was silently ignored"
        assert "invalid per-directory filter" in (result.stderr + result.stdout)


class TestWouldDeleteEscaping:
    """Blocker #5: -n --delete --out-format must escape control bytes in a
    peer-supplied would-delete path so it cannot forge output lines."""

    @pytest.mark.ci
    def test_out_format_escapes_control_chars(self):
        source = os.path.join(TEST_DATA_DIR, "esc_src")
        dest = os.path.join(TEST_DATA_DIR, "esc_dst")
        clean_dir(source)
        _write(os.path.join(source, "a.txt"), b"a\n")
        received = get_dest_received_dir(dest, source)
        clean_dir(received)
        _write(os.path.join(received, "a.txt"), b"a\n")
#A newline in a destination filename must not split the printed line.
        with open(os.path.join(received, "evil\nname.txt"), "wb") as fh:
            fh.write(b"x\n")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest,
                                   flags=["-a", "-n", "--delete", "--out-format=%n"],
                                   port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        assert "\\#012" in result.stdout, result.stdout
        assert "evil\nname.txt" not in result.stdout, result.stdout


class TestEmptySourceDirectoryDelete:
    """Blocker #10: an empty in-scope source directory must survive
    --delete-during/--delete-delay (rsync keeps it) while its extras are still
    removed."""

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("timing", ["--delete-during", "--delete-delay"])
    def test_empty_source_dir_survives_matches_rsync(self, timing):
        source = os.path.join(TEST_DATA_DIR, "emptydir_src")
        dest = os.path.join(TEST_DATA_DIR, "emptydir_dst")
        rdst = os.path.join(TEST_DATA_DIR, "emptydir_rdst")
        clean_dir(source)
        os.makedirs(os.path.join(source, "empty"))
        _write(os.path.join(source, "keep.txt"), b"keep\n")
        received = get_dest_received_dir(dest, source)
        for root in (rdst, received):
            clean_dir(root)
            _write(os.path.join(root, "keep.txt"), b"keep\n")
            _write(os.path.join(root, "empty", "extra.txt"), b"extra\n")
        rsync_result = _rsync(["-a", timing, source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        assert os.path.isdir(os.path.join(rdst, "empty"))
        assert not os.path.exists(os.path.join(rdst, "empty", "extra.txt"))
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["-a", timing], port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        assert os.path.isdir(os.path.join(received, "empty")), \
            "empty source directory was removed"
        assert not os.path.exists(os.path.join(received, "empty", "extra.txt"))
        assert _tree(received) == _tree(rdst)
