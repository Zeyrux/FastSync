"""Output-parity tests (#291 selection/output, #292 output formatting).

These tests exercise rsync-style selection ordering and output formatting.  The
differential tests run the SAME transfer with real ``rsync 3.4.1`` and with
fastsync and compare stdout, so they are skipped when rsync is unavailable.
"""
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import TEST_DATA_DIR, run_client, clean_dir, get_dest_received_dir

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run(
        [RSYNC] + args, capture_output=True, text=True, env=env, timeout=120
    )


def _make_selection_tree(root):
    clean_dir(root)
    os.makedirs(os.path.join(root, "sub"))
    with open(os.path.join(root, "a.txt"), "wb") as fh:
        fh.write(b"top text\n")
    with open(os.path.join(root, "b.log"), "wb") as fh:
        fh.write(b"log data\n")
    with open(os.path.join(root, "sub", "c.txt"), "wb") as fh:
        fh.write(b"nested text\n")
    with open(os.path.join(root, "sub", "d.log"), "wb") as fh:
        fh.write(b"nested log\n")


class TestSelectionOrdering:
    """#291: --include/--exclude compile into one ordered rule list."""

    @pytest.mark.ci
    def test_include_then_exclude_keeps_only_matching(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "out_inc_src")
        dest = os.path.join(TEST_DATA_DIR, "out_inc_dst")
        _make_selection_tree(source)
        clean_dir(dest)
        result, _ = run_client(
            source, dest,
            flags=["--preserve", "--include=*.txt", "--exclude=*"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"include/exclude failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.path.exists(os.path.join(received, "a.txt"))
        # `*` also excludes the directory, so nothing below sub/ is sent.
        assert not os.path.exists(os.path.join(received, "b.log"))
        assert not os.path.exists(os.path.join(received, "sub", "c.txt"))

    @pytest.mark.ci
    def test_include_dirs_then_files_idiom(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "out_inc2_src")
        dest = os.path.join(TEST_DATA_DIR, "out_inc2_dst")
        _make_selection_tree(source)
        clean_dir(dest)
        result, _ = run_client(
            source, dest,
            flags=["--preserve", "--include=*/", "--include=*.txt", "--exclude=*"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"include/exclude failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.path.exists(os.path.join(received, "a.txt"))
        assert os.path.exists(os.path.join(received, "sub", "c.txt"))
        assert not os.path.exists(os.path.join(received, "b.log"))
        assert not os.path.exists(os.path.join(received, "sub", "d.log"))

    @requires_rsync
    def test_include_idiom_matches_rsync_selection(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "out_inc3_src")
        dest = os.path.join(TEST_DATA_DIR, "out_inc3_dst")
        rdst = os.path.join(TEST_DATA_DIR, "out_inc3_rdst")
        _make_selection_tree(source)
        clean_dir(dest)
        clean_dir(rdst)
        flags = ["--include=*/", "--include=*.txt", "--exclude=*"]
        rsync_result = _rsync(["-a"] + flags + [source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["--preserve"] + flags,
                               port=shared_server.port)
        assert result.returncode == 0
        received = get_dest_received_dir(dest, source)
        assert os.path.exists(os.path.join(received, "a.txt"))
        assert os.path.exists(os.path.join(received, "sub", "c.txt"))
        assert not os.path.exists(os.path.join(received, "b.log"))
        # rsync -a src/ dst/ writes directly into dst/
        assert os.path.exists(os.path.join(rdst, "a.txt"))
        assert os.path.exists(os.path.join(rdst, "sub", "c.txt"))
        assert not os.path.exists(os.path.join(rdst, "b.log"))


class TestOneFileSystem:
    """#291: -x emits the mount-point directory but not its contents."""

    def test_one_file_system_emits_mount_point_dir(self, shared_server):
        local = os.stat(".")
        shm = "/dev/shm"
        try:
            shm_stat = os.stat(shm)
        except OSError:
            pytest.skip("/dev/shm not available")
        if shm_stat.st_dev == local.st_dev:
            pytest.skip("no cross-device filesystem available")

        source = os.path.join(TEST_DATA_DIR, "out_ofs_src")
        dest = os.path.join(TEST_DATA_DIR, "out_ofs_dst")
        clean_dir(source)
        clean_dir(dest)
        os.makedirs(os.path.join(source, "nested"))
        os.makedirs(os.path.join(shm, "fastsync_ofs_probe"), exist_ok=True)
        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"keep\n")
        with open(os.path.join(shm, "fastsync_ofs_probe", "inside.txt"), "wb") as fh:
            fh.write(b"cross\n")
        link = os.path.join(source, "nested", "link")
        try:
            os.symlink(os.path.join(shm, "fastsync_ofs_probe"), link)
        except OSError:
            pytest.skip("cannot create symlink")

        try:
            result, _ = run_client(
                source, dest,
                flags=["--preserve", "--copy-links", "-x"],
                port=shared_server.port,
            )
            assert result.returncode == 0, f"-x failed: {result.stderr[:300]}"
            received = get_dest_received_dir(dest, source)
            assert os.path.exists(os.path.join(received, "keep.txt"))
            # The mount-point directory entry is created but its contents are not.
            assert os.path.isdir(os.path.join(received, "nested", "link"))
            assert not os.path.exists(os.path.join(received, "nested", "link", "inside.txt"))
        finally:
            shutil.rmtree(os.path.join(shm, "fastsync_ofs_probe"), ignore_errors=True)


def _make_output_tree(root):
    clean_dir(root)
    os.makedirs(os.path.join(root, "sub"))
    with open(os.path.join(root, "a.txt"), "wb") as fh:
        fh.write(b"hello\n")
    with open(os.path.join(root, "sub", "b.txt"), "wb") as fh:
        fh.write("wörld\n".encode("utf-8"))
    os.symlink("a.txt", os.path.join(root, "link"))


class TestItemizeParity:
    """#292: -i output matches rsync 3.4.1 for the cases fastsync can observe."""

    @requires_rsync
    @pytest.mark.ci
    def test_itemize_first_transfer_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "out_item_src")
        dest = os.path.join(TEST_DATA_DIR, "out_item_dst")
        rdst = os.path.join(TEST_DATA_DIR, "out_item_rdst")
        _make_output_tree(source)
        clean_dir(dest)
        clean_dir(rdst)
        rsync_result = _rsync(["-a", "-i", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_lines = sorted(
            line for line in rsync_result.stdout.splitlines()
            if line.startswith(">f") or line.startswith("cL")
        )
        result, _ = run_client(source, dest, flags=["-a", "-i"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        fast_lines = sorted(
            line for line in result.stdout.splitlines()
            if line.startswith(">f") or line.startswith("cL")
        )
        assert fast_lines == rsync_lines, f"rsync={rsync_lines} fastsync={fast_lines}"

    @requires_rsync
    @pytest.mark.ci
    def test_itemize_modified_file_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "out_item2_src")
        dest = os.path.join(TEST_DATA_DIR, "out_item2_dst")
        rdst = os.path.join(TEST_DATA_DIR, "out_item2_rdst")
        _make_output_tree(source)
        clean_dir(dest)
        clean_dir(rdst)
        seed = run_client(source, dest, flags=["-a"], port=shared_server.port)
        assert seed[0].returncode == 0, seed[0].stderr[:300]
        assert _rsync(["-a", source + "/", rdst + "/"]).returncode == 0

        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"hello changed and longer\n")
        # Pin the source mtime so rsync's `t` column is deterministic (a write
        # that lands in the same whole second as the seed would not show `t`).
        os.utime(os.path.join(source, "a.txt"), (1000000000, 1000000000))

        rsync_result = _rsync(["-a", "-i", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_lines = sorted(
            line for line in rsync_result.stdout.splitlines() if line.startswith(">f")
        )
        result, _ = run_client(source, dest,
                               flags=["-a", "-i", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        fast_lines = sorted(
            line for line in result.stdout.splitlines() if line.startswith(">f")
        )
        assert fast_lines == rsync_lines, f"rsync={rsync_lines} fastsync={fast_lines}"


class TestOutFormatParity:
    @requires_rsync
    @pytest.mark.ci
    def test_out_format_n_l_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "out_fmt_src")
        dest = os.path.join(TEST_DATA_DIR, "out_fmt_dst")
        rdst = os.path.join(TEST_DATA_DIR, "out_fmt_rdst")
        _make_output_tree(source)
        clean_dir(dest)
        clean_dir(rdst)
        fmt = "%n %l"
        rsync_result = _rsync(["-a", "--out-format=" + fmt, source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_lines = sorted(
            line for line in rsync_result.stdout.splitlines()
            if line and not line.split(" ", 1)[0].endswith("/")
        )
        result, _ = run_client(source, dest,
                               flags=["-a", "--out-format=" + fmt],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        fast_lines = sorted(
            line for line in result.stdout.splitlines()
            if line and not line.split(" ", 1)[0].endswith("/")
        )
        assert fast_lines == rsync_lines, f"rsync={rsync_lines} fastsync={fast_lines}"

    @requires_rsync
    @pytest.mark.ci
    def test_out_format_M_datetime_shape(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "out_M_src")
        dest = os.path.join(TEST_DATA_DIR, "out_M_dst")
        _make_output_tree(source)
        clean_dir(dest)
        result, _ = run_client(source, dest,
                               flags=["-a", "--out-format=%M %f"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        import re
        pattern = re.compile(r"^\d{4}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2} ")
        for line in result.stdout.splitlines():
            if line:
                assert pattern.match(line), f"bad %M format: {line!r}"


class TestListOnlyParity:
    @requires_rsync
    @pytest.mark.ci
    def test_list_only_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "out_list_src")
        dest = os.path.join(TEST_DATA_DIR, "out_list_dst")
        _make_output_tree(source)
        clean_dir(dest)
        rsync_result = _rsync(["-r", "--list-only", source + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_lines = sorted(rsync_result.stdout.splitlines())
        result, _ = run_client(source, dest, flags=["--list-only", "-l"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        fast_lines = sorted(result.stdout.splitlines())
        assert fast_lines == rsync_lines, (
            f"rsync={rsync_lines}\nfastsync={fast_lines}"
        )
