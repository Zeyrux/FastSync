"""Output-parity tests (#291 selection/output, #292 output formatting).

These tests exercise rsync-style selection ordering and output formatting.  The
differential tests run the SAME transfer with real ``rsync 3.4.1`` and with
fastsync and compare stdout, so they are skipped when rsync is unavailable.
"""
import os
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import TEST_DATA_DIR, run_client, clean_dir, get_dest_received_dir, ServerManager

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run(
        [RSYNC] + args, capture_output=True, text=True, env=env, timeout=120
    )


def _file_entry_line(text):
    """The file entry line for a single-file transfer.

    -i/--out-format emit the transfer-root (and directory) lines too, so the
    file entry is not necessarily the first line; for the one-file corpora used
    by the wire-counter tests it is the last non-empty line.
    """
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


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
    def test_itemize_directory_lines_match_rsync(self, shared_server):
        """#292: -i/--out-format emit rsync's directory lines (including the
        transfer root) in rsync's depth-first order."""
        source = os.path.join(TEST_DATA_DIR, "out_itemdir_src")
        dest = os.path.join(TEST_DATA_DIR, "out_itemdir_dst")
        rdst = os.path.join(TEST_DATA_DIR, "out_itemdir_rdst")
        clean_dir(source)
        os.makedirs(os.path.join(source, "sub", "deep"))
        os.makedirs(os.path.join(source, "emptydir"))
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"hello\n")
        with open(os.path.join(source, "sub", "b.txt"), "wb") as fh:
            fh.write(b"world\n")
        with open(os.path.join(source, "sub", "deep", "d.txt"), "wb") as fh:
            fh.write(b"deep\n")
        clean_dir(dest)
        clean_dir(rdst)

        def dir_lines(text):
            # Any line whose name ends with '/' is a directory entry.
            return sorted(
                line for line in text.splitlines()
                if line.rsplit(" ", 1)[-1].endswith("/")
            )

        for fmt in (None, "%i %n%L"):
            rsync_flags = ["-a", "-i"] if fmt is None else ["-a", "--out-format=" + fmt]
            fast_flags = rsync_flags
            clean_dir(rdst)
            clean_dir(dest)
            rsync_result = _rsync(rsync_flags + [source + "/", rdst + "/"])
            assert rsync_result.returncode == 0, rsync_result.stderr
            result, _ = run_client(source, dest, flags=fast_flags,
                                   port=shared_server.port)
            assert result.returncode == 0, result.stderr[:300]
            expected = [l for l in dir_lines(rsync_result.stdout)
                        if not l.rsplit(" ", 1)[-1] == "./"]
            fast = dir_lines(result.stdout)
            assert [l for l in fast if not l.rsplit(" ", 1)[-1] == "./"] == expected, (
                f"fmt={fmt} rsync={rsync_result.stdout!r} fastsync={result.stdout!r}"
            )
            assert ".d..t...... ./" in fast, f"missing root line: {result.stdout!r}"

    @requires_rsync
    @pytest.mark.ci
    def test_itemize_info_flist_header_matches_rsync(self, shared_server):
        """`-i --info=flist` prints rsync's file-list header: the -i change
        lines alone do not enable the flist category, but an explicit --info=flist
        must not be suppressed when itemizing."""
        source = os.path.join(TEST_DATA_DIR, "out_itemfl_src")
        dest = os.path.join(TEST_DATA_DIR, "out_itemfl_dst")
        rdst = os.path.join(TEST_DATA_DIR, "out_itemfl_rdst")
        _make_output_tree(source)
        clean_dir(dest)
        clean_dir(rdst)
        flags = ["-a", "-i", "--info=flist"]
        rsync_result = _rsync(flags + [source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert "sending incremental file list" in rsync_result.stdout
        assert "sending incremental file list" in result.stdout, result.stdout
        # -i alone (no explicit --info=flist) must stay silent like rsync.
        clean_dir(dest)
        clean_dir(rdst)
        rsync_plain = _rsync(["-a", "-i", source + "/", rdst + "/"])
        plain, _ = run_client(source, dest, flags=["-a", "-i"],
                              port=shared_server.port)
        assert "sending incremental file list" not in rsync_plain.stdout
        assert "sending incremental file list" not in plain.stdout, plain.stdout

    @requires_rsync
    @pytest.mark.ci
    def test_itemize_files_from_dirs_root_and_ancestors(self, shared_server):
        """The -d/--files-from dirs generator emits the transfer-root line and
        rsync's implied ancestor directory lines.  The generator traverses no
        directories, so those must be synthesized from the listed entries."""
        source = os.path.join(TEST_DATA_DIR, "out_itemff_src")
        dest = os.path.join(TEST_DATA_DIR, "out_itemff_dst")
        rdst = os.path.join(TEST_DATA_DIR, "out_itemff_rdst")
        clean_dir(source)
        os.makedirs(os.path.join(source, "sub", "deep"))
        with open(os.path.join(source, "sub", "deep", "d.txt"), "wb") as fh:
            fh.write(b"deep\n")
        clean_dir(dest)
        clean_dir(rdst)
        listing = os.path.join(TEST_DATA_DIR, "out_itemff.list")
        with open(listing, "w") as fh:
            fh.write("sub/deep/d.txt\n")

        flags = ["-d", "-i", "--files-from=" + listing]
        rsync_result = _rsync(flags + [source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]

        def dir_lines(text):
            return sorted(line for line in text.splitlines()
                          if line.rsplit(" ", 1)[-1].endswith("/"))

        # rsync emits the implied parents (sub/, sub/deep/) but never the root
        # here; FastSync emits the same set plus its unconditional root line.
        expected = [line for line in dir_lines(rsync_result.stdout)
                    if not line.rsplit(" ", 1)[-1] == "./"]
        fast = dir_lines(result.stdout)
        assert [line for line in fast if not line.rsplit(" ", 1)[-1] == "./"] == expected, (
            f"rsync={rsync_result.stdout!r} fastsync={result.stdout!r}"
        )
        assert "cd+++++++++ sub/" in fast, result.stdout
        assert "cd+++++++++ sub/deep/" in fast, result.stdout
        assert any(line.rsplit(" ", 1)[-1] == "./" for line in fast), result.stdout

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

    @requires_rsync
    @pytest.mark.ci
    def test_out_format_directory_metadata_with_delete_during(self):
        """--delete-during/--delete-delay reuse the per-directory plan pre-scan,
        whose list carries no metadata.  Directory %M/%B/%U/%G must still come
        from the source, exactly as the plain recursive scan renders them."""
        source = os.path.join(TEST_DATA_DIR, "out_fmtmeta_src")
        dest = os.path.join(TEST_DATA_DIR, "out_fmtmeta_dst")
        rdst = os.path.join(TEST_DATA_DIR, "out_fmtmeta_rdst")
        clean_dir(source)
        os.makedirs(os.path.join(source, "sub", "deep"))
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"hello\n")
        with open(os.path.join(source, "sub", "b.txt"), "wb") as fh:
            fh.write(b"world\n")
        clean_dir(dest)
        clean_dir(rdst)

        def dir_lines(text):
            # Directory names are the last whitespace-separated token.
            return sorted(line for line in text.splitlines()
                          if line.rsplit(" ", 1)[-1].endswith("/")
                          and line.rsplit(" ", 1)[-1] != "./")

        for timing in ("--delete-during", "--delete-delay"):
            for fmt in ("%M %n", "%B %n", "%U %G %n"):
                clean_dir(dest)
                clean_dir(rdst)
                flags = ["-a", "--out-format=" + fmt, timing]
                rsync_result = _rsync(flags + [source + "/", rdst + "/"])
                assert rsync_result.returncode == 0, rsync_result.stderr
                with ServerManager() as server:
                    server.start(extra_args=["--allow-delete"])
                    result, _ = run_client(source, dest, flags=flags, port=server.port)
                assert result.returncode == 0, result.stderr[:300]
                assert dir_lines(result.stdout) == dir_lines(rsync_result.stdout), (
                    f"{timing} {fmt}: rsync={rsync_result.stdout!r} "
                    f"fastsync={result.stdout!r}"
                )
                assert "1970/" not in result.stdout, result.stdout


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


def _make_one_file(root, name="f.bin", size=100):
    clean_dir(root)
    with open(os.path.join(root, name), "wb") as fh:
        fh.write(bytes((i * 7 + 3) & 0xFF for i in range(size)))


def _make_multidir_tree(root):
    """Multi-directory corpus for the --progress file-list tests: nested files,
    a directory-only branch, an empty directory and a symlink."""
    clean_dir(root)
    for rel, data in (("a.txt", b"alpha\n"), ("b.txt", b"bravo\n"),
                      ("sub1/c.txt", b"charlie\n"), ("sub1/deep/d.txt", b"delta\n"),
                      ("sub2/e.txt", b"echo\n")):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
    os.symlink("a.txt", os.path.join(root, "link1"))
    os.makedirs(os.path.join(root, "emptydir"), exist_ok=True)


def _parse_progress(text):
    """Name lines and the `to-chk` denominators from a --progress run."""
    names = []
    totals = set()
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line == "sending incremental file list":
            continue
        if "%" in line:
            match = re.search(r"to-chk=\d+/(\d+)", line)
            if match:
                totals.add(int(match.group(1)))
            continue
        if line == "./":  # root-line trigger is a separate documented residual
            continue
        names.append(line)
    return sorted(names), totals


def _pick_stats(text, keys):
    out = {}
    for line in text.splitlines():
        for key in keys:
            if line.startswith(key + ":"):
                out[key] = line
    return out


class TestWireStatsParity:
    """Wire-counter output parity: --out-format %b/%c/%C, --progress and
    --stats versus real rsync 3.4.1."""

    @requires_rsync
    @pytest.mark.ci
    def test_out_format_checksum_matches_rsync(self, shared_server):
        """%C (whole-file xxh128, seed 0) is protocol-independent, so the full
        `%C %l %n` line must be byte-identical to rsync."""
        source = os.path.join(TEST_DATA_DIR, "wire_ck_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_ck_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_ck_rdst")
        _make_one_file(source, "f.bin", 200000)
        clean_dir(dest)
        clean_dir(rdst)
        fmt = "%C %l %n"
        rsync_result = _rsync(["-a", "--out-format=" + fmt, source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["-a", "--out-format=" + fmt],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]

        def file_lines(text):
            # Ignore the root directory entry: fastsync does not transfer the
            # source-root dir itself (a separate pre-existing divergence).
            return [
                line for line in text.splitlines() if not line.rsplit(" ", 1)[-1].endswith("/")
            ]

        assert file_lines(result.stdout) == file_lines(rsync_result.stdout), (
            f"rsync={rsync_result.stdout!r} fastsync={result.stdout!r}"
        )

    @requires_rsync
    @pytest.mark.ci
    def test_out_format_b_is_wire_bytes(self, shared_server):
        """%b is the bytes actually transferred (wire), not the source length.

        A differential run against rsync confirms both implementations report a
        framed value greater than %l.  The exact numbers are not compared: each
        counts its own protocol framing and checksum trailer, so the two are
        protocol-specific and cannot be numerically equal (documented
        divergence)."""
        source = os.path.join(TEST_DATA_DIR, "wire_b_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_b_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_b_rdst")
        _make_one_file(source, "f.bin", 5000)
        clean_dir(dest)
        clean_dir(rdst)
        fmt = "%b %l"
        rsync_result = _rsync(["-a", "--out-format=" + fmt, source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["-a", "--out-format=" + fmt],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        rb, rl = (int(x) for x in _file_entry_line(rsync_result.stdout).split()[:2])
        fb, fl = (int(x) for x in _file_entry_line(result.stdout).split()[:2])
        assert rl == fl == 5000, (rsync_result.stdout, result.stdout)
        assert rb > rl, f"rsync %b must include framing: {rsync_result.stdout!r}"
        assert fb > fl, f"fastsync %b must include framing: {result.stdout!r}"

    @requires_rsync
    @pytest.mark.ci
    def test_out_format_c_whole_file_matches_rsync(self, shared_server):
        """%c is the block-checksum bytes received.  rsync reports its 16-byte
        sum header even for a whole-file transfer (no basis), so `%c` must match
        rsync exactly for the whole-file case."""
        source = os.path.join(TEST_DATA_DIR, "wire_c_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_c_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_c_rdst")
        _make_one_file(source, "f.bin", 5000)
        clean_dir(dest)
        clean_dir(rdst)
        fmt = "%c %l %n"
        rsync_result = _rsync(["-a", "--out-format=" + fmt, source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["-a", "--out-format=" + fmt],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]

        def file_lines(text):
            return [
                line for line in text.splitlines()
                if line and not line.rsplit(" ", 1)[-1].endswith("/")
            ]

        assert file_lines(result.stdout) == file_lines(rsync_result.stdout), (
            f"rsync={rsync_result.stdout!r} fastsync={result.stdout!r}"
        )
        fs_c = _file_entry_line(result.stdout).split()[0]
        rs_c = _file_entry_line(rsync_result.stdout).split()[0]
        assert fs_c == rs_c == "16", (
            f"%c must be rsync's 16-byte sum header: {result.stdout!r}"
        )

    @requires_rsync
    @pytest.mark.ci
    def test_out_format_c_delta_mode_divergence(self, shared_server):
        """Documented residual: with delta enabled, rsync's %c is its 16-byte sum
        header plus one checksum entry per block (protocol-specific, so it grows
        with the basis size), while FastSync's %c is the bytes of its own delta
        handshake.  FastSync's delta %c therefore cannot match rsync numerically;
        only the whole-file case is aligned.  Pinned here so a future change is
        noticed."""
        source = os.path.join(TEST_DATA_DIR, "wire_cd_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_cd_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_cd_rdst")
        _make_one_file(source, "f.bin", 5000)
        clean_dir(dest)
        clean_dir(rdst)
        fmt = "%c %l"
        # rsync local default is whole-file; force the block-delta path.
        rsync_result = _rsync(["-a", "--no-whole-file", "--out-format=" + fmt,
                               source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest,
                               flags=["-a", "--incremental", "--delta",
                                      "--out-format=" + fmt],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        rs_c = int(_file_entry_line(rsync_result.stdout).split()[0])
        fs_c = int(_file_entry_line(result.stdout).split()[0])
        # No basis exists, so rsync still reports only its sum header.
        assert rs_c == 16, rsync_result.stdout
        # FastSync reports its own handshake bytes and is not aligned.
        assert fs_c > 16, (
            f"FastSync delta %c changed to {fs_c}; the documented divergence "
            "may be closable now"
        )

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    @pytest.mark.parametrize("progress_flag", ["--progress", "-P"])
    def test_progress_first_frame_matches_rsync(self, shared_server, progress_flag, mt):
        """For a sub-32 KiB file the first --progress/-P frame is deterministic
        (0.00 kB/s, 0:00:00) and must be byte-identical to rsync's, in both the
        single-threaded and --threads send paths."""
        source = os.path.join(TEST_DATA_DIR, "wire_pg_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_pg_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_pg_rdst")
        _make_one_file(source, "f.bin", 100)
        clean_dir(dest)
        clean_dir(rdst)
        rsync_result = _rsync(["-a", progress_flag, source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        flags = ["-a", progress_flag] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]

        def frames(text):
            # subprocess text mode normalizes \r to \n (universal newlines).
            return [p for p in text.split("\n") if "%" in p]

        rsync_frames = frames(rsync_result.stdout)
        fast_frames = frames(result.stdout)
        assert rsync_frames and fast_frames, (rsync_result.stdout, result.stdout)
        assert fast_frames[0] == rsync_frames[0], (rsync_frames[0], fast_frames[0])
        assert "(xfr#1," in fast_frames[-1], fast_frames[-1]

    @requires_rsync
    @pytest.mark.ci
    def test_progress_leading_root_line_and_to_chk_match_rsync(self, shared_server):
        """A single-file transfer: rsync emits the transfer-root `./` name line
        and a `to-chk=0/2` denominator that counts that root entry.  Both must
        match FastSync byte-for-byte for the deterministic frames."""
        source = os.path.join(TEST_DATA_DIR, "wire_pgroot_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_pgroot_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_pgroot_rdst")
        _make_one_file(source, "f.bin", 100)
        clean_dir(dest)
        # rsync prints the `./` root line only when the transfer root itself is
        # created, so make the rsync destination absent.  The "created directory"
        # line it then emits has no FastSync counterpart (different mirror
        # layout), so only the name/frame lines are compared.
        shutil.rmtree(rdst, ignore_errors=True)
        rsync_result = _rsync(["-a", "--progress", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["-a", "--progress"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]

        # subprocess text mode normalizes \r to \n (universal newlines).
        def lines_of(text):
            return [ln for ln in text.splitlines() if ln and not ln.startswith("created directory")]

        rsync_lines = lines_of(rsync_result.stdout)
        fast_lines = lines_of(result.stdout)
        rsync_names = [ln for ln in rsync_lines if "%" not in ln]
        fast_names = [ln for ln in fast_lines if "%" not in ln]

        assert rsync_names == ["sending incremental file list", "./", "f.bin"], rsync_names
        assert fast_names == rsync_names, (rsync_names, fast_names)
        # The final frame's to-chk denominator must include the source-root entry.
        assert "to-chk=0/2" in fast_lines[-1], fast_lines[-1]
        assert fast_lines[-1] == rsync_lines[-1], (rsync_lines[-1], fast_lines[-1])

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_progress_multidir_file_list_matches_rsync(self, shared_server, mt):
        """A multi-directory tree: the paths-only pre-count must reproduce
        rsync's file-list set and `to-chk` denominator.  Per-directory name
        lines are emitted for directories, symlinks and the empty directory; the
        name set and the denominator (every entry plus the transfer root) match
        rsync, while the emitted *order* remains a documented residual (rsync
        sorts depth-first, FastSync streams in readdir/BFS order)."""
        source = os.path.join(TEST_DATA_DIR, "wire_pgmd_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_pgmd_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_pgmd_rdst")
        _make_multidir_tree(source)
        clean_dir(dest)
        clean_dir(rdst)

        rsync_result = _rsync(["-a", "--progress", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        flags = ["-a", "--progress"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]

        rsync_names, rsync_totals = _parse_progress(rsync_result.stdout)
        fast_names, fast_totals = _parse_progress(result.stdout)
        assert sorted(rsync_names) == [
            "a.txt", "b.txt", "emptydir/", "link1 -> a.txt", "sub1/",
            "sub1/c.txt", "sub1/deep/", "sub1/deep/d.txt", "sub2/", "sub2/e.txt",
        ], rsync_names
        assert fast_names == rsync_names, (rsync_names, fast_names)
        # 10 entries + the transfer-root "." counted by rsync's file list.
        assert rsync_totals == {11}, rsync_totals
        assert fast_totals == rsync_totals, (rsync_totals, fast_totals)

    @pytest.mark.ci
    def test_progress_delete_during_reuses_pre_scan(self):
        """--delete-during + --progress reuses the keep-set pre-scan instead of
        walking the tree a second time: the file-list total and directory name
        lines are identical to a plain --progress run."""
        source = os.path.join(TEST_DATA_DIR, "wire_pgdel_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_pgdel_dst")
        _make_multidir_tree(source)
        clean_dir(dest)
        server = ServerManager()
        server.start(extra_args=["--allow-super", "--allow-delete"])
        try:
            result, _ = run_client(source, dest, flags=["-a", "--progress", "--delete-during"],
                                   port=server.port)
        finally:
            server.stop()
        assert result.returncode == 0, result.stderr[:300]
        names, totals = _parse_progress(result.stdout)
        assert totals == {11}, totals
        assert "sub1/" in names and "sub1/deep/" in names and "emptydir/" in names, names
        assert "link1 -> a.txt" in names, names

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_stats_selected_lines_match_rsync(self, shared_server, mt):
        """The protocol-independent --stats lines must match rsync exactly, in
        both the single-threaded and --threads (multithreaded) send paths."""
        source = os.path.join(TEST_DATA_DIR, "wire_st_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_st_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_st_rdst")
        _make_one_file(source, "f.bin", 6000)
        clean_dir(dest)
        clean_dir(rdst)
        # Start both tools from the same state: rsync's destination root exists,
        # so pre-create FastSync's mirrored logical root as well.
        os.makedirs(get_dest_received_dir(dest, source), exist_ok=True)
        rsync_result = _rsync(["-a", "--stats", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        flags = ["-a", "--stats"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        keys = (
            "Number of regular files transferred",
            "Total file size",
            "Total transferred file size",
            "Literal data",
            "Matched data",
            "Number of deleted files",
            "File list size",
        )

        def pick(text):
            out = {}
            for line in text.splitlines():
                for key in keys:
                    if line.startswith(key + ":"):
                        out[key] = line
            return out

        assert pick(result.stdout) == pick(rsync_result.stdout), (
            f"rsync={pick(rsync_result.stdout)} fastsync={pick(result.stdout)}"
        )

    @requires_rsync
    @pytest.mark.ci
    def test_stats_file_count_breakdown_matches_rsync(self, shared_server):
        """`Number of files` and `Number of created files` both carry rsync's
        per-type breakdown (protocol 2.28.0 reports the receiver-created
        reg/dir/link/special split over STATUS_STATS)."""
        source = os.path.join(TEST_DATA_DIR, "wire_stc_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_stc_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_stc_rdst")
        _make_one_file(source, "f.bin", 6000)
        clean_dir(dest)
        clean_dir(rdst)
        # Start both tools from the same state: rsync's destination root exists,
        # so pre-create FastSync's mirrored logical root as well.
        os.makedirs(get_dest_received_dir(dest, source), exist_ok=True)
        rsync_result = _rsync(["-a", "--stats", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["-a", "--stats"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]

        def stats_line(text, key):
            for line in text.splitlines():
                if line.startswith(key + ":"):
                    return line
            return None

        r_files = stats_line(rsync_result.stdout, "Number of files")
        r_created = stats_line(rsync_result.stdout, "Number of created files")
        f_files = stats_line(result.stdout, "Number of files")
        f_created = stats_line(result.stdout, "Number of created files")

        assert re.match(r"Number of files: 2 \(reg: 1, dir: 1\)$", r_files), r_files
        assert r_files == f_files, (r_files, f_files)
        assert re.match(r"Number of created files: 1 \(reg: 1\)$", r_created), r_created
        assert f_created == r_created, (r_created, f_created)

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_stats_r_directory_breakdown_matches_rsync(self, shared_server, mt):
        """A recursive `-r` scan (no -t/-p) exposes no directory metadata, but
        rsync still counts every directory in `Number of files`; the sender's
        lightweight directory counter must reproduce the `dir: N` category."""
        source = os.path.join(TEST_DATA_DIR, "wire_stdir_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_stdir_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_stdir_rdst")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(rdst)
        os.makedirs(os.path.join(source, "sub", "deep"))
        os.makedirs(os.path.join(source, "empty"))
        for rel in ("a.txt", os.path.join("sub", "b.txt"), os.path.join("sub", "deep", "c.txt")):
            with open(os.path.join(source, rel), "wb") as fh:
                fh.write(b"x\n")
        os.makedirs(get_dest_received_dir(dest, source), exist_ok=True)

        rsync_result = _rsync(["-r", "--stats", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        flags = ["-r", "--stats"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]

        def stats_line(text, key):
            for line in text.splitlines():
                if line.startswith(key + ":"):
                    return line
            return None

        r_files = stats_line(rsync_result.stdout, "Number of files")
        f_files = stats_line(result.stdout, "Number of files")
        # 3 regular files, 4 directories (root, sub, sub/deep, empty).
        assert re.match(r"Number of files: 7 \(reg: 3, dir: 4\)$", r_files), r_files
        assert f_files == r_files, (r_files, f_files)
        assert (stats_line(result.stdout, "Number of regular files transferred") ==
                stats_line(rsync_result.stdout, "Number of regular files transferred"))

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_stats_created_and_literal_fresh_update_delta(self, shared_server, mt):
        """The receiver-observed counters must match rsync for the three
        transfer shapes: a fresh create (created breakdown + whole-file literal),
        an update (created == 0, whole-file literal), and a delta update (only
        the literal delta fragments are counted, not the whole file)."""
        source = os.path.join(TEST_DATA_DIR, "wire_stcd_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_stcd_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_stcd_rdst")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(rdst)
        os.makedirs(source, exist_ok=True)
        os.makedirs(get_dest_received_dir(dest, source), exist_ok=True)
        with open(os.path.join(source, "big.bin"), "wb") as fh:
            fh.write(bytes(range(256)) * 4096)  # 1 MiB
        mt_flag = ["--threads"] if mt else []

        def compare(tag):
            # Pin the delta block size on both ends: rsync's adaptive block size
            # would otherwise make the literal/matched split non-comparable.
            rsync_result = _rsync(["-a", "--stats", "--no-whole-file", "-B8192",
                                   source + "/", rdst + "/"])
            assert rsync_result.returncode == 0, rsync_result.stderr
            result, _ = run_client(
                source, dest,
                flags=["-a", "--stats", "--incremental", "--delta", "-B8192"] + mt_flag,
                port=shared_server.port)
            assert result.returncode == 0, result.stderr[:300]
            keys = ("Number of created files", "Literal data", "Matched data",
                    "Total transferred file size")
            r = _pick_stats(rsync_result.stdout, keys)
            f = _pick_stats(result.stdout, keys)
            assert r == f, f"{tag}: rsync={r} fastsync={f}"
            return r

        fresh = compare("fresh")
        assert re.match(r"Number of created files: 1 \(reg: 1\)$",
                        fresh["Number of created files"]), fresh

        # Update the source and re-run: the destination already exists.
        sleep_mtime = os.path.getmtime(os.path.join(source, "big.bin")) + 2
        with open(os.path.join(source, "big.bin"), "r+b") as fh:
            fh.seek(100)
            fh.write(b"XXXXXXXXXX")
        os.utime(os.path.join(source, "big.bin"), (sleep_mtime, sleep_mtime))
        update = compare("update")
        assert update["Number of created files"] == "Number of created files: 0", update

        # Second delta update: change bytes far apart, so rsync ships only the
        # literal fragments and FastSync must report the same Literal data.
        sleep_mtime = os.path.getmtime(os.path.join(source, "big.bin")) + 2
        with open(os.path.join(source, "big.bin"), "r+b") as fh:
            fh.seek(500000)
            fh.write(b"YYYYYYYYYY")
        os.utime(os.path.join(source, "big.bin"), (sleep_mtime, sleep_mtime))
        delta = compare("delta")
        assert delta["Number of created files"] == "Number of created files: 0", delta
        lit = int(delta["Literal data"].split(":", 1)[1].strip().split()[0].replace(",", ""))
        assert 0 < lit < 1024 * 1024, delta

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("choice", ["xxh128", "xxh64", "xxh3", "md5", "md4", "sha1", "none"])
    def test_out_format_C_selected_algorithm_matches_rsync(self, shared_server, choice):
        """`%C` must use the algorithm selected by --checksum-choice, not always
        xxh128, and render it exactly like rsync (big-endian for the 64-bit
        hashes, high-then-low for xxh128, standard hex for md5/md4/sha1)."""
        source = os.path.join(TEST_DATA_DIR, f"wire_cc_{choice}_src")
        dest = os.path.join(TEST_DATA_DIR, f"wire_cc_{choice}_dst")
        rdst = os.path.join(TEST_DATA_DIR, f"wire_cc_{choice}_rdst")
        _make_one_file(source, "f.bin", 200000)
        clean_dir(dest)
        clean_dir(rdst)
        fmt = "%C %l %n"
        rsync_result = _rsync(["-a", "--checksum-choice=" + choice,
                               "--out-format=" + fmt, source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest,
                               flags=["-a", "--checksum-choice=" + choice,
                                      "--out-format=" + fmt],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]

        def file_lines(text):
            return [line for line in text.splitlines()
                    if line and not line.rsplit(" ", 1)[-1].endswith("/")]

        assert file_lines(result.stdout) == file_lines(rsync_result.stdout), (
            f"choice={choice}: rsync={rsync_result.stdout!r} fastsync={result.stdout!r}"
        )

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_dry_run_delete_lines_match_rsync(self, mt):
        """-n --delete emits transfer-relative `*deleting` lines like rsync
        (single-threaded and --threads)."""
        source = os.path.join(TEST_DATA_DIR, "wire_del_src")
        dest = os.path.join(TEST_DATA_DIR, "wire_del_dst")
        rdst = os.path.join(TEST_DATA_DIR, "wire_del_rdst")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(rdst)
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"a\n")
        for root, entries in (
            (rdst, {"extra.txt": b"x\n"}),
            (rdst, {"sub/y.txt": b"y\n", "extradir/z.txt": b"z\n"}),
        ):
            for rel, data in entries.items():
                full = os.path.join(root, rel)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "wb") as fh:
                    fh.write(data)
        # FastSync mirrors the source's absolute path under dest.
        received = get_dest_received_dir(dest, source)
        for rel, data in (
            ("extra.txt", b"x\n"),
            ("sub/y.txt", b"y\n"),
            ("extradir/z.txt", b"z\n"),
        ):
            full = os.path.join(received, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(data)

        rsync_result = _rsync(["-a", "-n", "--delete", "-i", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_del = sorted(
            line for line in rsync_result.stdout.splitlines() if line.startswith("*deleting")
        )
        # The shared session server refuses deletion; start one that allows it.
        flags = ["-a", "-n", "--delete", "-i"] + (["--threads"] if mt else [])
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
        assert result.returncode == 0, result.stderr[:300]
        fast_del = sorted(
            line for line in result.stdout.splitlines() if line.startswith("*deleting")
        )
        assert fast_del == rsync_del, f"rsync={rsync_del}\nfastsync={fast_del}"
