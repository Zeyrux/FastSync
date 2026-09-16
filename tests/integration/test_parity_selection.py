"""rsync 3.4.1 parity for selection/path semantics and client option aliases.

Each test pins behaviour against real ``rsync 3.4.1``; the differential tests
skip cleanly when rsync is not installed.
"""
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    TEST_DATA_DIR,
    CLIENT_CMD,
    ServerManager,
    run_client,
    clean_dir,
    get_dest_received_dir,
)

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")


def _tree(root):
    """Sorted relative paths of directories (``D ``) and files (``F ``)."""
    out = []
    for dirpath, dirs, files in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        for d in dirs:
            out.append("D " + (d if rel == "." else os.path.join(rel, d)))
        for f in files:
            out.append("F " + (f if rel == "." else os.path.join(rel, f)))
    return sorted(out)


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([RSYNC] + args, capture_output=True, text=True, env=env, timeout=120)


def _make_tree(root):
    clean_dir(root)
    for rel, content in {
        "top.txt": b"top\n",
        "foo/bar/baz/f.txt": b"deep\n",
        "sub/x.txt": b"x\n",
    }.items():
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(content)
    return root


class TestRelativeGeneral:
    """#11: -R without --files-from uses rsync's '/./' cut and relative
    reconstruction instead of always mirroring the full source path."""

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("suffix", ["", "/./foo", "/./foo/bar", "/./"])
    def test_relative_cut_matches_rsync(self, shared_server, suffix):
        source = _make_tree(os.path.join(TEST_DATA_DIR, "sel_rel_src"))
        dest = os.path.join(TEST_DATA_DIR, "sel_rel_dst")
        rdst = os.path.join(TEST_DATA_DIR, "sel_rel_rdst")
        clean_dir(dest)
        clean_dir(rdst)
        spec = source + suffix
        r = _rsync(["-aR", spec, rdst + "/"])
        assert r.returncode == 0, r.stderr
        result, _ = run_client(spec, dest, flags=["-R"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert _tree(rdst) == _tree(dest), f"layout mismatch for {spec!r}"

    @requires_rsync
    @pytest.mark.ci
    def test_no_implied_dirs_matches_rsync(self, shared_server):
        source = _make_tree(os.path.join(TEST_DATA_DIR, "sel_nid_src"))
        a = os.path.join(source, "foo")
        b = os.path.join(source, "foo", "bar")
        os.chmod(a, 0o700)
        os.chmod(b, 0o711)
        os.utime(a, (978307200, 978307200))
        os.utime(b, (978307200, 978307200))
        spec = source + "/./foo/bar"
        for extra in ([], ["--no-implied-dirs"]):
            dest = os.path.join(TEST_DATA_DIR, "sel_nid_dst")
            rdst = os.path.join(TEST_DATA_DIR, "sel_nid_rdst")
            clean_dir(dest)
            clean_dir(rdst)
            r = _rsync(["-aR"] + extra + [spec, rdst + "/"])
            assert r.returncode == 0, r.stderr
            result, _ = run_client(spec, dest, flags=["-a", "-R"] + extra,
                                   port=shared_server.port)
            assert result.returncode == 0, result.stderr[:300]
            for rel in ("foo", "foo/bar"):
                rs = os.stat(os.path.join(rdst, rel))
                fs = os.stat(os.path.join(dest, rel))
                assert (rs.st_mode & 0o7777) == (fs.st_mode & 0o7777), \
                    f"mode mismatch for {rel} with {extra}"
                assert int(rs.st_mtime) == int(fs.st_mtime), \
                    f"mtime mismatch for {rel} with {extra}"


class TestClientAliases:
    """#5: safe rsync option aliases accepted client-side."""

    def _seed(self):
        source = _make_tree(os.path.join(TEST_DATA_DIR, "sel_alias_src"))
        return source

    @pytest.mark.parametrize(
        "flag",
        [
            "--ignore-non-existing",
            "--protect-args",
            "--msgs2stderr",
            "--no-msgs2stderr",
            "--no-iconv",
            "--iconv=.",
            "--iconv=-",
        ],
    )
    def test_alias_accepted(self, shared_server, flag):
        source = self._seed()
        dest = os.path.join(TEST_DATA_DIR, "sel_alias_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=[flag], port=shared_server.port)
        assert result.returncode == 0, f"{flag} rejected: {result.stderr[:300]}"

    def test_lone_h_prints_help(self):
        result = subprocess.run([CLIENT_CMD[0], "-h"], capture_output=True, text=True,
                                timeout=30)
        assert result.returncode == 0, result.stderr
        assert "Usage" in (result.stdout + result.stderr)

    def test_h_with_args_still_human_readable(self, shared_server):
        source = self._seed()
        dest = os.path.join(TEST_DATA_DIR, "sel_h_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["-h"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        received = get_dest_received_dir(dest, source)
        assert os.path.isfile(os.path.join(received, "top.txt"))
