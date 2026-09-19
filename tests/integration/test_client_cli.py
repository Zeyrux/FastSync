"""Differential tests for the client CLI's codec defaults and env lists.

Track 3a of the rsync-parity plan pins two rsync 3.4.1 behaviors that are
resolved entirely on the client:

* the per-codec default ``--compress-level`` (zstd 3, zlib/zlibx 6, lz4
  ignored) applied when the user omits ``--compress-level``/``--zl``, with an
  explicit level clamped to the codec's range; and
* the ``RSYNC_COMPRESS_LIST`` / ``RSYNC_CHECKSUM_LIST`` preference lists that
  rsync's ``auto`` consults before its compiled-in order (whitespace-separated,
  unknown names skipped, first supported wins, all-unknown is exit 4).

The rsync side is observed through ``--debug=NSTR1``; FastSync publishes its
resolved codec/level through ``--debug=util``.  The checksum side is confirmed
byte-for-byte through ``--out-format %C``.  The rsync-based tests skip cleanly
when rsync is not installed.
"""
import os
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    TEST_DATA_DIR,
    run_client,
    clean_dir,
    get_dest_received_dir,
)

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")

CODEC_ROOT = os.path.join(TEST_DATA_DIR, "cli_differential")

_COMPRESS_RE = re.compile(r"compress(?:ion)?: (\w+) \(level (-?\d+)\)")


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([RSYNC] + args, capture_output=True, text=True, env=env, timeout=120)


def _scratch(tag):
    path = os.path.join(CODEC_ROOT, tag)
    clean_dir(path)
    os.makedirs(path, exist_ok=True)
    return path


def _make_corpus(root):
    clean_dir(root)
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "big.bin"), "wb") as fh:
        fh.write(b"FastSync codec payload " * 4096)
    with open(os.path.join(root, "small.txt"), "wb") as fh:
        fh.write(b"hello codec world\n" * 32)
    return root


def _rsync_compress_level(choice, level):
    src = _make_corpus(_scratch(f"lvl_src_{choice}_{level}"))
    dst = _scratch(f"lvl_rsync_{choice}_{level}")
    args = ["-a", "-z", f"--zc={choice}"]
    if level is not None:
        args.append(f"--zl={level}")
    args += ["--debug=NSTR1", src + "/", dst + "/"]
    result = _rsync(args)
    assert result.returncode == 0, result.stderr
    match = _COMPRESS_RE.search(result.stdout + result.stderr)
    assert match, (result.stdout, result.stderr)
    return match.group(1), int(match.group(2))


def _fastsync_compress_level(choice, level, shared_server):
    src = _make_corpus(_scratch(f"lvl_src_fs_{choice}_{level}"))
    dst = _scratch(f"lvl_fs_{choice}_{level}")
    args = ["-a", "-z", f"--zc={choice}"]
    if level is not None:
        args.append(f"--zl={level}")
    args += ["-v", "--debug=util"]
    result, _ = run_client(src, dst, flags=args, port=shared_server.port)
    assert result.returncode == 0, (result.stderr or result.stdout)[:300]
    match = _COMPRESS_RE.search(result.stdout)
    assert match, result.stdout[:500]
    return match.group(1), int(match.group(2))


class TestPerCodecCompressionLevelDefaults:
    """``--compress-level`` defaults and clamping match rsync per codec."""

    # FastSync uses a positive lz4 placeholder because its "level > 0" gate
    # enables compression; lz4_compress ignores the value, so rsync's level 0
    # and FastSync's level 1 produce the same bytes.
    CASES = [
        ("zstd", None, 3),
        ("zlib", None, 6),
        ("zlibx", None, 6),
        ("lz4", None, 1),
        ("zstd", 10, 10),
        ("zlib", 15, 9),
        ("zlib", 3, 3),
        ("lz4", 15, 1),
    ]

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("choice,level,fs_level", CASES)
    def test_level_matches_rsync(self, choice, level, fs_level, shared_server):
        rsync_algo, rsync_level = _rsync_compress_level(choice, level)
        fs_algo, fs_level_actual = _fastsync_compress_level(choice, level, shared_server)
        assert rsync_algo == choice
        assert fs_algo == choice
        if choice == "lz4":
            assert rsync_level == 0 and fs_level_actual > 0
        else:
            assert rsync_level == fs_level
            assert fs_level_actual == fs_level


class TestEnvPreferenceLists:
    """``RSYNC_COMPRESS_LIST`` / ``RSYNC_CHECKSUM_LIST`` drive auto like rsync."""

    # (env value, expected codec, rsync level, FastSync level)
    COMPRESS_CASES = [
        ("zlib lz4", "zlib", 6, 6),
        ("lz4 zstd", "lz4", 0, 1),
        ("bogus zstd zlib", "zstd", 3, 3),
        ("   ", "zstd", 3, 3),
    ]

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("env,algo,rsync_level,fs_level", COMPRESS_CASES)
    def test_compress_list_matches_rsync(self, env, algo, rsync_level, fs_level, shared_server,
                                         monkeypatch):
        monkeypatch.setenv("RSYNC_COMPRESS_LIST", env)
        src = _make_corpus(_scratch(f"envc_src_{algo}"))
        rdst = _scratch(f"envc_rsync_{algo}")
        rs = _rsync(["-a", "-z", "--debug=NSTR1", src + "/", rdst + "/"])
        assert rs.returncode == 0, rs.stderr
        rm = _COMPRESS_RE.search(rs.stdout + rs.stderr)
        assert rm, (rs.stdout, rs.stderr)
        assert rm.group(1) == algo
        assert int(rm.group(2)) == rsync_level

        fdst = _scratch(f"envc_fs_{algo}")
        result, _ = run_client(src, fdst, flags=["-a", "-z", "-v", "--debug=util"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        fm = _COMPRESS_RE.search(result.stdout)
        assert fm, result.stdout[:500]
        assert fm.group(1) == algo
        assert int(fm.group(2)) == fs_level
        received = get_dest_received_dir(fdst, src)
        assert _tree_bytes(received) == _tree_bytes(src)

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("env,algo", [("md5", "md5"), ("sha1", "sha1"), ("xxh3 md5", "xxh3")])
    def test_checksum_list_matches_rsync(self, env, algo, shared_server, monkeypatch):
        monkeypatch.setenv("RSYNC_CHECKSUM_LIST", env)
        src = _make_corpus(_scratch(f"envcc_src_{algo}"))
        rdst = _scratch(f"envcc_rsync_{algo}")
        rs = _rsync(["-a", "--checksum", "--out-format=%C %n", src + "/", rdst + "/"])
        assert rs.returncode == 0, rs.stderr
        rs_digests = _digests(rs.stdout)

        fdst = _scratch(f"envcc_fs_{algo}")
        result, _ = run_client(src, fdst, flags=["-a", "--checksum", "--out-format=%C %n"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        assert _digests(result.stdout) == rs_digests

    @requires_rsync
    @pytest.mark.ci
    def test_all_unknown_lists_fail_like_rsync(self, shared_server, monkeypatch):
        src = _make_corpus(_scratch("envbad_src"))
        monkeypatch.setenv("RSYNC_COMPRESS_LIST", "bogus")
        rs = _rsync(["-a", "-z", src + "/", _scratch("envbad_rsync_c") + "/"])
        assert rs.returncode == 4, rs.stderr
        result, _ = run_client(src, _scratch("envbad_fs_c"), flags=["-a", "-z"],
                               port=shared_server.port)
        assert result.returncode == 4, (result.stderr or result.stdout)[:200]

        monkeypatch.setenv("RSYNC_CHECKSUM_LIST", "bogus")
        rs = _rsync(["-a", src + "/", _scratch("envbad_rsync_s") + "/"])
        assert rs.returncode == 4, rs.stderr
        result, _ = run_client(src, _scratch("envbad_fs_s"), flags=["-a"],
                               port=shared_server.port)
        assert result.returncode == 4, (result.stderr or result.stdout)[:200]


def _tree_bytes(root):
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            with open(path, "rb") as fh:
                out[os.path.relpath(path, root)] = fh.read()
    return out


def _digests(output):
    out = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0]:
            out[parts[1]] = parts[0]
    return out
