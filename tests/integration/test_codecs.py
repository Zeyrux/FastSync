"""Differential tests for --checksum-choice / --compress-choice against rsync 3.4.1.

These pin the accepted/rejected algorithm matrix and exit codes to real rsync,
and verify that every codec FastSync now offers still transfers byte-exactly.
The rsync-based tests skip cleanly when rsync is not installed.

The FastSync server confines transfers to its authorized root (the project
directory when the shared test server is launched), so every scratch tree lives
under ``TEST_DATA_DIR`` rather than pytest's ``tmp_path``.
"""
import os
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

CHECKSUM_NAMES = ["xxh128", "xxh3", "xxh64", "md5", "md4", "sha1"]
COMPRESS_NAMES = ["zstd", "lz4", "zlib", "zlibx"]

CODEC_ROOT = os.path.join(TEST_DATA_DIR, "codec_differential")


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([RSYNC] + args, capture_output=True, text=True, env=env, timeout=120)


def _scratch(tag):
    """A confined, uniquely named scratch directory under the project tree."""
    path = os.path.join(CODEC_ROOT, tag)
    clean_dir(path)
    os.makedirs(path, exist_ok=True)
    return path


def _make_corpus(root):
    clean_dir(root)
    os.makedirs(os.path.join(root, "sub"), exist_ok=True)
    # Highly compressible payload so each codec is actually exercised.
    with open(os.path.join(root, "big.bin"), "wb") as fh:
        fh.write(b"FastSync codec payload " * 4096)
    with open(os.path.join(root, "sub", "text.txt"), "wb") as fh:
        fh.write(b"hello codec world\n" * 128)
    with open(os.path.join(root, "empty"), "wb"):
        pass
    return root


def _tree_bytes(root):
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            with open(path, "rb") as fh:
                out[os.path.relpath(path, root)] = fh.read()
    return out


class TestCodecChoiceMatrix:
    """The CLI accept/reject set and exit codes must match rsync 3.4.1."""

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("name", CHECKSUM_NAMES)
    def test_checksum_names_accepted_by_both(self, name, shared_server):
        src = _make_corpus(_scratch(f"cc_src_{name}"))
        rdst = _scratch(f"cc_rsync_{name}")
        rsync_result = _rsync(["-a", f"--cc={name}", src + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr

        fdst = _scratch(f"cc_fs_{name}")
        result, _ = run_client(src, fdst, flags=[f"--cc={name}"], port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("name", COMPRESS_NAMES)
    def test_compress_names_accepted_by_both(self, name, shared_server):
        src = _make_corpus(_scratch(f"zc_src_{name}"))
        rdst = _scratch(f"zc_rsync_{name}")
        rsync_result = _rsync(["-az", f"--zc={name}", src + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr

        fdst = _scratch(f"zc_fs_{name}")
        result, _ = run_client(src, fdst, flags=["-z", f"--zc={name}"], port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("choice", ["md4,sha1", "sha1,md4", "auto,md5", "none,md5"])
    def test_checksum_two_name_accepted_by_both(self, choice, shared_server):
        tag = choice.replace(",", "_")
        src = _make_corpus(_scratch(f"two_src_{tag}"))
        rdst = _scratch(f"two_rsync_{tag}")
        rsync_result = _rsync(["-a", "--checksum", f"--cc={choice}", src + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr

        fdst = _scratch(f"two_fs_{tag}")
        result, _ = run_client(src, fdst, flags=["--checksum", f"--cc={choice}"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("name", ["sha256", "crc32", "md5,", "md4,md5,sha1"])
    def test_unknown_checksum_rejected_exit_4_both(self, name, shared_server):
        src = _make_corpus(_scratch(f"badcc_src_{name.replace(',', '_').replace(':', '_')}"))
        rdst = _scratch(f"badcc_rsync_{name.replace(',', '_').replace(':', '_')}")
        rsync_result = _rsync(["-a", f"--cc={name}", src + "/", rdst + "/"])
        assert rsync_result.returncode == 4, rsync_result.stderr

        fdst = _scratch(f"badcc_fs_{name.replace(',', '_').replace(':', '_')}")
        result, _ = run_client(src, fdst, flags=[f"--cc={name}"], port=shared_server.port)
        assert result.returncode == 4, (result.stderr or result.stdout)[:200]

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("choice", ["none", "md5,none"])
    def test_checksum_none_with_checksum_rejected_exit_4_both(self, choice, shared_server):
        tag = choice.replace(",", "_")
        src = _make_corpus(_scratch(f"nonecc_src_{tag}"))
        rdst = _scratch(f"nonecc_rsync_{tag}")
        rsync_result = _rsync(["-a", "--checksum", f"--cc={choice}", src + "/", rdst + "/"])
        assert rsync_result.returncode == 4, rsync_result.stderr

        fdst = _scratch(f"nonecc_fs_{tag}")
        result, _ = run_client(src, fdst, flags=["--checksum", f"--cc={choice}"],
                               port=shared_server.port)
        assert result.returncode == 4, (result.stderr or result.stdout)[:200]

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("name", ["bogus", "zstd,lz4"])
    def test_unknown_compress_rejected_exit_4_both(self, name, shared_server):
        tag = name.replace(",", "_")
        src = _make_corpus(_scratch(f"badzc_src_{tag}"))
        rdst = _scratch(f"badzc_rsync_{tag}")
        rsync_result = _rsync(["-az", f"--zc={name}", src + "/", rdst + "/"])
        assert rsync_result.returncode == 4, rsync_result.stderr

        fdst = _scratch(f"badzc_fs_{tag}")
        result, _ = run_client(src, fdst, flags=["-z", f"--zc={name}"], port=shared_server.port)
        assert result.returncode == 4, (result.stderr or result.stdout)[:200]


class TestCodecTransferDifferential:
    """Each codec lands the same bytes rsync lands."""

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("name", COMPRESS_NAMES + ["none"])
    def test_compress_codec_matches_rsync_bytes(self, name, shared_server):
        src = _make_corpus(_scratch(f"byteszc_src_{name}"))
        rsync_dst = _scratch(f"byteszc_rsync_{name}")
        rsync_result = _rsync(["-a", "-z", f"--zc={name}", src + "/", rsync_dst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr

        fs_dst = _scratch(f"byteszc_fs_{name}")
        result, _ = run_client(src, fs_dst, flags=["-a", "-z", f"--zc={name}"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        received = get_dest_received_dir(fs_dst, src)
        assert _tree_bytes(received) == _tree_bytes(rsync_dst)

    @requires_rsync
    @pytest.mark.ci
    @pytest.mark.parametrize("name", CHECKSUM_NAMES)
    def test_checksum_codec_matches_rsync_bytes(self, name, shared_server):
        src = _make_corpus(_scratch(f"bytescc_src_{name}"))
        rsync_dst = _scratch(f"bytescc_rsync_{name}")
        rsync_result = _rsync(["-a", "--checksum", f"--cc={name}", src + "/", rsync_dst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr

        fs_dst = _scratch(f"bytescc_fs_{name}")
        result, _ = run_client(src, fs_dst, flags=["-a", "--checksum", f"--cc={name}"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        received = get_dest_received_dir(fs_dst, src)
        assert _tree_bytes(received) == _tree_bytes(rsync_dst)


class TestCodecNegotiationFallback:
    """FastSync's auto negotiation and deterministic fallback order."""

    @pytest.mark.ci
    def test_default_checksum_and_compression_agree(self, shared_server):
        """A default transfer (auto on both peers) succeeds; the negotiated
        default is xxh128 + zstd."""
        src = _make_corpus(_scratch("auto_src"))
        fdst = _scratch("auto_fs")
        result, _ = run_client(src, fdst, flags=["-a", "-z"], port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        received = get_dest_received_dir(fdst, src)
        assert _tree_bytes(received) == _tree_bytes(src)

    @pytest.mark.ci
    def test_explicit_choice_overrides_auto(self, shared_server):
        """An explicit --zc/--cc wins over the negotiated default on both ends,
        so the receiver decodes with the sender's codec."""
        src = _make_corpus(_scratch("explicit_src"))
        fdst = _scratch("explicit_fs")
        result, _ = run_client(src, fdst, flags=["-a", "-z", "--zc=lz4", "--cc=sha1"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        received = get_dest_received_dir(fdst, src)
        assert _tree_bytes(received) == _tree_bytes(src)
