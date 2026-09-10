"""--iconv=CONVERT_SPEC file-NAME charset conversion integration tests.

The client converts every source file name from LOCAL to REMOTE before it goes
on the wire, and the receiver converts it back from REMOTE to LOCAL, so a
source tree using one charset can be written into a destination tree using
another (rsync compatibility; content bytes are never touched).
"""
import os
import shutil

import pytest

from common import TEST_DATA_DIR, run_client, clean_dir, ServerManager

LATIN1_NAME = b"caf\xe9.txt"
UTF8_NAME = "caf\u00e9.txt".encode("utf-8")


def _make(tag):
    source = os.path.join(TEST_DATA_DIR, f"iconv_{tag}_src")
    dest = os.path.join(TEST_DATA_DIR, f"iconv_{tag}_dst")
    clean_dir(source)
    shutil.rmtree(dest, ignore_errors=True)
    # The destination ROOT must pre-exist on the receiver (the --mkpath contract:
    # without --mkpath the server requires the root directory to exist).
    os.makedirs(dest, exist_ok=True)
    return source, dest


def _place_bytes(root, name_bytes, data=b"latin1 payload\n"):
    full = os.path.join(os.fsencode(root), name_bytes)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as fh:
        fh.write(data)
    return full


def _dest_file(source, dest, name):
    base = os.path.join(dest, os.path.abspath(source).lstrip(os.sep))
    return os.path.join(os.fsencode(base), name)


@pytest.mark.ci
def test_iconv_latin1_roundtrip(shared_server):
    """A source file whose name is ISO-8859-1 bytes is transferred with
    --iconv=iso-8859-1,utf-8 and lands on the destination with the ORIGINAL
    latin1 name (the wire carried it as UTF-8)."""
    source, dest = _make("latin1")
    _place_bytes(source, LATIN1_NAME)

    result, _ = run_client(
        source, dest, flags=["--iconv=iso-8859-1,utf-8"], port=shared_server.port
    )
    assert result.returncode == 0, (result.stderr or result.stdout)[:400]

    dst = _dest_file(source, dest, LATIN1_NAME)
    assert os.path.exists(dst), f"dest latin1-named file not found under {dest}"


@pytest.mark.ci
def test_iconv_to_utf8_on_wire(shared_server):
    """--iconv=utf-8 (single, identity both ways) on an ascii filename transfers
    cleanly with no error."""
    source, dest = _make("utf8")
    src_path = os.path.join(source, "plain.txt")
    with open(src_path, "wb") as fh:
        fh.write(b"identity\n")

    result, _ = run_client(source, dest, flags=["--iconv=utf-8"], port=shared_server.port)
    assert result.returncode == 0, (result.stderr or result.stdout)[:400]

    dst = _dest_file(source, dest, os.fsencode("plain.txt"))
    assert os.path.exists(dst)


@pytest.mark.ci
def test_iconv_passthrough_identity(shared_server):
    """No --iconv flag: the transfer is unchanged (regression guard -- the common
    path must not go through iconv at all)."""
    source, dest = _make("identity")
    for name, data in (("a.txt", b"aaa\n"), ("sub/b.txt", b"bbb\n")):
        p = os.path.join(source, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)

    result, _ = run_client(source, dest, port=shared_server.port)
    assert result.returncode == 0, (result.stderr or result.stdout)[:400]

    for name in ("a.txt", "sub/b.txt"):
        assert os.path.exists(_dest_file(source, dest, os.fsencode(name)))


@pytest.mark.ci
def test_iconv_receiver_own_charset(shared_server):
    """A dedicated server started with its OWN --iconv converts received names
    to ITS charset: the source holds a latin1-named file, the wire carries it
    as UTF-8 (from the client's spec), and the receiver re-decodes it to UTF-8
    on disk.  This discriminates a real wire conversion from a no-op passthrough
    (a latin1 byte sequence is not valid UTF-8, so the receiver decoding it as
    UTF-8 would fail the transfer)."""
    with ServerManager() as server:
        server.start(extra_args=["--iconv=utf-8"])
        source, dest = _make("recv_charset")
        _place_bytes(source, LATIN1_NAME)

        result, _ = run_client(
            source, dest, flags=["--iconv=iso-8859-1,utf-8"], port=server.port
        )
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]

        dst = _dest_file(source, dest, UTF8_NAME)
        assert os.path.exists(dst), f"dest UTF-8-named file not found under {dest}"


@pytest.mark.ci
def test_iconv_invalid_charset_rejected(shared_server):
    """An unsupported charset name is rejected at startup with a nonzero exit."""
    source, dest = _make("badcharset")
    src_path = os.path.join(source, "f.txt")
    with open(src_path, "wb") as fh:
        fh.write(b"x")

    result, _ = run_client(
        source, dest, flags=["--iconv=no-such-charset,utf-8"], port=shared_server.port
    )
    assert result.returncode != 0


@pytest.mark.ci
def test_iconv_garbage_spec_rejected(shared_server):
    """A malformed CONVERT_SPEC is rejected at startup with a nonzero exit."""
    source, dest = _make("garbage")
    src_path = os.path.join(source, "f.txt")
    with open(src_path, "wb") as fh:
        fh.write(b"x")

    result, _ = run_client(source, dest, flags=["--iconv=,,,"], port=shared_server.port)
    assert result.returncode != 0