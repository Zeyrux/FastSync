"""--iconv=CONVERT_SPEC file-NAME charset conversion integration tests.

rsync's spec is ``--iconv=LOCAL,REMOTE`` (the order is the same push or pull).
The sender converts each source name from LOCAL to REMOTE for the wire, and on
a PUSH the receiver's charset is the spec's REMOTE half, so it writes the wire
bytes verbatim (only a server with its own ``--iconv`` declares a different
destination charset and re-converts).  Content bytes are never touched.
"""
import codecs
import os
import shutil

import pytest

from common import TEST_DATA_DIR, run_client, clean_dir, ServerManager

LATIN1_NAME = b"caf\xe9.txt"
UTF8_NAME = "caf\u00e9.txt".encode("utf-8")


def _to_utf8(name_bytes):
    """The UTF-8 encoding of a name that is stored as ISO-8859-1 bytes."""
    return codecs.encode(codecs.decode(name_bytes, "iso-8859-1"), "utf-8")


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
def test_iconv_latin1_to_utf8_dest(shared_server):
    """rsync push parity: --iconv=iso-8859-1,utf-8 converts a latin1 source name
    to the spec's REMOTE (UTF-8) on the wire and the default receiver writes it
    verbatim, so the destination name is UTF-8 (not the source's latin1)."""
    source, dest = _make("latin1")
    _place_bytes(source, LATIN1_NAME)

    result, _ = run_client(
        source, dest, flags=["--iconv=iso-8859-1,utf-8"], port=shared_server.port
    )
    assert result.returncode == 0, (result.stderr or result.stdout)[:400]

    dst = _dest_file(source, dest, UTF8_NAME)
    assert os.path.exists(dst), f"dest UTF-8-named file not found under {dest}"
    assert not os.path.exists(_dest_file(source, dest, LATIN1_NAME)), \
        "destination kept the latin1 name instead of the wire (UTF-8) charset"


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


@pytest.mark.ci
def test_iconv_expanding_name_growth(shared_server):
    """A long latin1 name whose UTF-8 encoding expands past the initial output
    buffer exercises the E2BIG growth path in charset_convert (each high-bit
    latin1 byte doubles in UTF-8), and must land unchanged on the destination."""
    source, dest = _make("growth")
    name_bytes = b"a" * 40 + bytes(range(0x80, 0x80 + 40)) + b".txt"
    _place_bytes(source, name_bytes, data=b"growth\n")

    result, _ = run_client(
        source, dest, flags=["--iconv=iso-8859-1,utf-8"], port=shared_server.port
    )
    assert result.returncode == 0, (result.stderr or result.stdout)[:400]

    assert os.path.exists(_dest_file(source, dest, _to_utf8(name_bytes)))


def test_iconv_symlink_path_and_target(shared_server):
    """A latin1-named symlink pointing at a latin1-named target survives the
    transfer: both the link name and the link target are wire-converted and
    re-decoded on the destination (-l preserves links)."""
    source, dest = _make("symlink")
    target = b"target\xe9.dat"
    _place_bytes(source, target, data=b"t\n")
    os.symlink(target, os.path.join(os.fsencode(source), b"link\xe9"))

    result, _ = run_client(
        source, dest, flags=["--iconv=iso-8859-1,utf-8", "--links"], port=shared_server.port
    )
    assert result.returncode == 0, (result.stderr or result.stdout)[:400]

    utf8_target = _to_utf8(target)
    utf8_link = _to_utf8(b"link\xe9")
    dst_target = _dest_file(source, dest, utf8_target)
    dst_link = _dest_file(source, dest, utf8_link)
    assert os.path.exists(dst_target), "dest UTF-8 target file missing"
    assert os.path.islink(dst_link), "dest UTF-8 symlink missing"
    assert os.readlink(dst_link) == utf8_target, "symlink target not wire-converted"
    with open(dst_link, "rb") as fh:
        assert fh.read() == b"t\n"


def test_iconv_hardlink_path_and_target(shared_server):
    """A latin1-named hard-linked pair is preserved: -H transmits later group
    members as a path+target link to the first member, so both the member name
    and the target wire-convert (the two destination names must stay one
    inode)."""
    source, dest = _make("hardlink")
    a = b"hl_a\xe9.txt"
    b = b"hl_b\xe9.txt"
    src_a = os.path.join(os.fsencode(source), a)
    with open(src_a, "wb") as fh:
        fh.write(b"shared\n")
    os.link(src_a, os.path.join(os.fsencode(source), b))

    result, _ = run_client(
        source, dest, flags=["--iconv=iso-8859-1,utf-8", "--hard-links"],
        port=shared_server.port,
    )
    assert result.returncode == 0, (result.stderr or result.stdout)[:400]

    dst_a = _dest_file(source, dest, _to_utf8(a))
    dst_b = _dest_file(source, dest, _to_utf8(b))
    assert os.path.exists(dst_a) and os.path.exists(dst_b)
    assert os.stat(dst_a).st_ino == os.stat(dst_b).st_ino, \
        "hard-link relationship not preserved across the transfer"


def test_iconv_delete_manifest_consistent(shared_server):
    """Combining --iconv with --delete: the delete manifest's keep-set paths are
    wire-converted on send and disk-converted on receive, so the receiver's
    delete walker compares like with like and removes exactly the missing
    latin1-named file (never a wrong-named mirror)."""
    source, dest = _make("delete")
    keep = b"keep\xe9.txt"
    gone = b"gone\xe9.txt"
    _place_bytes(source, keep, data=b"k\n")
    _place_bytes(source, gone, data=b"g\n")

    with ServerManager() as server:
        server.start(extra_args=["--allow-delete"])
        flags = ["--iconv=iso-8859-1,utf-8"]
        result, _ = run_client(source, dest, flags=flags, port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]
        assert os.path.exists(_dest_file(source, dest, _to_utf8(keep)))
        assert os.path.exists(_dest_file(source, dest, _to_utf8(gone)))

        os.remove(os.path.join(os.fsencode(source), gone))
        result, _ = run_client(
            source, dest, flags=flags + ["--delete"], port=server.port
        )
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]
        assert os.path.exists(_dest_file(source, dest, _to_utf8(keep))), "kept file deleted"
        assert not os.path.exists(_dest_file(source, dest, _to_utf8(gone))), \
            "missing file was not deleted"


def test_iconv_chunk_serialization_blob(shared_server):
    """-s (chunk serialization) embeds paths and symlink targets inside the
    serialized chunk blob rather than as separate frames; a latin1 name must
    still wire-convert and re-decoded on the destination."""
    source, dest = _make("chunk")
    name = b"\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9.txt"
    _place_bytes(source, name, data=b"blob\n")

    result, _ = run_client(
        source, dest, flags=["--iconv=iso-8859-1,utf-8", "--chunk-serialization"], port=shared_server.port
    )
    assert result.returncode == 0, (result.stderr or result.stdout)[:400]

    assert os.path.exists(_dest_file(source, dest, _to_utf8(name)))