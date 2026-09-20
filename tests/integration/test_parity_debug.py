"""`--debug=FLAGS` natural-event categories (no-wire).

FastSync maps the rsync `--debug` categories that correspond to a real event it
already performs (``flist``, ``del``, ``hash``/``deltasum``, ``recv``,
``filter`` and ``send``) onto debug output.  A normal run prints none of it.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import TEST_DATA_DIR, run_client, clean_dir, get_dest_received_dir, ServerManager


def _make_tree(root):
    clean_dir(root)
    os.makedirs(os.path.join(root, "sub"))
    with open(os.path.join(root, "a.txt"), "wb") as fh:
        fh.write(b"alpha\n")
    with open(os.path.join(root, "keep.log"), "wb") as fh:
        fh.write(b"log\n")
    with open(os.path.join(root, "sub", "b.txt"), "wb") as fh:
        fh.write(b"beta\n")


@pytest.mark.ci
def test_debug_flist_and_send_emit_output(shared_server):
    """`--debug=flist,send` produces category-tagged debug output."""
    source = os.path.join(TEST_DATA_DIR, "dbg_src")
    dest = os.path.join(TEST_DATA_DIR, "dbg_dst")
    _make_tree(source)
    clean_dir(dest)
    result, _ = run_client(source, dest, flags=["-a", "--debug=flist,send"],
                           port=shared_server.port)
    assert result.returncode == 0, (result.stderr or result.stdout)[:300]
    assert "flist: scanning" in result.stdout, result.stdout
    assert "send: " in result.stdout, result.stdout


@pytest.mark.ci
def test_debug_filter_emits_excluded_entry(shared_server):
    source = os.path.join(TEST_DATA_DIR, "dbg_filter_src")
    dest = os.path.join(TEST_DATA_DIR, "dbg_filter_dst")
    _make_tree(source)
    clean_dir(dest)
    result, _ = run_client(source, dest,
                           flags=["-a", "--debug=filter", "--exclude=*.log"],
                           port=shared_server.port)
    assert result.returncode == 0, (result.stderr or result.stdout)[:300]
    assert "filter: excluded keep.log" in result.stdout, result.stdout


@pytest.mark.ci
def test_debug_hash_and_recv_emit_on_incremental(shared_server):
    source = os.path.join(TEST_DATA_DIR, "dbg_hash_src")
    dest = os.path.join(TEST_DATA_DIR, "dbg_hash_dst")
    _make_tree(source)
    clean_dir(dest)
    result, _ = run_client(source, dest,
                           flags=["-a", "--incremental", "--checksum",
                                  "--debug=hash,recv"],
                           port=shared_server.port)
    assert result.returncode == 0, (result.stderr or result.stdout)[:300]
    assert "hash: " in result.stdout, result.stdout
    assert "recv: " in result.stdout, result.stdout


@pytest.mark.ci
def test_debug_del_emits_deleted_path():
    """`--debug=del` reports the paths the receiver actually removed.

    A deletion-capable server is required (the shared fixture refuses
    client-requested deletion)."""
    source = os.path.join(TEST_DATA_DIR, "dbg_del_src")
    dest = os.path.join(TEST_DATA_DIR, "dbg_del_dst")
    _make_tree(source)
    clean_dir(dest)
    seeded = get_dest_received_dir(dest, source)
    os.makedirs(seeded)
    with open(os.path.join(seeded, "extra.tmp"), "wb") as fh:
        fh.write(b"stale\n")
    server = ServerManager()
    server.start(extra_args=["--allow-super", "--allow-delete"])
    try:
        result, _ = run_client(source, dest, flags=["-a", "--delete", "--debug=del"],
                               port=server.port)
    finally:
        server.stop()
    assert result.returncode == 0, (result.stderr or result.stdout)[:300]
    assert "del: " in result.stdout and "extra.tmp" in result.stdout, result.stdout
    assert not os.path.exists(os.path.join(seeded, "extra.tmp"))


@pytest.mark.ci
def test_normal_run_has_no_debug_output(shared_server):
    source = os.path.join(TEST_DATA_DIR, "dbg_quiet_src")
    dest = os.path.join(TEST_DATA_DIR, "dbg_quiet_dst")
    _make_tree(source)
    clean_dir(dest)
    result, _ = run_client(source, dest, flags=["-a"], port=shared_server.port)
    assert result.returncode == 0, (result.stderr or result.stdout)[:300]
    assert "[DEBUG]" not in result.stdout
    assert "flist: scanning" not in result.stdout
    assert "send: " not in result.stdout
