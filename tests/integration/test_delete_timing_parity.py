"""Differential + regression coverage for rsync's delete timing.

``--delete-during``/``--delete-delay`` stream a per-directory delete plan instead
of one whole-tree manifest, so the timing is observable:

  * ``--delete-during`` removes a directory's extras as it processes that
    directory (so an interrupted transfer has already removed the extras of the
    directories it reached);
  * ``--delete-delay`` snapshots those extras while scanning and commits the
    removals only after a fully-successful transfer (so an extra created in the
    destination after its directory's plan survives, and a failed transfer
    removes nothing);
  * ``--delete-after`` re-scans the destination at the end (so that same
    late-created extra is removed).

The final-state tests compare against real ``rsync 3.4.1`` where a deterministic
comparison exists; the timing tests use a byte-slicing proxy to force a
mid-transfer failure or to create a destination entry while the transfer is in
flight.
"""
import os
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    BUILD_DIR,
    TEST_DATA_DIR,
    ServerManager,
    clean_dir,
    get_dest_received_dir,
    run_client,
)

# Every test here is deterministic (the proxy throttles until the delete-plan
# frames are processed), so the PR gate runs the whole module.
pytestmark = pytest.mark.ci

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")

BIG_BYTES = 8 * 1024 * 1024
# Forward/cut this far into the stream: past the (small) delete-plan frames and
# well into the big payload, so the receiver has already processed the plan.
MID_TRANSFER_BYTES = 256 * 1024
# Throttle the proxy so the receiver keeps up with the (fast) client and the
# plan frames are provably processed before the hook/cut offset is reached.
PROXY_THROTTLE = 0.001


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)


def _seed_pair(tag, big=False):
    """Create a source tree and a destination mirror seeded with extras.

    The tree is a single directory ``d`` containing the transferred files plus,
    in the destination, an extra ``d/old_extra``.
    """
    source = os.path.join(TEST_DATA_DIR, f"dtp_{tag}_src")
    dest = os.path.join(TEST_DATA_DIR, f"dtp_{tag}_dst")
    clean_dir(source)
    clean_dir(dest)
    _write(os.path.join(source, "d", "keep.txt"), b"kept payload\n")
    if big:
        _write(os.path.join(source, "d", "big.bin"), b"B" * BIG_BYTES)
    received = get_dest_received_dir(dest, source)
    os.makedirs(os.path.join(received, "d"), exist_ok=True)
    _write(os.path.join(received, "d", "old_extra"), b"stale extra\n")
    return source, dest, received


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


class _SlicingProxy:
    """Forward the client stream to a server, optionally cutting it or invoking a
    hook after a byte threshold.  ``forward_limit`` mode resets both ends after
    that many client bytes (a mid-transfer failure).  ``hook`` mode calls the
    hook once and keeps forwarding to completion."""

    def __init__(self, target_port, forward_limit=None, hook=None, hook_after=0,
                 throttle=0.0):
        self.target = ("127.0.0.1", target_port)
        self.forward_limit = forward_limit
        self.hook = hook
        self.hook_after = hook_after
        self.throttle = throttle
        self.hook_called = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(20)
        self.port = self.listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            client, _ = self.listener.accept()
        except OSError:
            return
        try:
            backend = socket.create_connection(self.target, timeout=10)
        except OSError:
            client.close()
            return
        client.settimeout(20)
        backend.settimeout(20)
        forwarded = 0
        socks = [client, backend]
        try:
            while socks:
                ready, _, _ = select.select(socks, [], [], 20)
                if not ready:
                    break
                for sock in ready:
                    data = sock.recv(65536)
                    if not data:
                        socks.remove(sock)
                        peer = backend if sock is client else client
                        try:
                            peer.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    if sock is client:
                        if self.forward_limit is not None:
                            room = self.forward_limit - forwarded
                            if room <= 0:
                                socks = []
                                break
                            data = data[:room]
                        backend.sendall(data)
                        forwarded += len(data)
                        if (self.hook is not None and not self.hook_called.is_set()
                                and forwarded >= self.hook_after):
                            # Give the receiver time to process the (tiny) plan
                            # frames that precede this offset before the hook
                            # mutates the destination.
                            if self.throttle > 0:
                                time.sleep(0.2)
                            self.hook()
                            self.hook_called.set()
                        if self.forward_limit is not None and forwarded >= self.forward_limit:
                            socks = []
                            break
                        if self.throttle > 0:
                            time.sleep(self.throttle)
                    else:
                        client.sendall(data)
        except OSError:
            pass
        for sock in (client, backend):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        try:
            self.listener.close()
        except OSError:
            pass

    def finish(self):
        self._thread.join(30)
        try:
            self.listener.close()
        except OSError:
            pass


class TestDeleteTimingFinalStateParity:
    """On a successful transfer the per-directory timings match rsync's result."""

    def _run_fastsync(self, tag, timing):
        source, dest, received = _seed_pair(tag)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=[timing], port=server.port)
        return result, received

    @pytest.mark.parametrize("timing", ["--delete-during", "--delete-delay"])
    @requires_rsync
    def test_success_final_state_matches_rsync(self, timing):
        # Build the rsync fixture from the same seed so both sides start equal.
        source, dest, received = _seed_pair("parity_rsync")
        source2 = source
        rsync_dst = os.path.join(TEST_DATA_DIR, "dtp_parity_rsync_dst")
        clean_dir(rsync_dst)
        # rsync mirrors src/ into dst/; seed the same extra.
        _write(os.path.join(rsync_dst, "d", "old_extra"), b"stale extra\n")

        rsync_result = _rsync(["-a", timing, source2 + "/", rsync_dst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_tree = _tree(rsync_dst)

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=[timing], port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        fastsync_tree = _tree(received)
        assert fastsync_tree == rsync_tree, (
            f"{timing}: fastsync tree {fastsync_tree} != rsync tree {rsync_tree}"
        )


class TestDeleteTimingTypeConflictParity:
    """A destination entry whose type differs from the source is replaced, in
    both per-directory timings and in both directions, exactly like rsync."""

    @pytest.mark.parametrize("timing", ["--delete-during", "--delete-delay"])
    @requires_rsync
    def test_type_conflicts_match_rsync(self, timing):
        source = os.path.join(TEST_DATA_DIR, "dtc_src")
        clean_dir(source)
        _write(os.path.join(source, "foo"), b"now a file\n")
        _write(os.path.join(source, "bar", "inner.txt"), b"now a dir\n")

        def seed_dest(root):
            clean_dir(root)
            _write(os.path.join(root, "foo", "inner.txt"), b"was a dir\n")
            _write(os.path.join(root, "bar"), b"was a file\n")

        rsync_dst = os.path.join(TEST_DATA_DIR, "dtc_rsync_dst")
        seed_dest(rsync_dst)
        rsync_result = _rsync(["-a", timing, source + "/", rsync_dst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_tree = _tree(rsync_dst)

        dest = os.path.join(TEST_DATA_DIR, "dtc_dst")
        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        seed_dest(received)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=[timing], port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        assert _tree(received) == rsync_tree, (
            f"{timing}: fastsync tree {_tree(received)} != rsync tree {rsync_tree}"
        )


class TestDeleteTimingFailure:
    """A mid-transfer failure distinguishes during from delay."""

    @pytest.mark.parametrize("mt", [False, True])
    def test_during_removes_delay_preserves_on_failure(self, mt):
        source, dest, received = _seed_pair("failure", big=True)
        extra = os.path.join(received, "d", "old_extra")
        assert os.path.exists(extra)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            for timing, expect_removed in (("--delete-during", True),
                                           ("--delete-delay", False)):
                # Re-seed the extra before each run.
                _write(extra, b"stale extra\n")
                proxy = _SlicingProxy(server.port, forward_limit=MID_TRANSFER_BYTES, throttle=PROXY_THROTTLE)
                flags = [timing] + (["--threads"] if mt else [])
                result, _ = run_client(source, dest, flags=flags, port=proxy.port)
                proxy.finish()
                assert result.returncode != 0, f"{timing}: truncated transfer succeeded"
                present = os.path.exists(extra)
                assert present != expect_removed, (
                    f"{timing} (mt={mt}): extra present={present}, expected "
                    f"removed={expect_removed}"
                )


class TestDeleteDelayVsAfterSnapshot:
    """A destination entry created after its directory's scan survives under
    --delete-delay but is removed by --delete-after's fresh end scan."""

    @pytest.mark.parametrize("mt", [False, True])
    def test_late_created_extra_survives_delay_not_after(self, mt):
        source, dest, received = _seed_pair("latecreate", big=True)
        old_extra = os.path.join(received, "d", "old_extra")
        new_extra = os.path.join(received, "d", "new_extra")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            for timing, new_survives in (("--delete-delay", True),
                                         ("--delete-after", False)):
                _write(old_extra, b"stale extra\n")
                if os.path.exists(new_extra):
                    os.unlink(new_extra)

                def hook():
                    # Runs on the proxy thread while the big file is in flight,
                    # after the directory's plan (delay) has been processed.
                    _write(new_extra, b"created mid-transfer\n")

                proxy = _SlicingProxy(server.port, hook=hook, hook_after=MID_TRANSFER_BYTES, throttle=PROXY_THROTTLE)
                flags = [timing] + (["--threads"] if mt else [])
                result, _ = run_client(source, dest, flags=flags, port=proxy.port)
                proxy.finish()
                assert result.returncode == 0, (
                    f"{timing}: {(result.stderr or result.stdout)[:300]}"
                )
                assert proxy.hook_called.is_set(), f"{timing}: hook never fired"
                assert not os.path.exists(old_extra), f"{timing}: old extra survived"
                assert os.path.exists(new_extra) == new_survives, (
                    f"{timing} (mt={mt}): new_extra present="
                    f"{os.path.exists(new_extra)}, expected survives={new_survives}"
                )
