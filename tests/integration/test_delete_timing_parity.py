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
    hook once and keeps forwarding to completion.

    With ``wait_for_reply`` the hook is a real barrier, not a timing guess: it
    fires only after the server has sent *any* reply, which the receiver does
    only after it has consumed the frames that precede the payload (the
    per-directory delete plan for ``--delete-delay``).  The caller pairs it with
    ``--incremental`` so a per-file handshake reply is guaranteed mid-transfer.
    """

    def __init__(self, target_port, forward_limit=None, hook=None, hook_after=0,
                 throttle=0.0, wait_for_reply=False, hook_after_config_ack=False):
        self.target = ("127.0.0.1", target_port)
        self.forward_limit = forward_limit
        self.hook = hook
        self.hook_after = hook_after
        self.throttle = throttle
        self.wait_for_reply = wait_for_reply
        # When set, the hook fires on the FIRST client->server bytes that follow
        # the config-frame ack, BEFORE they are forwarded.  For --delete-before
        # those bytes are the keep-set manifest, so this runs the hook after the
        # client's source pre-scan but before the receiver's delete ack releases
        # the client into its data pass -- a deterministic late-file window.
        self.hook_after_config_ack = hook_after_config_ack
        self.config_acked = False
        self.server_replied = threading.Event()
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
                        if (self.hook_after_config_ack and self.config_acked and self.hook is not None
                                and not self.hook_called.is_set()):
                            # The first client bytes after the config ack are the
                            # pre-scan keep-set manifest: run the injection before
                            # forwarding so it is causally after the source scan.
                            self.hook()
                            self.hook_called.set()
                        backend.sendall(data)
                        forwarded += len(data)
                        self._maybe_hook(forwarded)
                        if self.forward_limit is not None and forwarded >= self.forward_limit:
                            socks = []
                            break
                        if self.throttle > 0:
                            time.sleep(self.throttle)
                    else:
                        client.sendall(data)
                        # Any server reply proves the receiver consumed the
                        # frames that precede it, so the hook barrier is met.
                        self.config_acked = True
                        self.server_replied.set()
                        self._maybe_hook(forwarded)
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

    def _maybe_hook(self, forwarded):
        """Fire the one-shot hook once its barrier is satisfied: enough client
        bytes have been forwarded and, when ``wait_for_reply`` is set, the
        server has sent a reply proving it processed the preceding frames.

        ``hook_after_config_ack`` uses its own barrier (see ``_serve``), so the
        byte/reply heuristic is bypassed entirely."""
        if self.hook is None or self.hook_called.is_set() or self.hook_after_config_ack:
            return
        if forwarded < self.hook_after:
            return
        if self.wait_for_reply and not self.server_replied.is_set():
            return
        self.hook()
        self.hook_called.set()

    def finish(self):
        self._thread.join(30)
        try:
            self.listener.close()
        except OSError:
            pass


class TestDeleteTimingFinalStateParity:
    """On a successful transfer the per-directory timings match rsync's result.

    Plain ``--delete`` has no rsync-incompatible spelling: it defaults to
    delete-during on both tools, so it is compared against rsync's own default.
    ``--delete-commit`` is FastSync-only and selects the late whole-tree commit,
    which is rsync's ``--delete-after`` timing.
    """

    # (fastsync flag, rsync flag)
    PAIRS = [
        ("--delete", "--delete"),
        ("--delete-during", "--delete-during"),
        ("--delete-delay", "--delete-delay"),
        ("--delete-commit", "--delete-after"),
    ]

    def _run_fastsync(self, tag, timing):
        source, dest, received = _seed_pair(tag)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=[timing], port=server.port)
        return result, received

    @pytest.mark.parametrize("fs_timing,rs_timing", PAIRS)
    @requires_rsync
    def test_success_final_state_matches_rsync(self, fs_timing, rs_timing):
        # Worker-safe names: xdist may run the parametrizations concurrently, so
        # the flags are part of every fixture path.
        label = f"{fs_timing.lstrip('-')}_vs_{rs_timing.lstrip('-')}"
        # Build the rsync fixture from the same seed so both sides start equal.
        source, dest, received = _seed_pair(f"parity_rsync_{label}")
        source2 = source
        rsync_dst = os.path.join(TEST_DATA_DIR, f"dtp_rsync_{label}_dst")
        clean_dir(rsync_dst)
        # rsync mirrors src/ into dst/; seed the same extra.
        _write(os.path.join(rsync_dst, "d", "old_extra"), b"stale extra\n")

        rsync_result = _rsync(["-a", rs_timing, source2 + "/", rsync_dst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_tree = _tree(rsync_dst)

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=[fs_timing], port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        fastsync_tree = _tree(received)
        assert fastsync_tree == rsync_tree, (
            f"{fs_timing} vs rsync {rs_timing}: fastsync tree {fastsync_tree} != "
            f"rsync tree {rsync_tree}"
        )


class TestDeleteTimingTypeConflictParity:
    """A destination entry whose type differs from the source is replaced, in
    both per-directory timings and in both directions, exactly like rsync."""

    @pytest.mark.parametrize("timing", ["--delete-during", "--delete-delay"])
    @requires_rsync
    def test_type_conflicts_match_rsync(self, timing):
        label = timing.lstrip("-")
        source = os.path.join(TEST_DATA_DIR, f"dtc_{label}_src")
        clean_dir(source)
        _write(os.path.join(source, "foo"), b"now a file\n")
        _write(os.path.join(source, "bar", "inner.txt"), b"now a dir\n")

        def seed_dest(root):
            clean_dir(root)
            _write(os.path.join(root, "foo", "inner.txt"), b"was a dir\n")
            _write(os.path.join(root, "bar"), b"was a file\n")

        rsync_dst = os.path.join(TEST_DATA_DIR, f"dtc_{label}_rsync_dst")
        seed_dest(rsync_dst)
        rsync_result = _rsync(["-a", timing, source + "/", rsync_dst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_tree = _tree(rsync_dst)

        dest = os.path.join(TEST_DATA_DIR, f"dtc_{label}_dst")
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
    """A mid-transfer failure distinguishes the during timings from the late
    commit timings.

    Plain ``--delete`` must behave like ``--delete-during`` (the rsync default),
    removing the extras of the directories already reached; ``--delete-commit``
    must behave like ``--delete-after`` and remove nothing until the transfer
    has fully succeeded.
    """

    @pytest.mark.parametrize("mt", [False, True])
    def test_during_removes_delay_preserves_on_failure(self, mt):
        source, dest, received = _seed_pair(f"failure_mt{int(mt)}", big=True)
        extra = os.path.join(received, "d", "old_extra")
        assert os.path.exists(extra)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            for timing, expect_removed in (
                    ("--delete-during", True),
                    ("--delete", True),
                    ("--delete-delay", False),
                    ("--delete-commit", False),
                    ("--delete-after", False)):
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


class TestDeleteDelayDeletedCount:
    """The reported deleted count must reflect entries actually removed."""

    def test_refilled_deferred_dir_is_recursively_removed_and_counted(self):
        """A directory snapshotted into a --delete-delay plan that is refilled
        before the commit is re-scanned and removed recursively (rsync parity):
        the late file and the directory are both counted as deleted."""
        source = os.path.join(TEST_DATA_DIR, "ddc_src")
        dest = os.path.join(TEST_DATA_DIR, "ddc_dst")
        clean_dir(source)
        clean_dir(dest)
        _write(os.path.join(source, "d", "keep.txt"), b"kept payload\n")
        _write(os.path.join(source, "d", "big.bin"), b"B" * BIG_BYTES)
        received = get_dest_received_dir(dest, source)
        extra_dir = os.path.join(received, "d", "extradir")
        os.makedirs(extra_dir, exist_ok=True)

        def hook():
            # Runs while big.bin is in flight, after d's delete plan was processed.
            _write(os.path.join(extra_dir, "new.txt"), b"created mid-transfer\n")

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            proxy = _SlicingProxy(server.port, hook=hook, hook_after=MID_TRANSFER_BYTES,
                                  throttle=PROXY_THROTTLE, wait_for_reply=True)
            flags = ["--delete-delay", "--incremental", "--ignore-times", "--stats"]
            result, _ = run_client(source, dest, flags=flags, port=proxy.port)
            proxy.finish()
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]
        assert proxy.hook_called.is_set(), "hook never fired"
        assert not os.path.exists(os.path.join(extra_dir, "new.txt")), "late file survived"
        assert not os.path.isdir(extra_dir), "refilled extra dir survived"
        deleted = None
        for line in result.stdout.splitlines():
            if line.startswith("Number of deleted files:"):
                deleted = int(line.split(":", 1)[1].split()[0])
        assert deleted == 2, (deleted, result.stdout)


class TestDeleteDelayMaxDeleteParity:
    """--max-delete with --delete-delay: a partial deletion still reports the
    number of entries actually removed, matching rsync (the exact surviving set
    can differ; only the count is compared)."""

    @requires_rsync
    def test_max_delete_count_matches_rsync(self):
        source = os.path.join(TEST_DATA_DIR, "ddm_src")
        rsync_dst = os.path.join(TEST_DATA_DIR, "ddm_rsync_dst")
        clean_dir(source)
        clean_dir(rsync_dst)
        _write(os.path.join(source, "d", "keep.txt"), b"keep\n")
        for i in range(1, 6):
            _write(os.path.join(rsync_dst, "d", f"e{i}.txt"), f"extra{i}\n".encode())

        rsync_result = _rsync(["-a", "--delete-delay", "--max-delete=2", "--stats",
                               source + "/", rsync_dst + "/"])
        # rsync exits 25 ("the --max-delete limit stopped deletions").
        assert rsync_result.returncode == 25, rsync_result.stderr
        rsync_count = _deleted_count(rsync_result.stdout)
        assert rsync_count == 2, rsync_result.stdout

        dest = os.path.join(TEST_DATA_DIR, "ddm_dst")
        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        for i in range(1, 6):
            _write(os.path.join(received, "d", f"e{i}.txt"), f"extra{i}\n".encode())
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(
                source, dest,
                flags=["--delete-delay", "--max-delete=2", "--stats"],
                port=server.port,
            )
        # A capped --max-delete commit is a successful transfer that both tools
        # report with exit 25.
        assert result.returncode == 25, (result.stderr or result.stdout)[:300]
        assert _deleted_count(result.stdout) == rsync_count, result.stdout


def _deleted_count(text):
    for line in text.splitlines():
        if line.startswith("Number of deleted files:"):
            return int(line.split(":", 1)[1].split()[0])
    return None


class TestDeleteDelayVsAfterSnapshot:
    """A destination entry created after its directory's scan survives under
    --delete-delay but is removed by --delete-after's fresh end scan."""

    @pytest.mark.parametrize("mt", [False, True])
    def test_late_created_extra_survives_delay_not_after(self, mt):
        source, dest, received = _seed_pair(f"latecreate_mt{int(mt)}", big=True)
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

                # --incremental gives the receiver a mid-transfer handshake
                # reply; the proxy waits for it (wait_for_reply) so the hook is
                # causally after the plan frame, never a timing guess.
                # --ignore-times forces the big file to transfer on the second
                # timing too (the first run already installed it), keeping the
                # mid-transfer reply present in both iterations.
                proxy = _SlicingProxy(server.port, hook=hook,
                                      hook_after=MID_TRANSFER_BYTES,
                                      throttle=PROXY_THROTTLE, wait_for_reply=True)
                flags = [timing, "--incremental", "--ignore-times"] + (["--threads"] if mt else [])
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


class TestDeleteAfterThreadsKeepSet:
    """Regression: -j/--threads must still transmit the delete keep-set in every
    timing.  PipelineContextSender.delete_suppressed was left uninitialized, so a
    garbage true silently skipped the late keep-set manifest under --threads.
    Plain --delete now uses the per-directory plans, while --delete-commit /
    --delete-after keep exercising the late whole-tree manifest."""

    @pytest.mark.parametrize("delete_flag", ["--delete", "--delete-commit", "--delete-after"])
    def test_threads_delete_after_sends_keep_set(self, delete_flag):
        source, dest, received = _seed_pair("mtkeep")
        extra = os.path.join(received, "d", "old_extra")
        assert os.path.exists(extra)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["--threads", delete_flag],
                                   port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        assert not os.path.exists(extra), (
            f"{delete_flag} --threads did not remove an extra: delete keep-set was suppressed"
        )

class TestDeleteDelayMaxDeleteRefilledDir:
    """--delete-delay charges the --max-delete budget on ACTUAL removals: the
    refilled directory's late content is removed first (consuming the one slot),
    so the directory itself and a later extra are skipped, matching rsync.

    The refilled directory is at the destination ROOT (its plan is always sent
    first) and the skipped extra is under a separate source directory, so the
    ordering that decides the budget charge is deterministic -- not readdir
    order.  The refill is injected through the byte-barrier proxy so it is
    causally after the plan frame."""

    def test_budget_charged_on_actual_removal(self):
        source = os.path.join(TEST_DATA_DIR, "ddmb_src")
        dest = os.path.join(TEST_DATA_DIR, "ddmb_dst")
        clean_dir(source)
        clean_dir(dest)
        _write(os.path.join(source, "a", "keep.bin"), b"B" * BIG_BYTES)
        _write(os.path.join(source, "b", "keep.txt"), b"keep\n")
        received = get_dest_received_dir(dest, source)
        refilled_dir = os.path.join(received, "xdir")
        os.makedirs(refilled_dir, exist_ok=True)
        later_dir = os.path.join(received, "b", "ydir")
        os.makedirs(later_dir, exist_ok=True)

        def hook():
            _write(os.path.join(refilled_dir, "new.txt"), b"created mid-transfer\n")

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            proxy = _SlicingProxy(server.port, hook=hook, hook_after=MID_TRANSFER_BYTES,
                                  throttle=PROXY_THROTTLE, wait_for_reply=True)
            flags = ["--delete-delay", "--max-delete=1", "--incremental", "--ignore-times", "--stats"]
            result, _ = run_client(source, dest, flags=flags, port=proxy.port)
            proxy.finish()
        assert result.returncode == 25, (result.stderr or result.stdout)[:400]
        assert proxy.hook_called.is_set(), "hook never fired"
        # The late content consumes the single budget slot; the refilled
        # directory itself and the later extra are skipped.
        assert not os.path.exists(os.path.join(refilled_dir, "new.txt")), "late file survived"
        assert os.path.isdir(later_dir), "later extra was not skipped by the budget"
        # The one actual removal is reported.
        assert _deleted_count(result.stdout) == 1, result.stdout


class TestDeleteBeforeLateFileParity:
    """rsync builds its file list once, so a source file created after that scan
    is NOT transferred and its destination extra is deleted.  FastSync's
    single-threaded --delete-before used to re-scan the source in its data pass
    and would transfer the late file (a safe superset); it now replays the
    pre-scan file list instead, matching rsync.

    The late file is injected through the config-ack barrier: the first client
    bytes after the config ack are the pre-scan keep-set manifest, so the hook
    runs causally after the source scan and before the receiver's delete ack
    releases the client into its data pass -- deterministic, no timing guess.
    """

    @requires_rsync
    def test_late_source_file_not_transferred_and_extra_deleted(self):
        source = os.path.join(TEST_DATA_DIR, "dblate_src")
        dest = os.path.join(TEST_DATA_DIR, "dblate_dst")
        rsync_dst = os.path.join(TEST_DATA_DIR, "dblate_rsync_dst")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(rsync_dst)
        _write(os.path.join(source, "d", "keep.txt"), b"kept payload\n")
        # Both destinations carry the would-be late file as an extra.
        for root in (dest, rsync_dst):
            _write(os.path.join(get_dest_received_dir(root, source), "d", "late.txt"),
                   b"stale extra\n")

        # rsync reference: the same source with no late file; the extra is removed
        # and nothing is transferred for the (never-scanned) late path.
        rsync_result = _rsync(["-a", "--delete-before", source + "/", rsync_dst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_tree = _tree(rsync_dst)
        assert "d/late.txt" not in rsync_tree

        received = get_dest_received_dir(dest, source)
        late_source = os.path.join(source, "d", "late.txt")

        def hook():
            # Runs after the pre-scan and before the data pass begins.
            _write(late_source, b"created after the scan\n")

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            proxy = _SlicingProxy(server.port, hook=hook, hook_after_config_ack=True)
            result, _ = run_client(source, dest, flags=["--delete-before"], port=proxy.port)
            proxy.finish()
        assert result.returncode == 0, (result.stderr or result.stdout)[:400]
        assert proxy.hook_called.is_set(), "late-file hook never fired"
        assert os.path.exists(late_source), "the source late file unexpectedly vanished"
        assert not os.path.exists(os.path.join(received, "d", "late.txt")), (
            "late source file was transferred: the single-threaded data pass re-scanned"
        )
        assert _tree(received) == rsync_tree, (
            f"fastsync tree {_tree(received)} != rsync tree {rsync_tree}"
        )
