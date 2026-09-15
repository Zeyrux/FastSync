"""Feature tests: incremental sync, bandwidth limiting, dry run, metadata, filters."""
import filecmp
import os
import random
import shutil
import socket
import stat
import subprocess
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    PROJECT_ROOT, BUILD_DIR, TEST_DATA_DIR,
    run_client, CountingProxy,
    generate_test_files, verify_transfer, clean_dir, make_result,
    get_dest_received_dir, CLIENT_CMD, SERVER_CMD, ServerManager,
    _find_free_port, _wait_for_port, _wait_proc,
)

SOURCE_DIR = os.path.join(TEST_DATA_DIR, "feature_source")
DEST_DIR = os.path.join(TEST_DATA_DIR, "feature_dest")
DEVICE_SOURCE = os.path.join(TEST_DATA_DIR, "device_source")
DEVICE_DEST = os.path.join(TEST_DATA_DIR, "device_dest")


def _start_captured_server(prefix=None, extra_args=None):
    """Start a plain-TCP server with captured stdout/stderr for one test.

    Returns (proc, port).  The caller owns `proc` and must terminate it via
    `_wait_proc` so a server that ignores SIGTERM is killed instead of leaving
    a zombie or raising TimeoutExpired.  The shared session server discards its
    output, so tests that lock in a receiver-side warning need their own.  The
    server's SIGTERM handler exits via `_exit`, which does not flush stdio, so
    `stdbuf -oL` keeps stdout line-buffered and the warning observable."""
    port = _find_free_port()
    cmd = ["stdbuf", "-oL"] + (prefix or []) + SERVER_CMD + ["-p", str(port), "--allow-unauthenticated"]
    if extra_args:
        cmd += extra_args
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _wait_for_port(port)
    return proc, port


def _stop_captured_server(proc):
    """Terminate a captured server and return its (stdout, stderr) text."""
    proc.terminate()
    _wait_proc(proc)
    return proc.communicate()


class TestDeviceSpecial:
    """Phase 4: --devices / --specials / -D / --copy-devices / --write-devices.

    Device node CREATION (mknod) is privileged (CAP_MKNOD); CI runs non-root, so
    only the FIFO path (mkfifo, unprivileged) is asserted unconditionally.  The
    real-device-created assertions are guarded to run only as root.  Everything
    else must simply succeed / skip without aborting.
    """

    def _setup(self):
        clean_dir(DEVICE_SOURCE)
        clean_dir(DEVICE_DEST)
        with open(os.path.join(DEVICE_SOURCE, "plain.txt"), "wb") as f:
            f.write(b"regular content\n")

    def test_specials_recreates_fifo(self, shared_server):
        self._setup()
        os.mkfifo(os.path.join(DEVICE_SOURCE, "pipe.fifo"))
        result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                               flags=["--specials"], port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        fifo = os.path.join(received, "pipe.fifo")
        assert os.path.exists(fifo) and stat.S_ISFIFO(os.stat(fifo).st_mode), (
            "source FIFO was not recreated as a FIFO on the destination"
        )
        # The regular file alongside it still transferred normally.
        with open(os.path.join(received, "plain.txt")) as f:
            assert f.read() == "regular content\n"

    def test_D_implies_devices_and_specials_fifo(self, shared_server):
        """-D implies --devices --specials; a FIFO is preserved without a crash
        even though no device mknod is attempted on the (non-root) receiver."""
        self._setup()
        os.mkfifo(os.path.join(DEVICE_SOURCE, "pipe.fifo"))
        result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                               flags=["-D"], port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        assert stat.S_ISFIFO(os.stat(os.path.join(received, "pipe.fifo")).st_mode)

    @pytest.mark.ci
    def test_specials_recreates_socket(self, shared_server):
        """--specials recreates a unix-domain socket with mknod(S_IFSOCK), which
        Linux permits unprivileged; the adjacent regular file still transfers."""
        self._setup()
        sock_path = os.path.join(DEVICE_SOURCE, "source.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(sock_path)
            result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                                   flags=["--specials"], port=shared_server.port)
        finally:
            s.close()
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        with open(os.path.join(received, "plain.txt")) as f:
            assert f.read() == "regular content\n"
        dest_sock = os.path.join(received, "source.sock")
        assert os.path.lexists(dest_sock), "socket source was not recreated"
        assert stat.S_ISSOCK(os.lstat(dest_sock).st_mode), (
            "socket source must be recreated as a socket node"
        )

    @pytest.mark.ci
    def test_special_default_skips_non_regular(self, shared_server):
        """Without --specials, rsync skips a FIFO/socket as a non-regular file;
        FastSync must skip it (never copy it as an empty regular file)."""
        self._setup()
        os.mkfifo(os.path.join(DEVICE_SOURCE, "skip.fifo"))
        sock_path = os.path.join(DEVICE_SOURCE, "skip.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(sock_path)
            result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST, flags=[], port=shared_server.port)
        finally:
            s.close()
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        assert not os.path.lexists(os.path.join(received, "skip.fifo"))
        assert not os.path.lexists(os.path.join(received, "skip.sock"))
        with open(os.path.join(received, "plain.txt")) as f:
            assert f.read() == "regular content\n"

    @pytest.mark.ci
    @pytest.mark.parametrize("flags", [["--copy-devices"], ["--copy-devices", "--sendfile"]])
    def test_copy_devices_skips_fifo_without_specials(self, shared_server, flags):
        """rsync's --copy-devices applies to device nodes only; a FIFO/socket is
        a non-regular entry and is skipped unless --specials is also given.  In
        particular it must never hang in the sendfile open()."""
        self._setup()
        os.mkfifo(os.path.join(DEVICE_SOURCE, "device_copy.fifo"))
        result, dur = run_client(DEVICE_SOURCE, DEVICE_DEST,
                                 flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        assert not os.path.lexists(os.path.join(received, "device_copy.fifo")), (
            "a FIFO under --copy-devices alone must be skipped, not materialized"
        )
        assert dur < 60, f"{' '.join(flags)} hung on a FIFO source"

    def test_write_devices_non_crash(self, shared_server):
        """--write-devices writes into an existing device only; when the
        destination holds no device node the entry is skipped safely and the
        run still succeeds (never aborts)."""
        self._setup()
        # Destination already holds a regular file at the source FIFO's path:
        # the receiver must not clobber it and must not crash.
        os.mkfifo(os.path.join(DEVICE_SOURCE, "target.fifo"))
        result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                               flags=["--write-devices"], port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"

    @pytest.mark.ci
    def test_write_devices_regular_file_target_skipped(self, shared_server):
        """--write-devices only ever writes into an existing char/block node: a
        pre-existing REGULAR file at the destination path is left byte-identical
        (not clobbered) and the run still succeeds."""
        self._setup()
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        os.makedirs(received, exist_ok=True)
        target = os.path.join(received, "plain.txt")
        with open(target, "wb") as f:
            f.write(b"pre-existing local content\n")
        result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                               flags=["--write-devices"], port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        with open(target, "rb") as f:
            assert f.read() == b"pre-existing local content\n", (
                "write-devices clobbered a non-device destination"
            )

    @pytest.mark.setpriv
    def test_devices_nonroot_receiver_skips_safely(self):
        """A receiver without CAP_MKNOD must skip a device entry with a warning
        and never abort.  A root runner drops the receiver (server) to nobody
        via setpriv; on a non-root runner (or without setpriv) the test skips."""
        if os.geteuid() != 0 or shutil.which("setpriv") is None:
            pytest.skip("requires root + setpriv to run the receiver unprivileged")
        self._setup()
        os.mknod(os.path.join(DEVICE_SOURCE, "chardev"), stat.S_IFCHR | 0o666,
                 os.makedev(1, 3))
        # The unprivileged receiver must be able to create the destination tree.
        os.makedirs(DEVICE_DEST, exist_ok=True)
        os.chmod(DEVICE_DEST, 0o777)
        server, port = _start_captured_server(
            prefix=["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"])
        try:
            result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                                   flags=["--devices"], port=port)
        finally:
            out, err = _stop_captured_server(server)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:300]}"
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        with open(os.path.join(received, "plain.txt")) as f:
            assert f.read() == "regular content\n"
        assert not os.path.lexists(os.path.join(received, "chardev")), (
            "a receiver without CAP_MKNOD must skip the device node, not create it"
        )
        assert ("cannot create device node" in (out + err)
                or "device-node creation is not permitted" in (out + err)), (
            f"receiver did not log the documented device skip: out={out!r} err={err!r}"
        )

    @pytest.mark.skipif(os.geteuid() != 0, reason="requires root to create device nodes")
    def test_devices_recreates_real_char_device(self, shared_server):
        """Root-only: a source char device node is recreated on the destination
        with the same type and rdev (privilege-gated mknod path)."""
        self._setup()
        src_dev = os.path.join(DEVICE_SOURCE, "realdev")
        os.mknod(src_dev, stat.S_IFCHR | 0o666, os.makedev(1, 3))
        result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                               flags=["--devices"], port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        st = os.lstat(os.path.join(received, "realdev"))
        assert stat.S_ISCHR(st.st_mode)
        assert os.major(st.st_rdev) == 1 and os.minor(st.st_rdev) == 3

    @pytest.mark.skipif(os.geteuid() != 0, reason="requires root to create device nodes")
    def test_copy_devices_copies_device_as_regular(self, shared_server):
        """Root-only: --copy-devices copies a device's content into an ordinary
        regular file instead of recreating the node.  /dev/null (1,3) has size 0,
        so the result is a 0-byte REGULAR file."""
        self._setup()
        src_dev = os.path.join(DEVICE_SOURCE, "copieddev")
        os.mknod(src_dev, stat.S_IFCHR | 0o666, os.makedev(1, 3))
        result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                               flags=["-a", "--copy-devices"], port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        st = os.lstat(os.path.join(received, "copieddev"))
        assert stat.S_ISREG(st.st_mode), (
            f"--copy-devices must produce a regular file, got mode {oct(st.st_mode)}"
        )
        assert st.st_size == 0

    def test_m_remove_source_files_keeps_recreated_fifo(self, shared_server):
        """--threads --remove-source-files --specials: a recreated FIFO must NOT be
        acknowledged as a removable source (its outcome must not shift the
        per-file status stream, which would break the run and mis-remove the
        adjacent regular file).  The regular file is removed; the FIFO stays."""
        self._setup()
        os.mkfifo(os.path.join(DEVICE_SOURCE, "pipe.fifo"))
        result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                               flags=["--threads", "--remove-source-files", "--specials"],
                               port=shared_server.port)
        assert result.returncode == 0, (
            f"Exit {result.returncode}: {result.stderr[:300]}"
        )
        assert not os.path.exists(os.path.join(DEVICE_SOURCE, "plain.txt")), (
            "regular source file should have been removed"
        )
        assert os.path.exists(os.path.join(DEVICE_SOURCE, "pipe.fifo")), (
            "recreated FIFO source must never be removed"
        )

    @pytest.mark.skipif(os.geteuid() != 0, reason="requires root to create device nodes")
    def test_m_remove_source_files_keeps_recreated_device(self, shared_server):
        """Root-only: --threads --remove-source-files --devices must not remove a
        source device node the receiver recreated (mirrors the single-threaded
        behavior; the special is never acknowledged as a removable source)."""
        self._setup()
        src_dev = os.path.join(DEVICE_SOURCE, "realdev")
        os.mknod(src_dev, stat.S_IFCHR | 0o666, os.makedev(1, 3))
        result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                               flags=["--threads", "--remove-source-files", "--devices"],
                               port=shared_server.port)
        assert result.returncode == 0, (
            f"Exit {result.returncode}: {result.stderr[:300]}"
        )
        assert not os.path.exists(os.path.join(DEVICE_SOURCE, "plain.txt")), (
            "regular source file should have been removed"
        )
        assert os.path.exists(src_dev) and stat.S_ISCHR(os.lstat(src_dev).st_mode), (
            "recreated device source must never be removed"
        )

    def test_write_devices_fifo_target_skips_not_hangs(self, shared_server):
        """--write-devices must never block on a pre-existing FIFO at the
        destination mirror: opening with O_NONBLOCK fails with ENXIO and the
        entry is skipped (the FIFO is left untouched and the run succeeds)."""
        self._setup()
        # Pre-plant a FIFO at the destination mirror of the source file's path.
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        os.makedirs(received, exist_ok=True)
        target = os.path.join(received, "plain.txt")
        os.mkfifo(target)
        result, dur = run_client(DEVICE_SOURCE, DEVICE_DEST,
                                 flags=["--write-devices"], port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        assert stat.S_ISFIFO(os.lstat(target).st_mode), "FIFO target was clobbered"
        assert dur < 60, "write-devices hung on a FIFO target"

    def test_special_confined_to_receive_root(self, shared_server):
        """A special node is created only under the receive root; nothing is
        ever materialized outside it (the receiver is confined to its
        authorized root)."""
        self._setup()
        os.mkfifo(os.path.join(DEVICE_SOURCE, "confined.fifo"))
        result, _ = run_client(DEVICE_SOURCE, DEVICE_DEST,
                               flags=["--specials"], port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        # The only new FIFO is under the receive tree; its sibling watchers
        # confirm the confined dest layout (no stray node at the source root).
        source_fifo_escaped = os.path.join(DEVICE_DEST, "confined.fifo")
        assert not os.path.lexists(source_fifo_escaped), "special escaped the receive root"
        received = get_dest_received_dir(DEVICE_DEST, DEVICE_SOURCE)
        assert stat.S_ISFIFO(os.stat(os.path.join(received, "confined.fifo")).st_mode)


@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    generate_test_files(SOURCE_DIR, full=False)
    clean_dir(DEST_DIR)
    yield
    # Remove only this module's own dirs.  Under pytest-xdist the whole
    # (worker-keyed) TEST_DATA_DIR is shared with concurrently-interleaved
    # modules, so never rmtree it here.
    shutil.rmtree(SOURCE_DIR, ignore_errors=True)
    shutil.rmtree(DEST_DIR, ignore_errors=True)


class TestDryRun:
    def test_trust_sender_transfer_completes(self, shared_server):
        """--trust-sender is a receiver-local policy (never sent to the peer).
        A transfer run with it must still complete and produce byte-identical
        results: the receiver keeps its low-level root confinement, so a normal
        trusted transfer is unchanged."""
        clean_dir(DEST_DIR)
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--trust-sender"], port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:200]}"
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing files: {missing[:5]}"
        assert not mismatches, f"Mismatched files: {mismatches[:5]}"

    def test_human_readable_dry_run(self):
        result, dur = run_client(SOURCE_DIR, DEST_DIR, flags=["-h", "--dry-run"])
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert "Total:" in result.stdout
        assert "KB" in result.stdout

    def test_dry_run(self):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-n"],
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert "Dry run:" in result.stdout, f"No dry run output: {result.stdout[:200]}"

    def test_quiet_suppresses_dry_run_output(self):
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-q", "-n", "--progress", "--stats"],
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert result.stdout == ""
        assert result.stderr == ""

    def test_quiet_preserves_errors(self):
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--quiet", "--server-port", "1"],
        )
        assert result.returncode != 0
        assert result.stderr != ""

    @pytest.mark.parametrize("flags", [["-q", "-v"], ["-v", "-q"]])
    def test_quiet_successful_transfer_and_verbose_order(self, shared_server, flags):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=flags,
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert result.stdout == ""
        assert result.stderr == ""
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


def _snapshot_xattrs(path):
    """Return a stable, comparable tuple of (name, value) xattr pairs.

    Returns None when the platform/filesystem does not expose xattrs so both
    snapshots agree on "unavailable" instead of one being treated as changed."""
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except (AttributeError, OSError):
        return None
    if not names:
        return ()
    pairs = []
    for name in sorted(names):
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
        except OSError:
            value = None
        pairs.append((name, value))
    return tuple(pairs)


def _snapshot_tree(root):
    """Return a structural snapshot of a directory tree.

    Every entry (including directories) is recorded as
    (inode, mtime_ns, mode, xattrs, kind-specific payload) so a dry-run that
    touched a mode, inode, mtime, xattr, or content is observable.  Regular
    files carry their size+bytes, symlinks their target, and special entries
    (FIFO/socket/device) their size only -- opening a special file could block.
    Returns an empty dict for a missing root so "nothing was created" is also
    observable."""
    snapshot = {}
    if not os.path.exists(root):
        return snapshot
    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames) + filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            st = os.lstat(path)
            entry = [st.st_ino, st.st_mtime_ns, stat.S_IMODE(st.st_mode), _snapshot_xattrs(path)]
            if stat.S_ISLNK(st.st_mode):
                entry.append(("symlink", os.readlink(path)))
            elif stat.S_ISREG(st.st_mode):
                with open(path, "rb") as fh:
                    data = fh.read()
                entry += [st.st_size, data]
            else:
                entry.append(st.st_size)
            snapshot[rel] = tuple(entry)
    return snapshot


class TestRemoteDryRun:
    """Server-contacting --dry-run (protocol 2.21.0): contacts the receiver,
    reports what WOULD transfer/skip based on receiver state, and mutates
    nothing on either side."""

    def _seed(self, source):
        clean_dir(source)
        os.makedirs(os.path.join(source, "nested"), exist_ok=True)
        with open(os.path.join(source, "keep.txt"), "wb") as f:
            f.write(b"unchanged content\n")
        with open(os.path.join(source, "changed.txt"), "wb") as f:
            f.write(b"original content\n")
        with open(os.path.join(source, "nested", "deep.txt"), "wb") as f:
            f.write(b"deep file\n")

    @pytest.mark.ci
    def test_remote_dry_run_reports_changes_and_mutates_nothing(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remote_dry_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_dst")
        self._seed(source)
        clean_dir(dest)

        # Populate the destination with a real transfer that preserves mtimes
        # (--preserve), then make exactly one file differ (content+size) and add
        # a brand-new file.
        result, _ = run_client(source, dest, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0, f"seed transfer failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)

        with open(os.path.join(source, "changed.txt"), "wb") as f:
            f.write(b"a much longer replacement payload\n")
        with open(os.path.join(source, "added.txt"), "wb") as f:
            f.write(b"newly added\n")

        before = _snapshot_tree(received)
        # --checksum must NOT read destination contents in a dry-run (B3), so
        # the up-to-date decision is metadata-only.  The --preserve seed made
        # keep.txt and deep.txt size+mtime-identical; the dry-run must also
        # transmit metadata (--preserve) for that metadata to be comparable.
        result, _ = run_client(source, dest, flags=["--dry-run", "--checksum", "--preserve"],
                               port=shared_server.port)
        assert result.returncode == 0, f"remote dry-run failed: {result.stderr[:300]}"
        assert "Dry run:" in result.stdout, result.stdout[:200]
        assert "changed.txt" in result.stdout, result.stdout
        assert "added.txt" in result.stdout, result.stdout
        assert "keep.txt" not in result.stdout, (
            f"up-to-date file must not be reported as would-transfer: {result.stdout}"
        )
        assert "deep.txt" not in result.stdout, result.stdout
        assert _snapshot_tree(received) == before, "remote dry-run mutated the destination"

    @pytest.mark.ci
    def test_remote_dry_run_checksum_does_not_read_destination(self, shared_server):
        """B3: --dry-run --checksum against a read-only module must not read the
        destination file's content (a 1-bit hash oracle).  A same-size/same-content
        file whose mtime differs is therefore reported as would-transfer because
        the metadata-only decision is inconclusive, instead of being hashed and
        silently skipped."""
        source = os.path.join(TEST_DATA_DIR, "remote_dry_oracle_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_oracle_dst")
        self._seed(source)
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        received = get_dest_received_dir(dest, source)

        target = os.path.join(received, "keep.txt")
        # Identical size and content, but a deliberately different mtime.
        os.utime(target, (1000000000, 1000000000))
        before = _snapshot_tree(received)

        result, _ = run_client(source, dest, flags=["--dry-run", "--checksum", "--preserve"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert "keep.txt" in result.stdout, (
            f"dry-run --checksum must not read the destination to prove equality: {result.stdout}"
        )
        assert _snapshot_tree(received) == before, "dry-run mutated the destination"

    @pytest.mark.ci
    def test_remote_dry_run_into_empty_dest_creates_nothing(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remote_dry_empty_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_empty_dst")
        self._seed(source)
        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        assert not os.path.exists(received)

        result, _ = run_client(source, dest, flags=["--dry-run"], port=shared_server.port)
        assert result.returncode == 0, f"exit {result.returncode}: {result.stderr[:300]}"
        assert "keep.txt" in result.stdout
        assert "changed.txt" in result.stdout
        assert "deep.txt" in result.stdout
        # Nowhere may the receiver have created the destination mirror.
        assert not os.path.exists(received), "dry-run created directories on the receiver"
        assert _snapshot_tree(received) == {}

    @pytest.mark.ci
    def test_remote_dry_run_mkpath_does_not_create_root(self, shared_server):
        """A wire dry_run cannot make --mkpath create anything, and it cannot
        relax the precondition either: a nonexistent root is rejected (a real
        run without the created root is impossible in dry-run) while nothing is
        created."""
        source = os.path.join(TEST_DATA_DIR, "remote_dry_mk_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_mk_dst")
        self._seed(source)
        shutil.rmtree(dest, ignore_errors=True)
        assert not os.path.exists(dest)

        result, _ = run_client(source, dest, flags=["--dry-run", "--mkpath"],
                               port=shared_server.port)
        assert result.returncode != 0, "dry-run --mkpath accepted a nonexistent receive root"
        assert not os.path.exists(dest), "dry-run --mkpath created the destination root"

    @pytest.mark.ci
    def test_remote_dry_run_with_delete_does_not_delete(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remote_dry_del_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_del_dst")
        self._seed(source)
        clean_dir(dest)
        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        received = get_dest_received_dir(dest, source)
        extra = os.path.join(received, "extra.txt")
        with open(extra, "wb") as f:
            f.write(b"must survive a dry-run delete\n")
        before = _snapshot_tree(received)

        for flags in (["--dry-run", "--delete"], ["--dry-run", "--delete-after"]):
            result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
            assert result.returncode == 0, f"{flags}: {result.stderr[:300]}"
            assert os.path.exists(extra), f"{flags} deleted an extra in dry-run"
            assert _snapshot_tree(received) == before, f"{flags} mutated the destination"

    @pytest.mark.ci
    def test_remote_dry_run_quiet_is_silent(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remote_dry_quiet_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_quiet_dst")
        self._seed(source)
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["-q", "--dry-run"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert result.stdout == ""
        assert result.stderr == ""

    @pytest.mark.ci
    def test_remote_dry_run_threaded_routes_to_server(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remote_dry_mt_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_mt_dst")
        self._seed(source)
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["--dry-run", "--threads"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert "changed.txt" in result.stdout
        assert _snapshot_tree(get_dest_received_dir(dest, source)) == {}

    @pytest.mark.ci
    def test_normal_transfer_unaffected_by_dry_run(self, shared_server):
        """A real transfer after dry-run still installs the changes."""
        source = os.path.join(TEST_DATA_DIR, "remote_dry_normal_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_normal_dst")
        self._seed(source)
        clean_dir(dest)
        run_client(source, dest, port=shared_server.port)
        received = get_dest_received_dir(dest, source)
        with open(os.path.join(source, "changed.txt"), "wb") as f:
            f.write(b"updated payload for the real transfer\n")
        run_client(source, dest, flags=["--dry-run"], port=shared_server.port)

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        with open(os.path.join(received, "changed.txt"), "rb") as f:
            assert f.read() == b"updated payload for the real transfer\n"

    @pytest.mark.ci
    def test_remote_dry_run_delay_updates_mutates_nothing(self, shared_server):
        """--delay-updates stages under the receive root; a dry-run must neither
        create that staging tree nor publish anything (mode/inode/mtime intact)."""
        source = os.path.join(TEST_DATA_DIR, "remote_dry_delay_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_delay_dst")
        self._seed(source)
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["--delay-updates"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]

        with open(os.path.join(source, "changed.txt"), "wb") as f:
            f.write(b"changed for delay-updates dry-run\n")
        before = _snapshot_tree(dest)
        result, _ = run_client(source, dest, flags=["--dry-run", "--delay-updates"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert "changed.txt" in result.stdout, result.stdout
        assert _snapshot_tree(dest) == before, "delay-updates dry-run mutated the destination"

    @pytest.mark.ci
    def test_remote_dry_run_backup_mutates_nothing(self, shared_server):
        """--backup would rename the old file aside; a dry-run must not."""
        source = os.path.join(TEST_DATA_DIR, "remote_dry_backup_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_backup_dst")
        self._seed(source)
        clean_dir(dest)
        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]

        with open(os.path.join(source, "changed.txt"), "wb") as f:
            f.write(b"changed for backup dry-run\n")
        before = _snapshot_tree(dest)
        result, _ = run_client(source, dest, flags=["--dry-run", "--backup"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert "changed.txt" in result.stdout, result.stdout
        assert _snapshot_tree(dest) == before, "--backup dry-run mutated the destination"

    @pytest.mark.ci
    def test_remote_dry_run_symlink_mutates_nothing(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remote_dry_symlink_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_symlink_dst")
        self._seed(source)
        os.symlink("changed.txt", os.path.join(source, "link"))
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["-a"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        received = get_dest_received_dir(dest, source)
        assert os.path.islink(os.path.join(received, "link"))

        # Re-point the source link so the entry is genuinely stale, then prove a
        # dry-run leaves the destination link target, inode, and mtime untouched.
        os.unlink(os.path.join(source, "link"))
        os.symlink("keep.txt", os.path.join(source, "link"))
        before = _snapshot_tree(dest)
        result, _ = run_client(source, dest, flags=["-a", "--dry-run"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert _snapshot_tree(dest) == before, "symlink dry-run mutated the destination"
        assert os.readlink(os.path.join(received, "link")) == "changed.txt"

    @pytest.mark.ci
    def test_remote_dry_run_hardlink_mutates_nothing(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remote_dry_hardlink_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_hardlink_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "h1.txt"), "wb") as f:
            f.write(b"hardlinked payload\n")
        os.link(os.path.join(source, "h1.txt"), os.path.join(source, "h2.txt"))
        result, _ = run_client(source, dest, flags=["-H"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        received = get_dest_received_dir(dest, source)
        assert os.stat(os.path.join(received, "h1.txt")).st_ino == \
            os.stat(os.path.join(received, "h2.txt")).st_ino

        # Change the shared inode; both names are now stale in the destination.
        with open(os.path.join(source, "h1.txt"), "wb") as f:
            f.write(b"changed hardlinked payload\n")
        before = _snapshot_tree(dest)
        result, _ = run_client(source, dest, flags=["-H", "--dry-run"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert _snapshot_tree(dest) == before, "hardlink dry-run mutated the destination"

    @pytest.mark.ci
    def test_remote_dry_run_fifo_special_mutates_nothing(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remote_dry_fifo_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_fifo_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "plain.txt"), "wb") as f:
            f.write(b"plain\n")
        os.mkfifo(os.path.join(source, "existing.fifo"))
        result, _ = run_client(source, dest, flags=["--specials"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        received = get_dest_received_dir(dest, source)
        assert stat.S_ISFIFO(os.lstat(os.path.join(received, "existing.fifo")).st_mode)

        os.mkfifo(os.path.join(source, "new.fifo"))
        before = _snapshot_tree(dest)
        result, _ = run_client(source, dest, flags=["--specials", "--dry-run"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert not os.path.exists(os.path.join(received, "new.fifo")), \
            "dry-run created a FIFO on the receiver"
        assert _snapshot_tree(dest) == before, "special-node dry-run mutated the destination"

    @pytest.mark.ci
    def test_read_batch_with_dry_run_is_refused(self, shared_server):
        """A dry-run of a local batch apply is meaningless (and must not become a
        mutation escape hatch): the CLI rejects the combination up front."""
        source = os.path.join(TEST_DATA_DIR, "remote_dry_batch_src")
        dest = os.path.join(TEST_DATA_DIR, "remote_dry_batch_dst")
        self._seed(source)
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["--read-batch=/nonexistent.batch", "--dry-run"],
                               port=shared_server.port)
        assert result.returncode != 0, "read-batch + dry-run was accepted"
        combined = (result.stderr or "") + (result.stdout or "")
        assert "cannot be combined" in combined or "--dry-run" in combined, combined[:300]

    @pytest.mark.ci
    def test_remote_dry_run_bad_root_fails_like_real_run(self, shared_server):
        """A wire dry_run must not relax the destination-root precondition: a
        missing or non-directory root that fails a real run fails a dry-run too,
        and the dry-run must not create/replace anything."""
        source = os.path.join(TEST_DATA_DIR, "remote_dry_badroot_src")
        self._seed(source)

        missing = os.path.join(TEST_DATA_DIR, "remote_dry_badroot_missing")
        shutil.rmtree(missing, ignore_errors=True)
        real, _ = run_client(source, missing, port=shared_server.port)
        assert real.returncode != 0, "real run accepted a missing receive root"
        assert not os.path.exists(missing), "real run created the missing root"
        dry, _ = run_client(source, missing, flags=["--dry-run"], port=shared_server.port)
        assert dry.returncode != 0, "dry-run accepted a missing receive root a real run rejects"
        assert not os.path.exists(missing), "dry-run created the missing receive root"

        fileroot = os.path.join(TEST_DATA_DIR, "remote_dry_badroot_file")
        shutil.rmtree(fileroot, ignore_errors=True)
        with open(fileroot, "wb") as f:
            f.write(b"i am a regular file, not a directory\n")
        real, _ = run_client(source, fileroot, port=shared_server.port)
        assert real.returncode != 0, "real run accepted a regular-file receive root"
        dry, _ = run_client(source, fileroot, flags=["--dry-run"], port=shared_server.port)
        assert dry.returncode != 0, "dry-run accepted a regular-file receive root a real run rejects"
        with open(fileroot, "rb") as f:
            assert f.read() == b"i am a regular file, not a directory\n", \
                "dry-run clobbered a regular-file receive root"


class TestRemoveSourceFiles:
    def test_removes_only_transferred_regular_files(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_source")
        dest = os.path.join(TEST_DATA_DIR, "remove_dest")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "one.txt"), "wb") as f:
            f.write(b"one")
        with open(os.path.join(source, "two.txt"), "wb") as f:
            f.write(b"two")
        os.makedirs(os.path.join(source, "directory"))
        os.symlink("one.txt", os.path.join(source, "link.txt"))

        result, _ = run_client(source, dest, flags=["--remove-source-files", "--threads"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Remove-source sync failed: {result.stderr[:200]}"
        assert not os.path.exists(os.path.join(source, "one.txt"))
        assert not os.path.exists(os.path.join(source, "two.txt"))
        assert os.path.isdir(os.path.join(source, "directory"))
        assert os.path.islink(os.path.join(source, "link.txt"))

    def test_single_threaded_removes_transferred_file(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_single_source")
        dest = os.path.join(TEST_DATA_DIR, "remove_single_dest")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"single threaded")

        result, _ = run_client(source, dest, flags=["--remove-source-files"],
                               port=shared_server.port)
        assert result.returncode == 0
        assert not os.path.exists(source_file)

    def test_dry_run_preserves_source_files(self):
        source = os.path.join(TEST_DATA_DIR, "remove_dry_source")
        dest = os.path.join(TEST_DATA_DIR, "remove_dry_dest")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"keep")

        result, _ = run_client(source, dest, flags=["--remove-source-files", "--dry-run"])
        assert result.returncode == 0
        assert os.path.isfile(source_file)

    def test_failed_connection_preserves_source_files(self):
        source = os.path.join(TEST_DATA_DIR, "remove_failed_source")
        dest = os.path.join(TEST_DATA_DIR, "remove_failed_dest")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"keep after failure")

        result, _ = run_client(source, dest, flags=["--remove-source-files"], port=1)
        assert result.returncode != 0
        assert os.path.isfile(source_file)

    def test_incremental_skip_preserves_source_file(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_skipped_source")
        dest = os.path.join(TEST_DATA_DIR, "remove_skipped_dest")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"keep after skip")

        # The seed run preserves timestamps (--preserve) so the destination copy has the
        # source's exact mtime; otherwise the incremental skip would depend on
        # both writes landing in the same whole second (a race).
        result, _ = run_client(source, dest, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0
        result, _ = run_client(source, dest,
                               flags=["--remove-source-files", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0
        assert os.path.isfile(source_file)


class TestArchiveMode:
    @pytest.mark.ci
    def test_archive_mode(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-a"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_archive_with_negated_links(self, shared_server):
        # --archive implies links + metadata + devices + specials.  Devices/specials
        # force metadata transmission (recreating a node needs the metadata mode), so
        # the post-parse layer keeps use_metadata on even under --no-preserve; only the
        # independently-negatable --no-links actually takes effect here.
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--archive", "--no-links"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestExecutability:
    @pytest.mark.ci
    def test_preserves_only_executable_bits(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "executability_source")
        dest = os.path.join(TEST_DATA_DIR, "executability_dest")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "tool.sh")
        with open(source_file, "w") as f:
            f.write("#!/bin/sh\necho test\n")
        os.chmod(source_file, 0o751)

        result, _ = run_client(source, dest, flags=["-E"], port=shared_server.port)
        assert result.returncode == 0, f"Executability sync failed: {result.stderr[:200]}"
        received_file = os.path.join(get_dest_received_dir(dest, source), "tool.sh")
        received_mode = os.stat(received_file).st_mode
        # rsync -E on a fresh destination: the base is source & ~umask, then the
        # execute bits are derived from that base's read bits.  For a source of
        # 0751 this is exactly source & ~umask (owner rwx, group r-x, other --x
        # under the usual 022 umask => group/other bits 0o051, not 0o011).
        current_umask = os.umask(0)
        os.umask(current_umask)
        expected_mode = 0o751 & ~current_umask
        assert received_mode & 0o777 == expected_mode, (
            f"expected mode {oct(expected_mode)}, got {oct(received_mode & 0o777)}"
        )


class TestChmod:
    @pytest.mark.ci
    def test_chmod_applies_to_transferred_files(self, shared_server):
        clean_dir(DEST_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        os.chmod(source_file, 0o777)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--chmod=u=rw,go=r"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert (os.stat(os.path.join(received, "small.txt")).st_mode & 0o777) == 0o644


class TestPreallocate:
    """--preallocate allocates the destination file space up front; the final
    destination content must be byte-identical to a normal run."""

    def test_preallocate_transfer_succeeds(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "prealloc_source")
        dest = os.path.join(TEST_DATA_DIR, "prealloc_dest")
        clean_dir(source)
        clean_dir(dest)
        payload = os.urandom(2 * 1024 * 1024 + 137)
        with open(os.path.join(source, "data.bin"), "wb") as f:
            f.write(payload)
        with open(os.path.join(source, "small.txt"), "wb") as f:
            f.write(b"hello\n")

        result, _ = run_client(source, dest, flags=["--preallocate"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"--preallocate failed: {(result.stderr or result.stdout)[:400]}"

        received_dir = os.path.join(dest, os.path.abspath(source).lstrip(os.sep))
        data_path = os.path.join(received_dir, "data.bin")
        assert os.path.isfile(data_path), f"destination file not created: {data_path}"
        with open(data_path, "rb") as f:
            assert f.read() == payload, "destination content mismatch"
        small_path = os.path.join(received_dir, "small.txt")
        with open(small_path, "rb") as f:
            assert f.read() == b"hello\n", "small file content mismatch"

    def test_preallocate_combines_with_partial(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "prealloc_partial_src")
        dest = os.path.join(TEST_DATA_DIR, "prealloc_partial_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "f.txt"), "wb") as f:
            f.write(b"partial + preallocate\n")
        result, _ = run_client(source, dest, flags=["--preallocate", "--partial"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"--preallocate --partial failed: {(result.stderr or result.stdout)[:400]}"
        received_dir = os.path.join(dest, os.path.abspath(source).lstrip(os.sep))
        with open(os.path.join(received_dir, "f.txt"), "rb") as f:
            assert f.read() == b"partial + preallocate\n"


class TestCompressionChoice:
    @pytest.mark.ci
    def test_zstd_choice_compresses(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--zc", "zstd"],
                               port=shared_server.port)
        assert result.returncode == 0, f"zstd sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_none_choice_disables_compression(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-z", "--compress-choice", "none"],
                               port=shared_server.port)
        assert result.returncode == 0, f"none sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestSkipCompress:
    @pytest.mark.ci
    def test_skip_compress_case_insensitive(self, shared_server):
        clean_dir(DEST_DIR)
        with open(os.path.join(SOURCE_DIR, "skip-case.TXT"), "wb") as f:
            f.write((b"skip compression case test\n" * 100))
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-z", "--skip-compress=.txt"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Skip-compress sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        with open(os.path.join(received, "skip-case.TXT"), "rb") as f:
            assert f.read() == b"skip compression case test\n" * 100

    def test_skip_compress_empty_list(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-z", "--skip-compress="],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Empty skip-compress sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_skip_compress_incremental_full_fallback(self, shared_server):
        clean_dir(DEST_DIR)
        path = os.path.join(SOURCE_DIR, "incremental-skip.TXT")
        with open(path, "wb") as f:
            f.write(b"original skipped content\n")
        flags = ["-z", "--preserve", "--skip-compress=.txt"]
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"Initial sync failed: {(result.stderr or result.stdout)[:200]}"
        with open(path, "wb") as f:
            f.write(b"updated skipped content\n")
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=flags + ["--incremental"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Incremental sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        with open(os.path.join(received, "incremental-skip.TXT"), "rb") as f:
            assert f.read() == b"updated skipped content\n"

    def test_skip_compress_rejects_chunk_serialization(self, shared_server):
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-z", "--chunk-serialization", "--skip-compress=.txt"],
            port=shared_server.port,
        )
        assert result.returncode != 0
        assert "cannot be combined" in (result.stderr or result.stdout)


class TestExclude:
    def test_exclude_single(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--exclude", "small.txt"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert "small.txt" in missing, "small.txt should be excluded but was transferred"
        other_missing = [m for m in missing if m != "small.txt"]
        assert not other_missing, f"Other files missing: {other_missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_exclude_glob(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--exclude", "*.txt"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert not os.path.exists(os.path.join(received, "small.txt")), "small.txt should be excluded"
        assert os.path.exists(os.path.join(received, "binary.bin")), "binary.bin should be present"


class TestInclude:
    def test_include_single(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--include", "binary.bin"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert os.path.exists(os.path.join(received, "binary.bin")), "binary.bin should be included"
        assert not os.path.exists(os.path.join(received, "small.txt")), "small.txt should not be included"

    def test_include_glob(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--include", "*.bin"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert os.path.exists(os.path.join(received, "binary.bin")), "binary.bin should be included"


class TestSizeFilters:
    def test_max_size(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--max-size", "100"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert os.path.exists(os.path.join(received, "small.txt")), "small.txt should be present"
        assert not os.path.exists(os.path.join(received, "medium.txt")), "medium.txt should be skipped"

    def test_min_size(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--min-size", "1000"],
            port=shared_server.port,
        )
        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert not os.path.exists(os.path.join(received, "small.txt")), "small.txt should be skipped"
        assert os.path.exists(os.path.join(received, "medium.txt")), "medium.txt should be present"


class TestIncremental:
    @pytest.mark.ci
    def test_incremental_skips_unchanged(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--preserve"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"First sync failed: {result.stderr[:100]}"

        start = time.monotonic()
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--preserve", "--incremental"],
            port=shared_server.port,
        )
        incremental_time = time.monotonic() - start

        assert result.returncode == 0, f"Incremental sync failed: {(result.stderr or result.stdout)[:200]}"

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    @pytest.mark.ci
    def test_incremental_detects_changes(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--preserve"],
            port=shared_server.port,
        )
        assert result.returncode == 0

        modified_file = os.path.join(SOURCE_DIR, "small.txt")
        with open(modified_file, "wb") as f:
            f.write(b"modified content for incremental test\n")

        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--preserve", "--incremental"],
            port=shared_server.port,
        )
        assert result.returncode == 0

        with open(modified_file, "wb") as f:
            f.write(b"hello world\n")

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        received_file = os.path.join(received, "small.txt")
        assert os.path.exists(received_file), "Modified file should be present"
        with open(received_file, "rb") as f:
            content = f.read()
        assert b"modified content" in content, f"Modified content not transferred: {content[:50]}"

    def test_checksum_detects_same_size_and_mtime_change(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        received_file = os.path.join(received, "small.txt")
        source_stat = os.stat(source_file)
        with open(received_file, "wb") as f:
            f.write(b"different!\n")
        os.utime(received_file, (source_stat.st_atime, source_stat.st_mtime))

        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--preserve", "--incremental", "--checksum"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Checksum sync failed: {result.stderr[:200]}"
        with open(received_file, "rb") as f:
            assert f.read() == b"hello world\n"

    def test_size_only_skips_same_size_with_different_mtime(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        received_file = os.path.join(received, "small.txt")
        with open(received_file, "wb") as f:
            f.write(b"different!!\n")
        os.utime(received_file, (time.time() - 3600, time.time() - 3600))

        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--preserve", "--incremental", "--size-only"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Size-only sync failed: {result.stderr[:200]}"
        with open(received_file, "rb") as f:
            assert f.read() == b"different!!\n"

    def test_ignore_times_transfers_same_size_and_mtime(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        received_file = os.path.join(received, "small.txt")
        source_stat = os.stat(source_file)
        with open(received_file, "wb") as f:
            f.write(b"stale data!\n")
        os.utime(received_file, (source_stat.st_atime, source_stat.st_mtime))

        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--preserve", "--incremental", "--ignore-times"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Ignore-times sync failed: {result.stderr[:200]}"
        with open(received_file, "rb") as f:
            assert f.read() == b"hello world\n"

    def test_modify_window_allows_subsecond_mtime_difference(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        received_file = os.path.join(received, "small.txt")
        source_stat = os.stat(source_file)
        with open(received_file, "wb") as f:
            f.write(b"modified!!!\n")
        os.utime(received_file, ns=(source_stat.st_atime_ns,
                                    source_stat.st_mtime_ns - 1500000000))

        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--preserve", "--incremental", "--modify-window=2"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Modify-window sync failed: {result.stderr[:200]}"
        with open(received_file, "rb") as f:
            assert f.read() == b"modified!!!\n"

    def test_whole_file_disables_delta_and_keeps_compression(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0

        source_file = os.path.join(SOURCE_DIR, "medium.txt")
        with open(source_file, "wb") as f:
            f.write(b"whole-file replacement\n" * 5000)

        result, _ = run_client(
            SOURCE_DIR,
            DEST_DIR,
            flags=["--preserve", "--incremental", "--delta", "-W", "-z"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Whole-file sync failed: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


class TestChecksumChoice:
    """--checksum-choice/--cc and --checksum-seed: the whole-file digest used by
    the --incremental/--checksum handshake is selectable and seedable.  The
    receiver hashes the on-disk old file with the SAME algorithm+seed, so an
    unchanged file is skipped and a changed file (even with identical size and
    mtime) is transferred -- and the transfer always lands byte-exact.
    FastSync accepts xxh64 (default, seed-aware) and md5; names it does not
    implement are rejected, never silently ignored."""

    def test_unsupported_algorithm_is_rejected(self, shared_server):
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--checksum", "--checksum-choice=sha256"],
            port=shared_server.port,
        )
        assert result.returncode != 0, "sha256 must be rejected, not silently ignored"

    @pytest.mark.ci
    def test_checksum_alone_skips_unchanged(self, shared_server):
        """-c alone (no explicit --incremental) must switch the quick-check to a
        content digest: an unchanged file whose mtime differs is skipped."""
        source = os.path.join(TEST_DATA_DIR, "checksum_alone_src")
        dest = os.path.join(TEST_DATA_DIR, "checksum_alone_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "f.txt"), "wb") as fh:
            fh.write(b"same content\n")
        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        received = os.path.join(get_dest_received_dir(dest, source), "f.txt")
        assert os.path.exists(received)
        # Make the destination mtime differ without changing the bytes.
        bumped = os.stat(received).st_mtime + 100
        os.utime(received, (bumped, bumped))

        result, _ = run_client(source, dest, flags=["-c"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        # A skip leaves our bumped mtime in place; a transfer would rewrite it.
        assert os.stat(received).st_mtime == pytest.approx(bumped), \
            "-c did not skip an unchanged file"

        # A same-size, same-mtime content change is still detected.
        with open(received, "wb") as fh:
            fh.write(b"DIFF content\n")
        os.utime(received, (bumped, bumped))
        result, _ = run_client(source, dest, flags=["-c"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        with open(received, "rb") as fh:
            assert fh.read() == b"same content\n"

    @pytest.mark.ci
    def test_checksum_choice_md4_single_name_rejected(self, shared_server):
        for bad in ("md4", "sha1", "none", "xxh64,md5"):
            result, _ = run_client(SOURCE_DIR, DEST_DIR,
                                   flags=[f"--checksum-choice={bad}"],
                                   port=shared_server.port)
            assert result.returncode != 0, f"{bad} must be rejected"

    @pytest.mark.ci
    def test_compress_choice_unsupported_rejected(self, shared_server):
        for bad in ("lz4", "zlib", "zlibx"):
            result, _ = run_client(SOURCE_DIR, DEST_DIR,
                                   flags=[f"--compress-choice={bad}"],
                                   port=shared_server.port)
            assert result.returncode != 0, f"{bad} must be rejected"

    @pytest.mark.parametrize("algo", ["xxh64", "xxh3", "xxh128", "md5"])
    @pytest.mark.parametrize("mt", [False, True])
    def test_unchanged_skipped_and_bytes_preserved(self, shared_server, algo, mt):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"

        flags = (["--preserve", "--incremental", "--checksum", f"--checksum-choice={algo}"] +
                 (["--threads"] if mt else []))
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"checksum {algo} run failed: {result.stderr[:200]}"

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    # A changed source file with the SAME size and mtime must still be
    # detected (and re-transferred byte-exactly) because the whole-file digest
    # differs -- the explicit reason --checksum exists.  This exercises the
    # sender/receiver digest agreement for a non-default algorithm.
    @pytest.mark.parametrize("algo", ["xxh64", "xxh3", "xxh128", "md5"])
    @pytest.mark.parametrize("mt", [False, True])
    def test_changed_same_size_mtime_redetected(self, shared_server, algo, mt):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")  # "hello world\n" (12 bytes)
        received_file = os.path.join(received, "small.txt")
        source_stat = os.stat(source_file)
        with open(received_file, "wb") as f:
            f.write(b"DDDDDDDDDDDD")  # same size, different content
        os.utime(received_file, (source_stat.st_atime, source_stat.st_mtime))

        flags = (["--preserve", "--incremental", "--checksum", f"--checksum-choice={algo}"] +
                 (["--threads"] if mt else []))
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"checksum {algo} redetect failed: {result.stderr[:200]}"
        with open(received_file, "rb") as f:
            assert f.read() == b"hello world\n"

    @pytest.mark.parametrize("algo", ["xxh64", "md5"])
    def test_unchanged_run_transfers_almost_no_data(self, shared_server, algo):
        # A fully-unchanged --checksum run skips every file: only the config + a
        # small handshake travels, not the payloads.  Proxy byte counts are not
        # available for -m (multithreaded connections), so single-thread only.
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0

        flags = ["--preserve", "--incremental", "--checksum", f"--checksum-choice={algo}"]
        proxy = CountingProxy(shared_server.port)
        cmd = (CLIENT_CMD + ["--source-dir", SOURCE_DIR, "--dest-dir", DEST_DIR,
                             "--save-to-disk", "--server-port", str(proxy.port)] + flags)
        result = proxy.run(cmd)
        assert result.returncode == 0, f"checksum {algo} skip run failed: {result.stderr[:200]}"
        assert proxy.client_to_server < 100000, \
            f"unchanged --checksum run sent {proxy.client_to_server} bytes; expected a skip"

    @pytest.mark.parametrize("mt", [False, True])
    def test_seed_is_deterministic_and_preserves_content(self, shared_server, mt):
        clean_dir(DEST_DIR)
        flags = ["--preserve", "--incremental", "--checksum",
                 "--checksum-choice=xxh64", "--checksum-seed=987654"] + (["--threads"] if mt else [])
        first, _ = run_client(SOURCE_DIR, DEST_DIR, flags=flags, port=shared_server.port)
        assert first.returncode == 0, f"seeded run failed: {first.stderr[:200]}"

        # A second run with the SAME seed and unchanged content skips everything
        # deterministically (same digests both sides).
        second, _ = run_client(SOURCE_DIR, DEST_DIR, flags=flags, port=shared_server.port)
        assert second.returncode == 0, f"deterministic rerun failed: {second.stderr[:200]}"

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing and not mismatches, f"missing={missing} mismatches={mismatches}"

        # A changed file with the same size and mtime is still caught and fixed
        # (a non-zero seed does not weaken the comparison).
        source_file = os.path.join(SOURCE_DIR, "medium.txt")
        received_file = os.path.join(received, "medium.txt")
        source_stat = os.stat(source_file)
        with open(received_file, "wb") as f:
            f.write(b"z" * os.path.getsize(source_file))
        os.utime(received_file, (source_stat.st_atime, source_stat.st_mtime))
        third, _ = run_client(SOURCE_DIR, DEST_DIR, flags=flags, port=shared_server.port)
        assert third.returncode == 0, f"seeded redetect failed: {third.stderr[:200]}"
        with open(received_file, "rb") as f:
            assert f.read() == open(source_file, "rb").read()

    # --checksum-seed also feeds the delta path's per-block strong checksum on
    # both ends (receiver signature and sender window hash use the same seed),
    # so a seeded delta transfer still lands byte-exact.
    @pytest.mark.parametrize("mt", [False, True])
    def test_seed_delta_block_hash_transfers_byte_exact(self, shared_server, mt):
        source = os.path.join(TEST_DATA_DIR, f"ccseed_{'m' if mt else 's'}_src")
        dest = os.path.join(TEST_DATA_DIR, f"ccseed_{'m' if mt else 's'}_dst")
        clean_dir(source)
        clean_dir(dest)
        big = os.path.join(source, "big.bin")
        with open(big, "wb") as f:
            f.write(bytes(range(256)) * 200)  # 51200 bytes > delta 16K floor
        result, _ = run_client(source, dest, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0, f"seed delta seed failed: {result.stderr[:200]}"

        # Edit a region so the receiver must match a changed block with the seed.
        with open(big, "r+b") as f:
            f.seek(1000)
            f.write(b"\x00" * 64)
        # Force an mtime mismatch: the incremental quick-check skips files whose
        # stored mtime second equals the source's, which can collide when the
        # edit and the prior sync share a second.  Setting an old dest mtime
        # guarantees the delta path is exercised deterministically.
        os.utime(os.path.join(get_dest_received_dir(dest, source), "big.bin"), (0, 0))
        flags = (["--preserve", "--incremental", "--delta", "--checksum-seed=314159"] +
                 (["--threads"] if mt else []))
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"seed delta run failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "big.bin")) == _read_file(big), \
            "seeded delta transfer is not byte-exact"


class TestUpdate:
    @pytest.mark.ci
    def test_update_skips_older_destination_and_allows_equal_or_newer_source(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        received_file = os.path.join(received, "small.txt")
        source_stat = os.stat(source_file)

        with open(received_file, "wb") as f:
            f.write(b"newer destination\n")
        os.utime(received_file, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns + 10_000_000_000))
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
        assert result.returncode == 0
        with open(received_file, "rb") as f:
            assert f.read() == b"newer destination\n"

        os.utime(received_file, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
        assert result.returncode == 0
        with open(received_file, "rb") as f:
            assert f.read() == b"hello world\n"

    def test_update_skips_unreadable_newer_destination(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
        assert result.returncode == 0

        received_file = os.path.join(get_dest_received_dir(DEST_DIR, SOURCE_DIR), "small.txt")
        source_stat = os.stat(os.path.join(SOURCE_DIR, "small.txt"))
        with open(received_file, "wb") as f:
            f.write(b"protected destination\n")
        os.utime(received_file, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns + 10_000_000_000))
        original_mode = os.stat(received_file).st_mode
        try:
            os.chmod(received_file, 0)
            result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
            assert result.returncode == 0
            os.chmod(received_file, original_mode)
            with open(received_file, "rb") as f:
                assert f.read() == b"protected destination\n"
        finally:
            os.chmod(received_file, original_mode)

        with open(received_file, "wb") as f:
            f.write(b"older destination\n")
        os.utime(received_file, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns - 10_000_000_000))
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-u"], port=shared_server.port)
        assert result.returncode == 0
        with open(received_file, "rb") as f:
            assert f.read() == b"hello world\n"


class TestExisting:
    @pytest.mark.ci
    def test_existing_updates_existing_and_skips_new(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0, f"Initial sync failed: {(result.stderr or result.stdout)[:200]}"

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        source_file = os.path.join(SOURCE_DIR, "small.txt")
        new_source_file = os.path.join(SOURCE_DIR, "new-existing-test.txt")
        with open(source_file, "wb") as f:
            f.write(b"updated existing content\n")
        with open(new_source_file, "wb") as f:
            f.write(b"this file must not be created\n")

        try:
            result, _ = run_client(SOURCE_DIR, DEST_DIR,
                                   flags=["--preserve", "--existing"], port=shared_server.port)
            assert result.returncode == 0, f"--existing sync failed: {(result.stderr or result.stdout)[:200]}"

            with open(os.path.join(received, "small.txt"), "rb") as f:
                assert f.read() == b"updated existing content\n"
            assert not os.path.exists(os.path.join(received, "new-existing-test.txt"))
        finally:
            os.unlink(new_source_file)
            with open(source_file, "wb") as f:
                f.write(b"hello world\n")


class TestIgnoreExisting:
    def test_ignore_existing_preserves_existing_and_transfers_new(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        existing_file = os.path.join(received, "small.txt")
        with open(existing_file, "wb") as f:
            f.write(b"destination content\n")
        new_source = os.path.join(SOURCE_DIR, "new.txt")
        try:
            with open(new_source, "wb") as f:
                f.write(b"new file\n")

            result, _ = run_client(SOURCE_DIR, DEST_DIR,
                                   flags=["--ignore-existing"], port=shared_server.port)
            assert result.returncode == 0, f"Sync failed: {(result.stderr or result.stdout)[:200]}"
            with open(existing_file, "rb") as f:
                assert f.read() == b"destination content\n"
            with open(os.path.join(received, "new.txt"), "rb") as f:
                assert f.read() == b"new file\n"
        finally:
            if os.path.lexists(new_source):
                os.unlink(new_source)


class TestIgnoreExisting:
    def test_ignore_existing_preserves_existing_and_transfers_new(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        existing_file = os.path.join(received, "small.txt")
        with open(existing_file, "wb") as f:
            f.write(b"destination content\n")
        new_source = os.path.join(SOURCE_DIR, "new.txt")
        try:
            with open(new_source, "wb") as f:
                f.write(b"new file\n")

            result, _ = run_client(SOURCE_DIR, DEST_DIR,
                                   flags=["--ignore-existing"], port=shared_server.port)
            assert result.returncode == 0, f"Sync failed: {(result.stderr or result.stdout)[:200]}"
            with open(existing_file, "rb") as f:
                assert f.read() == b"destination content\n"
            with open(os.path.join(received, "new.txt"), "rb") as f:
                assert f.read() == b"new file\n"
        finally:
            if os.path.lexists(new_source):
                os.unlink(new_source)


class TestDelete:
    @pytest.mark.ci
    def test_delete_removes_extra_files(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--preserve"],
            port=shared_server.port,
        )
        assert result.returncode == 0

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        extra_file = os.path.join(received, "extra_file.txt")
        extra_dir = os.path.join(received, "extra_dir")
        with open(extra_file, "w") as f:
            f.write("should be deleted")
        os.makedirs(extra_dir, exist_ok=True)
        with open(os.path.join(extra_dir, "nested.txt"), "w") as f:
            f.write("nested extra")

        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--preserve", "--delete"],
            port=shared_server.port,
        )

        assert result.returncode == 0, f"Delete sync failed: {(result.stderr or result.stdout)[:200]}"
        # The default server policy intentionally refuses client-requested
        # deletion unless it is started with --allow-delete.
        assert os.path.exists(extra_file), "unauthorized delete removed an extra file"
        assert os.path.exists(extra_dir), "unauthorized delete removed an extra directory"

        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    @pytest.mark.ci
    def test_force_cannot_replace_directory_without_allow_delete(self):
        """C2: --force is deletion authority (an incoming file may recursively
        remove a non-empty destination directory tree).  A server started without
        --allow-delete must clear it, so the operator's delete policy cannot be
        bypassed with --force."""
        source = os.path.join(TEST_DATA_DIR, "force_src")
        dest = os.path.join(TEST_DATA_DIR, "force_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "blocker"), "wb") as f:
            f.write(b"incoming file\n")
        received = get_dest_received_dir(dest, source)
        blocker = os.path.join(received, "blocker")
        os.makedirs(blocker)
        nested = os.path.join(blocker, "nested.txt")
        with open(nested, "w") as f:
            f.write("survivor")
        # Deliberately NO --allow-delete.
        server = ServerManager()
        server.start()
        try:
            run_client(source, dest, flags=["--force"], port=server.port)
        finally:
            server.stop()
        assert os.path.isdir(blocker), "unauthorized --force removed a destination directory"
        assert os.path.exists(nested), "unauthorized --force removed a nested file"
    def test_progress_output(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--progress"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        output = result.stdout + result.stderr
        assert "Sent " in output and "MB" in output, "--progress produced no stable byte marker"
        assert "Done." in output, "--progress did not report completion"

    def test_human_readable_stats(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["-h", "--stats"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert "Stats:" in result.stderr
        assert "KB" in result.stderr

    def test_human_readable_stats_multithreaded(self, shared_server):
        # The multithreaded sender shares the single-threaded --stats format,
        # including --human-readable and the rate suffix.
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--threads", "-h", "--stats"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        assert "Stats:" in result.stderr
        assert "KB" in result.stderr
        assert "/s" in result.stderr

    def test_human_readable_progress_multithreaded(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--threads", "-h", "--progress"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:100]}"
        output = result.stdout + result.stderr
        assert "Sent " in output
        assert "KB" in output
        assert "Done." in output


class TestInfo:
    def test_info_copy_reports_transfers(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--info=copy"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Info sync failed: {(result.stderr or result.stdout)[:200]}"
        output = result.stdout + result.stderr
        assert "[INFO]" in output and "Transferring" in output

    def test_info_stats_reports_multithreaded_transfer(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--threads", "--info=stats"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Info stats sync failed: {(result.stderr or result.stdout)[:200]}"
        output = result.stdout + result.stderr
        assert "[INFO]" in output and "Transfer summary:" in output

    def test_info_rejects_unknown_flag(self):
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--info=unknown"],
        )
        assert result.returncode != 0
        assert "unsupported --info flag" in result.stderr

    @pytest.mark.parametrize("flags", [
        ["--info=none", "--verbose"],
        ["--verbose", "--info=none"],
    ])
    def test_info_none_suppresses_verbose_info(self, shared_server, flags):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"Info sync failed: {(result.stderr or result.stdout)[:200]}"
        output = result.stdout + result.stderr
        assert "[INFO]" not in output
        assert "Transferring" not in output
        assert "Transfer summary:" not in output


class TestBandwidthLimit:
    def test_bwlimit_runs(self, shared_server):
        clean_dir(DEST_DIR)
        result, dur = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--bwlimit", "10240"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"


def _read_file(path):
    with open(path, "rb") as fh:
        return fh.read()


class TestRemoveSourceFilesSkips:
    """--remove-source-files must not delete sources the receiver skipped
    (rsync reference behavior)."""

    def test_existing_first_sync_keeps_new_source(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_rsf_existing_src")
        dest = os.path.join(TEST_DATA_DIR, "remove_rsf_existing_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "only.txt"), "wb") as f:
            f.write(b"keep me")

        result, _ = run_client(source, dest, flags=["--remove-source-files", "--existing"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Sync failed: {result.stderr[:200]}"
        # The file exists only on the source side, so --existing makes the
        # receiver skip it; the source must therefore not be removed.
        assert os.path.isfile(os.path.join(source, "only.txt"))
        received = get_dest_received_dir(dest, source)
        assert not os.path.exists(os.path.join(received, "only.txt"))

    def test_ignore_existing_keeps_skipped_source(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_rsf_ignore_src")
        dest = os.path.join(TEST_DATA_DIR, "remove_rsf_ignore_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"payload")

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0

        result, _ = run_client(source, dest, flags=["--remove-source-files", "--ignore-existing"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Sync failed: {result.stderr[:200]}"
        # Destination already has the file, so the second run is a receiver
        # skip; the source file must survive.
        assert os.path.isfile(source_file)
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "file.txt")) == b"payload"

    def test_update_newer_destination_keeps_source(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "remove_rsf_update_src")
        dest = os.path.join(TEST_DATA_DIR, "remove_rsf_update_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"source payload")

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0

        received = get_dest_received_dir(dest, source)
        received_file = os.path.join(received, "file.txt")
        with open(received_file, "wb") as f:
            f.write(b"newer destination payload")
        os.utime(received_file, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))

        result, _ = run_client(source, dest, flags=["--remove-source-files", "--update"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Sync failed: {result.stderr[:200]}"
        # --update skips a destination that is newer than the source, so the
        # source must not be removed.
        assert os.path.isfile(source_file)
        assert _read_file(received_file) == b"newer destination payload"

    def test_multithreaded_ignore_existing_keeps_skipped_source(self, shared_server):
        """The multithreaded writer path must also report per-file outcomes so a
        --remove-source-files sender does not delete skipped sources."""
        source = os.path.join(TEST_DATA_DIR, "remove_rsf_mt_ignore_src")
        dest = os.path.join(TEST_DATA_DIR, "remove_rsf_mt_ignore_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "file.txt")
        with open(source_file, "wb") as f:
            f.write(b"payload")

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0

        result, _ = run_client(source, dest,
                               flags=["--remove-source-files", "--ignore-existing", "--threads"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Sync failed: {result.stderr[:200]}"
        # Destination already has the file, so the receiver (writer thread)
        # skips it; the source must survive.
        assert os.path.isfile(source_file)
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "file.txt")) == b"payload"


class TestBackup:
    def _sync(self, source, dest, flags, port):
        return run_client(source, dest, flags=flags, port=port)

    def test_plain_backup_keeps_previous_version(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "backup_src")
        dest = os.path.join(TEST_DATA_DIR, "backup_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "f.txt")
        with open(source_file, "wb") as f:
            f.write(b"AAAA")

        result, _ = self._sync(source, dest, ["--backup"], shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"

        with open(source_file, "wb") as f:
            f.write(b"BBBB")
        result, _ = self._sync(source, dest, ["--backup"], shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"

        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "f.txt")) == b"BBBB"
        # rsync default suffix "~" keeps the overwritten version.
        assert _read_file(os.path.join(received, "f.txt~")) == b"AAAA"

    def test_backup_custom_suffix(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "backup_suffix_src")
        dest = os.path.join(TEST_DATA_DIR, "backup_suffix_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "f.txt")
        with open(source_file, "wb") as f:
            f.write(b"AAAA")

        flags = ["--backup", "--suffix", ".bak"]
        result, _ = self._sync(source, dest, flags, shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"
        with open(source_file, "wb") as f:
            f.write(b"BBBB")
        result, _ = self._sync(source, dest, flags, shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"

        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "f.txt")) == b"BBBB"
        assert _read_file(os.path.join(received, "f.txt.bak")) == b"AAAA"

    def test_backup_dir_stores_backups_separately(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "backup_dir_src")
        dest = os.path.join(TEST_DATA_DIR, "backup_dir_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "f.txt")
        with open(source_file, "wb") as f:
            f.write(b"AAAA")

        flags = ["--backup", "--backup-dir", "backups"]
        result, _ = self._sync(source, dest, flags, shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"
        with open(source_file, "wb") as f:
            f.write(b"BBBB")
        result, _ = self._sync(source, dest, flags, shared_server.port)
        assert result.returncode == 0, f"Backup sync failed: {result.stderr[:200]}"

        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "f.txt")) == b"BBBB"
        backup = os.path.join(dest, "backups", os.path.relpath(source_file, os.path.sep))
        assert _read_file(backup) == b"AAAA"


class TestPartialDir:
    def test_completed_transfer_installed_in_destination(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "partial_src")
        dest = os.path.join(TEST_DATA_DIR, "partial_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "f.txt")
        with open(source_file, "wb") as f:
            f.write(b"partial payload")

        result, _ = run_client(source, dest, flags=["--partial", "--partial-dir", ".partial"],
                               port=shared_server.port)
        assert result.returncode == 0, f"Partial sync failed: {result.stderr[:200]}"

        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "f.txt")) == b"partial payload"
        # A completed transfer must not remain under the partial directory.
        partial = os.path.join(dest, ".partial", os.path.relpath(source_file, os.path.sep))
        assert not os.path.exists(partial)


class TestLargeFile:
    def test_transfer_100mb_file(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "large_src")
        dest = os.path.join(TEST_DATA_DIR, "large_dst")
        clean_dir(source)
        clean_dir(dest)
        source_file = os.path.join(source, "big.bin")
        chunk = os.urandom(1024 * 1024)
        with open(source_file, "wb") as f:
            for _ in range(100):
                f.write(chunk)

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, f"Large-file sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        assert filecmp.cmp(source_file, os.path.join(received, "big.bin"), shallow=False)

class TestOneFileSystem:
    def _make_tree(self, source):
        clean_dir(source)
        os.makedirs(os.path.join(source, "nested", "deeper"))
        with open(os.path.join(source, "root.txt"), "wb") as f:
            f.write(b"root")
        with open(os.path.join(source, "nested", "inner.txt"), "wb") as f:
            f.write(b"inner")
        with open(os.path.join(source, "nested", "deeper", "deep.txt"), "wb") as f:
            f.write(b"deep")

    def _assert_full_tree_transferred(self, source, dest, port, flags):
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=flags, port=port)
        assert result.returncode == 0, f"Sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    def test_x_transfer_matches_plain_over_single_filesystem(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "ofs_src")
        self._make_tree(source)
        self._assert_full_tree_transferred(source, os.path.join(TEST_DATA_DIR, "ofs_dst"),
                                           shared_server.port, ["-x"])

    def test_x_multithreaded_transfer_matches_plain_over_single_filesystem(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "ofs_m_src")
        self._make_tree(source)
        self._assert_full_tree_transferred(source, os.path.join(TEST_DATA_DIR, "ofs_m_dst"),
                                           shared_server.port, ["--threads", "--one-file-system"])

    def test_x_skips_other_device_mountpoint(self, shared_server):
        if os.geteuid() != 0 or shutil.which("mount") is None or shutil.which("umount") is None:
            pytest.skip("cross-device test requires root and mount(8)")
        source = os.path.join(TEST_DATA_DIR, "ofs_mnt_src")
        dest = os.path.join(TEST_DATA_DIR, "ofs_mnt_dst")
        dest_plain = os.path.join(TEST_DATA_DIR, "ofs_mnt_plain_dst")
        mountpoint = os.path.join(source, "external")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(dest_plain)
        os.makedirs(mountpoint)
        os.makedirs(os.path.join(source, "nested"))
        with open(os.path.join(source, "root.txt"), "wb") as f:
            f.write(b"root")
        with open(os.path.join(source, "nested", "inner.txt"), "wb") as f:
            f.write(b"inner")
        mounted = False
        unmount_error = ""
        try:
            mount = subprocess.run(["mount", "-t", "tmpfs", "tmpfs", mountpoint],
                                   capture_output=True, text=True)
            if mount.returncode != 0:
                pytest.skip(f"cannot mount tmpfs: {mount.stderr.strip()}")
            mounted = True
            with open(os.path.join(mountpoint, "away.txt"), "wb") as f:
                f.write(b"cross device")
            result, _ = run_client(source, dest, flags=["-x"], port=shared_server.port)
            assert result.returncode == 0, f"-x sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            assert os.path.isfile(os.path.join(received, "root.txt"))
            assert os.path.isfile(os.path.join(received, "nested", "inner.txt"))
            assert not os.path.exists(os.path.join(received, "external", "away.txt")), \
                "-x must not cross into the mounted filesystem"
            result, _ = run_client(source, dest_plain, port=shared_server.port)
            assert result.returncode == 0, f"plain sync failed: {result.stderr[:200]}"
            received_plain = get_dest_received_dir(dest_plain, source)
            assert os.path.isfile(os.path.join(received_plain, "external", "away.txt")), \
                "without -x the mounted subtree must be transferred"
        finally:
            if mounted:
                umount = subprocess.run(["umount", mountpoint], capture_output=True, text=True)
                if umount.returncode != 0:
                    unmount_error = umount.stderr.strip()
        if unmount_error:
            pytest.fail(f"test mountpoint {mountpoint} still mounted after umount: {unmount_error}")


def _walk_tmp_files(root):
    """Recursively list *.tmp* leftovers under root (empty if root missing)."""
    leftovers = []
    if not os.path.isdir(root):
        return leftovers
    for base, _, files in os.walk(root):
        for name in files:
            if ".tmp." in name:
                leftovers.append(os.path.join(base, name))
    return leftovers


class TestTempDir:
    """--temp-dir=DIR puts the receiver's temporary working copies in a scratch
    directory below the destination root and atomically renames each completed
    file into its final destination.  Files sharing a basename across
    directories exercise the flat scratch namespace."""

    def _make_source(self, name):
        source = os.path.join(TEST_DATA_DIR, name)
        clean_dir(source)
        entries = {
            "top.txt": b"top level\n",
            "sub/file.txt": b"nested file\n" * 20,
            "other/file.txt": b"other nested file\n",
            "sub/deep.bin": bytes(range(256)) * 8,
        }
        for rel, content in entries.items():
            full = os.path.join(source, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(content)
        return source

    def _assert_clean_scratch(self, scratch):
        assert os.path.isdir(scratch), f"scratch dir {scratch} was not created"
        leftovers = _walk_tmp_files(scratch)
        assert leftovers == [], f"leftover temp files in scratch dir: {leftovers}"

    @pytest.mark.parametrize("mt", [False, True])
    def test_temp_dir_scratch(self, shared_server, mt):
        source = self._make_source("tempdir_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_dst")
        clean_dir(dest)
        # rsync requires the temp dir to already exist (it is not created).
        os.makedirs(os.path.join(dest, "scratch"), exist_ok=True)
        flags = ["--temp-dir=scratch"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"temp-dir sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        self._assert_clean_scratch(os.path.join(dest, "scratch"))

    def test_default_behavior_has_no_scratch_dir(self, shared_server):
        source = self._make_source("tempdir_default_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_default_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, f"Default sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        assert not os.path.exists(os.path.join(dest, "scratch"))

    def test_temp_dir_ignored_with_inplace(self, shared_server):
        """--inplace writes directly into the destination; --temp-dir must not
        redirect those writes into a scratch dir."""
        source = self._make_source("tempdir_inplace_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_inplace_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest,
                               flags=["--inplace", "--temp-dir=scratch"],
                               port=shared_server.port)
        assert result.returncode == 0, f"inplace+temp-dir sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        assert not os.path.exists(os.path.join(dest, "scratch")), \
            "--inplace wrote through the scratch dir"

    def test_temp_dir_ignored_with_partial_dir(self, shared_server):
        """--partial --partial-dir already stages in a separate directory;
        --temp-dir must not be used on top of it."""
        source = self._make_source("tempdir_partial_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_partial_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest,
                               flags=["--partial", "--partial-dir", ".partial",
                                      "--temp-dir=scratch"],
                               port=shared_server.port)
        assert result.returncode == 0, f"partial+temp-dir sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        partial = os.path.join(dest, ".partial",
                               os.path.relpath(os.path.join(source, "top.txt"), os.path.sep))
        assert not os.path.exists(partial), "completed file remained under the partial dir"
        assert not os.path.exists(os.path.join(dest, "scratch")), \
            "--partial-dir wrote through the scratch dir"

    def test_temp_dir_must_exist(self, shared_server):
        """rsync does not create the temp dir; a missing one is a clear error."""
        source = self._make_source("tempdir_missing_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_missing_dst")
        clean_dir(dest)
        missing_rel = os.path.join(dest, "no_such_scratch")
        assert not os.path.lexists(missing_rel)
        result, _ = run_client(source, dest, flags=["--temp-dir=no_such_scratch"],
                               port=shared_server.port)
        assert result.returncode != 0, "a missing relative --temp-dir must fail"

        missing_abs = os.path.join(TEST_DATA_DIR, "no_such_abs_scratch")
        assert not os.path.lexists(missing_abs)
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["--temp-dir", missing_abs],
                               port=shared_server.port)
        assert result.returncode != 0, "a missing absolute --temp-dir must fail"

    def test_temp_dir_absolute_outside_root_is_used(self, shared_server):
        """rsync accepts any temp dir, including one outside the destination
        tree; the completed files are still installed below the root and no
        temp files remain in the scratch dir."""
        source = self._make_source("tempdir_abs_src")
        dest = os.path.join(TEST_DATA_DIR, "tempdir_abs_dst")
        clean_dir(dest)
        scratch = os.path.join(TEST_DATA_DIR, "tempdir_abs_scratch")
        shutil.rmtree(scratch, ignore_errors=True)
        os.makedirs(scratch)

        result, _ = run_client(source, dest, flags=["--temp-dir", scratch],
                               port=shared_server.port)
        assert result.returncode == 0, f"absolute temp-dir sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        self._assert_clean_scratch(scratch)
        shutil.rmtree(scratch, ignore_errors=True)


class TestTimeoutAndAllocLimits:
    """#295: rsync defaults --timeout=0 (disabled), --contimeout=60, and
    --max-alloc=0 (no limit); 0 must be accepted for all three."""

    def _seed(self, name):
        source = os.path.join(TEST_DATA_DIR, name)
        dest = os.path.join(TEST_DATA_DIR, name + "_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "f.txt"), "wb") as fh:
            fh.write(b"payload\n" * 100)
        return source, dest

    @pytest.mark.ci
    def test_timeout_zero_disables_and_transfers(self, shared_server):
        source, dest = self._seed("timeout_zero_src")
        result, _ = run_client(source, dest, flags=["--timeout=0", "--contimeout=0"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing and not mismatches

    @pytest.mark.ci
    def test_no_timeout_forms(self, shared_server):
        source, dest = self._seed("timeout_no_src")
        result, _ = run_client(source, dest, flags=["--timeout=30", "--no-timeout",
                                                    "--no-contimeout"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]

    @pytest.mark.ci
    def test_max_alloc_zero_means_no_limit(self, shared_server):
        source, dest = self._seed("max_alloc_zero_src")
        result, _ = run_client(source, dest, flags=["--max-alloc=0"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:200]
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing and not mismatches

    def test_temp_dir_cross_filesystem_fallback(self, shared_server):
        """A --temp-dir on another filesystem must fall back to a non-atomic
        copy instead of aborting (rsync parity).  Skipped when no second
        filesystem is available."""
        shm = "/dev/shm"
        if not os.path.isdir(shm):
            pytest.skip("/dev/shm not available")
        if os.stat(shm).st_dev == os.stat(TEST_DATA_DIR).st_dev:
            pytest.skip("/dev/shm is on the same filesystem as the test data")
        scratch = os.path.join(shm, f"fastsync_tmp_{os.getpid()}")
        shutil.rmtree(scratch, ignore_errors=True)
        os.makedirs(scratch)
        try:
            source, dest = self._seed("tempdir_xdev_src")
            result, _ = run_client(source, dest, flags=["--temp-dir", scratch],
                                   port=shared_server.port)
            assert result.returncode == 0, f"cross-fs temp-dir failed: {result.stderr[:300]}"
            received = get_dest_received_dir(dest, source)
            mismatches, missing = verify_transfer(source, received)
            assert not missing, f"Missing: {missing}"
            assert not mismatches, f"Mismatch: {mismatches}"
            assert os.listdir(scratch) == [], "temp files left behind"
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


class TestRemoteOptionTransport:
    """#296: -M/--remote-option is SSH-only; a daemon/TCP destination rejects it
    instead of silently ignoring it."""

    @pytest.mark.ci
    def test_remote_option_rejected_for_tcp(self, shared_server):
        for flag in ("--remote-option=--allow-delete", "-M--allow-delete", "-M=--allow-delete"):
            result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=[flag],
                                   port=shared_server.port)
            assert result.returncode != 0, f"{flag} must be rejected for a TCP destination"
            assert "remote-option" in (result.stderr + result.stdout), \
                f"{flag}: error must name --remote-option"


class TestTrustSenderServerPath:
    """--trust-sender is a receiver-local policy: only the receiving SERVER's
    own flag matters.  For a push, a client --trust-sender is never sent to the
    peer, so it must not relax a server that did not opt in; a server started
    with --trust-sender must copy an escaping symlink target verbatim (its
    normal mode skips it while still confining the link itself)."""

    def _make_source(self, name):
        source = os.path.join(TEST_DATA_DIR, name)
        clean_dir(source)
        with open(os.path.join(source, "file.txt"), "wb") as fh:
            fh.write(b"content\n")
        os.symlink("/etc/passwd", os.path.join(source, "escape_link"))
        return source

    def _run_with_server(self, extra_args, flags, tag):
        server = ServerManager()
        server.start(extra_args=extra_args)
        try:
            source = self._make_source(f"trust_sender_src_{tag}")
            dest = os.path.join(TEST_DATA_DIR, f"trust_sender_dst_{tag}")
            clean_dir(dest)
            result, _ = run_client(source, dest, flags=["-l"] + flags, port=server.port)
            link = os.path.join(get_dest_received_dir(dest, source), "escape_link")
            return result, link
        finally:
            server.stop()

    @pytest.mark.ci
    def test_client_flag_does_not_relax_server(self):
        result, link = self._run_with_server([], ["--trust-sender"], "client")
        assert result.returncode == 0, result.stderr[:200]
        assert not os.path.lexists(link), \
            "a client --trust-sender must not relax a server that did not opt in"

    @pytest.mark.ci
    def test_server_flag_materializes_escaping_symlink(self):
        result, link = self._run_with_server(["--trust-sender"], [], "server")
        assert result.returncode == 0, result.stderr[:200]
        assert os.path.islink(link), "server --trust-sender should materialize the symlink"
        assert os.readlink(link) == "/etc/passwd"


def _source_files():
    """All source paths (absolute) that a transfer would send right now."""
    return [
        os.path.join(root, name)
        for root, _dirs, names in os.walk(SOURCE_DIR)
        for name in names
    ]


class TestListOnly:
    """--list-only prints every transfer candidate and changes nothing."""

    def test_list_only_prints_each_file_and_does_not_transfer(self):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--list-only"])
        assert result.returncode == 0, f"list-only failed: {result.stderr[:200]}"
        for full_path in _source_files():
            assert full_path in result.stdout, f"list-only omitted {full_path}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert not os.path.exists(received), "list-only wrote to the destination"

    def test_list_only_with_dry_run_does_not_error(self):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--list-only", "--dry-run"])
        assert result.returncode == 0, f"list-only -n failed: {result.stderr[:200]}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert not os.path.exists(received)

    def test_list_only_multithreaded(self):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--list-only", "--threads"])
        assert result.returncode == 0, f"list-only -m failed: {result.stderr[:200]}"
        for full_path in _source_files():
            assert full_path in result.stdout, f"list-only -m omitted {full_path}"
        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        assert not os.path.exists(received), "list-only -m wrote to the destination"


class TestItemizeChanges:
    """-i/--itemize-changes prints rsync-style lines only for files sent."""

    def test_first_run_prints_sent_lines(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--preserve", "-i"], port=shared_server.port)
        assert result.returncode == 0, f"itemize sync failed: {result.stderr[:200]}"
        sent_lines = {">f+++++++++ " + p for p in _source_files()}
        assert sent_lines <= set(result.stdout.splitlines()), (
            f"missing itemize lines; got {result.stdout[:500]}"
        )

    def test_incremental_second_run_prints_no_line_for_unchanged(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--preserve", "-i", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, f"incremental itemize failed: {result.stderr[:200]}"
        itemized = [line for line in result.stdout.splitlines() if line and line[0] in ">.<c"]
        assert itemized == [], f"unchanged files were itemized: {itemized[:5]}"

    def test_multithreaded_emits_same_itemize_lines(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--preserve", "-i", "--threads"], port=shared_server.port)
        assert result.returncode == 0, f"itemize -m sync failed: {result.stderr[:200]}"
        sent_lines = {">f+++++++++ " + p for p in _source_files()}
        assert sent_lines <= set(result.stdout.splitlines()), (
            f"missing itemize lines in -m mode; got {result.stdout[:500]}"
        )

    def test_dry_run_with_itemize_does_not_error(self):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR, flags=["-i", "--dry-run"])
        assert result.returncode == 0, f"dry-run -i failed: {result.stderr[:200]}"

    def test_changed_file_on_second_incremental_run_prints_exactly_one_line(self, shared_server):
        """A changed file itemizes exactly once on an incremental rerun while
        unchanged files print nothing (no double emission)."""
        source = os.path.join(TEST_DATA_DIR, "itemize_change_src")
        dest = os.path.join(TEST_DATA_DIR, "itemize_change_dst")
        clean_dir(source)
        clean_dir(dest)
        changed = os.path.join(source, "changed.txt")
        untouched = os.path.join(source, "untouched.txt")
        with open(changed, "wb") as fh:
            fh.write(b"original\n")
        with open(untouched, "wb") as fh:
            fh.write(b"stable\n")

        result, _ = run_client(source, dest, flags=["--preserve"], port=shared_server.port)
        assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"

        with open(changed, "wb") as fh:
            fh.write(b"edited payload\n")

        result, _ = run_client(source, dest,
                               flags=["--preserve", "-i", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, f"incremental itemize failed: {result.stderr[:200]}"
        itemized = [line for line in result.stdout.splitlines() if line.startswith(">f")]
        assert itemized == [">f+++++++++ " + changed], (
            f"expected exactly one itemize line for {changed}, got {itemized}"
        )
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "changed.txt")) == b"edited payload\n"
        assert _read_file(os.path.join(received, "untouched.txt")) == b"stable\n"


class TestOutFormat:
    """--out-format prints a line per transferred file using the template."""

    def test_out_format_path_and_size(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--out-format=%f %l"], port=shared_server.port)
        assert result.returncode == 0, f"out-format sync failed: {result.stderr[:200]}"
        expected = {f"{p} {os.path.getsize(p)}" for p in _source_files()}
        got = set(result.stdout.splitlines())
        assert expected <= got, f"out-format lines missing: expected {len(expected)} got {len(got)}"

    def test_out_format_multithreaded_matches_single(self, shared_server):
        clean_dir(DEST_DIR)
        result, _ = run_client(SOURCE_DIR, DEST_DIR,
                               flags=["--out-format=%f %l", "--threads"], port=shared_server.port)
        assert result.returncode == 0, f"out-format -m sync failed: {result.stderr[:200]}"
        expected = {f"{p} {os.path.getsize(p)}" for p in _source_files()}
        got = set(result.stdout.splitlines())
        assert expected <= got, f"out-format -m lines missing: {result.stdout[:500]}"


class TestLogFileFormat:
    """--log-file plus --log-file-format writes per-file lines to the log."""

    def test_log_file_format_writes_transferred_files(self, shared_server):
        clean_dir(DEST_DIR)
        log_path = os.path.join(TEST_DATA_DIR, "itemize_transfer.log")
        if os.path.exists(log_path):
            os.unlink(log_path)
        result, _ = run_client(
            SOURCE_DIR, DEST_DIR,
            flags=["--log-file", log_path, "--log-file-format=%f %l"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"log-file sync failed: {result.stderr[:200]}"
        assert os.path.exists(log_path), "--log-file created no log"
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        expected = {f"{p} {os.path.getsize(p)}" for p in _source_files()}
        for line in expected:
            assert line in content, f"log file missing {line!r}"

    def test_log_file_format_multithreaded_writes_transferred_files(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "itemize_log_mt_src")
        dest = os.path.join(TEST_DATA_DIR, "itemize_log_mt_dst")
        clean_dir(source)
        clean_dir(dest)
        files = {"a.txt": b"alpha\n", "b.txt": b"beta\n"}
        for rel, data in files.items():
            with open(os.path.join(source, rel), "wb") as fh:
                fh.write(data)
        log_path = os.path.join(TEST_DATA_DIR, "itemize_mt.log")
        if os.path.exists(log_path):
            os.unlink(log_path)
        result, _ = run_client(
            source,
            dest,
            flags=["--log-file", log_path, "--log-file-format=%f %l", "--threads"],
            port=shared_server.port,
        )
        assert result.returncode == 0, f"log-file --threads sync failed: {result.stderr[:200]}"
        assert os.path.exists(log_path), "--log-file created no log"
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        expected = {f"{os.path.join(source, rel)} {len(data)}" for rel, data in files.items()}
        for line in expected:
            assert line in content, f"log file (--threads) missing {line!r}"


class TestDelayUpdates:
    """--delay-updates stages every updated file under a private 0700 staging
    directory inside the receive root and atomically publishes all of them only
    after the whole transfer succeeds."""

    STAGING = ".fastsync-stage"

    def _make_source(self, name):
        source = os.path.join(TEST_DATA_DIR, name)
        clean_dir(source)
        entries = {
            "top.txt": b"top level\n",
            "sub/deep.txt": b"deeply nested file\n",
            "sub/another.txt": b"another nested file\n" * 20,
            "binary.bin": bytes(range(256)) * 4,
        }
        for rel, content in entries.items():
            full = os.path.join(source, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(content)
        return source

    @pytest.mark.parametrize("mt", [False, True])
    def test_delay_updates_matches_plain_transfer(self, shared_server, mt):
        source = self._make_source("delay_match_src")
        plain_dest = os.path.join(TEST_DATA_DIR, "delay_match_plain_dst")
        delay_dest = os.path.join(TEST_DATA_DIR, "delay_match_delay_dst")
        clean_dir(plain_dest)
        clean_dir(delay_dest)

        result, _ = run_client(source, plain_dest, port=shared_server.port)
        assert result.returncode == 0, f"plain sync failed: {result.stderr[:200]}"
        flags = ["--delay-updates"] + (["--threads"] if mt else [])
        result, _ = run_client(source, delay_dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"delay-updates sync failed: {result.stderr[:200]}"

        plain_received = get_dest_received_dir(plain_dest, source)
        delay_received = get_dest_received_dir(delay_dest, source)
        mismatches, missing = verify_transfer(source, delay_received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"
        for root, _dirs, files in os.walk(delay_received):
            for name in files:
                rel = os.path.relpath(os.path.join(root, name), delay_received)
                assert filecmp.cmp(os.path.join(plain_received, rel),
                                   os.path.join(delay_received, rel), shallow=False), rel
        assert not os.path.isdir(os.path.join(delay_dest, self.STAGING)), \
            "staging directory left behind after a successful delayed transfer"

    @pytest.mark.parametrize("mt", [False, True])
    def test_delay_updates_incremental_rerun_no_leftovers(self, shared_server, mt):
        source = self._make_source("delay_rerun_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_rerun_dst")
        clean_dir(dest)
        flags = ["--delay-updates", "--preserve", "--incremental"] + (["--threads"] if mt else [])

        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"first delayed sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing and not mismatches
        assert not os.path.isdir(os.path.join(dest, self.STAGING))

        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"second delayed sync failed: {result.stderr[:200]}"
        assert not os.path.isdir(os.path.join(dest, self.STAGING)), \
            "fully-skipped delayed run left a staging directory"

    @pytest.mark.parametrize("mt", [False, True])
    def test_remove_source_files_with_delay_updates(self, shared_server, mt):
        source = self._make_source("delay_rsf_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_rsf_dst")
        clean_dir(dest)
        flags = ["--remove-source-files", "--delay-updates"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"delayed remove-source sync failed: {result.stderr[:200]}"

        # Sources are removed only after the receiver published every file.
        for root, _dirs, files in os.walk(source):
            assert files == [], f"source files survived delayed remove-source-files: {files}"
        received = get_dest_received_dir(dest, source)
        assert os.path.isfile(os.path.join(received, "top.txt"))
        assert os.path.isfile(os.path.join(received, "sub", "deep.txt"))
        assert not os.path.isdir(os.path.join(dest, self.STAGING))

    @pytest.mark.parametrize("mt", [False, True])
    def test_delete_with_delay_updates(self, mt):
        """--delete runs before publication, so the delete walker must not treat
        the staging directory as a set of extras: a changed file must still be
        published after genuine extras are removed.  Uses its own server started
        with --allow-delete (the shared session server refuses deletion)."""
        source = os.path.join(TEST_DATA_DIR, "delay_delete_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_delete_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "f.txt"), "wb") as fh:
            fh.write(b"AAAA")
        with open(os.path.join(source, "extra.txt"), "wb") as fh:
            fh.write(b"seed extra")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            assert _read_file(os.path.join(received, "extra.txt")) == b"seed extra"

            # Second source state: f.txt changed, extra.txt removed from source.
            with open(os.path.join(source, "f.txt"), "wb") as fh:
                fh.write(b"BBBB")
            os.remove(os.path.join(source, "extra.txt"))

            flags = ["--delete", "--delay-updates"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"delete+delay-updates sync failed: {result.stderr[:200]}"
            assert _read_file(os.path.join(received, "f.txt")) == b"BBBB", \
                "changed file was not published after deletion"
            assert not os.path.exists(os.path.join(received, "extra.txt")), \
                "genuine extra file was not deleted"
            assert not os.path.isdir(os.path.join(dest, self.STAGING))

    def test_delay_updates_rejects_reserved_backup_dir(self):
        """--backup-dir equal to the internal staging name must be rejected so
        an old backup can never be silently installed as the "new" file."""
        source = self._make_source("delay_reserved_bak_src")
        for variant, suffix in (("bare", ""), ("slash", "/")):
            dest = os.path.join(TEST_DATA_DIR, f"delay_reserved_bak_{variant}_dst")
            clean_dir(dest)
            flags = ["--delay-updates", "--backup", "--backup-dir",
                     ".fastsync-stage" + suffix]
            result, _ = run_client(source, dest, flags=flags, port=None)
            assert result.returncode != 0, \
                f"reserved --backup-dir '{suffix}' was accepted"
            assert not os.path.isdir(os.path.join(dest, self.STAGING)), \
                "staging directory created by a rejected run"

    @pytest.mark.parametrize("remove_source_files", [False, True])
    @pytest.mark.parametrize("mt", [False, True])
    def test_mid_publish_failure_keeps_published_no_rollback(self, shared_server, mt,
                                                             remove_source_files):
        """A stage->publish rename failing part way through publication must
        fail the whole transfer, keep the already-published top-level file (no
        rollback), leave the not-yet-published nested file absent, and clean up
        the staging area.  A regular file is planted where the final "sub"
        directory must be created, so the nested rename fails (mkdir over a
        file is impossible even for root) while the top-level file, which is
        always staged first, publishes.  With --remove-source-files the sender
        must keep every source because no success/outcome frame is ever sent."""
        source = os.path.join(TEST_DATA_DIR, "delay_mid_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_mid_dst")
        clean_dir(source)
        clean_dir(dest)
        top_path = os.path.join(source, "top.txt")
        deep_path = os.path.join(source, "sub", "deep.txt")
        with open(top_path, "wb") as fh:
            fh.write(b"top payload\n")
        os.makedirs(os.path.dirname(deep_path))
        with open(deep_path, "wb") as fh:
            fh.write(b"deep payload\n")

        received = get_dest_received_dir(dest, source)
        os.makedirs(received)
        with open(os.path.join(received, "sub"), "wb") as fh:
            fh.write(b"blocks the nested destination directory")

        flags = ["--delay-updates"] + (["--threads"] if mt else [])
        if remove_source_files:
            flags += ["--remove-source-files"]
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode != 0, "blocked nested publish did not fail"

        # The top-level file was published before the nested rename failed and
        # is intentionally NOT rolled back.
        assert _read_file(os.path.join(received, "top.txt")) == b"top payload\n"
        # The nested file was never published.
        assert not os.path.lexists(os.path.join(received, "sub", "deep.txt")), \
            "nested file appeared despite a failed publish"
        assert not os.path.isdir(os.path.join(dest, self.STAGING)), \
            "staging leftovers after a failed mid-publish"
        # Sources survive: no success frame was sent, so a remove-source-files
        # sender must not delete anything.
        assert os.path.isfile(top_path)
        assert os.path.isfile(deep_path)

    @pytest.mark.parametrize("mt", [False, True])
    def test_remove_source_files_keeps_receiver_skipped_source(self, shared_server, mt):
        """With --delay-updates + --ignore-existing a receiver-skipped source
        must survive (its outcome is sent only after publication) while a
        freshly delivered file is published and its source removed."""
        source = os.path.join(TEST_DATA_DIR, "delay_rsf_skip_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_rsf_skip_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"existing on dest")
        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"

        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"changed on source")
        with open(os.path.join(source, "deliver.txt"), "wb") as fh:
            fh.write(b"new file")
        flags = ["--remove-source-files", "--ignore-existing", "--delay-updates"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"delayed skip sync failed: {result.stderr[:200]}"
        # keep.txt already existed at the destination: receiver skip -> source stays.
        assert os.path.isfile(os.path.join(source, "keep.txt")), \
            "receiver-skipped source was removed despite --ignore-existing"
        # deliver.txt was new: staged, published, and its source removed.
        assert not os.path.isfile(os.path.join(source, "deliver.txt")), \
            "published source was not removed"
        received = get_dest_received_dir(dest, source)
        assert not os.path.isdir(os.path.join(dest, self.STAGING))

    def test_delay_updates_rejects_inplace(self):
        source = self._make_source("delay_inplace_src")
        dest = os.path.join(TEST_DATA_DIR, "delay_inplace_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["--delay-updates", "--inplace"])
        assert result.returncode != 0, "--inplace with --delay-updates was accepted"
        assert not os.path.isdir(os.path.join(dest, self.STAGING))

class TestFilesFrom:
    """--files-from transfers exactly the listed files; a listed directory
    transfers its whole subtree. The manifest (and thus --delete) derives from
    what was actually sent."""


def _make_relative_source(name):
    """A small tree used by the -R/--dirs/--no-implied-dirs tests."""
    source = os.path.join(TEST_DATA_DIR, name)
    clean_dir(source)
    entries = {
        "top.txt": b"top\n",
        "a/b.txt": b"nested\n",
        "sub/x.txt": b"x\n",
        "sub/y.txt": b"y\n",
        "dir1/keep.txt": b"dir content\n",
    }
    for rel, content in entries.items():
        full = os.path.join(source, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(content)
    return source


def _write_rel_list(rel_text):
    path = os.path.join(TEST_DATA_DIR, "rel_list.txt")
    with open(path, "wb") as fh:
        fh.write(rel_text)
    return path


class TestRelativeFilesFrom:
    """-R/--relative with --files-from keeps each listed entry's bare relative
    destination path below the destination root instead of mirroring the full
    source path.  Without -R the layout is unchanged (full source mirror)."""

    @pytest.mark.parametrize("mt", [False, True])
    def test_relative_files_from_keeps_relative_layout(self, shared_server, mt):
        source = _make_relative_source("rel_src")
        dest = os.path.join(TEST_DATA_DIR, "rel_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"top.txt\nsub/x.txt\n")
        flags = ["--files-from", lst, "-R"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"-R files-from sync failed: {result.stderr[:200]}"
        assert _read_file(os.path.join(dest, "sub", "x.txt")) == b"x\n", \
            "listed file must land at <dest>/sub/x.txt"
        assert _read_file(os.path.join(dest, "top.txt")) == b"top\n", \
            "top-level listed file must land at <dest>/top.txt"
        assert not os.path.exists(os.path.join(dest, "sub", "y.txt"))
        # The source-root mirror must not be reproduced under -R.
        assert not os.path.exists(get_dest_received_dir(dest, source)), \
            "-R must not mirror the full source path"

    @pytest.mark.parametrize("mt", [False, True])
    def test_relative_without_files_from_has_no_effect(self, shared_server, mt):
        """-R alone (no --files-from) must leave the normal full-source mirror
        layout untouched."""
        source = _make_relative_source("rel_only_src")
        dest = os.path.join(TEST_DATA_DIR, "rel_only_dst")
        clean_dir(dest)
        flags = ["-R"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"-R alone sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing and not mismatches

    @pytest.mark.parametrize("mt", [False, True])
    def test_without_relative_layout_unchanged(self, shared_server, mt):
        source = _make_relative_source("rel_noR_src")
        dest = os.path.join(TEST_DATA_DIR, "rel_noR_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"sub/x.txt\n")
        flags = ["--files-from", lst] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"files-from sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "sub", "x.txt")) == b"x\n", \
            "without -R the full source mirror layout is preserved"
        assert not os.path.exists(os.path.join(dest, "sub")), \
            "bare relative layout must not appear without -R"

    def test_relative_delete_manifest_stays_consistent(self):
        """--delete derives from the sent (-R) relative paths, so a later
        subset run removes unlisted relative entries but keeps listed ones."""
        source = _make_relative_source("rel_del_src")
        dest = os.path.join(TEST_DATA_DIR, "rel_del_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            lst = _write_rel_list(b"sub/x.txt\nsub/y.txt\n")
            result, _ = run_client(source, dest, flags=["--files-from", lst, "-R"],
                                   port=server.port)
            assert result.returncode == 0, f"seed -R sync failed: {result.stderr[:200]}"
            assert os.path.isfile(os.path.join(dest, "sub", "y.txt"))

            subset = _write_rel_list(b"sub/x.txt\n")
            result, _ = run_client(source, dest,
                                   flags=["--files-from", subset, "-R", "--delete"],
                                   port=server.port)
            assert result.returncode == 0, f"-R delete sync failed: {result.stderr[:200]}"
            assert os.path.isfile(os.path.join(dest, "sub", "x.txt")), "listed file was deleted"
            assert not os.path.exists(os.path.join(dest, "sub", "y.txt")), \
                "unlisted relative file was not deleted"


class TestMissingArgs:
    """--ignore-missing-args / --delete-missing-args: a --files-from entry that
    does not exist under the source is skipped instead of failing the run, and
    (delete-missing) its destination mirror is removed receiver-side.  Following
    rsync, --delete-missing-args implies --ignore-missing-args but is
    independent of --delete: unrelated extras stay unless --delete is also
    given, and the missing-args deletion (an explicit user request) is never
    blocked by filter-exclusion protection."""

    def _make_source(self, name):
        source = os.path.join(TEST_DATA_DIR, name)
        clean_dir(source)
        for rel, content in {
            "a.txt": b"a\n",
            "sub/b.txt": b"b\n",
            "keep.txt": b"keep\n",
            "prot/kept.txt": b"kept\n",
        }.items():
            full = os.path.join(source, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(content)
        return source

    @pytest.mark.parametrize("mt", [False, True])
    def test_missing_entry_is_hard_error_before_transfer(self, shared_server, mt):
        source = self._make_source("mg_default_src")
        dest = os.path.join(TEST_DATA_DIR, "mg_default_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"a.txt\ngone.txt\nsub/b.txt\n")
        flags = ["--files-from", lst] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode != 0, "a listed-but-missing entry did not fail the run"
        assert "gone.txt" in (result.stderr or result.stdout)
        received = get_dest_received_dir(dest, source)
        assert not os.path.isfile(os.path.join(received, "a.txt")), \
            "the transfer started despite the missing-entry hard error"

    @pytest.mark.parametrize("mt", [False, True])
    def test_ignore_missing_args_transfers_the_rest(self, shared_server, mt):
        source = self._make_source("mg_ignore_src")
        dest = os.path.join(TEST_DATA_DIR, "mg_ignore_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"a.txt\ngone.txt\nsub/b.txt\n")
        flags = ["--files-from", lst, "--ignore-missing-args"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"ignore-missing-args sync failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "a.txt")) == b"a\n"
        assert _read_file(os.path.join(received, "sub", "b.txt")) == b"b\n"
        assert not os.path.exists(os.path.join(received, "gone.txt")), \
            "nothing was transferred for the missing entry"
        assert "--ignore-missing-args" in (result.stderr or result.stdout), \
            "the skipped entry must be observable (not a silent no-op)"

    @pytest.mark.parametrize("mt", [False, True])
    def test_all_missing_entries_succeed_transferring_nothing(self, shared_server, mt):
        source = self._make_source("mg_all_missing_src")
        dest = os.path.join(TEST_DATA_DIR, "mg_all_missing_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"gone1.txt\ngone2.txt\n")
        flags = ["--files-from", lst, "--ignore-missing-args"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"all-missing run should succeed (rsync parity): {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert not os.path.exists(os.path.join(received, "gone1.txt"))

    @pytest.mark.parametrize("mt", [False, True])
    def test_empty_list_stays_a_hard_error(self, shared_server, mt):
        source = self._make_source("mg_empty_src")
        dest = os.path.join(TEST_DATA_DIR, "mg_empty_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"")
        flags = ["--files-from", lst, "--ignore-missing-args"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode != 0, "an empty --files-from list must stay a hard error"
        assert "contains no entries" in (result.stderr or result.stdout)

    @pytest.mark.parametrize("mt", [False, True])
    def test_delete_missing_removes_mirror_not_unrelated(self, mt):
        """-R layout: --delete-missing-args deletes exactly the missing entry's
        destination mirror (bare relative path) and leaves unrelated extras
        untouched; with --delete also present the unrelated extras go too."""
        source = self._make_source("mg_del_src")
        dest = os.path.join(TEST_DATA_DIR, "mg_del_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            seed = _write_rel_list(b"a.txt\nsub/b.txt\n")
            result, _ = run_client(source, dest,
                                   flags=["--files-from", seed, "-R"] + (["--threads"] if mt else []),
                                   port=server.port)
            assert result.returncode == 0, f"seed -R sync failed: {result.stderr[:200]}"
            assert os.path.isfile(os.path.join(dest, "a.txt"))
            assert os.path.isfile(os.path.join(dest, "sub", "b.txt"))

            # Plant the missing entry's destination mirror and an unrelated extra.
            with open(os.path.join(dest, "gone.txt"), "w") as fh:
                fh.write("stale mirror")
            with open(os.path.join(dest, "unrelated.txt"), "w") as fh:
                fh.write("unrelated")

            lst = _write_rel_list(b"a.txt\ngone.txt\nsub/b.txt\n")
            flags = ["--files-from", lst, "-R", "--delete-missing-args"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, f"delete-missing sync failed: {result.stderr[:300]}"
            assert not os.path.exists(os.path.join(dest, "gone.txt")), \
                "the missing entry's destination mirror was not deleted"
            assert os.path.isfile(os.path.join(dest, "unrelated.txt")), \
                "--delete-missing-args removed an unrelated extra (only --delete may)"
            assert os.path.isfile(os.path.join(dest, "a.txt"))
            assert os.path.isfile(os.path.join(dest, "sub", "b.txt"))

            # Now with --delete the unrelated extra is an ordinary extra and must go.
            lst2 = _write_rel_list(b"a.txt\ngone.txt\nsub/b.txt\n")
            flags2 = ["--files-from", lst2, "-R", "--delete-missing-args", "--delete"] + \
                     (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags2, port=server.port)
            assert result.returncode == 0, f"delete-missing + delete sync failed: {result.stderr[:300]}"
            assert not os.path.exists(os.path.join(dest, "unrelated.txt")), \
                "--delete did not remove the unrelated extra"
            assert not os.path.exists(os.path.join(dest, "gone.txt"))
            assert os.path.isfile(os.path.join(dest, "a.txt"))

    @pytest.mark.parametrize("mt", [False, True])
    def test_delete_missing_mirror_outside_relative_layout(self, mt):
        """Without -R the missing entry's mirror mirrors the full source path
        below the destination root, exactly like a present sibling's."""
        source = self._make_source("mg_del_nor_src")
        dest = os.path.join(TEST_DATA_DIR, "mg_del_nor_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            # Full-tree seed places every current source file in the mirrored layout.
            result, _ = run_client(source, dest, flags=["--delete"], port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            assert os.path.isfile(os.path.join(received, "a.txt"))

            # Plant a stale mirror for an entry not (yet) on the source.
            with open(os.path.join(received, "gone.txt"), "w") as fh:
                fh.write("stale")
            lst = _write_rel_list(b"a.txt\ngone.txt\n")
            result, _ = run_client(source, dest,
                                   flags=["--files-from", lst, "--delete-missing-args"],
                                   port=server.port)
            assert result.returncode == 0, f"delete-missing no-R sync failed: {result.stderr[:300]}"
            assert not os.path.exists(os.path.join(received, "gone.txt")), \
                "the full-source-mirror path of the missing entry was not deleted"
            assert os.path.isfile(os.path.join(received, "a.txt"))

    @pytest.mark.parametrize("mt", [False, True])
    def test_delete_missing_args_not_blocked_by_exclude_protection(self, mt):
        """A missing-arg mirror that sits under a filter-excluded directory is an
        explicit user request, so --delete-missing-args removes it even though an
        ordinary --delete honours the exclusion protection (rsync parity).  Uses
        the non-relative layout: exclusion protection is only recorded there."""
        source = self._make_source("mg_excl_src")
        dest = os.path.join(TEST_DATA_DIR, "mg_excl_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            # Full-tree seed mirrors the whole source below the destination root.
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            assert os.path.isfile(os.path.join(received, "prot", "kept.txt"))

            # A stale mirror under the (now excluded) prot/ directory, plus an extra.
            with open(os.path.join(received, "prot", "gone.txt"), "w") as fh:
                fh.write("stale")
            with open(os.path.join(received, "extra.txt"), "w") as fh:
                fh.write("extra")

            lst = _write_rel_list(b"a.txt\nprot/gone.txt\n")
            flags = ["--files-from", lst, "--filter=- prot/", "--delete-missing-args",
                     "--delete"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, f"delete-missing exclude sync failed: {result.stderr[:300]}"
            assert not os.path.exists(os.path.join(received, "prot", "gone.txt")), \
                "the explicit missing-arg deletion was blocked by exclusion protection"
            assert os.path.isfile(os.path.join(received, "prot", "kept.txt")), \
                "the excluded-but-present destination file must stay (default protection)"
            assert not os.path.exists(os.path.join(received, "extra.txt")), \
                "--delete did not remove the unrelated extra"
            assert os.path.isfile(os.path.join(received, "a.txt"))

    @pytest.mark.parametrize("mt", [False, True])
    def test_delete_missing_args_with_delete_before(self, mt):
        """--delete-before (early delete timing) composes with --delete-missing-args:
        the exact-path deletions commit with the early manifest, before data, and
        --delete-before implies --delete (so unrelated extras go too)."""
        source = self._make_source("mg_early_src")
        dest = os.path.join(TEST_DATA_DIR, "mg_early_dst")
        clean_dir(dest)
        with open(os.path.join(dest, "gone.txt"), "w") as fh:
            fh.write("stale")
        with open(os.path.join(dest, "extra.txt"), "w") as fh:
            fh.write("extra")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            lst = _write_rel_list(b"a.txt\ngone.txt\ngone2.txt\n")
            flags = ["--files-from", lst, "-R", "--delete-missing-args", "--delete-before"] + \
                    (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, f"early delete-missing sync failed: {result.stderr[:300]}"
            assert not os.path.exists(os.path.join(dest, "gone.txt")), \
                "early timing did not remove the missing-arg mirror"
            assert os.path.isfile(os.path.join(dest, "a.txt")), "a.txt was not transferred"
            assert not os.path.exists(os.path.join(dest, "extra.txt")), \
                "--delete-before implies --delete: unrelated extras must go"

    @pytest.mark.parametrize("mt", [False, True])
    @pytest.mark.parametrize("relative", [False, True])
    def test_delete_missing_deep_entry_with_absent_parent(self, mt, relative):
        """A missing entry whose destination mirror's parent directory does not
        exist is a no-op (nothing to delete), never a run failure: the
        exact-path deletions must not abort the --delete extras walk.  Covers
        the -R bare-relative layout and the full source-mirror layout."""
        source = self._make_source("mg_deep_src")
        dest = os.path.join(TEST_DATA_DIR, "mg_deep_dst")
        clean_dir(dest)
        rel_flags = ["-R"] if relative else []
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            if relative:
                target_root = dest
            else:
                # Non-relative layout: seed a.txt so the receive-root mirror
                # tree exists (its sub/ sibling deliberately does not).
                seed = _write_rel_list(b"a.txt\n")
                result, _ = run_client(source, dest,
                                       flags=["--files-from", seed] + rel_flags,
                                       port=server.port)
                assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
                target_root = get_dest_received_dir(dest, source)
                assert os.path.isfile(os.path.join(target_root, "a.txt"))
            with open(os.path.join(target_root, "extra.txt"), "w") as fh:
                fh.write("extra")

            lst = _write_rel_list(b"a.txt\nsub/gone.txt\n")
            flags = ["--files-from", lst, "--delete-missing-args", "--delete"] + rel_flags + \
                    (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"deep missing-entry sync failed: {result.stderr[:300]}"
            assert _read_file(os.path.join(target_root, "a.txt")) == b"a\n"
            assert not os.path.exists(os.path.join(target_root, "extra.txt")), \
                "--delete extras walk was aborted by the absent-parent missing entry"
            assert not os.path.exists(os.path.join(target_root, "sub")), \
                "the absent parent directory of the missing entry was created"

    @pytest.mark.parametrize("mt", [False, True])
    def test_dirs_missing_entry_skipped_in_scanner(self, shared_server, mt):
        """--dirs + --files-from: a listed-but-missing entry is skipped in the
        --dirs generator (which would otherwise hard-fail), transferring the
        rest of the list."""
        source = self._make_source("mg_dirs_src")
        dest = os.path.join(TEST_DATA_DIR, "mg_dirs_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"a.txt\ngone.txt\n")
        flags = ["--files-from", lst, "--dirs", "-R", "--ignore-missing-args"] + \
                (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"--dirs ignore-missing sync failed: {result.stderr[:300]}"
        assert _read_file(os.path.join(dest, "a.txt")) == b"a\n", \
            "the listed present file was not transferred"
        assert not os.path.exists(os.path.join(dest, "gone.txt")), \
            "a directory/file was created for the missing --dirs entry"


class TestNoImpliedDirs:
    """--no-implied-dirs (only meaningful with -R + --files-from) refuses to
    place a listed file whose parent directory is not itself listed."""

    def _make(self):
        return _make_relative_source("noimplied_src")

    @pytest.mark.parametrize("mt", [False, True])
    def test_implied_dir_only_fails_entry(self, shared_server, mt):
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "noimplied_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"a/b.txt\n")  # "a" itself is not listed
        flags = ["--files-from", lst, "-R", "--no-implied-dirs"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode != 0, "implied parent directory was not rejected"
        assert "--no-implied-dirs" in (result.stderr or result.stdout)
        assert not os.path.exists(os.path.join(dest, "a", "b.txt"))

    @pytest.mark.parametrize("mt", [False, True])
    def test_listed_dir_allows_file(self, shared_server, mt):
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "noimplied_ok_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"a\na/b.txt\n")
        flags = ["--files-from", lst, "-R", "--no-implied-dirs"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"listed dir + file sync failed: {result.stderr[:200]}"
        assert _read_file(os.path.join(dest, "a", "b.txt")) == b"nested\n"

    @pytest.mark.parametrize("mt", [False, True])
    def test_no_implied_dirs_without_relative_changes_nothing(self, shared_server, mt):
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "noimplied_noR_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"a/b.txt\n")
        flags = ["--files-from", lst, "--no-implied-dirs"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, "--no-implied-dirs without -R changed behavior"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "a", "b.txt")) == b"nested\n"


class TestDirs:
    """-d/--dirs (and the --old-dirs/--old-d aliases) transfer directory entries
    without recursing into their contents."""

    def _make(self):
        return _make_relative_source("dirs_src")

    def _assert_only_empty_mirror(self, dest, source):
        mirror = get_dest_received_dir(dest, source)
        assert os.path.isdir(mirror), "source-root mirror directory was not created"
        files = []
        for root, _dirs, names in os.walk(mirror):
            files.extend(os.path.relpath(os.path.join(root, n), mirror) for n in names)
        assert files == [], f"--dirs descended into contents: {files}"

    @pytest.mark.parametrize("flag", ["--dirs", "-d", "--old-dirs", "--old-d"])
    @pytest.mark.parametrize("mt", [False, True])
    def test_dirs_transfers_empty_dir_only(self, shared_server, flag, mt):
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_dst")
        clean_dir(dest)
        flags = [flag] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"{flag} sync failed: {result.stderr[:200]}"
        self._assert_only_empty_mirror(dest, source)

    @pytest.mark.parametrize("mt", [False, True])
    def test_dirs_with_files_from(self, shared_server, mt):
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_ff_dst")
        clean_dir(dest)
        # A listed directory is created empty; a listed file is transferred.
        lst = _write_rel_list(b"dir1\nsub/x.txt\n")
        flags = ["--files-from", lst, "--dirs", "-R"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"dirs files-from sync failed: {result.stderr[:200]}"
        assert os.path.isdir(os.path.join(dest, "dir1")), "listed dir was not created"
        assert not os.path.exists(os.path.join(dest, "dir1", "keep.txt")), \
            "--dirs must not descend into a listed directory"
        assert _read_file(os.path.join(dest, "sub", "x.txt")) == b"x\n", \
            "listed file content was not transferred"
        assert not os.path.exists(os.path.join(dest, "sub", "y.txt")), \
            "unlisted file appeared"

    @pytest.mark.parametrize("mt", [False, True])
    def test_dirs_with_files_from_mirror_layout(self, shared_server, mt):
        """Without -R the dirs+files-from entries still mirror the source path."""
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_ff_noR_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"dir1\n")
        flags = ["--files-from", lst, "--dirs"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"dirs files-from no-R sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        assert os.path.isdir(os.path.join(received, "dir1")), "mirrored dir entry not created"
        assert not os.path.exists(os.path.join(received, "dir1", "keep.txt")), \
            "--dirs must not descend into a listed directory"
        assert not os.path.exists(os.path.join(received, "sub")), \
            "unlisted subtree appeared"

    @pytest.mark.parametrize("mt", [False, True])
    def test_dirs_chunk_serialization(self, shared_server, mt):
        """--dirs entries survive the chunk-serialization wire path (type
        marker round-trips); a listed dir lands empty and a listed file lands
        with content, with no protocol desync under -s -m."""
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_s_dst")
        clean_dir(dest)
        lst = _write_rel_list(b"dir1\nsub/x.txt\n")
        flags = ["--files-from", lst, "--dirs", "-R", "--chunk-serialization"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"dirs -s sync failed: {result.stderr[:200]}"
        assert os.path.isdir(os.path.join(dest, "dir1")), "listed dir was not created"
        assert not os.path.exists(os.path.join(dest, "dir1", "keep.txt")), \
            "--dirs must not descend into a listed directory"
        assert _read_file(os.path.join(dest, "sub", "x.txt")) == b"x\n", \
            "listed file content was not transferred"

    def test_dirs_delete_keeps_transferred_empty_dir(self):
        """Directory entries appear in the delete manifest, so the empty dir a
        --dirs run just created is not pruned as an extra by --delete."""
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_del_dst")
        clean_dir(dest)
        extra = os.path.join(dest, "extra.txt")
        with open(extra, "wb") as fh:
            fh.write(b"delete me")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["--dirs", "--delete"],
                                   port=server.port)
            assert result.returncode == 0, f"--dirs --delete sync failed: {result.stderr[:200]}"
            assert not os.path.exists(extra), "--delete did not remove the extra file"
            mirror = get_dest_received_dir(dest, source)
            assert os.path.isdir(mirror), "transferred empty dir was pruned as an extra"
            files = []
            for root, _dirs, names in os.walk(mirror):
                files.extend(os.path.relpath(os.path.join(root, n), mirror) for n in names)
            assert files == [], f"--dirs descended into contents: {files}"

    def test_dirs_listed_dir_colliding_with_file_fails(self, shared_server):
        """A listed directory that already exists as a regular file at the
        destination fails the transfer cleanly instead of clobbering the file."""
        source = self._make()
        dest = os.path.join(TEST_DATA_DIR, "dirs_coll_dst")
        clean_dir(dest)
        blocker = os.path.join(dest, "dir1")
        with open(blocker, "wb") as fh:
            fh.write(b"blocking file")
        lst = _write_rel_list(b"dir1\n")
        result, _ = run_client(source, dest, flags=["--files-from", lst, "--dirs", "-R"],
                               port=shared_server.port)
        assert result.returncode != 0, "dir entry over an existing file did not fail"
        assert os.path.isfile(blocker), "blocking regular file was clobbered"


class TestMkpath:
    """--mkpath tells the server to create the destination root directory (and
    missing leading components) when it does not exist yet; without it a missing
    destination root fails the transfer."""

    @pytest.mark.parametrize("mt", [False, True])
    def test_missing_root_fails_without_mkpath(self, mt):
        source = _make_relative_source("mkpath_fail_src")
        dest = os.path.join(TEST_DATA_DIR, "mkpath_missing_dst")
        shutil.rmtree(dest, ignore_errors=True)
        with ServerManager() as server:
            server.start()
            flags = ["--threads"] if mt else []
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode != 0, "missing destination root did not fail without --mkpath"
            assert not os.path.exists(dest), "missing root was created without --mkpath"

    @pytest.mark.parametrize("mt", [False, True])
    def test_mkpath_creates_missing_root(self, mt):
        source = _make_relative_source("mkpath_ok_src")
        dest = os.path.join(TEST_DATA_DIR, "deep", "mkpath_dst")
        shutil.rmtree(os.path.join(TEST_DATA_DIR, "deep"), ignore_errors=True)
        with ServerManager() as server:
            server.start()
            flags = ["--mkpath"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, f"--mkpath sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            assert _read_file(os.path.join(received, "sub", "x.txt")) == b"x\n", \
                "file not transferred into the --mkpath-created root"

    @pytest.mark.parametrize("mkpath", [False, True])
    def test_existing_dest_with_trailing_slash(self, shared_server, mkpath):
        """A destination root written with a trailing slash must keep working:
        an existing root is accepted both with and without --mkpath."""
        source = _make_relative_source("mkpath_trail_src")
        dest = os.path.join(TEST_DATA_DIR, "mkpath_trail_dst")
        clean_dir(dest)
        dest_slash = dest + "/"
        flags = ["--mkpath"] if mkpath else []
        result, _ = run_client(source, dest_slash, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"trailing-slash dest sync (mkpath={mkpath}) failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, "sub", "x.txt")) == b"x\n", \
            "file not transferred into the trailing-slash destination root"

    @pytest.mark.parametrize("mkpath", [False, True])
    def test_dest_equal_authorized_root(self, mkpath):
        """A destination that is exactly the server's authorized root works
        without --mkpath, and with --mkpath creates no stray <root>/<basename>
        nested directory."""
        root = os.path.join(TEST_DATA_DIR, "mkpath_eq_root")
        clean_dir(root)
        source = _make_relative_source("mkpath_eq_src")
        with ServerManager() as server:
            server.start(extra_args=["--destination-root", root])
            flags = ["--mkpath"] if mkpath else []
            result, _ = run_client(source, root, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"dest==authorized-root sync (mkpath={mkpath}) failed: {result.stderr[:200]}"
            received = get_dest_received_dir(root, source)
            assert _read_file(os.path.join(received, "sub", "x.txt")) == b"x\n", \
                "file not transferred when the dest equals the authorized root"
            basename = os.path.basename(root.rstrip(os.sep))
            assert not os.path.exists(os.path.join(root, basename)), \
                "--mkpath created a spurious nested <root>/<basename> directory"


class TestFilters:
    """--filter/-C/-F rule layer: excludes prune, ordering is first-match-wins,
    the default with no matching rule is include, and legacy --exclude remains
    an independent layer."""


class TestDeleteTiming:
    """rsync deletion-timing family.  --delete-before/--delete-during transmit
    the keep-set manifest BEFORE any file data (the receiver deletes extras and
    acks first); --delete/--delete-after/--delete-delay commit deletions only
    after the whole transfer succeeded.  Every timing flag implies --delete."""

    def _seed(self, tag):
        source = os.path.join(TEST_DATA_DIR, f"deltiming_{tag}_src")
        clean_dir(source)
        entries = {
            "top.txt": b"top level\n",
            "sub/deep.txt": b"deeply nested file\n",
        }
        for rel, content in entries.items():
            full = os.path.join(source, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(content)
        return source

    @pytest.mark.parametrize("flag", ["--delete-before", "--delete-during", "--del",
                                      "--delete-after", "--delete-delay"])
    @pytest.mark.parametrize("mt", [False, True])
    @pytest.mark.ci
    def test_flag_removes_extras_on_success(self, flag, mt):
        """Every timing flag is accepted, implies --delete, and on a successful
        transfer removes the destination extras exactly like plain --delete."""
        source = self._seed("ok")
        dest = os.path.join(TEST_DATA_DIR, "deltiming_ok_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            extra = os.path.join(received, "extra.txt")
            with open(extra, "wb") as fh:
                fh.write(b"should be deleted")

            flags = [flag] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"{flag} sync failed: {(result.stderr or result.stdout)[:300]}"
            assert not os.path.exists(extra), f"{flag} did not remove the extra file"
            mismatches, missing = verify_transfer(source, received)
            assert not missing, f"{flag} missing files: {missing}"
            assert not mismatches, f"{flag} mismatched files: {mismatches}"

    @pytest.mark.parametrize("flag", ["--delete-before", "--delete-during", "--del"])
    @pytest.mark.parametrize("mt", [False, True])
    def test_early_flags_delete_before_data(self, flag, mt):
        """--delete-before/--delete-during remove extras (and a file blocking a
        destination directory) BEFORE data is applied, so a nested write that
        would fail while the blocker still exists succeeds."""
        source = self._seed("early")
        dest = os.path.join(TEST_DATA_DIR, "deltiming_early_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            extra = os.path.join(received, "extra.txt")
            with open(extra, "wb") as fh:
                fh.write(b"extra file")
            blocker = os.path.join(received, "sub")
            shutil.rmtree(blocker)
            with open(blocker, "wb") as fh:
                fh.write(b"blocks the nested destination directory")

            flags = [flag] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"{flag} (early delete) did not remove the blocker in time: " \
                f"{(result.stderr or result.stdout)[:300]}"
            assert not os.path.exists(extra), f"{flag} did not delete the extra before data"
            assert _read_file(os.path.join(received, "sub", "deep.txt")) == b"deeply nested file\n", \
                f"{flag}: nested file was not written after the early deletion"

    @pytest.mark.parametrize("flag", ["--delete", "--delete-after", "--delete-delay"])
    @pytest.mark.parametrize("mt", [False, True])
    def test_late_flags_commit_only_after_success(self, flag, mt):
        """Plain --delete/--delete-after/--delete-delay defer deletion until the
        whole transfer succeeds: a mid-transfer write failure must leave every
        extra in place (commit-style safety).  The -m receiver must also keep
        the extras: the deferred keep-set is committed by the server only after
        the disk-writer thread has finished, and a failing writer means the
        manifest is freed, never applied."""
        source = self._seed("late")
        dest = os.path.join(TEST_DATA_DIR, "deltiming_late_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            extra = os.path.join(received, "extra.txt")
            with open(extra, "wb") as fh:
                fh.write(b"extra file")
            blocker = os.path.join(received, "sub")
            shutil.rmtree(blocker)
            with open(blocker, "wb") as fh:
                fh.write(b"blocks the nested destination directory")

            flags = [flag] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode != 0, \
                f"{flag} (mt={mt}) unexpectedly succeeded (deletion must be deferred)"
            assert os.path.exists(extra), \
                f"{flag} (mt={mt}) removed an extra although the transfer failed"
            assert os.path.isfile(blocker), \
                f"{flag} (mt={mt}) deleted the blocker although the transfer failed"

    def test_early_flag_respected_when_server_refuses_delete(self, shared_server):
        """With an --allow-delete-less server the client's early timing still
        completes (no deadlock on the pre-delete ack) and simply never deletes,
        exactly like the plain server policy."""
        source = self._seed("refused")
        dest = os.path.join(TEST_DATA_DIR, "deltiming_refused_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
        received = get_dest_received_dir(dest, source)
        extra = os.path.join(received, "extra.txt")
        with open(extra, "wb") as fh:
            fh.write(b"extra file")
        result, _ = run_client(source, dest, flags=["--delete-before"], port=shared_server.port)
        assert result.returncode == 0, \
            f"--delete-before against a refuse-delete server failed: {result.stderr[:300]}"
        assert os.path.exists(extra), "unauthorized delete removed an extra file"


def _seed_delete_tree(tag, entries, dest):
    """Create a source tree and seed a full mirror at `dest`, returning
    (source, received_mirror)."""
    source = os.path.join(TEST_DATA_DIR, f"delpol_{tag}_src")
    clean_dir(source)
    for rel, content in entries.items():
        full = os.path.join(source, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(content)
    clean_dir(dest)
    with ServerManager() as server:
        server.start(extra_args=["--allow-delete"])
        result, _ = run_client(source, dest, port=server.port)
        assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
    received = get_dest_received_dir(dest, source)
    return source, received


class TestDeletePolicy:
    """Deletion-policy family: --delete-excluded, --max-delete, --force,
    --ignore-errors and --prune-empty-dirs."""

    def _write(self, path, content):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(content)

    @pytest.mark.parametrize("mt", [False, True])
    @pytest.mark.parametrize("timing",
                             ["--delete", "--delete-before", "--delete-after", "--delete-delay"])
    def test_delete_protects_excluded_by_default_and_delete_excluded_removes(self, mt, timing):
        """rsync parity: with a --delete timing the destination mirror path whose
        source was excluded survives (protected by default); --delete-excluded
        opts back into deleting it.  Verified single-threaded and -m across every
        timing (commit and early)."""
        source = os.path.join(TEST_DATA_DIR, f"delexcl_{timing.strip('-')}_{mt}_src")
        clean_dir(source)
        entries = {
            "keep.txt": b"kept\n",
            "secret.log": b"secret\n",
            "sub/nested.log": b"nested secret\n",
        }
        for rel, content in entries.items():
            self._write(os.path.join(source, rel), content)
        dest = os.path.join(TEST_DATA_DIR, f"delexcl_{timing.strip('-')}_{mt}_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            self._write(os.path.join(received, "extra.txt"), b"extra\n")

            # Default: the excluded mirrors survive --delete, genuine extras die.
            flags = ["--exclude", "*.log", timing] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"default delete sync failed: {(result.stderr or result.stdout)[:300]}"
            assert os.path.exists(os.path.join(received, "secret.log")), \
                "excluded dest file was deleted under plain --delete (rsync protects it)"
            assert os.path.exists(os.path.join(received, "sub", "nested.log")), \
                "nested excluded dest file was deleted under plain --delete"
            assert not os.path.exists(os.path.join(received, "extra.txt")), \
                "genuine extra was not deleted"

            # --delete-excluded: excluded mirrors are extras again and die.
            self._write(os.path.join(received, "extra.txt"), b"extra\n")
            flags = ["--exclude", "*.log", timing, "--delete-excluded"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"--delete-excluded sync failed: {(result.stderr or result.stdout)[:300]}"
            assert not os.path.exists(os.path.join(received, "secret.log")), \
                "--delete-excluded did not remove the excluded dest file"
            assert not os.path.exists(os.path.join(received, "sub", "nested.log")), \
                "--delete-excluded did not remove the nested excluded dest file"
            assert not os.path.exists(os.path.join(received, "extra.txt")), \
                "genuine extra survived --delete-excluded"
            assert _read_file(os.path.join(received, "keep.txt")) == b"kept\n"

    @pytest.mark.parametrize("mt", [False, True])
    def test_delete_excluded_excluded_directory_subtree(self, mt):
        """A whole source directory excluded by a filter rule protects its whole
        destination mirror by default; --delete-excluded removes the subtree."""
        source = os.path.join(TEST_DATA_DIR, f"delexcldir_{mt}_src")
        clean_dir(source)
        self._write(os.path.join(source, "keep.txt"), b"kept\n")
        self._write(os.path.join(source, "skipdir", "a.log"), b"a\n")
        self._write(os.path.join(source, "skipdir", "deep", "b.log"), b"b\n")
        dest = os.path.join(TEST_DATA_DIR, f"delexcldir_{mt}_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)

            flags = ["--filter=- skipdir/", "--delete"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"default delete sync failed: {(result.stderr or result.stdout)[:300]}"
            assert os.path.exists(os.path.join(received, "skipdir", "a.log")), \
                "excluded dir subtree was deleted under plain --delete"
            assert os.path.exists(os.path.join(received, "skipdir", "deep", "b.log")), \
                "nested excluded dir content was deleted under plain --delete"

            flags = ["--filter=- skipdir/", "--delete", "--delete-excluded"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"--delete-excluded sync failed: {(result.stderr or result.stdout)[:300]}"
            assert not os.path.exists(os.path.join(received, "skipdir")), \
                "--delete-excluded did not remove the excluded dir subtree"

    @pytest.mark.parametrize("mt", [False, True])
    @pytest.mark.parametrize("timing", ["--delete", "--delete-before"])
    def test_max_delete_exceeded_fails_without_deleting(self, mt, timing):
        """A run that would exceed --max-delete deletes nothing and fails."""
        source = os.path.join(TEST_DATA_DIR, f"maxdel_{timing.strip('-')}_{mt}_src")
        clean_dir(source)
        self._write(os.path.join(source, "keep.txt"), b"kept\n")
        dest = os.path.join(TEST_DATA_DIR, f"maxdel_{timing.strip('-')}_{mt}_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            extras = []
            for i in range(4):
                name = f"e{i}.txt"
                self._write(os.path.join(received, name), b"extra\n")
                extras.append(os.path.join(received, name))

            flags = ["--max-delete=2", timing] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode != 0, \
                f"--max-delete=2 with 4 extras unexpectedly succeeded: {result.stderr[:300]}"
            for path in extras:
                assert os.path.exists(path), \
                    "--max-delete overrun deleted files (must be all-or-nothing)"

    @pytest.mark.parametrize("mt", [False, True])
    def test_max_delete_not_exceeded_deletes_exactly(self, mt):
        """When the extras are at or below --max-delete the run succeeds and
        removes exactly the extras."""
        source = os.path.join(TEST_DATA_DIR, f"maxdelok_{mt}_src")
        clean_dir(source)
        self._write(os.path.join(source, "keep.txt"), b"kept\n")
        dest = os.path.join(TEST_DATA_DIR, f"maxdelok_{mt}_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            for i in range(3):
                self._write(os.path.join(received, f"e{i}.txt"), b"extra\n")
            flags = ["--max-delete=3", "--delete"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"--max-delete=3 with 3 extras failed: {(result.stderr or result.stdout)[:300]}"
            for i in range(3):
                assert not os.path.exists(os.path.join(received, f"e{i}.txt")), \
                    f"extra e{i}.txt not deleted under --max-delete=3"

    @pytest.mark.parametrize("mt", [False, True])
    def test_force_replaces_nonempty_dir_with_file(self, mt):
        """--force lets an incoming regular file replace a non-empty destination
        directory; without it the write (and the run) fails."""
        source = os.path.join(TEST_DATA_DIR, f"force_{mt}_src")
        clean_dir(source)
        self._write(os.path.join(source, "sub", "old.txt"), b"old\n")
        self._write(os.path.join(source, "keep.txt"), b"kept\n")
        dest = os.path.join(TEST_DATA_DIR, f"force_{mt}_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)

            # The source path `sub` becomes a regular file (the dir is gone).
            os.unlink(os.path.join(source, "sub", "old.txt"))
            os.rmdir(os.path.join(source, "sub"))
            self._write(os.path.join(source, "sub"), b"now a file\n")

            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode != 0, \
                "a file over a non-empty directory must fail without --force"
            assert os.path.isdir(os.path.join(received, "sub")), \
                "directory was destroyed although the run failed without --force"
            assert os.path.exists(os.path.join(received, "sub", "old.txt")), \
                "non-empty dir content was lost although the run failed without --force"

            flags = ["--force"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"--force run failed: {(result.stderr or result.stdout)[:300]}"
            assert os.path.isfile(os.path.join(received, "sub")), \
                "--force did not replace the directory with the file"
            assert _read_file(os.path.join(received, "sub")) == b"now a file\n"

    def test_force_inert_under_delay_updates(self):
        """Documented divergence: --force acts on the immediate-install path; a
        --delay-updates run stages into its own tree and its publication renames
        over regular files only, so a blocking directory is not cleared and the
        run fails."""
        source = os.path.join(TEST_DATA_DIR, "force_delay_src")
        clean_dir(source)
        self._write(os.path.join(source, "sub", "old.txt"), b"old\n")
        self._write(os.path.join(source, "keep.txt"), b"kept\n")
        dest = os.path.join(TEST_DATA_DIR, "force_delay_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            os.unlink(os.path.join(source, "sub", "old.txt"))
            os.rmdir(os.path.join(source, "sub"))
            self._write(os.path.join(source, "sub"), b"now a file\n")
            result, _ = run_client(source, dest, flags=["--force", "--delay-updates"],
                                   port=server.port)
            assert result.returncode != 0, \
                "--force --delay-updates unexpectedly replaced the blocking directory"
            assert os.path.isdir(os.path.join(received, "sub")), \
                "blocking directory was cleared although --delay-updates should keep --force inert"
            assert os.path.exists(os.path.join(received, "sub", "old.txt")), \
                "blocking directory content was lost"

    @pytest.mark.parametrize("mt", [False, True])
    def test_prune_empty_dirs_dirs_mode(self, mt):
        """--prune-empty-dirs omits an empty source directory's explicit entry in
        --dirs mode (nothing is created, and an existing empty mirror is removed
        by --delete).  Recursive transfers never emit empty dirs, so the flag is
        a no-op there (documented rsync -m parity)."""
        source = os.path.join(TEST_DATA_DIR, f"prune_{mt}_src")
        clean_dir(source)
        os.makedirs(source, exist_ok=True)  # physically empty source dir

        dest = os.path.join(TEST_DATA_DIR, f"prune_{mt}_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["--dirs"], port=server.port)
            assert result.returncode == 0, f"-d seed failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            assert os.path.isdir(received), "-d should create the empty mirror dir"
            assert os.listdir(received) == []

            # prune-empty-dirs: the empty mirror is pruned by --delete.
            flags = ["--dirs", "--prune-empty-dirs", "--delete"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"--dirs --prune-empty-dirs --delete failed: {(result.stderr or result.stdout)[:300]}"
            assert not os.path.exists(received), \
                "--prune-empty-dirs did not prune the empty dir (--delete left it)"

        # A fresh destination: prune-empty-dirs means the empty dir is never sent.
        dest2 = os.path.join(TEST_DATA_DIR, f"prune2_{mt}_dst")
        clean_dir(dest2)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            flags = ["--dirs", "--prune-empty-dirs", "-i"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest2, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"--dirs --prune-empty-dirs failed: {(result.stderr or result.stdout)[:300]}"
            received2 = get_dest_received_dir(dest2, source)
            assert not os.path.exists(received2), \
                "--prune-empty-dirs transferred the empty directory"
            assert result.stdout == "", \
                f"--prune-empty-dirs leaked an itemize line: {result.stdout[:200]}"

    @pytest.mark.parametrize("mt", [False, True])
    def test_prune_empty_dirs_recursion_inherent(self, mt):
        """In recursive mode FastSync never transfers empty directories (rsync
        -m parity): a truly-empty destination directory chain is removed by
        --delete whether or not --prune-empty-dirs is given (the flag has no
        additional effect there), while directories holding kept files survive.
        A filter-excluded file's mirror is protected, so a directory that still
        holds one is left intact (rsync default delete-excluded semantics)."""
        source = os.path.join(TEST_DATA_DIR, f"prunerec_{mt}_src")
        clean_dir(source)
        self._write(os.path.join(source, "keep.txt"), b"kept\n")
        self._write(os.path.join(source, "a", "keep.log"), b"a log\n")
        self._write(os.path.join(source, "b", "deep", "kept.txt"), b"deep kept\n")
        dest = os.path.join(TEST_DATA_DIR, f"prunerec_{mt}_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            # A stray empty chain (FastSync recursion never creates such dirs, so
            # this models one left by an external tool / an earlier --dirs run).
            os.makedirs(os.path.join(received, "empty", "chain"))

            for prune in ([], ["--prune-empty-dirs"]):
                flags = prune + ["--delete"] + (["--threads"] if mt else [])
                result, _ = run_client(source, dest, flags=flags, port=server.port)
                assert result.returncode == 0, \
                    f"prune recursive sync failed: {(result.stderr or result.stdout)[:300]}"
                assert not os.path.exists(os.path.join(received, "empty")), \
                    "truly-empty dir chain was not removed by --delete"
                assert os.path.exists(os.path.join(received, "b", "deep", "kept.txt")), \
                    "non-empty dir subtree was wrongly removed"
                assert _read_file(os.path.join(received, "keep.txt")) == b"kept\n"

            # An excluded file's mirror is protected: the dir that holds it stays.
            flags = ["--exclude", "*.log", "--delete", "--prune-empty-dirs"] + (["--threads"] if mt else [])
            result, _ = run_client(source, dest, flags=flags, port=server.port)
            assert result.returncode == 0, \
                f"prune recursive sync failed: {(result.stderr or result.stdout)[:300]}"
            assert os.path.exists(os.path.join(received, "a", "keep.log")), \
                "excluded file mirror was deleted under --delete (rsync protects it)"

    def _run_client_as_nobody(self, source, dest, port, flags):
        cmd = CLIENT_CMD + ["--source-dir", source, "--dest-dir", dest,
                            "--save-to-disk", "--server-port", str(port)] + flags
        return subprocess.run(["setpriv", "--reuid=65534", "--regid=65534",
                               "--clear-groups"] + cmd, text=True, capture_output=True)

    @pytest.mark.parametrize("mt", [False, True])
    @pytest.mark.setpriv
    def test_ignore_errors_keeps_deletion_active_on_scan_error(self, mt):
        """A source I/O error (unreadable subdirectory) aborts the run so no
        deletion happens by default; --ignore-errors continues, still transfers
        the readable tree and still deletes, single-threaded and under -m.  Run
        as an unprivileged user so the mode-000 directory is genuinely
        unreadable."""
        if os.geteuid() != 0 or shutil.which("setpriv") is None:
            pytest.skip("requires root + setpriv to drop privileges for the client")
        tag = f"ioerr_{os.getpid()}_{mt}"
        source = os.path.join(TEST_DATA_DIR, f"{tag}_src")
        clean_dir(source)
        self._write(os.path.join(source, "top.txt"), b"top\n")
        self._write(os.path.join(source, "ok", "inside.txt"), b"inside\n")
        self._write(os.path.join(source, "locked", "blocked.txt"), b"blocked\n")
        dest = os.path.join(TEST_DATA_DIR, f"{tag}_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            # Seed as root (server is root too).
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            try:
                os.chmod(os.path.join(source, "locked"), 0)

                # Default: scan error aborts the run; nothing is deleted.
                self._write(os.path.join(received, "extra.txt"), b"extra\n")
                flags = ["--delete"] + (["--threads"] if mt else [])
                result = self._run_client_as_nobody(source, dest, server.port, flags)
                assert result.returncode != 0, "unreadable source dir did not fail the run"
                assert os.path.exists(os.path.join(received, "extra.txt")), \
                    "default run deleted although the scan hit an I/O error"

                # --ignore-errors: the readable tree transfers, deletion still runs.
                self._write(os.path.join(received, "extra.txt"), b"extra\n")
                flags = ["--delete", "--ignore-errors"] + (["--threads"] if mt else [])
                result = self._run_client_as_nobody(source, dest, server.port, flags)
                assert not os.path.exists(os.path.join(received, "extra.txt")), \
                    f"--ignore-errors did not keep deletion active: {result.stderr[:300]}"
                assert not os.path.exists(os.path.join(received, "locked")), \
                    "mirror of the unreadable dir was left behind (should be an extra)"
            finally:
                os.chmod(os.path.join(source, "locked"), 0o755)

    @pytest.mark.parametrize("mt", [False, True])
    @pytest.mark.parametrize("timing", ["--delete", "--delete-before"])
    @pytest.mark.setpriv
    def test_ignore_errors_unreadable_root_never_deletes(self, mt, timing):
        """An unreadable SOURCE ROOT must never be treated as a skippable scan
        error: with --ignore-errors the sequential scanner treats the root as
        fatal (matching the -m path, which cannot even create its scanner), so
        no empty keep-set manifest is sent and the destination is never wiped.
        Run as an unprivileged user so the mode-000 root is genuinely
        unreadable."""
        if os.geteuid() != 0 or shutil.which("setpriv") is None:
            pytest.skip("requires root + setpriv to drop privileges for the client")
        tag = f"rootio_{os.getpid()}_{mt}_{timing.strip('-')}"
        source = os.path.join(TEST_DATA_DIR, f"{tag}_src")
        clean_dir(source)
        self._write(os.path.join(source, "file.txt"), b"content\n")
        dest = os.path.join(TEST_DATA_DIR, f"{tag}_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            try:
                os.chmod(source, 0)
                self._write(os.path.join(received, "extra.txt"), b"extra\n")
                flags = [timing, "--ignore-errors"] + (["--threads"] if mt else [])
                result = self._run_client_as_nobody(source, dest, server.port, flags)
                assert result.returncode != 0, \
                    f"unreadable source root with {timing} (mt={mt}) unexpectedly succeeded"
                assert os.path.exists(os.path.join(received, "file.txt")), \
                    f"{timing} (mt={mt}) wiped a kept destination file"
                assert os.path.exists(os.path.join(received, "extra.txt")), \
                    f"{timing} (mt={mt}) deleted the extra although the scan could not read the root"
            finally:
                os.chmod(source, 0o755)

    def test_delete_excluded_protection_is_sender_derived(self):
        """Plain --delete protects destination mirrors of files the SOURCE scan
        excluded, but a destination-only file that merely matches an exclude
        rule is still an extra and is removed (protection never re-applies rules
        to the destination)."""
        source = os.path.join(TEST_DATA_DIR, "senderderived_src")
        clean_dir(source)
        self._write(os.path.join(source, "keep.txt"), b"kept\n")
        self._write(os.path.join(source, "secret.log"), b"secret\n")
        dest = os.path.join(TEST_DATA_DIR, "senderderived_dst")
        clean_dir(dest)
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode == 0, f"seed sync failed: {result.stderr[:200]}"
            received = get_dest_received_dir(dest, source)
            # A destination-only file that happens to match the exclude rule.
            self._write(os.path.join(received, "stray.log"), b"never on the source\n")
            result, _ = run_client(source, dest, flags=["--exclude", "*.log", "--delete"],
                                   port=server.port)
            assert result.returncode == 0, \
                f"delete sync failed: {(result.stderr or result.stdout)[:300]}"
            assert os.path.exists(os.path.join(received, "secret.log")), \
                "source-excluded mirror was deleted under plain --delete"
            assert not os.path.exists(os.path.join(received, "stray.log")), \
                "destination-only file matching the exclude rule was left (should be deleted)"


def _pin_mtime(path, ts):
    os.utime(path, (ts, ts))


class TestBasisDestDirs:
    """--compare-dest / --copy-dest / --link-dest alternate basis directories.

    FastSync's basis directories are relative to the destination root and are
    confined below it.  The "unchanged" decision is receiver-side and requires
    the per-file --incremental handshake (implied by these flags), so the basis
    snapshot must reproduce the exact destination-relative mirror path of the
    incoming files.
    """

    STAGING = ".fastsync-stage"
    TS = 1577836800  # 2020-01-01 00:00:00 UTC, used to pin matching mtimes

    # fixture files: source and basis share the mtime pin, so a basis "match"
    # is decided purely by content (xxHash).  unchanged.txt is byte-identical;
    # changed.txt is byte-DIFFERENT but has the SAME SIZE as the source (and
    # the same pinned mtime), which is what forces the content-hash gate;
    # added.txt does not exist in the basis at all.
    UNCHANGED = "unchanged.txt"
    CHANGED = "changed.txt"
    ADDED = "added.txt"

    def _make_source(self, name, source_files):
        src = os.path.join(TEST_DATA_DIR, name)
        clean_dir(src)
        for rel, content in source_files.items():
            full = os.path.join(src, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(content)
            _pin_mtime(full, self.TS)
        return src

    def _seed_basis_file(self, dest, source, basis_dir, rel, content, ts=None):
        base = os.path.join(dest, basis_dir, os.path.relpath(
            get_dest_received_dir(dest, source), dest))
        full = os.path.join(base, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(content)
        _pin_mtime(full, self.TS if ts is None else ts)
        return full

    def _seed_basis(self, dest, source, basis_dir, basis_files):
        for rel, content in basis_files.items():
            self._seed_basis_file(dest, source, basis_dir, rel, content)
        return os.path.join(dest, basis_dir, os.path.relpath(
            get_dest_received_dir(dest, source), dest))

    def _source_tree(self, prefix):
        return {
            self.UNCHANGED: b"stable content v1\n",
            self.CHANGED: b"changed content now\n",
            self.ADDED: b"brand new content\n",
        }

    def _basis_tree(self, prefix):
        # unchanged.txt is identical to the source; changed.txt has the SAME
        # byte size and pinned mtime but a different body (equal size forces
        # the xxHash gate); added.txt is missing from the basis.
        return {
            self.UNCHANGED: b"stable content v1\n",
            self.CHANGED: b"CHANGED CONTENT NOW\n",
        }

    def test_same_size_different_content_is_not_a_basis_match(self, shared_server):
        # Core safety property: equal size + pinned mtime but different content
        # must NEVER be hard-linked or copied from the basis -- the xxHash gate
        # rejects it and the sender's data is transferred instead.
        for flag, basis_dir in (("--link-dest", "szlb"), ("--copy-dest", "szcp"),
                                ("--compare-dest", "szcmp")):
            source = self._make_source("basis_same_size_src",
                                       {self.UNCHANGED: b"same length body\n"})
            dest = os.path.join(TEST_DATA_DIR, f"basis_same_size_dst_{basis_dir}")
            clean_dir(dest)
            basis_file = self._seed_basis_file(dest, source, basis_dir, self.UNCHANGED,
                                               b"SAME LENGTH BODY!")
            result, _ = run_client(source, dest, flags=[f"{flag}={basis_dir}"],
                                   port=shared_server.port)
            assert result.returncode == 0, \
                f"{flag} same-size mismatch failed: {result.stderr[:300]}"
            received = get_dest_received_dir(dest, source)
            dest_file = os.path.join(received, self.UNCHANGED)
            assert _read_file(dest_file) == b"same length body\n", \
                f"{flag}: basis content leaked into the destination on a hash mismatch"
            if flag != "--compare-dest":
                assert os.stat(dest_file).st_ino != os.stat(basis_file).st_ino, \
                    f"{flag}: linked/copied from a content-mismatched basis file"

    @pytest.mark.ci
    def test_compare_dest_skips_matching_and_transfers_missing(self, shared_server):
        source = self._make_source("basis_compare_src", self._source_tree("c"))
        dest = os.path.join(TEST_DATA_DIR, "basis_compare_dst")
        clean_dir(dest)
        self._seed_basis(dest, source, "cbasis", self._basis_tree("c"))
        result, _ = run_client(source, dest,
                               flags=["--compare-dest=cbasis"],
                               port=shared_server.port)
        assert result.returncode == 0, f"compare-dest failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        # compare-dest never copies: an exact basis match is skipped, leaving a
        # sparse destination (rsync parity).
        assert not os.path.exists(os.path.join(received, self.UNCHANGED)), \
            "compare-dest materialized the unchanged file"
        # Files the destination lacks AND the basis cannot satisfy are still
        # transferred normally.
        assert _read_file(os.path.join(received, self.CHANGED)) == \
            self._source_tree("c")[self.CHANGED], "changed file not transferred"
        assert _read_file(os.path.join(received, self.ADDED)) == \
            self._source_tree("c")[self.ADDED], "added file not transferred"

    @pytest.mark.ci
    def test_dry_run_compare_dest_does_not_read_basis(self, shared_server):
        # A dry-run --compare-dest must never read/hash the basis file: doing so
        # is a 1-bit content oracle against the client-supplied digest.  Even a
        # byte-identical basis with a matching size+mtime is therefore reported
        # as would-transfer, and nothing is created.
        source = self._make_source("basis_dry_src", {self.UNCHANGED: b"stable content v1\n"})
        dest = os.path.join(TEST_DATA_DIR, "basis_dry_dst")
        clean_dir(dest)
        self._seed_basis(dest, source, "drybasis", {self.UNCHANGED: b"stable content v1\n"})
        before = _snapshot_tree(dest)
        result, _ = run_client(source, dest,
                               flags=["--compare-dest=drybasis", "--dry-run"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"dry-run compare-dest failed: {result.stderr[:300]}"
        assert self.UNCHANGED in result.stdout, (
            "dry-run compare-dest silently skipped: receiver read the basis content"
        )
        assert _snapshot_tree(dest) == before, "dry-run compare-dest mutated the destination"

    def test_compare_dest_content_mismatch_forces_transfer(self, shared_server):
        # The basis holds a file with a DIFFERENT body: even though it shares
        # the mtime pin, the xxHash check fails and the data must be sent.
        source = self._make_source("basis_compare_mismatch_src", {self.UNCHANGED: b"real data\n"})
        dest = os.path.join(TEST_DATA_DIR, "basis_compare_mismatch_dst")
        clean_dir(dest)
        basis = self._seed_basis(dest, source, "cbasis", {self.UNCHANGED: b"stale data!!\n"})
        result, _ = run_client(source, dest, flags=["--compare-dest=cbasis"],
                               port=shared_server.port)
        assert result.returncode == 0, f"compare-dest mismatch failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.UNCHANGED)) == b"real data\n", \
            "content mismatch did not fall back to a normal transfer"
        assert os.stat(os.path.join(received, self.UNCHANGED)).st_ino != \
            os.stat(os.path.join(basis, self.UNCHANGED)).st_ino

    def test_copy_dest_copies_unchanged_and_transfers_changed(self, shared_server):
        source = self._make_source("basis_copy_src", self._source_tree("cp"))
        dest = os.path.join(TEST_DATA_DIR, "basis_copy_dst")
        clean_dir(dest)
        basis = self._seed_basis(dest, source, "cpbasis", self._basis_tree("cp"))
        result, _ = run_client(source, dest, flags=["--copy-dest=cpbasis"],
                               port=shared_server.port)
        assert result.returncode == 0, f"copy-dest failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        unchanged = os.path.join(received, self.UNCHANGED)
        assert _read_file(unchanged) == b"stable content v1\n", "unchanged file not materialized"
        # A real local copy, NOT a hard link to the basis file.
        assert os.stat(unchanged).st_ino != os.stat(os.path.join(basis, self.UNCHANGED)).st_ino
        # Equal-size/different-content basis file falls back to the sender data.
        assert _read_file(os.path.join(received, self.CHANGED)) == \
            self._source_tree("cp")[self.CHANGED]
        assert _read_file(os.path.join(received, self.ADDED)) == \
            self._source_tree("cp")[self.ADDED]

    def test_link_dest_hardlinks_and_falls_back(self, shared_server):
        source = self._make_source("basis_link_src", self._source_tree("ln"))
        dest = os.path.join(TEST_DATA_DIR, "basis_link_dst")
        clean_dir(dest)
        basis = self._seed_basis(dest, source, "lnbasis", self._basis_tree("ln"))
        result, _ = run_client(source, dest, flags=["--link-dest=lnbasis"],
                               port=shared_server.port)
        assert result.returncode == 0, f"link-dest failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        unchanged = os.path.join(received, self.UNCHANGED)
        basis_file = os.path.join(basis, self.UNCHANGED)
        # Real hard link: same inode as the DIR file, nlink >= 2, no data copy.
        assert os.path.exists(unchanged)
        assert os.stat(unchanged).st_ino == os.stat(basis_file).st_ino, \
            "link-dest did not produce a hard link"
        assert os.stat(unchanged).st_nlink >= 2
        # Equal-size/different-content basis file must fall back to a plain
        # transfer (not a link).
        changed = os.path.join(received, self.CHANGED)
        assert _read_file(changed) == self._source_tree("ln")[self.CHANGED]
        assert os.stat(changed).st_ino != os.stat(os.path.join(basis, self.CHANGED)).st_ino

    @pytest.mark.parametrize("flag", ["--compare-dest", "--copy-dest", "--link-dest"])
    def test_basis_dir_missing_is_a_clean_noop(self, shared_server, flag):
        # A basis directory that does not exist must simply transfer everything.
        source = self._make_source("basis_missing_src", {self.UNCHANGED: b"content\n"})
        dest = os.path.join(TEST_DATA_DIR, "basis_missing_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=[f"{flag}=nope"],
                               port=shared_server.port)
        assert result.returncode == 0, f"{flag} with missing dir failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.UNCHANGED)) == b"content\n"

    def test_link_dest_multithreaded(self, shared_server):
        source = self._make_source("basis_link_mt_src", self._source_tree("mt"))
        dest = os.path.join(TEST_DATA_DIR, "basis_link_mt_dst")
        clean_dir(dest)
        basis = self._seed_basis(dest, source, "mtbasis", self._basis_tree("mt"))
        result, _ = run_client(source, dest, flags=["--link-dest=mtbasis", "--threads"],
                               port=shared_server.port)
        assert result.returncode == 0, f"-m link-dest failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.stat(os.path.join(received, self.UNCHANGED)).st_ino == \
            os.stat(os.path.join(basis, self.UNCHANGED)).st_ino
        assert _read_file(os.path.join(received, self.ADDED)) == \
            self._source_tree("mt")[self.ADDED]

    def test_link_dest_with_delay_updates_stages_and_publishes_link(self, shared_server):
        source = self._make_source("basis_link_delay_src", {self.UNCHANGED: b"v1\n"})
        dest = os.path.join(TEST_DATA_DIR, "basis_link_delay_dst")
        clean_dir(dest)
        basis = self._seed_basis(dest, source, "delaybasis", {self.UNCHANGED: b"v1\n"})
        result, _ = run_client(source, dest,
                               flags=["--link-dest=delaybasis", "--delay-updates"],
                               port=shared_server.port)
        assert result.returncode == 0, f"delay-updates link-dest failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        unchanged = os.path.join(received, self.UNCHANGED)
        assert os.stat(unchanged).st_ino == \
            os.stat(os.path.join(basis, self.UNCHANGED)).st_ino
        assert not os.path.isdir(os.path.join(dest, self.STAGING)), \
            "delay-updates staging tree was not cleaned up"

    def test_delete_does_not_touch_basis_dir(self):
        """--delete removes genuine extras but must never treat a basis-dir
        snapshot (which a --link-dest run just linked from) as destination
        content."""
        source = self._make_source("basis_delete_src", {self.UNCHANGED: b"v1\n"})
        dest = os.path.join(TEST_DATA_DIR, "basis_delete_dst")
        clean_dir(dest)
        basis = self._seed_basis(dest, source, "delbasis", {self.UNCHANGED: b"v1\n"})
        received = get_dest_received_dir(dest, source)
        os.makedirs(received, exist_ok=True)
        extra = os.path.join(received, "extra.txt")
        with open(extra, "wb") as fh:
            fh.write(b"extra")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["--link-dest=delbasis", "--delete"],
                                   port=server.port)
            assert result.returncode == 0, \
                f"delete+link-dest failed: {result.stderr[:300]}"
            assert not os.path.exists(extra), "genuine extra file was not deleted"
            assert _read_file(os.path.join(received, self.UNCHANGED)) == b"v1\n"
            assert os.path.exists(os.path.join(basis, self.UNCHANGED)), \
                "basis directory was deleted by --delete"
            assert os.stat(os.path.join(received, self.UNCHANGED)).st_ino == \
                os.stat(os.path.join(basis, self.UNCHANGED)).st_ino

    def test_delay_delete_keeps_nested_staging_named_dir_as_content(self):
        # The real --delay-updates staging directory is protected from --delete
        # only as a DIRECT child of the receive root.  A nested destination
        # directory that merely shares the staging name is ordinary content, so
        # its extras must still be deleted (regression guard for the walker).
        source = self._make_source("basis_nested_stage_src",
                                   {"top.txt": b"top\n", "sub/real.txt": b"real\n"})
        dest = os.path.join(TEST_DATA_DIR, "basis_nested_stage_dst")
        clean_dir(dest)
        self._seed_basis(dest, source, "nstbasis",
                         {"top.txt": b"top\n", "sub/real.txt": b"real\n"})
        received = get_dest_received_dir(dest, source)
        nested = os.path.join(received, "sub", self.STAGING)
        os.makedirs(nested, exist_ok=True)
        extra = os.path.join(nested, "extra.txt")
        with open(extra, "wb") as fh:
            fh.write(b"nested extra")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest,
                                   flags=["--link-dest=nstbasis", "--delete",
                                          "--delay-updates"],
                                   port=server.port)
            assert result.returncode == 0, \
                f"delay-delete nested staging failed: {result.stderr[:300]}"
            assert not os.path.exists(extra), \
                "extra inside a nested .fastsync-stage dir was not deleted"
            assert not os.path.isdir(nested), \
                "nested .fastsync-stage dir should have been removed after its extra"
            assert _read_file(os.path.join(received, "sub", "real.txt")) == b"real\n"
            assert not os.path.isdir(os.path.join(dest, self.STAGING)), \
                "real delay-updates staging tree was not cleaned up"

    def test_basis_priority_first_match_wins(self, shared_server):
        # Two link-dest dirs both hold the exact file: the FIRST (command-line
        # order) basis directory must win and supply the hard link.
        source = self._make_source("basis_prio_src", {"f.txt": b"content\n"})
        dest = os.path.join(TEST_DATA_DIR, "basis_prio_dst")
        clean_dir(dest)
        first = self._seed_basis_file(dest, source, "b1", "f.txt", b"content\n")
        self._seed_basis_file(dest, source, "b2", "f.txt", b"content\n")
        result, _ = run_client(source, dest, flags=["--link-dest=b1", "--link-dest=b2"],
                               port=shared_server.port)
        assert result.returncode == 0, f"link-dest priority failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.stat(os.path.join(received, "f.txt")).st_ino == os.stat(first).st_ino, \
            "first basis dir did not win over the second"

    def test_basis_priority_across_compare_and_link(self, shared_server):
        # A compare-dest entry listed BEFORE a link-dest entry shadows it (the
        # exact match is found first and nothing is materialized); reversing the
        # order lets the link-dest entry win and materialize a hard link.
        source = self._make_source("basis_prio_mixed_src", {"f.txt": b"content\n"})

        dest = os.path.join(TEST_DATA_DIR, "basis_prio_mixed_dst")
        clean_dir(dest)
        self._seed_basis_file(dest, source, "cmpb", "f.txt", b"content\n")
        self._seed_basis_file(dest, source, "lnb", "f.txt", b"content\n")
        result, _ = run_client(source, dest,
                               flags=["--compare-dest=cmpb", "--link-dest=lnb"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"mixed priority (compare first) failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert not os.path.exists(os.path.join(received, "f.txt")), \
            "compare-dest matched first, so the file must stay sparse (no link-dest materialize)"

        dest = os.path.join(TEST_DATA_DIR, "basis_prio_mixed_dst2")
        clean_dir(dest)
        self._seed_basis_file(dest, source, "cmpb", "f.txt", b"content\n")
        linkb2 = self._seed_basis_file(dest, source, "lnb", "f.txt", b"content\n")
        result, _ = run_client(source, dest,
                               flags=["--link-dest=lnb", "--compare-dest=cmpb"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"mixed priority (link first) failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.stat(os.path.join(received, "f.txt")).st_ino == os.stat(linkb2).st_ino, \
            "link-dest did not materialize when listed before compare-dest"

    def test_link_dest_size_only_ignores_mtime(self, shared_server):
        # --size-only drops the mtime leg of the quick check: a basis file with
        # the SAME content but a DIFFERENT mtime is still an exact match.
        source = self._make_source("basis_sizeonly_src", {"f.txt": b"content\n"})
        dest = os.path.join(TEST_DATA_DIR, "basis_sizeonly_dst")
        clean_dir(dest)
        basis_file = self._seed_basis_file(dest, source, "sob", "f.txt", b"content\n",
                                           ts=self.TS + 500)
        result, _ = run_client(source, dest, flags=["--link-dest=sob", "--size-only"],
                               port=shared_server.port)
        assert result.returncode == 0, f"size-only link-dest failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.stat(os.path.join(received, "f.txt")).st_ino == os.stat(basis_file).st_ino, \
            "--size-only should link a basis file whose mtime differs"

    @pytest.mark.ci
    def test_link_dest_ignore_times_never_links(self, shared_server):
        # -I/--ignore-times forces every file to be updated, so a basis dir is
        # never used to hard-link (rsync parity).  The file is transferred and
        # stored as a fresh inode even though it matches the basis exactly.
        source = self._make_source("basis_igntimes_src", {"f.txt": b"content\n"})
        dest = os.path.join(TEST_DATA_DIR, "basis_igntimes_dst")
        clean_dir(dest)
        basis_file = self._seed_basis_file(dest, source, "itb", "f.txt", b"content\n")
        result, _ = run_client(source, dest, flags=["--link-dest=itb", "--ignore-times"],
                               port=shared_server.port)
        assert result.returncode == 0, f"ignore-times link-dest failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        dest_file = os.path.join(received, "f.txt")
        assert _read_file(dest_file) == b"content\n"
        assert os.stat(dest_file).st_ino != os.stat(basis_file).st_ino, \
            "--ignore-times must not hard-link to a basis file"

    def test_basis_refuses_file_above_whole_file_limit(self, shared_server):
        # Every whole-file payload path in FastSync (basis dirs included) is
        # bounded by MAX_RECEIVE_WHOLE_FILE_SIZE.  rsync supports basis dirs for
        # arbitrary sizes; FastSync refuses such a run up front with a clear
        # diagnostic instead of letting the receiver abort the whole transfer
        # mid-stream with no client-side explanation.
        source = self._make_source("basis_oversize_src", {"small.txt": b"ok\n"})
        big = os.path.join(source, "huge.bin")
        with open(big, "wb") as fh:
            os.ftruncate(fh.fileno(), 256 * 1024 * 1024 + 4096)
        dest = os.path.join(TEST_DATA_DIR, "basis_oversize_dst")
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["--link-dest=nope"],
                               port=shared_server.port)
        assert result.returncode != 0, \
            "basis run with an over-limit file unexpectedly succeeded"
        assert "larger than" in result.stderr, \
            f"no clear over-limit diagnostic: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert not os.path.exists(received), \
            "over-limit basis run transferred files before failing"


def _random_payloads(size=2 * 1024 * 1024, changed=64 * 1024, seed=1234):
    """Return (old, new) byte strings of equal length where `new` differs from
    `old` only in one contiguous `changed`-byte region.  Incompressible (random)
    data keeps the whole-file wire cost near the file size, so a delta transfer
    is distinguishable from a whole-file one by its wire bytes."""
    r = random.Random(seed)
    data = bytearray(r.randbytes(size))
    old = bytes(data)
    off = size // 3
    for i in range(off, off + changed):
        data[i] = r.randrange(256)
    return old, bytes(data)


class TestFuzzy:
    """-y/--fuzzy similar-file delta basis.

    Scenario modelled on rsync's --fuzzy: a file is recreated under a similar
    NEW basename in the same directory.  The destination still holds the
    old-named file (nothing deleted it), but the new path has no content of its
    own at the destination, so without --fuzzy the receiver has no delta basis
    and the whole file is sent.  With --fuzzy the receiver searches the
    destination directory, picks the similar-named sibling as the delta basis,
    sends its block signature, and the sender transmits only the differences.
    The reconstructed file must be byte-identical to the source in every mode;
    only the wire usage changes (observed through CountingProxy, because client
    --stats report source lengths, not wire bytes).
    """

    OLD_NAME = "report-2025.dat"
    NEW_NAME = "report-2026.dat"
    TS = 1577836800  # 2020-01-01, used to pin stale destination mtimes
    SIZE = 2 * 1024 * 1024

    def _client_via_proxy(self, source, dest, flags, proxy):
        cmd = (CLIENT_CMD + ["--source-dir", source, "--dest-dir", dest,
                             "--save-to-disk", "--server-port", str(proxy.port)] + flags)
        return proxy.run(cmd)

    def _seed_dest(self, source, dest, files, port):
        """Write `files` {rel: bytes} into source and mirror them to dest."""
        for rel, content in files.items():
            full = os.path.join(source, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(content)
        clean_dir(dest)
        result, _ = run_client(source, dest, port=port)
        assert result.returncode == 0, f"seed failed: {(result.stderr or result.stdout)[:300]}"

    def _prepare(self, tag):
        source = os.path.join(TEST_DATA_DIR, f"fuzzy_{tag}_src")
        dest = os.path.join(TEST_DATA_DIR, f"fuzzy_{tag}_dst")
        clean_dir(source)
        return source, dest

    def _run_measured(self, source, dest, flags, port):
        """Run a transfer through a byte-counting proxy. Returns (result, proxy)."""
        proxy = CountingProxy(port)
        result = self._client_via_proxy(source, dest, flags, proxy)
        return result, proxy

    def test_fuzzy_uses_similar_sibling_as_delta_basis(self, shared_server):
        source, dest = self._prepare("basis")
        old_bytes, new_bytes = _random_payloads()
        self._seed_dest(source, dest, {self.OLD_NAME: old_bytes}, shared_server.port)
        # Recreate the file under a similar new name; the old sibling stays on
        # the destination (nothing deletes it).
        os.unlink(os.path.join(source, self.OLD_NAME))
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(new_bytes)

        result, proxy = self._run_measured(source, dest, ["--fuzzy"], shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy rename transfer failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes, \
            "fuzzy reconstruction is not byte-exact"
        # The wire carried the delta, not the 2 MiB whole file.
        assert proxy.client_to_server < len(new_bytes) // 4, \
            f"fuzzy transfer sent {proxy.client_to_server} bytes; expected a delta"

    def test_without_fuzzy_sends_the_whole_file(self, shared_server):
        source, dest = self._prepare("whole")
        old_bytes, new_bytes = _random_payloads()
        self._seed_dest(source, dest, {self.OLD_NAME: old_bytes}, shared_server.port)
        os.unlink(os.path.join(source, self.OLD_NAME))
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(new_bytes)

        result, proxy = self._run_measured(source, dest, ["--incremental", "--delta"], shared_server.port)
        assert result.returncode == 0, f"no-fuzzy rename failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes
        # No similar basis: the whole file goes over the wire.
        assert proxy.client_to_server > len(new_bytes) // 2, \
            f"expected a whole-file transfer, got {proxy.client_to_server} bytes"

    @pytest.mark.parametrize("mt", [False, True])
    def test_fuzzy_byte_exact_single_and_multithreaded(self, shared_server, mt):
        source, dest = self._prepare(f"mt{'1' if mt else '0'}")
        old_bytes, new_bytes = _random_payloads()
        self._seed_dest(source, dest, {self.OLD_NAME: old_bytes}, shared_server.port)
        os.unlink(os.path.join(source, self.OLD_NAME))
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(new_bytes)

        flags = ["--fuzzy"] + (["--threads"] if mt else [])
        result, proxy = self._run_measured(source, dest, flags, shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy {'-m ' if mt else ''}rename failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes, \
            f"fuzzy {'-m ' if mt else ''}reconstruction is not byte-exact"
        assert proxy.client_to_server < len(new_bytes) // 4

    def test_no_candidate_falls_back_to_whole_file(self, shared_server):
        # A brand-new destination directory holds no sibling at all, so --fuzzy
        # finds nothing and the file is transferred whole (and correctly).
        source, dest = self._prepare("nocand")
        clean_dir(dest)
        os.makedirs(source, exist_ok=True)
        _, new_bytes = _random_payloads()
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(new_bytes)
        result, proxy = self._run_measured(source, dest, ["--fuzzy"], shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy no-candidate fallback failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes
        assert proxy.client_to_server > len(new_bytes) // 2, \
            "no-candidate fuzzy run should have sent the whole file"

    def test_dissimilar_sibling_is_not_used(self, shared_server):
        # The destination holds a large sibling whose basename is too different
        # from the incoming name; the name gate must reject it and fall back to
        # a whole-file transfer.
        source, dest = self._prepare("dissim")
        old_bytes, new_bytes = _random_payloads()
        self._seed_dest(source, dest, {"totally-unrelated-notes.bin": old_bytes},
                           shared_server.port)
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(new_bytes)
        result, proxy = self._run_measured(source, dest, ["--fuzzy"], shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy dissimilar-sibling run failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes
        assert proxy.client_to_server > len(new_bytes) // 2, \
            "a dissimilar-named sibling must not be used as a fuzzy basis"

    def test_fuzzy_helps_when_dest_holds_an_unsuitable_file(self, shared_server):
        # The destination DOES hold the exact new name, but it is a tiny stale
        # file (below the delta engine's minimum, ratio far outside its window),
        # so it cannot serve as the basis.  --fuzzy then falls back to the
        # similar-named sibling.
        source, dest = self._prepare("unsuitable")
        old_bytes, new_bytes = _random_payloads()
        self._seed_dest(source, dest,
                        {self.OLD_NAME: old_bytes, self.NEW_NAME: b"stale small file\n"},
                        shared_server.port)
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(new_bytes)
        result, proxy = self._run_measured(source, dest, ["--fuzzy"], shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy unsuitable-dest run failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes, \
            "byte-exactness broken when the destination file was unsuitable"
        assert proxy.client_to_server < len(new_bytes) // 4, \
            "fuzzy should have reused the similar sibling as the basis"

    def test_whole_file_makes_fuzzy_inert(self, shared_server):
        # -W/--whole-file switches the delta machinery off, so --fuzzy has
        # nothing to attach to and the file is transferred whole (rsync parity).
        source, dest = self._prepare("wholefile")
        old_bytes, new_bytes = _random_payloads()
        self._seed_dest(source, dest, {self.OLD_NAME: old_bytes}, shared_server.port)
        os.unlink(os.path.join(source, self.OLD_NAME))
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(new_bytes)
        result, proxy = self._run_measured(source, dest, ["--fuzzy", "-W"], shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy -W run failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes
        assert proxy.client_to_server > len(new_bytes) // 2, \
            "--whole-file must disable the fuzzy delta basis"

    def test_fuzzy_via_short_y_alias(self, shared_server):
        source, dest = self._prepare("shorty")
        old_bytes, new_bytes = _random_payloads()
        self._seed_dest(source, dest, {self.OLD_NAME: old_bytes}, shared_server.port)
        os.unlink(os.path.join(source, self.OLD_NAME))
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(new_bytes)
        result, proxy = self._run_measured(source, dest, ["-y"], shared_server.port)
        assert result.returncode == 0, f"-y rename failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes
        assert proxy.client_to_server < len(new_bytes) // 4, "-y did not enable fuzzy"

    def test_fuzzy_with_delay_updates_publishes_cleanly(self, shared_server):
        # A fuzzy-reconstructed file goes through the normal store engine, so
        # --delay-updates must stage and publish it with no staging leftovers.
        source, dest = self._prepare("delay")
        old_bytes, new_bytes = _random_payloads()
        self._seed_dest(source, dest, {self.OLD_NAME: old_bytes}, shared_server.port)
        os.unlink(os.path.join(source, self.OLD_NAME))
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(new_bytes)
        result, _ = run_client(source, dest,
                               flags=["--fuzzy", "--delay-updates"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy --delay-updates failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes
        assert not os.path.isdir(os.path.join(dest, ".fastsync-stage")), \
            "delay-updates staging tree was not cleaned up"

    def test_fuzzy_source_removed_after_transfer(self, shared_server):
        # A fuzzy transfer is a real transfer (not a skip), so
        # --remove-source-files must remove the renamed source file.
        source, dest = self._prepare("rm")
        old_bytes, new_bytes = _random_payloads()
        self._seed_dest(source, dest, {self.OLD_NAME: old_bytes}, shared_server.port)
        os.unlink(os.path.join(source, self.OLD_NAME))
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(new_bytes)
        result, _ = run_client(source, dest,
                               flags=["--fuzzy", "--remove-source-files"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy --remove-source-files failed: {(result.stderr or result.stdout)[:300]}"
        assert not os.path.exists(os.path.join(source, self.NEW_NAME)), \
            "a fuzzy-transferred source should have been removed"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes
        assert _read_file(os.path.join(received, self.OLD_NAME)) == old_bytes

    @staticmethod
    def _rand_bytes(size, seed):
        return random.Random(seed).randbytes(size)

    def _replace_source_file(self, source, old_name, new_name, new_bytes):
        """Remove old_name from source and add new_name with new_bytes."""
        os.unlink(os.path.join(source, old_name))
        with open(os.path.join(source, new_name), "wb") as fh:
            fh.write(new_bytes)

    def test_worthless_fuzzy_basis_falls_back_inside_handshake(self, shared_server):
        # The sibling passes the name AND size gates but shares no blocks with
        # the incoming file, so the sender's delta is not worthwhile: it replies
        # STATUS_NEXT and the receiver consumes the WHOLE file inside the delta
        # handshake.  This proves a bad fuzzy basis cannot desync the protocol
        # or corrupt the result.
        source, dest = self._prepare("worthless")
        basis = self._rand_bytes(self.SIZE, 424242)
        target = self._rand_bytes(self.SIZE, 777777)
        self._seed_dest(source, dest, {self.OLD_NAME: basis}, shared_server.port)
        self._replace_source_file(source, self.OLD_NAME, self.NEW_NAME, target)
        result, proxy = self._run_measured(source, dest, ["--fuzzy"], shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy worthless-basis run failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == target, \
            "whole-file fallback after a worthless fuzzy basis is not byte-exact"
        assert proxy.client_to_server > self.SIZE // 2, \
            "a worthless basis should have made the sender fall back to the whole file"

    def test_existing_dest_file_preferred_over_fuzzy_sibling(self, shared_server):
        # Non-displacement: the destination holds a file at the exact path that
        # is inside the delta size bounds (same size, different content, older
        # mtime).  FastSync must delta against THAT file -- even though it
        # shares nothing with the source -- and must NOT reuse a similar-named
        # sibling that is byte-identical to the source.
        source, dest = self._prepare("nondisp")
        sibling = self._rand_bytes(self.SIZE, 111)   # will equal the incoming file
        stale = self._rand_bytes(self.SIZE, 333)     # worthless exact-path file
        self._seed_dest(source, dest,
                        {self.OLD_NAME: sibling, self.NEW_NAME: stale},
                        shared_server.port)
        # Force the exact-path destination file's mtime into the past so the
        # quick check deterministically decides to transfer it.
        os.utime(os.path.join(get_dest_received_dir(dest, source), self.NEW_NAME),
                 (self.TS, self.TS))
        os.unlink(os.path.join(source, self.OLD_NAME))
        with open(os.path.join(source, self.NEW_NAME), "wb") as fh:
            fh.write(sibling)
        result, proxy = self._run_measured(source, dest, ["--fuzzy"], shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy non-displacement run failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == sibling
        assert proxy.client_to_server > self.SIZE // 2, \
            "the exact-path destination file must be the delta basis, not the fuzzy sibling"

    def test_fuzzy_basis_larger_than_source(self, shared_server):
        # The similar sibling is LARGER than the incoming file (within the delta
        # engine's 10x ratio); the new file is an exact prefix of the basis, so
        # every block matches and only a tiny delta travels.
        source, dest = self._prepare("largerbasis")
        big = self._rand_bytes(1536 * 1024, 1)
        prefix = big[:1024 * 1024]
        self._seed_dest(source, dest, {self.OLD_NAME: big}, shared_server.port)
        self._replace_source_file(source, self.OLD_NAME, self.NEW_NAME, prefix)
        result, proxy = self._run_measured(source, dest, ["--fuzzy"], shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy larger-basis run failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == prefix, \
            "shrunken file reconstructed from a larger fuzzy basis is not byte-exact"
        assert proxy.client_to_server < len(prefix) // 4, \
            "larger fuzzy basis should have carried most of the file as block matches"

    def test_fuzzy_basis_smaller_than_source(self, shared_server):
        # The similar sibling is SMALLER than the incoming file; the new file
        # appends data past the basis, so the appended tail travels as literals
        # while the shared prefix is block-matched.
        source, dest = self._prepare("smallerbasis")
        base = self._rand_bytes(self.SIZE, 2)
        tail = self._rand_bytes(64 * 1024, 3)
        new_bytes = base + tail
        self._seed_dest(source, dest, {self.OLD_NAME: base}, shared_server.port)
        self._replace_source_file(source, self.OLD_NAME, self.NEW_NAME, new_bytes)
        result, proxy = self._run_measured(source, dest, ["--fuzzy"], shared_server.port)
        assert result.returncode == 0, \
            f"--fuzzy smaller-basis run failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes, \
            "grown file reconstructed from a smaller fuzzy basis is not byte-exact"
        assert proxy.client_to_server < len(new_bytes) // 4, \
            "smaller fuzzy basis should have block-matched the shared prefix"

    def test_no_fuzzy_end_to_end_equals_no_flag(self, shared_server):
        # --no-fuzzy must not enable anything: a run with it behaves exactly
        # like a run without it (whole-file transfer, byte-exact output).
        source, dest = self._prepare("nofuzzye2e")
        old_bytes, new_bytes = _random_payloads()
        self._seed_dest(source, dest, {self.OLD_NAME: old_bytes}, shared_server.port)
        self._replace_source_file(source, self.OLD_NAME, self.NEW_NAME, new_bytes)
        result, proxy = self._run_measured(source, dest, ["--no-fuzzy"], shared_server.port)
        assert result.returncode == 0, \
            f"--no-fuzzy run failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert _read_file(os.path.join(received, self.NEW_NAME)) == new_bytes
        assert proxy.client_to_server > len(new_bytes) // 2, \
            "--no-fuzzy should leave the default whole-file behavior intact"



class TestIdentityMapping:
    """Ownership-application flags (--numeric-ids / --usermap / --groupmap /
    --chown).  In CI the receiver usually runs unprivileged, so ownership apply
    is expected to fail from lack of privilege: the transfer must STILL succeed
    and exit 0 (the receiver warns and continues, rsync parity).  The only
    assertion that requires the ownership to actually change is gated on
    os.geteuid() == 0 so it is skipped (not failed) as a non-root user."""

    def test_numeric_ids_transfer_succeeds_unprivileged(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "identity_num_source")
        dest = os.path.join(TEST_DATA_DIR, "identity_num_dest")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "f.txt"), "wb") as f:
            f.write(b"hello identity")
        result, _ = run_client(source, dest,
                               flags=["--preserve", "--numeric-ids"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"exit {result.returncode}: {(result.stderr or '')[:200]}"
        received = get_dest_received_dir(dest, source)
        with open(os.path.join(received, "f.txt"), "rb") as f:
            assert f.read() == b"hello identity"

    def test_usermap_and_groupmap_and_chown_succeed_unprivileged(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "identity_map_source")
        dest = os.path.join(TEST_DATA_DIR, "identity_map_dest")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "f.txt"), "wb") as f:
            f.write(b"mapped")
        result, _ = run_client(
            source, dest,
            flags=["--preserve", "--usermap=@1000:@1001", "--groupmap=@100:@101", "--chown=@2000:@2001"],
            port=shared_server.port)
        assert result.returncode == 0, \
            f"exit {result.returncode}: {(result.stderr or '')[:200]}"
        received = get_dest_received_dir(dest, source)
        with open(os.path.join(received, "f.txt"), "rb") as f:
            assert f.read() == b"mapped"

    @pytest.mark.skipif(os.geteuid() != 0, reason="only root can change ownership")
    def test_numeric_ids_applies_ownership_as_root(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "identity_root_source")
        dest = os.path.join(TEST_DATA_DIR, "identity_root_dest")
        clean_dir(source)
        clean_dir(dest)
        src_file = os.path.join(source, "f.txt")
        with open(src_file, "wb") as f:
            f.write(b"owner")
        os.chown(src_file, 12345, 12346)
        result, _ = run_client(source, dest,
                               flags=["--preserve", "--numeric-ids"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"exit {result.returncode}: {(result.stderr or '')[:200]}"
        received = get_dest_received_dir(dest, source)
        dst_file = os.path.join(received, "f.txt")
        assert os.path.exists(dst_file)
        st = os.stat(dst_file)
        assert st.st_uid == 12345 and st.st_gid == 12346, \
            f"owner not applied: uid={st.st_uid} gid={st.st_gid}"

    @pytest.mark.skipif(os.geteuid() != 0, reason="only root can change ownership")
    def test_chown_overrides_ownership_as_root(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "identity_chown_root_source")
        dest = os.path.join(TEST_DATA_DIR, "identity_chown_root_dest")
        clean_dir(source)
        clean_dir(dest)
        src_file = os.path.join(source, "f.txt")
        with open(src_file, "wb") as f:
            f.write(b"root chown")
        os.chown(src_file, 1, 1)
        result, _ = run_client(source, dest,
                               flags=["--preserve", "--chown=@12345:@54321"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"exit {result.returncode}: {(result.stderr or '')[:200]}"
        received = get_dest_received_dir(dest, source)
        dst_file = os.path.join(received, "f.txt")
        assert os.path.exists(dst_file)
        st = os.stat(dst_file)
        assert st.st_uid == 12345 and st.st_gid == 54321, \
            f"--chown not applied: uid={st.st_uid} gid={st.st_gid}"


class TestSuperPrivilege:
    """P7 Wave E: --super / --no-super control the receiver's already-confined
    super-user activities (ownership application, char/block device nodes).
    FastSync never elevates, so on an unprivileged receiver --super only
    permits a confined attempt (which then skips); --no-super forbids the
    activity even for root."""

    def _seed(self, tag):
        source = os.path.join(TEST_DATA_DIR, f"super_{tag}_source")
        dest = os.path.join(TEST_DATA_DIR, f"super_{tag}_dest")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "f.txt"), "wb") as f:
            f.write(b"super privilege\n")
        return source, dest

    def test_super_and_no_super_transfer_successfully(self, shared_server):
        """Both flags parse and the transfer completes normally regardless of
        the receiver's privilege level."""
        for flag in ("--super", "--no-super"):
            source, dest = self._seed(flag.strip("-"))
            result, _ = run_client(source, dest, flags=[flag], port=shared_server.port)
            assert result.returncode == 0, \
                f"{flag} exit {result.returncode}: {(result.stderr or '')[:300]}"
            received = get_dest_received_dir(dest, source)
            with open(os.path.join(received, "f.txt"), "rb") as f:
                assert f.read() == b"super privilege\n"

    @pytest.mark.skipif(os.geteuid() != 0, reason="only root can change ownership")
    def test_no_super_suppresses_ownership_as_root(self, shared_server):
        """As root the default gate would apply a raw numeric id; --no-super
        must suppress that ownership application entirely."""
        source, dest = self._seed("nosuper")
        os.chown(os.path.join(source, "f.txt"), 12345, 12346)
        result, _ = run_client(source, dest,
                               flags=["--preserve", "--numeric-ids", "--no-super"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"exit {result.returncode}: {(result.stderr or '')[:300]}"
        received = get_dest_received_dir(dest, source)
        st = os.stat(os.path.join(received, "f.txt"))
        assert (st.st_uid, st.st_gid) != (12345, 12346), \
            f"--no-super must not apply ownership (uid={st.st_uid} gid={st.st_gid})"

    @pytest.mark.skipif(os.geteuid() != 0, reason="only root can change ownership")
    def test_super_alone_does_not_apply_ownership_as_root(self, shared_server):
        """A3: --super no longer implies --numeric-ids, so --super alone must NOT
        apply client-chosen ownership even for root; the destination keeps the
        receiver's owner (the exact ownership --no-super would also suppress)."""
        source, dest = self._seed("superonly")
        os.chown(os.path.join(source, "f.txt"), 12345, 12346)
        result, _ = run_client(source, dest,
                               flags=["--preserve", "--super"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"exit {result.returncode}: {(result.stderr or '')[:300]}"
        received = get_dest_received_dir(dest, source)
        st = os.stat(os.path.join(received, "f.txt"))
        assert (st.st_uid, st.st_gid) != (12345, 12346), \
            f"--super alone must not apply ownership (uid={st.st_uid} gid={st.st_gid})"

    @pytest.mark.skipif(os.geteuid() != 0, reason="only root can change ownership")
    def test_super_with_numeric_ids_applies_ownership_as_root(self, shared_server):
        """Control: an explicit identity policy is what enables ownership, so
        --numeric-ids --super still applies the raw ids as root (the very
        ownership --no-super suppresses)."""
        source, dest = self._seed("supernumeric")
        os.chown(os.path.join(source, "f.txt"), 12345, 12346)
        result, _ = run_client(source, dest,
                               flags=["--preserve", "--numeric-ids", "--super"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"exit {result.returncode}: {(result.stderr or '')[:300]}"
        received = get_dest_received_dir(dest, source)
        st = os.stat(os.path.join(received, "f.txt"))
        assert (st.st_uid, st.st_gid) == (12345, 12346), \
            f"--numeric-ids --super should apply raw ids: uid={st.st_uid} gid={st.st_gid}"

    @pytest.mark.ci
    @pytest.mark.skipif(os.geteuid() != 0, reason="only root can change ownership")
    def test_fake_super_no_super_does_not_change_owner(self, shared_server):
        """--fake-super records the source owner, but --no-super must suppress the
        live chown even for root: the destination keeps the receiver's owner
        instead of the recorded source owner."""
        source, dest = self._seed("fakesuper_nosuper")
        os.chown(os.path.join(source, "f.txt"), 12345, 12346)
        result, _ = run_client(source, dest,
                               flags=["--fake-super", "--preserve", "--no-super"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"exit {result.returncode}: {(result.stderr or '')[:300]}"
        received = get_dest_received_dir(dest, source)
        st = os.lstat(os.path.join(received, "f.txt"))
        assert (st.st_uid, st.st_gid) != (12345, 12346), \
            f"--no-super must suppress fake-super's owner replay: uid={st.st_uid} gid={st.st_gid}"


class TestStandaloneSuperDefault:
    """C3: a privileged (root) STANDALONE server without --allow-super forces
    SUPER_MODE_OFF, so a client cannot make it create device nodes, write raw
    devices, apply ownership, or use --copy-as.  The shared_server fixture opts in
    with --allow-super to keep the historical behavior available to the existing
    root-only tests; these tests start their own un-opted server."""

    @pytest.mark.ci
    def test_copy_as_refused_without_allow_super(self):
        """--copy-as is a client-chosen-ownership request and must be refused by
        a standalone server that did not opt in with --allow-super (on a non-root
        receiver it is refused for lack of privilege either way)."""
        source = os.path.join(TEST_DATA_DIR, "super_default_src")
        dest = os.path.join(TEST_DATA_DIR, "super_default_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "f.txt"), "wb") as f:
            f.write(b"no copy-as\n")
        server = ServerManager()
        server.start()  # deliberately no --allow-super
        try:
            result, _ = run_client(source, dest,
                                   flags=["--preserve", "--copy-as=@65534:@65534"],
                                   port=server.port)
        finally:
            server.stop()
        assert result.returncode != 0, (
            "standalone server accepted --copy-as without --allow-super"
        )

    @pytest.mark.skipif(os.geteuid() != 0, reason="root can create the source device node")
    def test_devices_skipped_without_allow_super(self):
        """Root standalone server without --allow-super must skip device-node
        creation even for a client --devices request (the run still succeeds and
        the regular file transfers)."""
        source = os.path.join(TEST_DATA_DIR, "super_default_dev_src")
        dest = os.path.join(TEST_DATA_DIR, "super_default_dev_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "plain.txt"), "wb") as f:
            f.write(b"regular\n")
        os.mknod(os.path.join(source, "null"), stat.S_IFCHR | 0o666, os.makedev(1, 3))
        server = ServerManager()
        server.start()  # deliberately no --allow-super
        try:
            result, _ = run_client(source, dest, flags=["--devices"], port=server.port)
        finally:
            server.stop()
        assert result.returncode == 0, f"exit {result.returncode}: {(result.stderr or '')[:200]}"
        received = get_dest_received_dir(dest, source)
        assert not os.path.lexists(os.path.join(received, "null")), (
            "root standalone server created a device node without --allow-super"
        )


class TestHardLinks:
    """-H/--hard-links: source files sharing an inode are re-created as hard
    links to one another on the destination (dedup preserved, first copy
    transferred once, the rest linked/copied). No root required."""

    STAGING = ".fastsync-stage"

    def _make_source(self, name):
        src = os.path.join(TEST_DATA_DIR, name)
        clean_dir(src)
        with open(os.path.join(src, "a.txt"), "wb") as fh:
            fh.write(b"shared content\n" * 2000)
        os.link(os.path.join(src, "a.txt"), os.path.join(src, "b.txt"))
        with open(os.path.join(src, "c.txt"), "wb") as fh:
            fh.write(b"independent content\n" * 2000)
        return src

    @pytest.mark.parametrize("flags", [[], ["--threads"], ["--delay-updates"]])
    def test_hard_links_preserved(self, shared_server, flags):
        src = self._make_source("hl_src")
        dest = os.path.join(TEST_DATA_DIR, "hl_dst")
        clean_dir(dest)
        result, _ = run_client(src, dest, flags=["-H"] + flags, port=shared_server.port)
        assert result.returncode == 0, f"Exit {result.returncode}: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, src)
        a = os.path.join(received, "a.txt")
        b = os.path.join(received, "b.txt")
        c = os.path.join(received, "c.txt")
        assert os.path.isfile(a) and os.path.isfile(b) and os.path.isfile(c), \
            "all three destination files exist"
        with open(a, "rb") as fa, open(b, "rb") as fb:
            assert fa.read() == fb.read(), "hard-linked pair content matches"
        assert os.stat(a).st_ino == os.stat(b).st_ino, \
            "source hard links were not preserved on the destination"
        assert os.stat(a).st_ino != os.stat(c).st_ino, \
            "independent files were incorrectly hard linked"
        with open(a, "rb") as fa, open(c, "rb") as fc:
            assert fa.read() != fc.read(), "independent files must differ in content"
        assert not os.path.isdir(os.path.join(dest, self.STAGING)), \
            "--delay-updates left a staging tree behind"

    def test_hard_links_rejects_chunk_serialization(self, shared_server):
        src = self._make_source("hl_reject_src")
        dest = os.path.join(TEST_DATA_DIR, "hl_reject_dst")
        clean_dir(dest)
        result, _ = run_client(src, dest, flags=["-H", "--chunk-serialization"], port=shared_server.port)
        assert result.returncode != 0, "-H with -s was accepted"

    def test_hard_links_rejects_append(self, shared_server):
        src = self._make_source("hl_reject_app_src")
        dest = os.path.join(TEST_DATA_DIR, "hl_reject_app_dst")
        clean_dir(dest)
        result, _ = run_client(src, dest, flags=["-H", "--append"], port=shared_server.port)
        assert result.returncode != 0, "-H with --append was accepted"

    def test_hard_links_link_to_existing_first_member(self, shared_server):
        """A sibling whose first member is already up-to-date at the destination
        must still be created as a hard link to that existing file."""
        src = os.path.join(TEST_DATA_DIR, "hl_exist_src")
        dest = os.path.join(TEST_DATA_DIR, "hl_exist_dst")
        clean_dir(src)
        clean_dir(dest)
        with open(os.path.join(src, "a.txt"), "wb") as fh:
            fh.write(b"seed content\n" * 1500)
        result, _ = run_client(src, dest, port=shared_server.port)
        assert result.returncode == 0, f"seed failed: {result.stderr[:200]}"
        # Introduce a hard-link sibling to the already-transferred first member.
        os.link(os.path.join(src, "a.txt"), os.path.join(src, "b.txt"))
        result, _ = run_client(src, dest, flags=["-H"], port=shared_server.port)
        assert result.returncode == 0, f"-H sync failed: {result.stderr[:300]}"
        received = get_dest_received_dir(dest, src)
        a = os.path.join(received, "a.txt")
        b = os.path.join(received, "b.txt")
        assert os.path.isfile(a) and os.path.isfile(b)
        assert os.stat(a).st_ino == os.stat(b).st_ino, \
            "new sibling was not linked to the existing first member"
        with open(a, "rb") as fa, open(b, "rb") as fb:
            assert fa.read() == fb.read()

    def test_hard_links_existing_asymmetric_group(self, shared_server):
        """-H --existing with an asymmetric link group must succeed: when the
        first member's destination is absent (so it is skipped by --existing)
        but a sibling's destination already exists, the existing sibling is left
        in place instead of the whole transfer aborting on the absent first
        member."""
        src = os.path.join(TEST_DATA_DIR, "hl_existing_src")
        dest = os.path.join(TEST_DATA_DIR, "hl_existing_dst")
        clean_dir(src)
        clean_dir(dest)
        with open(os.path.join(src, "a.txt"), "wb") as fh:
            fh.write(b"asymmetric group content\n" * 1200)
        # b.txt is a hard-link sibling of a.txt on the source.
        os.link(os.path.join(src, "a.txt"), os.path.join(src, "b.txt"))
        with open(os.path.join(src, "c.txt"), "wb") as fh:
            fh.write(b"independent\n" * 1200)
        # Pre-seed the destination with ONLY the sibling's file (the first
        # member has no destination entry).
        received = get_dest_received_dir(dest, src)
        os.makedirs(received, exist_ok=True)
        with open(os.path.join(received, "b.txt"), "wb") as fh:
            fh.write(b"asymmetric group content\n" * 1200)
        result, _ = run_client(src, dest, flags=["-H", "--existing"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"-H --existing asymmetric group failed: {result.stderr[:300]}"
        # The existing sibling was preserved and its content is intact.
        with open(os.path.join(received, "b.txt"), "rb") as fh:
            assert fh.read() == b"asymmetric group content\n" * 1200
        # Under --existing the absent first member is not created.
        assert not os.path.exists(os.path.join(received, "a.txt"))

class TestAtimes:
    """-U/--atimes preserves the source access time on the destination.

    The sender captures atime during the scan (a stat, before any read for
    transfer), so the value is not clobbered by reading the source.  This is
    verified by setting the source atime to a distinct value far in the past
    and comparing the destination atime to it (with whole-second tolerance;
    filesystems may round atime)."""

    PAYLOAD = b"atime preservation payload\n"

    @staticmethod
    def _make_source(source, dest):
        clean_dir(source)
        clean_dir(dest)
        path = os.path.join(source, "data.txt")
        with open(path, "wb") as f:
            f.write(TestAtimes.PAYLOAD)
        atime = 946684800  # 2000-01-01 00:00:00 UTC (far from "now")
        mtime = 951782400
        os.utime(path, ns=(atime * 10**9 + 123456789, mtime * 10**9))
        return path, atime

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_atimes_preserved(self, shared_server, mt):
        source = os.path.join(TEST_DATA_DIR, f"atime_{'m' if mt else 's'}_src")
        dest = os.path.join(TEST_DATA_DIR, f"atime_{'m' if mt else 's'}_dst")
        src_file, atime = self._make_source(source, dest)
        flags = ["-U"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"-U failed: {(result.stderr or result.stdout)[:300]}"

        received = get_dest_received_dir(dest, source)
        dst_file = os.path.join(received, "data.txt")
        assert os.path.exists(dst_file)
        dst_st = os.stat(dst_file)
        assert abs(dst_st.st_atime - atime) < 1.5, \
            f"dest atime {dst_st.st_atime} != source atime {atime}"

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_without_atimes_dest_differs(self, shared_server, mt):
        """Control: without -U the destination atime is not the source's old
        value (it reflects the fresh write, i.e. now), proving -U is what
        restores the source atime."""
        source = os.path.join(TEST_DATA_DIR, f"atime_ctrl_{'m' if mt else 's'}_src")
        dest = os.path.join(TEST_DATA_DIR, f"atime_ctrl_{'m' if mt else 's'}_dst")
        src_file, atime = self._make_source(source, dest)
        now = time.time()
        flags = (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, f"control run failed: {(result.stderr or '')[:200]}"
        received = get_dest_received_dir(dest, source)
        dst_st = os.stat(os.path.join(received, "data.txt"))
        # The fresh destination atime is ~now, not the source's year-2000 value.
        assert abs(dst_st.st_atime - atime) > 24 * 3600, \
            f"control dest atime {dst_st.st_atime} unexpectedly equals source atime {atime}"
        assert abs(dst_st.st_atime - now) < 24 * 3600, \
            f"control dest atime {dst_st.st_atime} not ~now ({now})"


class TestOpenNoatime:
    """--open-noatime opens the source with O_NOATIME so a transfer read does
    not bump the source's access time.  O_NOATIME is honoured for a file owned
    by the reading process (or with CAP_FOWNER), so it works as non-root here;
    where it is unavailable/refused FastSync degrades to a normal open and the
    assertion below is skipped."""

    @pytest.mark.skipif(not sys.platform.startswith("linux"),
                        reason="O_NOATIME is Linux-specific")
    @pytest.mark.parametrize("mt", [False, True])
    def test_open_noatime_preserves_source_atime(self, shared_server, mt):
        source = os.path.join(TEST_DATA_DIR, f"noatime_{'m' if mt else 's'}_src")
        dest = os.path.join(TEST_DATA_DIR, f"noatime_{'m' if mt else 's'}_dst")
        clean_dir(source)
        clean_dir(dest)
        path = os.path.join(source, "data.txt")
        with open(path, "wb") as f:
            f.write(b"open-noatime payload\n")
        atime = 730486800  # 1993-02-11, distinct and far from now
        os.utime(path, ns=(atime * 10**9, atime * 10**9))

        flags = ["--open-noatime"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"--open-noatime failed: {(result.stderr or result.stdout)[:300]}"

        after = os.stat(path)
        assert abs(after.st_atime - atime) < 1.5, \
            f"source atime {after.st_atime} was bumped by the readable read (wanted {atime})"


class TestCrtimes:
    """-N/--crtimes captures and transmits the source birth time.  There is no
    portable way to SET a birth time (utimensat only sets atime/mtime), so the
    receiver deliberately does not apply it.  The run must succeed without
    crashing; we do not assert the destination birth time changed.  When the
    platform exposes a birth time (statx STATX_BTIME on Linux) we additionally
    confirm a capture path exists."""

    @pytest.mark.parametrize("mt", [False, True])
    def test_crtimes_run_succeeds(self, shared_server, mt):
        source = os.path.join(TEST_DATA_DIR, f"crtime_{'m' if mt else 's'}_src")
        dest = os.path.join(TEST_DATA_DIR, f"crtime_{'m' if mt else 's'}_dst")
        clean_dir(source)
        clean_dir(dest)
        path = os.path.join(source, "data.txt")
        payload = b"crtime transfer payload\n"
        with open(path, "wb") as f:
            f.write(payload)

        flags = ["-N"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"-N failed: {(result.stderr or result.stdout)[:300]}"

        received = get_dest_received_dir(dest, source)
        dst_file = os.path.join(received, "data.txt")
        assert os.path.exists(dst_file)
        with open(dst_file, "rb") as f:
            assert f.read() == payload

    def test_crtimes_combines_with_atimes(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "crtime_atime_combined_src")
        dest = os.path.join(TEST_DATA_DIR, "crtime_atime_combined_dst")
        clean_dir(source)
        clean_dir(dest)
        path = os.path.join(source, "data.txt")
        with open(path, "wb") as f:
            f.write(b"combined U N payload\n")
        atime = 946684800
        os.utime(path, ns=(atime * 10**9, 951782400 * 10**9))
        result, _ = run_client(source, dest, flags=["-U", "-N"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"-U -N failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        dst_st = os.stat(os.path.join(received, "data.txt"))
        assert abs(dst_st.st_atime - atime) < 1.5, \
            f"combined -U -N dest atime {dst_st.st_atime} != {atime}"


class TestSparse:
    """-S/--sparse: the receiver preserves holes by skipping long zero runs with
    lseek (no wire change; the full image is in memory).  The destination file
    must round-trip its logical size and content byte-for-byte; on filesystems
    that report holes (SEEK_HOLE/SEEK_DATA) we additionally assert the file is
    genuinely sparse via st_blocks, but that check is tolerant (CI filesystems
    may report no holes)."""

    def _make_sparse_source(self, name, total, zero_start, zero_len):
        source = os.path.join(TEST_DATA_DIR, name)
        clean_dir(source)
        sfile = os.path.join(source, "blob.bin")
        with open(sfile, "wb") as f:
            head = os.urandom(zero_start)
            tail = os.urandom(total - zero_start - zero_len)
            f.write(head)
            f.write(b"\x00" * zero_len)
            f.write(tail)
            assert f.tell() == total
        return source, sfile

    @pytest.mark.parametrize("flag", ["-S", "--sparse"])
    @pytest.mark.parametrize("mt", [False, True])
    def test_sparse_transfer_round_trips(self, shared_server, flag, mt):
        total = 4 * 1024 * 1024
        source = os.path.join(TEST_DATA_DIR, f"sparse_mt{mt}_{flag.lstrip('-')}_src")
        dest = os.path.join(TEST_DATA_DIR, f"sparse_mt{mt}_{flag.lstrip('-')}_dst")
        clean_dir(source)
        clean_dir(dest)
        zero_start = 1 * 1024 * 1024
        zero_len = 2 * 1024 * 1024
        _, sfile = self._make_sparse_source(os.path.basename(source), total, zero_start, zero_len)
        with open(sfile, "rb") as f:
            src_bytes = f.read()

        flags = [flag] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"{flag} transfer failed: {(result.stderr or result.stdout)[:300]}"

        received = get_dest_received_dir(dest, source)
        dfile = os.path.join(received, "blob.bin")
        assert os.path.getsize(dfile) == total, "logical size must match data_size"
        with open(dfile, "rb") as f:
            assert f.read() == src_bytes, "sparse destination content must round-trip exactly"

        # Tolerant sparseness assert: if the filesystem reports holes, the file
        # must actually be sparse (fewer allocated blocks than its size).
        with open(dfile, "rb") as f:
            off = os.lseek(f.fileno(), zero_start, os.SEEK_DATA)
            if off >= 0:
                hole = os.lseek(f.fileno(), off, os.SEEK_HOLE)
            else:
                hole = -1
        if hole > zero_start:
            st = os.stat(dfile)
            assert st.st_blocks * 512 < total, \
                f"-S file not sparse: {st.st_blocks} blocks for {total} bytes"

    def test_sparse_inplace(self, shared_server):
        """--sparse must also preserve holes in the --inplace write path."""
        total = 2 * 1024 * 1024
        source = os.path.join(TEST_DATA_DIR, "sparse_inplace_src")
        dest = os.path.join(TEST_DATA_DIR, "sparse_inplace_dst")
        clean_dir(source)
        clean_dir(dest)
        _, sfile = self._make_sparse_source(os.path.basename(source), total, total // 2,
                                            total // 4)
        with open(sfile, "rb") as f:
            src_bytes = f.read()
        result, _ = run_client(source, dest, flags=["-S", "--inplace"], port=shared_server.port)
        assert result.returncode == 0, \
            f"-S --inplace failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        dfile = os.path.join(received, "blob.bin")
        assert os.path.getsize(dfile) == total
        with open(dfile, "rb") as f:
            assert f.read() == src_bytes


class TestBlockSize:
    """--block-size / --delta-block: the checksum block size is genuinely honored
    by the delta engine (both spellings parse to config->delta_block_size).  An
    end-to-end delta transfer with a non-default block size must still be
    byte-exact."""

    @pytest.mark.parametrize("flag", ["--block-size", "--delta-block"])
    def test_non_default_block_size_delta_transfer(self, shared_server, flag):
        source = os.path.join(TEST_DATA_DIR, "blocksize_delta_src")
        dest = os.path.join(TEST_DATA_DIR, "blocksize_delta_dst")
        clean_dir(source)
        clean_dir(dest)
        payload = os.urandom(300 * 1024)  # enough for several 1 KiB blocks
        with open(os.path.join(source, "big.bin"), "wb") as f:
            f.write(payload)
        # First run installs the file as the destination basis (do NOT wipe it
        # afterwards: the second run's delta must be computed against it).
        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0
        received = get_dest_received_dir(dest, source)
        # Extend the source so it differs from the installed basis: the second
        # run with --delta must compute a real delta against that basis.
        with open(os.path.join(source, "big.bin"), "ab") as f:
            f.write(os.urandom(4096))
        result, _ = run_client(source, dest,
                               flags=["--incremental", "--delta", flag, "1024"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"{flag} 1024 delta transfer failed: {(result.stderr or result.stdout)[:300]}"
        with open(os.path.join(received, "big.bin"), "rb") as f:
            with open(os.path.join(source, "big.bin"), "rb") as expect:
                assert f.read() == expect.read()

class TestOmitTimes:
    """-O/--omit-dir-times and -J/--omit-link-times are recognized and cross the
    wire as receiver-side preferences.  FastSync does not currently apply dir or
    symlink times at all, so they are forward-compatible preferences: the run
    must succeed and normal transfers must not break.  A regular file's mtime
    (from -M) is unaffected by -O/-J."""

    @pytest.mark.parametrize("flag", ["-O", "-J"])
    @pytest.mark.parametrize("mt", [False, True])
    def test_omit_times_accepted(self, shared_server, flag, mt):
        source = os.path.join(TEST_DATA_DIR, f"omit_{flag.strip('-')}_{'m' if mt else 's'}_src")
        dest = os.path.join(TEST_DATA_DIR, f"omit_{flag.strip('-')}_{'m' if mt else 's'}_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "a.txt"), "wb") as f:
            f.write(b"omit times content\n")
        flags = [flag] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"{flag} failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing, f"Missing: {missing}"
        assert not mismatches, f"Mismatch: {mismatches}"

    @pytest.mark.ci
    def test_omit_times_with_dirs_and_regular_metadata(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "omit_dirs_meta_src")
        dest = os.path.join(TEST_DATA_DIR, "omit_dirs_meta_dst")
        clean_dir(source)
        clean_dir(dest)
        os.makedirs(os.path.join(source, "subdir"))
        with open(os.path.join(source, "f.txt"), "wb") as f:
            f.write(b"regular mtime preserved under -O/-J\n")
        result, _ = run_client(source, dest, flags=["-d", "--omit-dir-times"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"-d -O failed: {(result.stderr or result.stdout)[:300]}"
        result, _ = run_client(source, dest, flags=["--preserve", "-O", "-J"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"-M -O -J failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        mismatches, missing = verify_transfer(source, received)
        assert not missing and not mismatches, f"missing={missing} mismatches={mismatches}"


class TestSymlinkTrust:
    """Phase-4 symlink trust boundaries: -k/--copy-dirlinks, -K/--keep-dirlinks
    and --munge-links.  Destination paths mirror the absolute source path below
    the destination root (run_client uses absolute --source-dir/--dest-dir)."""

    def test_copy_dirlinks_dereferences_dir_symlink(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "symlink_trust_copy_dirlinks")
        dest = os.path.join(TEST_DATA_DIR, "symlink_trust_copy_dirlinks_dst")
        clean_dir(source)
        clean_dir(dest)
        os.makedirs(os.path.join(source, "realdir"))
        with open(os.path.join(source, "realfile.txt"), "wb") as f:
            f.write(b"real file\n")
        with open(os.path.join(source, "realdir", "inside.txt"), "wb") as f:
            f.write(b"inside dir\n")
        os.symlink("realfile.txt", os.path.join(source, "link_file"))
        os.symlink("realdir", os.path.join(source, "link_dir"))

        # -k only dereferences directory symlinks; file symlinks need -l to be
        # carried as symlinks (rsync skips them otherwise).
        result, _ = run_client(source, dest, flags=["-l", "-k"], port=shared_server.port)
        assert result.returncode == 0, f"-l -k failed: {(result.stderr or result.stdout)[:300]}"

        received = get_dest_received_dir(dest, source)
        # link -> realdir dereferences into a real directory tree...
        link_dir = os.path.join(received, "link_dir")
        assert os.path.isdir(link_dir)
        assert not os.path.islink(link_dir)
        assert os.path.isfile(os.path.join(link_dir, "inside.txt"))
        # ... while a symlink to a regular file stays a symlink.
        link_file = os.path.join(received, "link_file")
        assert os.path.islink(link_file)
        assert os.readlink(link_file) == "realfile.txt"

    def test_keep_dirlinks_keeps_dest_symlink_to_dir(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "symlink_trust_keep_dirlinks")
        dest = os.path.join(TEST_DATA_DIR, "symlink_trust_keep_dirlinks_dst")
        clean_dir(source)
        clean_dir(dest)
        os.makedirs(os.path.join(source, "sub"))
        with open(os.path.join(source, "sub", "file.txt"), "wb") as f:
            f.write(b"under the kept symlinked dir\n")

        # Plant the destination's symlink-to-directory at the exact mirror path:
        #  sub -> realdir (relative, both siblings under the mirror parent).
        parent = os.path.join(dest, os.path.abspath(source).lstrip(os.sep))
        os.makedirs(parent)
        os.makedirs(os.path.join(parent, "realdir"))
        os.symlink("realdir", os.path.join(parent, "sub"))

        result, _ = run_client(source, dest, flags=["-K"], port=shared_server.port)
        assert result.returncode == 0, f"-K failed: {(result.stderr or result.stdout)[:300]}"

        received = get_dest_received_dir(dest, source)
        sub = os.path.join(received, "sub")
        # sub stays a symlink to the directory rather than being replaced...
        assert os.path.islink(sub)
        assert os.readlink(sub) == "realdir"
        # ... and the file is written beneath it, through to the referent dir.
        assert os.path.isfile(os.path.join(parent, "realdir", "file.txt"))

    @pytest.mark.ci
    def test_munge_links_prefixes_targets(self, shared_server):
        # rsync's --munge-links is a RECEIVER-side rewrite: every stored target
        # gets the /rsyncd-munged/ prefix, making the link unusable while that
        # directory does not exist.
        source = os.path.join(TEST_DATA_DIR, "symlink_munge")
        dest = os.path.join(TEST_DATA_DIR, "symlink_munge_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "a.txt"), "wb") as f:
            f.write(b"a\n")
        os.symlink("a.txt", os.path.join(source, "good"))
        os.symlink("/etc/passwd", os.path.join(source, "abs_escape"))
        os.symlink("../../escape", os.path.join(source, "dotdot_escape"))

        result, _ = run_client(source, dest, flags=["-l", "--munge-links"],
                               port=shared_server.port)
        assert result.returncode == 0, f"--munge-links failed: {(result.stderr or result.stdout)[:300]}"

        received = get_dest_received_dir(dest, source)
        assert os.readlink(os.path.join(received, "good")) == "/rsyncd-munged/a.txt"
        assert os.readlink(os.path.join(received, "abs_escape")) == "/rsyncd-munged//etc/passwd"
        assert os.readlink(os.path.join(received, "dotdot_escape")) == "/rsyncd-munged/../../escape"
        assert os.path.isfile(os.path.join(received, "a.txt"))

    @pytest.mark.ci
    def test_links_copies_symlinks_as_symlinks(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "symlink_links")
        dest = os.path.join(TEST_DATA_DIR, "symlink_links_dst")
        clean_dir(source)
        clean_dir(dest)
        os.makedirs(os.path.join(source, "realdir"))
        with open(os.path.join(source, "realfile.txt"), "wb") as f:
            f.write(b"real\n")
        with open(os.path.join(source, "realdir", "x.txt"), "wb") as f:
            f.write(b"x\n")
        os.symlink("realfile.txt", os.path.join(source, "lf"))
        os.symlink("realdir", os.path.join(source, "ld"))

        result, _ = run_client(source, dest, flags=["-l"], port=shared_server.port)
        assert result.returncode == 0, f"-l failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.path.islink(os.path.join(received, "lf"))
        assert os.readlink(os.path.join(received, "lf")) == "realfile.txt"
        assert os.path.islink(os.path.join(received, "ld"))
        assert os.readlink(os.path.join(received, "ld")) == "realdir"

    @pytest.mark.ci
    def test_links_preserves_absolute_and_dotdot_targets(self, shared_server):
        # rsync -l parity: -l stores a symlink target verbatim, including an
        # absolute target and an in-tree ".." target (no silent drop).
        source = os.path.join(TEST_DATA_DIR, "symlink_links_verbatim")
        dest = os.path.join(TEST_DATA_DIR, "symlink_links_verbatim_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "a.txt"), "wb") as f:
            f.write(b"a\n")
        os.makedirs(os.path.join(source, "sub"))
        os.symlink("a.txt", os.path.join(source, "good"))
        os.symlink("/etc/passwd", os.path.join(source, "unsafe_abs"))
        os.symlink("../a.txt", os.path.join(source, "sub", "up"))

        result, _ = run_client(source, dest, flags=["-l"], port=shared_server.port)
        assert result.returncode == 0, f"-l failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.readlink(os.path.join(received, "good")) == "a.txt"
        assert os.readlink(os.path.join(received, "unsafe_abs")) == "/etc/passwd"
        assert os.readlink(os.path.join(received, "sub", "up")) == "../a.txt"

    @pytest.mark.ci
    def test_safe_links_keeps_safe_skips_unsafe(self, shared_server):
        # --safe-links keeps symlinks that stay inside the transfer tree (even
        # with a ".." that does not climb out) and drops absolute / escaping /
        # internally-".."-bearing targets.
        source = os.path.join(TEST_DATA_DIR, "symlink_safe")
        dest = os.path.join(TEST_DATA_DIR, "symlink_safe_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "a.txt"), "wb") as f:
            f.write(b"a\n")
        os.makedirs(os.path.join(source, "sub"))
        os.symlink("a.txt", os.path.join(source, "safe_rel"))
        os.symlink("../a.txt", os.path.join(source, "sub", "up"))
        os.symlink("/etc/passwd", os.path.join(source, "abs"))
        os.symlink("../outside.txt", os.path.join(source, "esc"))
        os.symlink("sub/../a.txt", os.path.join(source, "internal"))

        result, _ = run_client(source, dest, flags=["-l", "--safe-links"],
                               port=shared_server.port)
        assert result.returncode == 0, f"--safe-links failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.readlink(os.path.join(received, "safe_rel")) == "a.txt"
        assert os.readlink(os.path.join(received, "sub", "up")) == "../a.txt"
        for unsafe in ("abs", "esc", "internal"):
            assert not os.path.lexists(os.path.join(received, unsafe)), (
                f"{unsafe} must be skipped by --safe-links"
            )

    @pytest.mark.ci
    def test_safe_links_protects_dest_from_delete(self):
        # rsync counts an unsafe link ignored by --safe-links as present in the
        # transfer, so its destination mirror survives --delete.  FastSync must
        # not delete it (no silent data loss).  Own server: deletion needs
        # --allow-delete, which the shared session server does not grant.
        source = os.path.join(TEST_DATA_DIR, "symlink_safe_delete")
        dest = os.path.join(TEST_DATA_DIR, "symlink_safe_delete_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "keep.txt"), "wb") as f:
            f.write(b"keep\n")
        os.symlink("/etc/passwd", os.path.join(source, "unsafe_abs"))

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            received = get_dest_received_dir(dest, source)
            os.makedirs(received, exist_ok=True)
            mirror = os.path.join(received, "unsafe_abs")
            with open(mirror, "wb") as f:
                f.write(b"existing destination data\n")
            extra = os.path.join(received, "extra.txt")
            with open(extra, "wb") as f:
                f.write(b"extra\n")

            result, _ = run_client(source, dest, flags=["-l", "--safe-links", "--delete"],
                                   port=server.port)
            assert result.returncode == 0, (
                f"--delete --safe-links failed: {(result.stderr or result.stdout)[:300]}"
            )
            assert os.path.exists(mirror), (
                "a destination mirror of a --safe-links-skipped link must survive --delete"
            )
            assert not os.path.exists(extra), "a genuine extra must still be deleted"

    @pytest.mark.ci
    def test_copy_unsafe_links_derefs_only_unsafe(self, shared_server):
        # --copy-unsafe-links keeps safe symlinks and dereferences unsafe ones
        # (absolute or escaping) into regular files.
        source = os.path.join(TEST_DATA_DIR, "symlink_copy_unsafe")
        dest = os.path.join(TEST_DATA_DIR, "symlink_copy_unsafe_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "a.txt"), "wb") as f:
            f.write(b"a\n")
        with open(os.path.join(source, "refer.txt"), "wb") as f:
            f.write(b"refer\n")
        external = os.path.join(TEST_DATA_DIR, "symlink_copy_unsafe_external.txt")
        with open(external, "wb") as f:
            f.write(b"external\n")
        os.symlink("a.txt", os.path.join(source, "safe_rel"))
        os.symlink("refer.txt", os.path.join(source, "from_rel"))
        os.symlink("../symlink_copy_unsafe_external.txt", os.path.join(source, "esc"))
        os.symlink("/etc/hostname", os.path.join(source, "abs"))

        result, _ = run_client(source, dest, flags=["-l", "--copy-unsafe-links"],
                               port=shared_server.port)
        assert result.returncode == 0, (
            f"--copy-unsafe-links failed: {(result.stderr or result.stdout)[:300]}"
        )
        received = get_dest_received_dir(dest, source)
        assert os.path.islink(os.path.join(received, "safe_rel"))
        assert os.readlink(os.path.join(received, "safe_rel")) == "a.txt"
        assert os.path.islink(os.path.join(received, "from_rel")), (
            "a safe symlink must be preserved, not dereferenced"
        )
        assert os.readlink(os.path.join(received, "from_rel")) == "refer.txt"
        # An escaping (..) symlink and an absolute symlink are both dereferenced
        # into regular files holding the referent's content.
        assert not os.path.islink(os.path.join(received, "esc"))
        with open(os.path.join(received, "esc"), "rb") as f:
            assert f.read() == b"external\n"
        assert not os.path.islink(os.path.join(received, "abs"))
        assert os.path.isfile(os.path.join(received, "abs"))

    def test_munge_prefix_roundtrip(self, shared_server):
        # A source target that already begins with /rsyncd-munged/ round-trips:
        # plain -l stores it verbatim, and --munge-links strips on the sender
        # then re-munges on the receiver, yielding the same stored value.
        source = os.path.join(TEST_DATA_DIR, "symlink_munge_roundtrip")
        dest = os.path.join(TEST_DATA_DIR, "symlink_munge_roundtrip_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "realfile.txt"), "wb") as f:
            f.write(b"real\n")
        os.symlink("/rsyncd-munged/realfile.txt", os.path.join(source, "prefixed"))
        os.symlink("#SYMLINK/realfile.txt", os.path.join(source, "oldmarker"))

        for flags, oldmarker_target in (
            (["-l"], "#SYMLINK/realfile.txt"),
            (["-l", "--munge-links"], "/rsyncd-munged/#SYMLINK/realfile.txt"),
        ):
            clean_dir(dest)
            result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
            assert result.returncode == 0, (
                f"{' '.join(flags)} failed: {(result.stderr or result.stdout)[:300]}"
            )
            received = get_dest_received_dir(dest, source)
            assert os.readlink(os.path.join(received, "prefixed")) == "/rsyncd-munged/realfile.txt"
            assert os.readlink(os.path.join(received, "oldmarker")) == oldmarker_target
def _xattr_supported(path):
    """True when the filesystem hosting `path` supports user xattrs."""
    try:
        os.setxattr(path, "user.fastsync-probe", b"p")
        os.removexattr(path, "user.fastsync-probe")
        return True
    except (OSError, AttributeError):
        return False


class TestExtendedAttributes:
    """-X/--xattrs, -A/--acls, --fake-super: portable extended metadata.

    Runs unprivileged (CI is non-root).  Everything is best-effort and guarded:
    a filesystem without xattr support, or an ACL toolchain/POSIX-ACL
    filesystem feature that is missing, is skipped rather than failed.  The
    security boundary (only user.* and the system.posix_acl_* namespaces are
    ever applied) is asserted alongside the happy path."""

    def _source_and_dest(self, name):
        source = os.path.join(TEST_DATA_DIR, name + "_src")
        dest = os.path.join(TEST_DATA_DIR, name + "_dst")
        clean_dir(source)
        clean_dir(dest)
        return source, dest

    @pytest.mark.ci
    def test_xattrs_preserves_user_namespace(self, shared_server):
        source, dest = self._source_and_dest("xattr")
        f = os.path.join(source, "data.txt")
        with open(f, "wb") as fh:
            fh.write(b"xattr payload\n")
        if not _xattr_supported(f):
            pytest.skip("filesystem does not support user xattrs")
        os.setxattr(f, "user.foo", b"preserved-value")

        result, _ = run_client(source, dest, flags=["-X"], port=shared_server.port)
        assert result.returncode == 0, \
            f"-X sync failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.getxattr(os.path.join(received, "data.txt"), "user.foo") == b"preserved-value"

    def test_without_xattrs_does_not_carry(self, shared_server):
        source, dest = self._source_and_dest("xattr_ctrl")
        f = os.path.join(source, "data.txt")
        with open(f, "wb") as fh:
            fh.write(b"plain\n")
        if not _xattr_supported(f):
            pytest.skip("filesystem does not support user xattrs")
        os.setxattr(f, "user.foo", b"must-not-travel")

        result, _ = run_client(source, dest, port=shared_server.port)
        assert result.returncode == 0, \
            f"control sync failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        with pytest.raises(OSError):
            os.getxattr(os.path.join(received, "data.txt"), "user.foo")

    def test_reserved_fake_super_key_not_forwarded(self, shared_server):
        """A source file that already carries the reserved user.fastsync.stat
        record must NOT have it planted on the receiver during a plain -X run
        (it is receiver-only, so it cannot be spoofed for a later privileged
        restore)."""
        source, dest = self._source_and_dest("xattr_reserved")
        f = os.path.join(source, "data.txt")
        with open(f, "wb") as fh:
            fh.write(b"reserved\n")
        if not _xattr_supported(f):
            pytest.skip("filesystem does not support user xattrs")
        os.setxattr(f, "user.fastsync.stat", b"0:0:644:0:0")
        # A normal user.* attr still travels alongside.
        os.setxattr(f, "user.keep", b"yes")

        result, _ = run_client(source, dest, flags=["-X"], port=shared_server.port)
        assert result.returncode == 0, \
            f"-X reserved-key sync failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.getxattr(os.path.join(received, "data.txt"), "user.keep") == b"yes"
        with pytest.raises(OSError):
            os.getxattr(os.path.join(received, "data.txt"), "user.fastsync.stat")

    @pytest.mark.ci
    def test_xattrs_multithreaded(self, shared_server):
        source, dest = self._source_and_dest("xattr_mt")
        f = os.path.join(source, "data.txt")
        with open(f, "wb") as fh:
            fh.write(b"mt xattr\n")
        if not _xattr_supported(f):
            pytest.skip("filesystem does not support user xattrs")
        os.setxattr(f, "user.k", b"v")
        result, _ = run_client(source, dest, flags=["-X", "--threads"], port=shared_server.port)
        assert result.returncode == 0, \
            f"-X -m sync failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.getxattr(os.path.join(received, "data.txt"), "user.k") == b"v"

    @pytest.mark.ci
    def test_acls_via_posix_acl_xattr(self, shared_server):
        source, dest = self._source_and_dest("acl")
        f = os.path.join(source, "data.txt")
        with open(f, "wb") as fh:
            fh.write(b"acl payload\n")
        if not _xattr_supported(f):
            pytest.skip("filesystem does not support xattrs")
        acl_blob = None
        if shutil.which("setfacl") is not None:
            acl = subprocess.run(["setfacl", "-m", "o::r", f], capture_output=True, text=True)
            if acl.returncode == 0:
                try:
                    acl_blob = os.getxattr(f, "system.posix_acl_access")
                except OSError:
                    acl_blob = None
        if acl_blob is None:
            # No setfacl (common in the minimal CI image): synthesize a valid
            # non-trivial POSIX ACL ("u:current-uid:r") xattr blob directly.
            import struct
            try:
                uid_for_acl = os.geteuid() if os.geteuid() != 0 else 65534
                struct_entry = struct.pack("<HHI", 0x01, 0x4, 0xFFFFFFFF)  # USER_OBJ r
                struct_entry += struct.pack("<HHI", 0x02, 0x4, uid_for_acl)  # USER r
                struct_entry += struct.pack("<HHI", 0x04, 0x4, 0xFFFFFFFF)  # GROUP_OBJ r
                struct_entry += struct.pack("<HHI", 0x10, 0x4, 0xFFFFFFFF)  # MASK r
                struct_entry += struct.pack("<HHI", 0x20, 0x0, 0xFFFFFFFF)  # OTHER ---
                blob = struct.pack("<I", 2) + struct_entry
                os.setxattr(f, "system.posix_acl_access", blob)
                acl_blob = os.getxattr(f, "system.posix_acl_access")
            except (OSError, struct.error) as e:
                pytest.skip(f"cannot set a POSIX ACL unprivileged: {e}")

        result, _ = run_client(source, dest, flags=["-A"], port=shared_server.port)
        assert result.returncode == 0, \
            f"-A sync failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.getxattr(os.path.join(received, "data.txt"),
                           "system.posix_acl_access") == acl_blob

    @pytest.mark.ci
    def test_acls_imply_xattr_transport(self, shared_server):
        """-A and -X enable the shared xattr transport; both attributes travel
        together, and a security.* attribute a malicious peer would send is
        never applied (receiver whitelist)."""
        source, dest = self._source_and_dest("acl_xattr")
        f = os.path.join(source, "data.txt")
        with open(f, "wb") as fh:
            fh.write(b"combined\n")
        if not _xattr_supported(f):
            pytest.skip("filesystem does not support xattrs")
        os.setxattr(f, "user.for-acl-flag", b"yes")
        result, _ = run_client(source, dest, flags=["-A", "-X"], port=shared_server.port)
        assert result.returncode == 0, \
            f"-A -X sync failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        assert os.getxattr(os.path.join(received, "data.txt"), "user.for-acl-flag") == b"yes"

    @pytest.mark.ci
    def test_fake_super_stores_source_stat(self, shared_server):
        source, dest = self._source_and_dest("fakesuper")
        f = os.path.join(source, "data.txt")
        with open(f, "wb") as fh:
            fh.write(b"fake-super\n")
        if not _xattr_supported(f):
            pytest.skip("filesystem does not support xattrs")
        uid = os.stat(f).st_uid

        result, _ = run_client(source, dest, flags=["--fake-super"], port=shared_server.port)
        assert result.returncode == 0, \
            f"--fake-super sync failed: {(result.stderr or result.stdout)[:300]}"
        received = get_dest_received_dir(dest, source)
        record = os.getxattr(os.path.join(received, "data.txt"), "user.fastsync.stat").decode()
        fields = record.split(":")
        assert len(fields) == 5
        assert fields[0] == str(uid), f"reserved uid field {fields[0]} != source uid {uid}"


class TestConnectivityClientOptions:
    """Phase 5 connectivity launch options (--outbuf, --blocking-io).

    These are client-side launch concerns: --outbuf only restyles stdout/stderr
    buffering and --blocking-io only skips the SSH transport socket timeouts.
    Over the TCP transport both must parse cleanly and be inert -- a transfer
    must still complete and verify byte-for-byte."""

    def _source_and_dest(self, name):
        source = os.path.join(TEST_DATA_DIR, name + "_src")
        dest = os.path.join(TEST_DATA_DIR, name + "_dst")
        clean_dir(source)
        clean_dir(dest)
        return source, dest

    @pytest.mark.parametrize("flag", ["--outbuf=N", "--outbuf=L", "--outbuf=B",
                                      "--blocking-io"])
    def test_option_does_not_break_transfer(self, shared_server, flag):
        source, dest = self._source_and_dest("connopt")
        with open(os.path.join(source, "hello.txt"), "wb") as f:
            f.write(b"connectivity options\n" * 100)
        with open(os.path.join(source, "data.bin"), "wb") as f:
            f.write(os.urandom(512 * 1024))

        result, _ = run_client(source, dest, flags=[flag], port=shared_server.port)
        assert result.returncode == 0, \
            f"{flag} failed: {(result.stderr or result.stdout)[:300]}"
        mismatches, missing = verify_transfer(source, get_dest_received_dir(dest, source))
        assert not mismatches and not missing, \
            f"{flag}: mismatches={mismatches[:3]} missing={missing[:3]}"

    def test_rejects_invalid_outbuf(self, shared_server):
        source, dest = self._source_and_dest("connopt_bad")
        with open(os.path.join(source, "x.txt"), "wb") as f:
            f.write(b"x")
        result, _ = run_client(source, dest, flags=["--outbuf=Z"], port=shared_server.port)
        assert result.returncode != 0, "--outbuf=Z must be rejected"

    def test_blocking_io_does_not_break_compressed_transfer(self, shared_server):
        source, dest = self._source_and_dest("connopt_zlib")
        with open(os.path.join(source, "text.txt"), "wb") as f:
            f.write(b"compress me\n" * 4096)
        result, _ = run_client(source, dest, flags=["--blocking-io", "-z"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"--blocking-io -c failed: {(result.stderr or result.stdout)[:300]}"
        mismatches, missing = verify_transfer(source, get_dest_received_dir(dest, source))
        assert not mismatches and not missing


DISTINCT_MTIME = 1_000_000_000  # 2001-09-09T01:46:40Z; a whole second


class TestDirectoryAndSymlinkTimes:
    """P7 Wave D: -O/--omit-dir-times and -J/--omit-link-times are real.

    FastSync now captures and applies directory mtimes (deferred to the end of
    the transfer, after children) and symlink mtimes (immediate, via no-follow
    primitives).  -O/-J suppress exactly their own class of times.
    """

    def _tree(self, name):
        source = os.path.join(TEST_DATA_DIR, name + "_src")
        dest = os.path.join(TEST_DATA_DIR, name + "_dst")
        clean_dir(source)
        clean_dir(dest)
        os.makedirs(os.path.join(source, "sub", "deep"), exist_ok=True)
        with open(os.path.join(source, "sub", "file.txt"), "wb") as fh:
            fh.write(b"content\n")
        with open(os.path.join(source, "sub", "deep", "deep.txt"), "wb") as fh:
            fh.write(b"deeper\n")
        dirs = (source, os.path.join(source, "sub"), os.path.join(source, "sub", "deep"))
        for d in dirs:
            os.utime(d, (DISTINCT_MTIME, DISTINCT_MTIME))
        if abs(os.stat(source).st_mtime - DISTINCT_MTIME) > 2:
            pytest.skip("filesystem does not preserve directory mtimes")
        return source, dest, ("", "sub", os.path.join("sub", "deep"))

    def _link_tree(self, name):
        source = os.path.join(TEST_DATA_DIR, name + "_src")
        dest = os.path.join(TEST_DATA_DIR, name + "_dst")
        clean_dir(source)
        clean_dir(dest)
        os.makedirs(os.path.join(source, "sub"), exist_ok=True)
        with open(os.path.join(source, "sub", "file.txt"), "wb") as fh:
            fh.write(b"target\n")
        link = os.path.join(source, "sub", "link")
        # A same-directory relative target (no ".."): FastSync refuses an
        # escaping/ambiguous symlink target, and ".." is a deliberate divergence.
        os.symlink("file.txt", link)
        os.utime(link, (DISTINCT_MTIME, DISTINCT_MTIME), follow_symlinks=False)
        if abs(os.lstat(link).st_mtime - DISTINCT_MTIME) > 2:
            pytest.skip("filesystem does not preserve symlink mtimes")
        return source, dest, os.path.join("sub", "link")

    def _run(self, source, dest, flags, shared_server):
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"{flags} failed: {(result.stderr or result.stdout)[:400]}"
        return get_dest_received_dir(dest, source)

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_directory_mtime_round_trip(self, shared_server, mt):
        source, dest, rels = self._tree("dirtime")
        flags = ["-a"] + (["--threads"] if mt else [])
        received = self._run(source, dest, flags, shared_server)
        for rel in rels:
            src_m = os.stat(os.path.join(source, rel)).st_mtime
            dst_m = os.stat(os.path.join(received, rel)).st_mtime
            assert abs(dst_m - src_m) < 2, \
                f"dir '{rel}': source={src_m} dest={dst_m} (flags={flags})"

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_omit_dir_times_suppresses_only_dirs(self, shared_server, mt):
        source, dest, rels = self._tree("omitdir")
        flags = ["-a", "-O"] + (["--threads"] if mt else [])
        received = self._run(source, dest, flags, shared_server)
        for rel in rels:
            dst_m = os.stat(os.path.join(received, rel)).st_mtime
            assert abs(dst_m - DISTINCT_MTIME) > 5, \
                f"-O must not apply directory times ('{rel}' got {dst_m})"

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_symlink_mtime_round_trip(self, shared_server, mt):
        source, dest, rel = self._link_tree("linktime")
        flags = ["-a"] + (["--threads"] if mt else [])
        received = self._run(source, dest, flags, shared_server)
        src_link = os.path.join(source, rel)
        dst_link = os.path.join(received, rel)
        assert os.path.islink(dst_link), f"{dst_link} is not a symlink"
        src_m = os.lstat(src_link).st_mtime
        dst_m = os.lstat(dst_link).st_mtime
        assert abs(dst_m - src_m) < 2, f"symlink times: source={src_m} dest={dst_m}"

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_omit_link_times_suppresses_only_links(self, shared_server, mt):
        source, dest, rel = self._link_tree("omitlink")
        flags = ["-a", "-J"] + (["--threads"] if mt else [])
        received = self._run(source, dest, flags, shared_server)
        dst_link = os.path.join(received, rel)
        assert os.path.islink(dst_link), f"{dst_link} is not a symlink"
        dst_m = os.lstat(dst_link).st_mtime
        assert abs(dst_m - DISTINCT_MTIME) > 5, \
            f"-J must not apply symlink times (got {dst_m})"

    @pytest.mark.ci
    def test_omit_flags_are_independent(self, shared_server):
        """-O suppresses only directory times and -J only symlink times: with
        -O the symlink time is still preserved, and with -J the dir times are."""
        source, dest, rel = self._link_tree("omitindep")
        # Add a subdirectory mtime to check alongside the symlink.
        sub = os.path.join(source, "sub")
        os.utime(sub, (DISTINCT_MTIME, DISTINCT_MTIME))

        # -O => dir times omitted, symlink time preserved.
        clean_dir(dest + "_o")
        recv_o = self._run(source, dest + "_o", ["-a", "-O"], shared_server)
        assert abs(os.lstat(os.path.join(recv_o, rel)).st_mtime - DISTINCT_MTIME) < 2, \
            "-O must not suppress symlink times"
        assert abs(os.stat(os.path.join(recv_o, "sub")).st_mtime - DISTINCT_MTIME) > 5, \
            "-O must suppress directory times"

        # -J => symlink times omitted, dir times preserved.
        clean_dir(dest + "_j")
        recv_j = self._run(source, dest + "_j", ["-a", "-J"], shared_server)
        assert abs(os.lstat(os.path.join(recv_j, rel)).st_mtime - DISTINCT_MTIME) > 5, \
            "-J must suppress symlink times"
        assert abs(os.stat(os.path.join(recv_j, "sub")).st_mtime - DISTINCT_MTIME) < 2, \
            "-J must not suppress directory times"

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_preserve_does_not_create_empty_source_dir(self, shared_server, mt):
        """P7 Wave D #1: a captured-but-EMPTY source directory is never created
        at the destination.  The scanner records its time (it is transmitted via
        STATUS_DIR_TIMES), but the receiver treats that entry as record-only, so
        `-a` keeps the documented "empty dirs are never transferred" behavior."""
        source = os.path.join(TEST_DATA_DIR, f"empty_dir_{'m' if mt else 's'}_src")
        dest = os.path.join(TEST_DATA_DIR, f"empty_dir_{'m' if mt else 's'}_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"regular file\n")
        os.makedirs(os.path.join(source, "empty_sub"))
        flags = ["-a"] + (["--threads"] if mt else [])
        received = self._run(source, dest, flags, shared_server)
        assert os.path.isfile(os.path.join(received, "keep.txt")), "regular file missing"
        assert not os.path.lexists(os.path.join(received, "empty_sub")), \
            f"-a created an empty source directory at {received}/empty_sub"

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_prune_empty_dirs_still_does_not_create_empty_dir(self, shared_server, mt):
        """P7 Wave D #1: `-a -m` (--prune-empty-dirs) keeps its semantics -- a
        captured empty directory is never created even though its time is
        recorded."""
        source = os.path.join(TEST_DATA_DIR, f"prune_empty_{'m' if mt else 's'}_src")
        dest = os.path.join(TEST_DATA_DIR, f"prune_empty_{'m' if mt else 's'}_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"regular file\n")
        os.makedirs(os.path.join(source, "empty_sub"))
        flags = ["-a", "-m"] + (["--threads"] if mt else [])
        received = self._run(source, dest, flags, shared_server)
        assert os.path.isfile(os.path.join(received, "keep.txt")), "regular file missing"
        assert not os.path.lexists(os.path.join(received, "empty_sub")), \
            f"-a -m created an empty source directory at {received}/empty_sub"

    @pytest.mark.ci
    @pytest.mark.parametrize("mt", [False, True])
    def test_collision_at_dir_time_path_does_not_abort(self, shared_server, mt):
        """P7 Wave D #1: a pre-existing regular file at a source-empty-dir's
        mirror path must not abort the transfer (the old mkdir failed and failed
        the run) and must not be clobbered."""
        source = os.path.join(TEST_DATA_DIR, f"dirtime_collide_{'m' if mt else 's'}_src")
        dest = os.path.join(TEST_DATA_DIR, f"dirtime_collide_{'m' if mt else 's'}_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"regular file\n")
        os.makedirs(os.path.join(source, "collide"))
        # Plant a regular file at exactly the mirror path of source/collide.
        received = get_dest_received_dir(dest, source)
        os.makedirs(received, exist_ok=True)
        blocker = os.path.join(received, "collide")
        with open(blocker, "wb") as fh:
            fh.write(b"pre-existing blocker\n")
        flags = ["-a"] + (["--threads"] if mt else [])
        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"-a aborted on a pre-existing file at an empty-dir path: " \
            f"{(result.stderr or result.stdout)[:400]}"
        assert os.path.isfile(blocker) and not os.path.islink(blocker), \
            "the pre-existing blocker was replaced by a directory"
        with open(blocker, "rb") as fh:
            assert fh.read() == b"pre-existing blocker\n", "the blocker file was clobbered"
        assert os.path.isfile(os.path.join(received, "keep.txt")), "regular file missing"


class TestCopyAs:
    """P7 Wave E: --copy-as=USER[:GROUP] safe subset.

    FastSync never switches the receiver's process credentials; the receiver
    forces the ownership of every entry it writes to the requested ids through
    the confined fd-relative identity path, which REQUIRES a privileged (root)
    receiver.  An unprivileged receiver refuses the whole transfer up front at
    the config handshake, before any file data moves.
    """

    @pytest.mark.ci
    def test_unprivileged_receiver_refuses_copy_as(self, shared_server):
        """The key assertable behavior: an unprivileged receiver REFUSES a
        --copy-as transfer cleanly (non-zero exit, no data written) instead of
        silently writing the wrong ownership."""
        source = os.path.join(TEST_DATA_DIR, "copyas_refuse_src")
        dest = os.path.join(TEST_DATA_DIR, "copyas_refuse_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "secret.txt"), "wb") as fh:
            fh.write(b"must not be written\n")

        captured = None
        if os.geteuid() == 0:
            if shutil.which("setpriv") is None:
                pytest.skip("root runner without setpriv cannot start an unprivileged receiver")
            # The unprivileged receiver must execute the server binary out of the
            # test workspace, so the workspace path has to be traversable by uid
            # 65534.  A checkout under a 0700 directory (e.g. /root) is not; skip
            # rather than fail — CI runs from a traversable workspace and still
            # exercises this behavior.
            probe = subprocess.run(
                ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
                 "test", "-x", os.path.abspath(SERVER_CMD[0])],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode != 0:
                pytest.skip("workspace is not traversable by the unprivileged receiver uid")
            os.chmod(dest, 0o777)
            proc, port = _start_captured_server(
                prefix=["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"])
            captured = proc
        else:
            # The session server already runs unprivileged.
            port = shared_server.port

        try:
            result, _ = run_client(source, dest,
                                   flags=["--copy-as=@65534:@65534"], port=port)
        finally:
            if captured is not None:
                out, err = _stop_captured_server(captured)
            else:
                out, err = "", ""

        assert result.returncode != 0, (
            f"an unprivileged receiver must refuse --copy-as: rc={result.returncode} "
            f"out={result.stdout[:200]!r} err={result.stderr[:200]!r}"
        )
        received = get_dest_received_dir(dest, source)
        assert not os.path.exists(os.path.join(received, "secret.txt")), (
            "--copy-as refusal leaked file data into the destination"
        )
        if captured is not None:
            assert "copy-as requires a privileged receiver" in (out + err), (
                f"refusal reason was not logged: out={out!r} err={err!r}"
            )

    @pytest.mark.ci
    @pytest.mark.skipif(os.geteuid() != 0, reason="requires a root receiver to chown")
    def test_root_copy_as_chowns_transferred_file(self, shared_server):
        """Root-gated: --copy-as=USER:GROUP forces the transferred file's
        ownership to exactly that uid/gid (numeric form for determinism)."""
        source = os.path.join(TEST_DATA_DIR, "copyas_root_src")
        dest = os.path.join(TEST_DATA_DIR, "copyas_root_dst")
        clean_dir(source)
        clean_dir(dest)
        with open(os.path.join(source, "owned.txt"), "wb") as fh:
            fh.write(b"owned by nobody\n")

        result, _ = run_client(source, dest,
                               flags=["--copy-as=@65534:@65534"], port=shared_server.port)
        assert result.returncode == 0, (
            f"--copy-as root transfer failed: {(result.stderr or result.stdout)[:400]}"
        )
        received = get_dest_received_dir(dest, source)
        target = os.path.join(received, "owned.txt")
        assert os.path.isfile(target), f"transferred file missing at {target}"
        st = os.lstat(target)
        assert (st.st_uid, st.st_gid) == (65534, 65534), (
            f"--copy-as did not force ownership: uid={st.st_uid} gid={st.st_gid}"
        )

    @pytest.mark.ci
    @pytest.mark.skipif(os.geteuid() != 0, reason="requires a root receiver to chown")
    def test_root_copy_as_owns_directory(self, shared_server):
        """--copy-as must own an explicitly-created directory entry, not just the
        files inside it.  A listed directory (--files-from + --dirs -R) is sent
        as a STATUS_MKDIR entry, exercising the directory ownership path."""
        source = os.path.join(TEST_DATA_DIR, "copyas_dir_src")
        dest = os.path.join(TEST_DATA_DIR, "copyas_dir_dst")
        clean_dir(source)
        clean_dir(dest)
        os.makedirs(os.path.join(source, "owned_dir"), exist_ok=True)
        lst = os.path.join(TEST_DATA_DIR, "copyas_dir_list.txt")
        with open(lst, "wb") as fh:
            fh.write(b"owned_dir\n")

        result, _ = run_client(
            source, dest,
            flags=["--copy-as=@65534:@65534", "--files-from", lst, "--dirs", "-R"],
            port=shared_server.port)
        assert result.returncode == 0, (
            f"--copy-as directory transfer failed: {(result.stderr or result.stdout)[:400]}"
        )
        target = os.path.join(dest, "owned_dir")
        assert os.path.isdir(target), f"explicit directory missing at {target}"
        st = os.stat(target)
        assert (st.st_uid, st.st_gid) == (65534, 65534), (
            f"--copy-as did not own the directory: uid={st.st_uid} gid={st.st_gid}"
        )

    @pytest.mark.ci
    @pytest.mark.skipif(os.geteuid() != 0, reason="requires a root receiver to chown")
    def test_root_copy_as_owns_implicit_parent_dirs(self, shared_server):
        """--copy-as must also own the intermediate directories that the receiver
        creates implicitly while writing a nested file (the scanner does not emit
        STATUS_MKDIR entries for ordinary traversal directories), not just the
        file itself."""
        source = os.path.join(TEST_DATA_DIR, "copyas_nested_src")
        dest = os.path.join(TEST_DATA_DIR, "copyas_nested_dst")
        clean_dir(source)
        clean_dir(dest)
        nested = os.path.join(source, "top", "mid", "leaf")
        os.makedirs(nested, exist_ok=True)
        with open(os.path.join(nested, "deep.txt"), "wb") as fh:
            fh.write(b"nested copy-as ownership\n")

        result, _ = run_client(source, dest,
                               flags=["--copy-as=@65534:@65534"],
                               port=shared_server.port)
        assert result.returncode == 0, (
            f"--copy-as nested transfer failed: {(result.stderr or result.stdout)[:400]}"
        )
        received = get_dest_received_dir(dest, source)
        for rel in ("top", os.path.join("top", "mid"), os.path.join("top", "mid", "leaf")):
            target = os.path.join(received, rel)
            assert os.path.isdir(target), f"implicit directory missing at {target}"
            st = os.stat(target)
            assert (st.st_uid, st.st_gid) == (65534, 65534), (
                f"--copy-as did not own implicit directory {rel}: "
                f"uid={st.st_uid} gid={st.st_gid}"
            )

    @pytest.mark.ci
    @pytest.mark.skipif(os.geteuid() != 0, reason="requires a root receiver to chown")
    def test_root_copy_as_owns_fifo(self, shared_server):
        """--copy-as must own a recreated FIFO special node."""
        source = os.path.join(TEST_DATA_DIR, "copyas_fifo_src")
        dest = os.path.join(TEST_DATA_DIR, "copyas_fifo_dst")
        clean_dir(source)
        clean_dir(dest)
        os.mkfifo(os.path.join(source, "pipe.fifo"))

        result, _ = run_client(source, dest,
                               flags=["--copy-as=@65534:@65534", "--specials"],
                               port=shared_server.port)
        assert result.returncode == 0, (
            f"--copy-as FIFO transfer failed: {(result.stderr or result.stdout)[:400]}"
        )
        received = get_dest_received_dir(dest, source)
        target = os.path.join(received, "pipe.fifo")
        assert stat.S_ISFIFO(os.lstat(target).st_mode), f"FIFO missing at {target}"
        st = os.lstat(target)
        assert (st.st_uid, st.st_gid) == (65534, 65534), (
            f"--copy-as did not own the FIFO: uid={st.st_uid} gid={st.st_gid}"
        )

    @pytest.mark.ci
    @pytest.mark.skipif(os.geteuid() != 0, reason="requires a root receiver to chown")
    def test_root_copy_as_with_fake_super_keeps_target_owner(self, shared_server):
        """--fake-super must not let the recorded source owner override the
        --copy-as forced owner (copy-as is authoritative)."""
        source = os.path.join(TEST_DATA_DIR, "copyas_fakesuper_src")
        dest = os.path.join(TEST_DATA_DIR, "copyas_fakesuper_dst")
        clean_dir(source)
        clean_dir(dest)
        src_file = os.path.join(source, "mixed.txt")
        with open(src_file, "wb") as fh:
            fh.write(b"copy-as wins over fake-super\n")
        os.chown(src_file, 12345, 12346)

        result, _ = run_client(source, dest,
                               flags=["--copy-as=@65534:@65534", "--fake-super"],
                               port=shared_server.port)
        assert result.returncode == 0, (
            f"--copy-as --fake-super transfer failed: "
            f"{(result.stderr or result.stdout)[:400]}"
        )
        received = get_dest_received_dir(dest, source)
        st = os.lstat(os.path.join(received, "mixed.txt"))
        assert (st.st_uid, st.st_gid) == (65534, 65534), (
            f"--fake-super overrode --copy-as: uid={st.st_uid} gid={st.st_gid}"
        )
