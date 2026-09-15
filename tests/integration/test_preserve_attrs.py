"""Wave 2b: per-attribute preservation split (-p/-t/-o/-g and their negations).

The receiver applies each attribute independently (see src/shared/file_attr.h).
These tests cover the per-flag behavior end-to-end, the CLI negations, directory
modes, and the unprivileged best-effort / root-only ownership paths.  They reuse
the established helpers from common.py.

The `-s` spelling is rsync's --secluded-args no-op in FastSync; chunk
serialization is the long-form --chunk-serialization, which is what the feature
matrix below exercises.
"""
import os
import stat
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    TEST_DATA_DIR,
    run_client,
    clean_dir,
    get_dest_received_dir,
    ServerManager,
)

DISTINCT_MTIME = 1_000_000_000  # 2001-09-09T01:46:40Z, a whole second


def _process_umask():
    current = os.umask(0)
    os.umask(current)
    return current


def _seed_file(source, dest, name, content, mode, mtime=None):
    """Create a one-file source tree at an explicit mode (and mtime), and a
    clean destination.  Returns the source file path."""
    clean_dir(source)
    clean_dir(dest)
    path = os.path.join(source, name)
    with open(path, "wb") as fh:
        fh.write(content)
    os.chmod(path, mode)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


def _received(dest, source, name):
    return os.path.join(get_dest_received_dir(dest, source), name)


class TestPreservePerms:
    @pytest.mark.ci
    def test_p_applies_source_mode(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "perms_p_src")
        dest = os.path.join(TEST_DATA_DIR, "perms_p_dst")
        _seed_file(source, dest, "f.txt", b"perms\n", 0o750)

        result, _ = run_client(source, dest, flags=["-p"], port=shared_server.port)
        assert result.returncode == 0, \
            f"-p failed: {(result.stderr or result.stdout)[:300]}"
        got = os.stat(_received(dest, source, "f.txt")).st_mode & 0o777
        assert got == 0o750, f"-p must apply the source mode, got {oct(got)}"

    @pytest.mark.ci
    def test_without_p_preexisting_dest_keeps_mode(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "perms_nop_exist_src")
        dest = os.path.join(TEST_DATA_DIR, "perms_nop_exist_dst")
        src_file = _seed_file(source, dest, "f.txt", b"one\n", 0o750)

        # Seed the destination.
        result, _ = run_client(source, dest, flags=["-p"], port=shared_server.port)
        assert result.returncode == 0, f"seed failed: {(result.stderr or '')[:200]}"

        # Give the destination a distinguishable mode, then re-transfer without
        # -p (but with -t so metadata still travels).
        dst_file = _received(dest, source, "f.txt")
        os.chmod(dst_file, 0o600)
        with open(src_file, "wb") as fh:
            fh.write(b"two, changed content\n")

        result, _ = run_client(source, dest, flags=["-t"], port=shared_server.port)
        assert result.returncode == 0, f"re-run failed: {(result.stderr or '')[:200]}"
        got = os.stat(dst_file).st_mode & 0o777
        assert got == 0o600, \
            f"without -p a pre-existing destination must keep its mode, got {oct(got)}"
        with open(dst_file, "rb") as fh:
            assert fh.read() == b"two, changed content\n"

    @pytest.mark.ci
    def test_without_p_new_dest_gets_source_and_umask(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "perms_nop_new_src")
        dest = os.path.join(TEST_DATA_DIR, "perms_nop_new_dst")
        # 0664 has group/other bits that the umask strips, so the result is not
        # just the source mode.  Under strict rsync parity the source mode is
        # masked only by the umask (group/other write is no longer force-cleared
        # on top of it).
        _seed_file(source, dest, "f.txt", b"new\n", 0o664)

        result, _ = run_client(source, dest, flags=["-t"], port=shared_server.port)
        assert result.returncode == 0, f"-t failed: {(result.stderr or result.stdout)[:300]}"
        want = 0o664 & ~_process_umask()
        got = os.stat(_received(dest, source, "f.txt")).st_mode & 0o777
        assert got == want, \
            f"new no--p destination mode: want {oct(want)}, got {oct(got)}"


class TestPreserveTimes:
    @pytest.mark.ci
    def test_t_applies_mtime(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "times_t_src")
        dest = os.path.join(TEST_DATA_DIR, "times_t_dst")
        _seed_file(source, dest, "f.txt", b"times\n", 0o644, mtime=DISTINCT_MTIME)

        result, _ = run_client(source, dest, flags=["-t"], port=shared_server.port)
        assert result.returncode == 0, f"-t failed: {(result.stderr or '')[:300]}"
        dst_m = os.stat(_received(dest, source, "f.txt")).st_mtime
        assert abs(dst_m - DISTINCT_MTIME) < 2, \
            f"-t must apply the source mtime, got {dst_m}"

    @pytest.mark.ci
    def test_without_t_dest_mtime_differs(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "times_not_src")
        dest = os.path.join(TEST_DATA_DIR, "times_not_dst")
        _seed_file(source, dest, "f.txt", b"times\n", 0o644, mtime=DISTINCT_MTIME)

        # -p transmits metadata but must not apply the source mtime.
        result, _ = run_client(source, dest, flags=["-p"], port=shared_server.port)
        assert result.returncode == 0, f"-p failed: {(result.stderr or '')[:300]}"
        dst_m = os.stat(_received(dest, source, "f.txt")).st_mtime
        assert abs(dst_m - DISTINCT_MTIME) > 24 * 3600, \
            f"without -t the destination mtime must not be the source mtime ({dst_m})"

    @pytest.mark.ci
    def test_incremental_t_retransfers_after_no_t(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "times_incr_src")
        dest = os.path.join(TEST_DATA_DIR, "times_incr_dst")
        _seed_file(source, dest, "f.txt", b"retransfer\n", 0o644, mtime=DISTINCT_MTIME)

        # First run without -t: the destination mtime becomes "now", differing
        # from the pinned source mtime.
        result, _ = run_client(source, dest, flags=["-p"], port=shared_server.port)
        assert result.returncode == 0, f"seed failed: {(result.stderr or '')[:200]}"
        dst_file = _received(dest, source, "f.txt")
        assert abs(os.stat(dst_file).st_mtime - DISTINCT_MTIME) > 24 * 3600

        # The incremental quick-check now sees a mtime mismatch, so the file is
        # re-transferred and -t stamps the source time.
        result, _ = run_client(source, dest, flags=["--incremental", "-t"],
                               port=shared_server.port)
        assert result.returncode == 0, f"incremental -t failed: {(result.stderr or '')[:300]}"
        dst_m = os.stat(dst_file).st_mtime
        assert abs(dst_m - DISTINCT_MTIME) < 2, \
            f"second --incremental -t run must re-transfer and stamp the mtime, got {dst_m}"


class TestPreserveNegations:
    @pytest.mark.ci
    def test_a_no_owner_no_group_keeps_perms_and_times(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "neg_owner_group_src")
        dest = os.path.join(TEST_DATA_DIR, "neg_owner_group_dst")
        _seed_file(source, dest, "f.txt", b"neg\n", 0o750, mtime=DISTINCT_MTIME)

        result, _ = run_client(source, dest, flags=["-a", "--no-owner", "--no-group"],
                               port=shared_server.port)
        assert result.returncode == 0, f"-a --no-owner --no-group: {(result.stderr or '')[:300]}"
        st = os.stat(_received(dest, source, "f.txt"))
        assert st.st_mode & 0o777 == 0o750, "perms must survive the owner/group negation"
        assert abs(st.st_mtime - DISTINCT_MTIME) < 2, "times must survive the owner/group negation"

    @pytest.mark.ci
    def test_a_no_perms_keeps_times_and_dest_mode(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "neg_perms_src")
        dest = os.path.join(TEST_DATA_DIR, "neg_perms_dst")
        src_file = _seed_file(source, dest, "f.txt", b"one\n", 0o750, mtime=DISTINCT_MTIME)

        result, _ = run_client(source, dest, flags=["-a"], port=shared_server.port)
        assert result.returncode == 0, f"seed failed: {(result.stderr or '')[:200]}"
        dst_file = _received(dest, source, "f.txt")
        os.chmod(dst_file, 0o600)
        with open(src_file, "wb") as fh:
            fh.write(b"changed\n")
        # Rewriting the source bumped its mtime; restore the pinned value so the
        # --no-perms run still has a distinct source time to apply.
        os.utime(src_file, (DISTINCT_MTIME, DISTINCT_MTIME))

        result, _ = run_client(source, dest, flags=["-a", "--no-perms"],
                               port=shared_server.port)
        assert result.returncode == 0, f"-a --no-perms: {(result.stderr or '')[:300]}"
        st = os.stat(dst_file)
        assert st.st_mode & 0o777 == 0o600, \
            f"--no-perms must keep the destination mode, got {oct(st.st_mode & 0o777)}"
        assert abs(st.st_mtime - DISTINCT_MTIME) < 2, "--no-perms must not disable times"

    @pytest.mark.ci
    def test_a_no_times_keeps_perms_but_not_mtime(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "neg_times_src")
        dest = os.path.join(TEST_DATA_DIR, "neg_times_dst")
        _seed_file(source, dest, "f.txt", b"neg times\n", 0o750, mtime=DISTINCT_MTIME)

        result, _ = run_client(source, dest, flags=["-a", "--no-times"],
                               port=shared_server.port)
        assert result.returncode == 0, f"-a --no-times: {(result.stderr or '')[:300]}"
        st = os.stat(_received(dest, source, "f.txt"))
        assert st.st_mode & 0o777 == 0o750, "--no-times must not disable perms"
        assert abs(st.st_mtime - DISTINCT_MTIME) > 24 * 3600, \
            "--no-times must not apply the source mtime"

    @pytest.mark.ci
    def test_preserve_no_preserve_clears_all(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "neg_bundle_src")
        dest = os.path.join(TEST_DATA_DIR, "neg_bundle_dst")
        _seed_file(source, dest, "f.txt", b"bundle\n", 0o750, mtime=DISTINCT_MTIME)

        result, _ = run_client(source, dest, flags=["--preserve", "--no-preserve"],
                               port=shared_server.port)
        assert result.returncode == 0, f"--preserve --no-preserve: {(result.stderr or '')[:300]}"
        dst_file = _received(dest, source, "f.txt")
        with open(dst_file, "rb") as fh:
            assert fh.read() == b"bundle\n"
        st = os.stat(dst_file)
        # No metadata travels at all: a new file gets the fixed safe 0644 and
        # the source mtime is not applied.
        assert st.st_mode & 0o777 == 0o644, \
            f"--no-preserve must not apply the source mode, got {oct(st.st_mode & 0o777)}"
        assert abs(st.st_mtime - DISTINCT_MTIME) > 24 * 3600, \
            "--no-preserve must not apply the source mtime"


class TestDirectoryModes:
    def _tree(self, name, dir_mode, pin_mtime):
        source = os.path.join(TEST_DATA_DIR, name + "_src")
        dest = os.path.join(TEST_DATA_DIR, name + "_dst")
        clean_dir(source)
        clean_dir(dest)
        sub = os.path.join(source, "sub")
        os.makedirs(sub)
        with open(os.path.join(sub, "file.txt"), "wb") as fh:
            fh.write(b"dir mode content\n")
        os.chmod(sub, dir_mode)
        if pin_mtime:
            os.utime(sub, (DISTINCT_MTIME, DISTINCT_MTIME))
        return source, dest, sub

    @pytest.mark.ci
    def test_p_applies_directory_mode(self, shared_server):
        source, dest, _ = self._tree("dirmode_p", 0o750, pin_mtime=False)
        result, _ = run_client(source, dest, flags=["-p"], port=shared_server.port)
        assert result.returncode == 0, f"-p failed: {(result.stderr or result.stdout)[:300]}"
        got = os.stat(os.path.join(get_dest_received_dir(dest, source), "sub")).st_mode & 0o777
        assert got == 0o750, f"-p must apply the source directory mode, got {oct(got)}"

    @pytest.mark.ci
    def test_p_preserves_directory_group_other_write(self, shared_server):
        # Strict rsync parity: -p copies the source directory mode exactly,
        # including group/other write (the old sanitization is gone).
        source, dest, _ = self._tree("dirmode_go_write", 0o777, pin_mtime=False)
        result, _ = run_client(source, dest, flags=["-p"], port=shared_server.port)
        assert result.returncode == 0, f"-p failed: {(result.stderr or result.stdout)[:300]}"
        mode = os.stat(os.path.join(get_dest_received_dir(dest, source), "sub")).st_mode & 0o777
        assert mode == 0o777, \
            f"-p must preserve the source directory mode exactly, got {oct(mode)}"

    @pytest.mark.ci
    def test_omit_dir_times_suppresses_times_not_modes(self, shared_server):
        source, dest, _ = self._tree("dirmode_omit", 0o750, pin_mtime=True)
        result, _ = run_client(source, dest, flags=["-a", "-O"], port=shared_server.port)
        assert result.returncode == 0, f"-a -O failed: {(result.stderr or result.stdout)[:300]}"
        st = os.stat(os.path.join(get_dest_received_dir(dest, source), "sub"))
        assert st.st_mode & 0o777 == 0o750, \
            f"-O must suppress only dir times, not dir modes (got {oct(st.st_mode & 0o777)})"
        assert abs(st.st_mtime - DISTINCT_MTIME) > 5, \
            f"-O must not apply the directory mtime (got {st.st_mtime})"


class TestOwnershipBestEffort:
    """-o/-g/-a must succeed with correct content even when the receiver cannot
    chown (the unprivileged CI case).  Ownership is deliberately not asserted."""

    @pytest.mark.ci
    @pytest.mark.parametrize("flags", [["-o"], ["-g"], ["-a"]])
    def test_ownership_flags_succeed_unprivileged(self, shared_server, flags):
        tag = flags[0].strip("-")
        source = os.path.join(TEST_DATA_DIR, f"best_effort_{tag}_src")
        dest = os.path.join(TEST_DATA_DIR, f"best_effort_{tag}_dst")
        _seed_file(source, dest, "f.txt", b"best effort ownership\n", 0o640)

        result, _ = run_client(source, dest, flags=flags, port=shared_server.port)
        assert result.returncode == 0, \
            f"{flags} exit {result.returncode}: {(result.stderr or result.stdout)[:300]}"
        with open(_received(dest, source, "f.txt"), "rb") as fh:
            assert fh.read() == b"best effort ownership\n"


@pytest.mark.skipif(os.geteuid() != 0, reason="only root can change ownership")
class TestOwnershipRoot:
    """Root-only per-attribute ownership application.  Not marked ci: the PR
    gate runs as an unprivileged user."""

    def _seed_owned(self, tag, uid, gid):
        source = os.path.join(TEST_DATA_DIR, f"root_owner_{tag}_src")
        dest = os.path.join(TEST_DATA_DIR, f"root_owner_{tag}_dst")
        path = _seed_file(source, dest, "f.txt", b"root ownership\n", 0o644)
        os.chown(path, uid, gid)
        return source, dest

    def test_o_applies_owner_only(self, shared_server):
        source, dest = self._seed_owned("o", 12345, 12346)
        result, _ = run_client(source, dest, flags=["-o"], port=shared_server.port)
        assert result.returncode == 0, f"-o failed: {(result.stderr or '')[:300]}"
        st = os.stat(_received(dest, source, "f.txt"))
        assert st.st_uid == 12345, f"-o must apply the owner, got uid={st.st_uid}"
        assert st.st_gid != 12346, "-o must not change the group"

    def test_g_applies_group_only(self, shared_server):
        source, dest = self._seed_owned("g", 12345, 54321)
        result, _ = run_client(source, dest, flags=["-g"], port=shared_server.port)
        assert result.returncode == 0, f"-g failed: {(result.stderr or '')[:300]}"
        st = os.stat(_received(dest, source, "f.txt"))
        assert st.st_gid == 54321, f"-g must apply the group, got gid={st.st_gid}"
        assert st.st_uid != 12345, "-g must not change the owner"

    def test_a_applies_owner_and_group(self, shared_server):
        source, dest = self._seed_owned("a", 12345, 54321)
        result, _ = run_client(source, dest, flags=["-a"], port=shared_server.port)
        assert result.returncode == 0, f"-a failed: {(result.stderr or '')[:300]}"
        st = os.stat(_received(dest, source, "f.txt"))
        assert (st.st_uid, st.st_gid) == (12345, 54321), \
            f"-a must apply owner+group, got uid={st.st_uid} gid={st.st_gid}"

    def test_chown_overrides_o(self, shared_server):
        source, dest = self._seed_owned("chown", 11111, 22222)
        result, _ = run_client(source, dest, flags=["-o", "--chown=@33333:@44444"],
                               port=shared_server.port)
        assert result.returncode == 0, f"-o --chown failed: {(result.stderr or '')[:300]}"
        st = os.stat(_received(dest, source, "f.txt"))
        assert (st.st_uid, st.st_gid) == (33333, 44444), \
            f"--chown must override -o, got uid={st.st_uid} gid={st.st_gid}"

    def test_fake_super_o_does_not_real_chown(self, shared_server):
        # #294: --fake-super only RECORDS ownership; it must never real-chown the
        # recorded source owner (that defeats the point of the flag).  With -o the
        # resolved owner is parked in the reserved xattr and the on-disk owner is
        # left as the receiver's.
        source, dest = self._seed_owned("fake_o", 12345, 54321)
        result, _ = run_client(source, dest, flags=["--fake-super", "-o"],
                               port=shared_server.port)
        assert result.returncode == 0, f"--fake-super -o failed: {(result.stderr or '')[:300]}"
        dst = _received(dest, source, "f.txt")
        st = os.stat(dst)
        assert st.st_uid != 12345, \
            f"--fake-super -o must NOT real-chown the source owner, got uid={st.st_uid}"
        record = os.getxattr(dst, "user.fastsync.stat").decode()
        fields = record.split(":")
        assert fields[0] == "12345", \
            f"--fake-super must record the resolved owner, got {fields[0]}"

    def test_o_applies_directory_owner(self, shared_server):
        """#286.2: -o must apply the source owner to DIRECTORIES too (the
        deferred directory-metadata application now runs the identity path)."""
        source = os.path.join(TEST_DATA_DIR, "root_dir_o_src")
        dest = os.path.join(TEST_DATA_DIR, "root_dir_o_dst")
        clean_dir(source)
        clean_dir(dest)
        os.makedirs(os.path.join(source, "sub", "deep"))
        with open(os.path.join(source, "sub", "deep", "f.txt"), "wb") as fh:
            fh.write(b"dir owner\n")
        os.chown(os.path.join(source, "sub"), 12345, 12346)
        os.chown(os.path.join(source, "sub", "deep"), 23456, 34567)

        result, _ = run_client(source, dest, flags=["-o", "-t"], port=shared_server.port)
        assert result.returncode == 0, f"-o dir failed: {(result.stderr or '')[:300]}"
        received = get_dest_received_dir(dest, source)
        sub = os.stat(os.path.join(received, "sub"))
        deep = os.stat(os.path.join(received, "sub", "deep"))
        assert sub.st_uid == 12345, f"dir 'sub' owner not applied: {sub.st_uid}"
        assert deep.st_uid == 23456, f"dir 'sub/deep' owner not applied: {deep.st_uid}"
        # -o alone must not change the group.
        assert sub.st_gid != 12346

    def test_a_applies_directory_owner_and_group(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "root_dir_a_src")
        dest = os.path.join(TEST_DATA_DIR, "root_dir_a_dst")
        clean_dir(source)
        clean_dir(dest)
        os.makedirs(os.path.join(source, "sub"))
        with open(os.path.join(source, "sub", "f.txt"), "wb") as fh:
            fh.write(b"dir owner group\n")
        os.chown(os.path.join(source, "sub"), 12345, 54321)

        result, _ = run_client(source, dest, flags=["-a"], port=shared_server.port)
        assert result.returncode == 0, f"-a dir failed: {(result.stderr or '')[:300]}"
        received = get_dest_received_dir(dest, source)
        st = os.stat(os.path.join(received, "sub"))
        assert (st.st_uid, st.st_gid) == (12345, 54321), \
            f"-a must apply dir owner+group, got uid={st.st_uid} gid={st.st_gid}"

    def test_numeric_ids_alone_does_not_chown(self, shared_server):
        """#286.1: --numeric-ids is a mapping modifier, not an ownership request.
        `-t --numeric-ids` must leave the receiver's ownership untouched."""
        source, dest = self._seed_owned("num_only", 12345, 54321)
        result, _ = run_client(source, dest, flags=["-t", "--numeric-ids"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"-t --numeric-ids failed: {(result.stderr or '')[:300]}"
        st = os.stat(_received(dest, source, "f.txt"))
        assert st.st_uid != 12345, \
            f"--numeric-ids alone must not chown, got uid={st.st_uid}"

    def test_numeric_ids_with_o_uses_raw_id(self, shared_server):
        source, dest = self._seed_owned("num_o", 12345, 54321)
        result, _ = run_client(source, dest, flags=["-o", "-t", "--numeric-ids"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"-o --numeric-ids failed: {(result.stderr or '')[:300]}"
        st = os.stat(_received(dest, source, "f.txt"))
        assert st.st_uid == 12345, \
            f"-o --numeric-ids must apply the raw id, got uid={st.st_uid}"


class TestPreserveFeatureMatrix:
    """A representative per-attribute check under the alternate transfer engines
    (chunk serialization, --delay-updates, and the multithreaded scanner)."""

    @pytest.mark.ci
    @pytest.mark.parametrize("extra", ["--chunk-serialization", "--delay-updates", "--threads"])
    def test_p_and_t_hold_under_engine(self, shared_server, extra):
        tag = extra.strip("-").replace("-", "_")
        source = os.path.join(TEST_DATA_DIR, f"matrix_{tag}_src")
        dest = os.path.join(TEST_DATA_DIR, f"matrix_{tag}_dst")
        _seed_file(source, dest, "f.txt", b"matrix\n", 0o750, mtime=DISTINCT_MTIME)

        result, _ = run_client(source, dest, flags=["-p", "-t", extra],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"-p -t {extra} failed: {(result.stderr or result.stdout)[:300]}"
        st = os.stat(_received(dest, source, "f.txt"))
        assert st.st_mode & 0o777 == 0o750, f"mode lost under {extra}"
        assert abs(st.st_mtime - DISTINCT_MTIME) < 2, f"mtime lost under {extra}"


class TestSpecialNodeModes:
    """Strict rsync parity: with -p the source FIFO mode is copied exactly,
    including group/other write.  Without -p the node follows the same
    source & ~umask base as any other new entry.  FIFOs are created
    unprivileged via mkfifo."""

    @pytest.mark.ci
    def test_specials_p_preserves_fifo_mode(self):
        source = os.path.join(TEST_DATA_DIR, "specialmode_src")
        dest = os.path.join(TEST_DATA_DIR, "specialmode_dst")
        clean_dir(source)
        clean_dir(dest)

        src_fifo = os.path.join(source, "world.fifo")
        os.mkfifo(src_fifo)
        os.chmod(src_fifo, 0o777)
        assert os.stat(src_fifo).st_mode & 0o777 == 0o777

        # Production daemonizes with umask(0) (server.c) so the source mode is
        # what reaches mkfifo.  The session server runs in the foreground and
        # would inherit the runner's umask, which alone would strip the write
        # bits and mask a regression.  Start a dedicated foreground server under
        # umask(0) to exercise the real path.
        server = ServerManager()
        saved_umask = os.umask(0)
        try:
            server.start(extra_args=["--allow-super"])
        finally:
            os.umask(saved_umask)
        try:
            result, _ = run_client(source, dest, flags=["--specials", "-p"],
                                   port=server.port)
        finally:
            server.stop()

        assert result.returncode == 0, \
            f"--specials -p failed: {(result.stderr or result.stdout)[:300]}"

        received = _received(dest, source, "world.fifo")
        assert os.path.lexists(received), "source FIFO was not recreated on the destination"
        st = os.lstat(received)
        assert stat.S_ISFIFO(st.st_mode), f"received entry is not a FIFO: {oct(st.st_mode)}"
        mode = st.st_mode & 0o777
        assert mode == 0o777, \
            f"-p must preserve the source FIFO mode exactly (want 0o777), got {oct(mode)}"
