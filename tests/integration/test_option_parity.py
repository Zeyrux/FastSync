"""Differential parity tests for the option wave (bwlimit, --info=*, -M,
--ignore-errors, --filter protect).

Every differential here runs the SAME scenario with real ``rsync 3.4.1`` and
with fastsync and compares the observable result, so the modules are skipped
when rsync is unavailable.  The privilege-dependent --ignore-errors differential
drops the client to an unprivileged uid so a mode-000 source directory is
genuinely unreadable; it is marked ``setpriv`` (run as root locally, excluded
from the root PR gate exactly like the other privilege tests).
"""
import os
import shutil
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (  # noqa: E402
    CLIENT_CMD,
    TEST_DATA_DIR,
    ServerManager,
    clean_dir,
    get_dest_received_dir,
    run_client,
)

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")


def _rsync(args, timeout=120, as_nobody=False):
    env = dict(os.environ, LC_ALL="C")
    cmd = [RSYNC] + args
    if as_nobody:
        cmd = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"] + cmd
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)


class TestBwlimitParity:
    """--bwlimit must accept rsync 3.4.1's spellings and pace like it."""

    ACCEPTED = ["100", "0", "1.5", "100K", "100KB", "100KiB", "1M", "1MB", "1m", "1G", "512"]
    REJECTED = ["-1", "abc", "1x", "1 000"]

    @requires_rsync
    @pytest.mark.ci
    def test_parse_acceptance_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "bwp_src")
        clean_dir(source)
        _write(os.path.join(source, "f.txt"), b"payload\n")

        for value in self.ACCEPTED + self.REJECTED:
            rdst = os.path.join(TEST_DATA_DIR, "bwp_rdst")
            clean_dir(rdst)
            rsync_result = _rsync(["-a", "--bwlimit=" + value, source + "/", rdst + "/"])
            dest = os.path.join(TEST_DATA_DIR, "bwp_dst")
            clean_dir(dest)
            result, _ = run_client(source, dest, flags=["-a", "--bwlimit=" + value],
                                   port=shared_server.port)
            assert (result.returncode == 0) == (rsync_result.returncode == 0), (
                f"--bwlimit={value}: fastsync rc={result.returncode} "
                f"({(result.stderr or result.stdout)[:120]!r}) "
                f"rsync rc={rsync_result.returncode} ({rsync_result.stderr[:120]!r})"
            )

    @requires_rsync
    @pytest.mark.ci
    def test_throttle_rate_matches_rsync(self, shared_server):
        """A 4 MiB transfer at --bwlimit=2048 (2 MiB/s) must take about the same
        wall-clock time for both tools (~2 s with rsync's leaky bucket)."""
        source = os.path.join(TEST_DATA_DIR, "bwt_src")
        clean_dir(source)
        _write(os.path.join(source, "big.bin"), os.urandom(4 * 1024 * 1024))
        dest = os.path.join(TEST_DATA_DIR, "bwt_dst")
        rdst = os.path.join(TEST_DATA_DIR, "bwt_rdst")

        clean_dir(rdst)
        start = time.monotonic()
        rsync_result = _rsync(["-a", "--bwlimit=2048", source + "/", rdst + "/"])
        rsync_secs = time.monotonic() - start
        assert rsync_result.returncode == 0, rsync_result.stderr

        clean_dir(dest)
        result, fast_secs = run_client(source, dest, flags=["-a", "--bwlimit=2048"],
                                       port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]
        # 4 MiB at 2 MiB/s rendezvous near 2 s.  Use a coarse band on each side
        # (an unthrottled transfer finishes well under 1.5 s) plus a generous
        # cross-tolerance so a loaded CI runner cannot flake the parity assert.
        lo, hi = 1.5, 4.5
        assert lo <= fast_secs <= hi, f"fastsync throttle out of band: {fast_secs:.2f}s"
        assert lo <= rsync_secs <= hi, f"rsync throttle out of band: {rsync_secs:.2f}s"
        assert abs(fast_secs - rsync_secs) < 2.0, (
            f"fastsync {fast_secs:.2f}s vs rsync {rsync_secs:.2f}s"
        )


def _output_tree(root):
    clean_dir(root)
    os.makedirs(os.path.join(root, "sub"))
    _write(os.path.join(root, "a.txt"), b"top\n")
    _write(os.path.join(root, "sub", "b.txt"), b"nested\n")
    os.symlink("a.txt", os.path.join(root, "link"))


class TestInfoParity:
    """The --info categories that map to a FastSync event must print rsync's
    line format."""

    @requires_rsync
    @pytest.mark.ci
    def test_info_flist_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "inf_fl_src")
        dest = os.path.join(TEST_DATA_DIR, "inf_fl_dst")
        rdst = os.path.join(TEST_DATA_DIR, "inf_fl_rdst")
        _output_tree(source)
        clean_dir(dest)
        clean_dir(rdst)
        rsync_result = _rsync(["-a", "--info=flist", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["-a", "--info=flist"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]
        assert "sending incremental file list" in result.stdout
        assert "sending incremental file list" in rsync_result.stdout

    @requires_rsync
    @pytest.mark.ci
    def test_info_name_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "inf_nm_src")
        dest = os.path.join(TEST_DATA_DIR, "inf_nm_dst")
        rdst = os.path.join(TEST_DATA_DIR, "inf_nm_rdst")
        _output_tree(source)
        clean_dir(dest)
        clean_dir(rdst)
        rsync_result = _rsync(["-a", "--info=name", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["-a", "--info=name"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]

        def entries(text):
            # Compare the transferred entries only: rsync also prints the
            # transfer-root `./` and every directory (FastSync records dirs),
            # which are a separate documented divergence.
            out = []
            for line in text.splitlines():
                if not line or line.startswith("sending ") or line.startswith("created "):
                    continue
                if line == "./" or line.endswith("/"):
                    continue
                out.append(line)
            return sorted(out)

        assert entries(result.stdout) == entries(rsync_result.stdout), (
            f"rsync={entries(rsync_result.stdout)} fastsync={entries(result.stdout)}"
        )

    @requires_rsync
    @pytest.mark.ci
    def test_info_name_root_line_matches_rsync(self, shared_server):
        """A fresh destination: rsync prints `created directory`, then the
        transfer-root `./` name line before the entries; FastSync must emit the
        same `./` line."""
        source = os.path.join(TEST_DATA_DIR, "inf_root_src")
        dest = os.path.join(TEST_DATA_DIR, "inf_root_dst")
        rdst = os.path.join(TEST_DATA_DIR, "inf_root_rdst")
        clean_dir(source)
        _write(os.path.join(source, "f.bin"), b"payload\n")
        clean_dir(dest)
        shutil.rmtree(rdst, ignore_errors=True)
        rsync_result = _rsync(["-a", "--info=name", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["-a", "--info=name"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]

        def names(text):
            return [l for l in text.splitlines()
                    if l and not l.startswith("created directory")
                    and not (l.endswith("/") and l != "./")]

        assert names(rsync_result.stdout) == ["./", "f.bin"], names(rsync_result.stdout)
        assert names(result.stdout) == ["./", "f.bin"], names(result.stdout)

    @requires_rsync
    @pytest.mark.ci
    def test_info_name2_uptodate_matches_rsync(self, shared_server):
        """--info=name2 prints `NAME is uptodate` for entries the receiver
        already has, matching rsync byte-for-byte."""
        source = os.path.join(TEST_DATA_DIR, "inf_up_src")
        dest = os.path.join(TEST_DATA_DIR, "inf_up_dst")
        rdst = os.path.join(TEST_DATA_DIR, "inf_up_rdst")
        clean_dir(source)
        os.makedirs(os.path.join(source, "sub"))
        _write(os.path.join(source, "a.txt"), b"a\n")
        _write(os.path.join(source, "sub", "b.txt"), b"b\n")
        clean_dir(rdst)
        assert _rsync(["-a", source + "/", rdst + "/"]).returncode == 0
        rsync_result = _rsync(["-a", "--info=name2", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr

        clean_dir(dest)
        seed, _ = run_client(source, dest, flags=["-a", "--incremental"],
                             port=shared_server.port)
        assert seed.returncode == 0, (seed.stderr or seed.stdout)[:200]
        result, _ = run_client(source, dest, flags=["-a", "--incremental", "--info=name2"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]
        rsync_lines = sorted(l for l in rsync_result.stdout.splitlines()
                             if l.endswith("is uptodate"))
        fast_lines = sorted(l for l in result.stdout.splitlines()
                            if l.endswith("is uptodate"))
        assert fast_lines == rsync_lines, (rsync_lines, fast_lines)
        assert fast_lines == ["a.txt is uptodate", "sub/b.txt is uptodate"], fast_lines

    @requires_rsync
    @pytest.mark.ci
    def test_info_nonreg_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "inf_nr_src")
        dest = os.path.join(TEST_DATA_DIR, "inf_nr_dst")
        rdst = os.path.join(TEST_DATA_DIR, "inf_nr_rdst")
        clean_dir(source)
        os.mkfifo(os.path.join(source, "fifo"))
        _write(os.path.join(source, "a.txt"), b"a\n")
        clean_dir(dest)
        clean_dir(rdst)
        rsync_result = _rsync(["-rlt", "--info=nonreg", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["-rlt", "--info=nonreg"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]
        rsync_lines = sorted(l for l in rsync_result.stdout.splitlines()
                             if l.startswith("skipping non-regular"))
        fast_lines = sorted(l for l in result.stdout.splitlines()
                            if l.startswith("skipping non-regular"))
        assert fast_lines == rsync_lines, (rsync_lines, fast_lines)
        assert fast_lines, "no non-regular skip line emitted"

    @requires_rsync
    @pytest.mark.ci
    def test_info_del_real_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "inf_dl_src")
        dest = os.path.join(TEST_DATA_DIR, "inf_dl_dst")
        rdst = os.path.join(TEST_DATA_DIR, "inf_dl_rdst")
        clean_dir(source)
        _write(os.path.join(source, "keep.txt"), b"keep\n")
        clean_dir(rdst)
        _write(os.path.join(rdst, "extra.txt"), b"x\n")
        _write(os.path.join(rdst, "extra2.txt"), b"y\n")
        rsync_result = _rsync(["-a", "--delete", "--info=del", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_lines = sorted(l for l in rsync_result.stdout.splitlines()
                             if l.startswith("deleting "))

        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        _write(os.path.join(received, "extra.txt"), b"x\n")
        _write(os.path.join(received, "extra2.txt"), b"y\n")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["-a", "--delete", "--info=del"],
                                   port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]
        fast_lines = sorted(l for l in result.stdout.splitlines()
                            if l.startswith("deleting "))
        assert fast_lines == rsync_lines, (rsync_lines, fast_lines)
        assert fast_lines, "no deletion lines emitted"

    @requires_rsync
    @pytest.mark.ci
    def test_info_del_itemize_real_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "inf_di_src")
        dest = os.path.join(TEST_DATA_DIR, "inf_di_dst")
        rdst = os.path.join(TEST_DATA_DIR, "inf_di_rdst")
        clean_dir(source)
        _write(os.path.join(source, "keep.txt"), b"keep\n")
        clean_dir(rdst)
        _write(os.path.join(rdst, "extra.txt"), b"x\n")
        rsync_result = _rsync(["-a", "-i", "--delete", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_lines = sorted(l for l in rsync_result.stdout.splitlines()
                             if l.startswith("*deleting"))

        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        _write(os.path.join(received, "extra.txt"), b"x\n")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["-a", "-i", "--delete"],
                                   port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]
        fast_lines = sorted(l for l in result.stdout.splitlines()
                            if l.startswith("*deleting"))
        assert fast_lines == rsync_lines, (rsync_lines, fast_lines)

    @requires_rsync
    @pytest.mark.ci
    def test_info_del_dry_run_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "inf_dd_src")
        dest = os.path.join(TEST_DATA_DIR, "inf_dd_dst")
        rdst = os.path.join(TEST_DATA_DIR, "inf_dd_rdst")
        clean_dir(source)
        _write(os.path.join(source, "keep.txt"), b"keep\n")
        clean_dir(rdst)
        _write(os.path.join(rdst, "extra.txt"), b"x\n")
        rsync_result = _rsync(["-a", "-n", "--delete", "--info=del", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_lines = sorted(l for l in rsync_result.stdout.splitlines()
                             if l.startswith("deleting "))

        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        _write(os.path.join(received, "extra.txt"), b"x\n")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["-a", "-n", "--delete", "--info=del"],
                                   port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]
        fast_lines = sorted(l for l in result.stdout.splitlines()
                            if l.startswith("deleting "))
        assert fast_lines == rsync_lines, (rsync_lines, fast_lines)

    @requires_rsync
    @pytest.mark.ci
    def test_info_remove_matches_rsync(self, shared_server):
        tag = "inf_rm"
        rsync_src = os.path.join(TEST_DATA_DIR, f"{tag}_rsrc")
        rsync_dst = os.path.join(TEST_DATA_DIR, f"{tag}_rdst")
        fast_src = os.path.join(TEST_DATA_DIR, f"{tag}_fsrc")
        fast_dst = os.path.join(TEST_DATA_DIR, f"{tag}_fdst")
        for root in (rsync_src, rsync_dst, fast_src, fast_dst):
            clean_dir(root)
        _write(os.path.join(rsync_src, "a.txt"), b"a\n")
        _write(os.path.join(rsync_src, "sub", "b.txt"), b"b\n")
        _write(os.path.join(fast_src, "a.txt"), b"a\n")
        _write(os.path.join(fast_src, "sub", "b.txt"), b"b\n")

        rsync_result = _rsync(["-a", "--remove-source-files", "--info=remove",
                               rsync_src + "/", rsync_dst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_lines = sorted(l for l in rsync_result.stdout.splitlines()
                             if l.startswith("sender removed "))

        result, _ = run_client(fast_src, fast_dst,
                               flags=["-a", "--remove-source-files", "--info=remove"],
                               port=shared_server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]
        fast_lines = sorted(l for l in result.stdout.splitlines()
                            if l.startswith("sender removed "))
        assert fast_lines == rsync_lines, (rsync_lines, fast_lines)
        assert fast_lines, "no source-removal lines emitted"


class TestIgnoreErrorsParity:
    """--ignore-errors: a source I/O error skips deletion by default; the flag
    lets deletion proceed.  Both exit 23.  Run the client as an unprivileged user
    so the mode-000 directory is genuinely unreadable."""

    @pytest.mark.setpriv
    def test_delete_after_io_error_matches_rsync(self):
        if os.geteuid() != 0 or shutil.which("setpriv") is None:
            pytest.skip("requires root + setpriv to drop privileges for the client")
        tag = f"ie_{os.getpid()}"
        source = os.path.join(TEST_DATA_DIR, f"{tag}_src")
        rsync_dst = os.path.join(TEST_DATA_DIR, f"{tag}_rdst")
        dest = os.path.join(TEST_DATA_DIR, f"{tag}_dst")
        clean_dir(source)
        clean_dir(rsync_dst)
        clean_dir(dest)
        _write(os.path.join(source, "top.txt"), b"top\n")
        _write(os.path.join(source, "locked", "blocked.txt"), b"blocked\n")
        os.chmod(os.path.join(source, "locked"), 0)
        os.chmod(TEST_DATA_DIR, 0o777)
        os.chmod(source, 0o755)
        os.chmod(rsync_dst, 0o777)
        os.chmod(dest, 0o777)
        try:
            for ignore in (False, True):
                flags = ["-a", "--delete-after"] + (["--ignore-errors"] if ignore else [])
                # rsync side
                _write(os.path.join(rsync_dst, "extra.txt"), b"x\n")
                os.chmod(os.path.join(rsync_dst, "extra.txt"), 0o666)
                rres = _rsync(flags + [source + "/", rsync_dst + "/"], as_nobody=True)
                rsync_extra = os.path.exists(os.path.join(rsync_dst, "extra.txt"))

                # fastsync side
                received = get_dest_received_dir(dest, source)
                _write(os.path.join(received, "extra.txt"), b"x\n")
                os.chmod(os.path.join(received, "extra.txt"), 0o666)
                with ServerManager() as server:
                    server.start(extra_args=["--allow-delete"])
                    fflags = (["--delete", "--ignore-errors"] if ignore else ["--delete"])
                    cmd = CLIENT_CMD + ["--source-dir", source, "--dest-dir", dest,
                                        "--save-to-disk", "--server-port", str(server.port)] + fflags
                    fres = subprocess.run(
                        ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"] + cmd,
                        text=True, capture_output=True)
                fast_extra = os.path.exists(os.path.join(received, "extra.txt"))

                assert rres.returncode == 23, (ignore, rres.returncode, rres.stderr[:200])
                assert fres.returncode == 23, (ignore, fres.returncode, fres.stderr[:200])
                assert rsync_extra == fast_extra, (
                    f"ignore_errors={ignore}: rsync extra={rsync_extra} fastsync extra={fast_extra}"
                )
                assert fast_extra is (not ignore), (ignore, fast_extra)
        finally:
            os.chmod(os.path.join(source, "locked"), 0o755)


class TestRemoteOptionDaemon:
    """rsync forwards -M/--remote-option to its remote process over a daemon
    connection; FastSync's daemon has no per-connection argv channel and rejects
    it.  This pins the documented divergence with evidence."""

    @requires_rsync
    def test_rsync_forwards_M_over_daemon_and_fastsync_rejects(self, tmp_path):
        import socket

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        module_root = tmp_path / "mod"
        module_root.mkdir()
        os.chmod(module_root, 0o777)
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.txt").write_bytes(b"hello\n")
        conf = tmp_path / "rsyncd.conf"
        conf.write_text(
            f"port = {port}\nuse chroot = no\n[m]\npath = {module_root}\nread only = no\n"
        )
        daemon = subprocess.Popen(
            [RSYNC, "--daemon", "--no-detach", "--port", str(port), "--config", str(conf)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                pytest.skip("rsync daemon did not start")

            # A well-formed -M option is forwarded and accepted by the daemon...
            ok = _rsync(["-a", "-M--safe-links", source.as_posix() + "/",
                         f"rsync://127.0.0.1:{port}/m/"])
            # ...and a bogus one is rejected ON THE REMOTE with "unknown option",
            # which proves the option reached the daemon's parser.
            bogus = _rsync(["-a", "-M--totally-bogus", source.as_posix() + "/",
                            f"rsync://127.0.0.1:{port}/m/"])
            assert bogus.returncode != 0
            assert "unknown option" in (bogus.stderr + bogus.stdout), bogus.stderr
            del ok
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()

        # FastSync rejects -M for a non-SSH transport up front.
        dest = os.path.join(TEST_DATA_DIR, "ro_dst")
        clean_dir(dest)
        result, _ = run_client(source.as_posix(), dest, flags=["-a", "-M--safe-links"])
        assert result.returncode != 0
        assert "remote-option" in (result.stderr + result.stdout)


class TestFilterProtect:
    """Receiver-derived delete protection: a `protect`/`P` rule is compiled by
    the sender and sent on the config frame, so the receiver shields a
    destination-only entry that never appeared on the sender, matching rsync."""

    @requires_rsync
    @pytest.mark.ci
    def test_protect_dest_only_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "fpd_src")
        dest = os.path.join(TEST_DATA_DIR, "fpd_dst")
        rdst = os.path.join(TEST_DATA_DIR, "fpd_rdst")
        clean_dir(source)
        _write(os.path.join(source, "keep.txt"), b"keep\n")
        clean_dir(rdst)
        _write(os.path.join(rdst, "extra.log"), b"extra\n")
        _write(os.path.join(rdst, "other.txt"), b"other\n")

        rsync_result = _rsync(["-a", "--delete", "--filter=P *.log", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        assert os.path.exists(os.path.join(rdst, "extra.log")), "rsync did not protect extra.log"
        assert not os.path.exists(os.path.join(rdst, "other.txt")), "rsync did not delete other.txt"

        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        _write(os.path.join(received, "extra.log"), b"extra\n")
        _write(os.path.join(received, "other.txt"), b"other\n")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest,
                                   flags=["-a", "--delete", "--filter=P *.log"],
                                   port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:200]
        assert os.path.exists(os.path.join(received, "extra.log")), (
            "FastSync must protect a destination-only P match like rsync")
        assert not os.path.exists(os.path.join(received, "other.txt"))

    @pytest.mark.ci
    def test_protect_dest_only_dry_run_enumeration(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "fpd_nd_src")
        dest = os.path.join(TEST_DATA_DIR, "fpd_nd_dst")
        clean_dir(source)
        _write(os.path.join(source, "keep.txt"), b"keep\n")
        received = get_dest_received_dir(dest, source)
        clean_dir(received)
        _write(os.path.join(received, "keep.txt"), b"keep\n")
        _write(os.path.join(received, "extra.log"), b"extra\n")
        _write(os.path.join(received, "other.txt"), b"other\n")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest,
                                   flags=["-a", "-n", "--delete", "--out-format=%n",
                                          "--filter=P *.log"],
                                   port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        assert "other.txt" in result.stdout, result.stdout
        assert "extra.log" not in result.stdout, result.stdout
        assert os.path.exists(os.path.join(received, "extra.log"))
        assert os.path.exists(os.path.join(received, "other.txt"))

    @pytest.mark.ci
    def test_perdir_protect_dest_only_matches_rsync(self):
        """#315: a `P` rule inside a per-directory `.rsync-filter` is carried to
        the receiver, so a destination-only extra matching ONLY that rule is
        shielded under --delete.  Both roots carry the same filter file (rsync's
        receiver reads the destination one; FastSync carries the source's)."""
        source = os.path.join(TEST_DATA_DIR, "fpdp_src")
        dest = os.path.join(TEST_DATA_DIR, "fpdp_dst")
        rdst = os.path.join(TEST_DATA_DIR, "fpdp_rdst")
        clean_dir(source)
        _write(os.path.join(source, "keep.txt"), b"keep\n")
        _write(os.path.join(source, ".rsync-filter"), b"P extra.log\n")
        clean_dir(rdst)
        _write(os.path.join(rdst, ".rsync-filter"), b"P extra.log\n")
        _write(os.path.join(rdst, "extra.log"), b"extra\n")
        _write(os.path.join(rdst, "other.txt"), b"other\n")

        rsync_result = _rsync(["-aF", "--delete", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        assert os.path.exists(os.path.join(rdst, "extra.log")), "rsync did not protect extra.log"
        assert not os.path.exists(os.path.join(rdst, "other.txt"))

        clean_dir(dest)
        received = get_dest_received_dir(dest, source)
        os.makedirs(received, exist_ok=True)
        _write(os.path.join(received, ".rsync-filter"), b"P extra.log\n")
        _write(os.path.join(received, "extra.log"), b"extra\n")
        _write(os.path.join(received, "other.txt"), b"other\n")
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["-aF", "--delete"], port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        assert os.path.exists(os.path.join(received, "extra.log")), (
            "FastSync must protect a destination-only per-directory P match like rsync")
        assert not os.path.exists(os.path.join(received, "other.txt"))

    @requires_rsync
    @pytest.mark.ci
    def test_perdir_protect_dry_run_enumeration(self, shared_server):
        """#315: the -n/--dry-run would-delete enumeration also honors the
        carried per-directory rules, matching rsync's `*deleting` set: a
        destination-only entry matching only a `.rsync-filter` P rule is not
        reported (nor removed)."""
        source = os.path.join(TEST_DATA_DIR, "fpdp_nd_src")
        dest = os.path.join(TEST_DATA_DIR, "fpdp_nd_dst")
        rdst = os.path.join(TEST_DATA_DIR, "fpdp_nd_rdst")
        clean_dir(source)
        _write(os.path.join(source, "keep.txt"), b"keep\n")
        _write(os.path.join(source, ".rsync-filter"), b"P extra.log\n")
        received = get_dest_received_dir(dest, source)
        clean_dir(rdst)
        clean_dir(received)
        for root in (rdst, received):
            _write(os.path.join(root, "keep.txt"), b"keep\n")
            _write(os.path.join(root, ".rsync-filter"), b"P extra.log\n")
            _write(os.path.join(root, "extra.log"), b"extra\n")
            _write(os.path.join(root, "other.txt"), b"other\n")

        rsync_result = _rsync(["-an", "-i", "-F", "--delete", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        rsync_del = sorted(l for l in rsync_result.stdout.splitlines()
                           if l.startswith("*deleting"))
        assert rsync_del == ["*deleting   other.txt"], f"unexpected rsync set: {rsync_del}"

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["-aF", "-n", "-i", "--delete"],
                                   port=server.port)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        fs_del = sorted(l for l in (result.stdout or "").splitlines()
                        if l.startswith("*deleting"))
        assert fs_del == rsync_del, f"rsync={rsync_del}\nfastsync={fs_del}"
        assert os.path.exists(os.path.join(received, "extra.log"))
        assert os.path.exists(os.path.join(received, "other.txt"))
