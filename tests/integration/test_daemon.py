"""Daemon mode (--daemon + module config + host::module/path destinations) tests.

These exercise the Wave A daemon foundation end to end: a fastsync-server
started with --daemon reads a FastSync-native module config file, the client
asks for a module with a host::module/path destination, and the transfer lands
in the configured module root only.  Read-only modules, unknown modules, and
auth-required modules without valid credentials are all refused cleanly before
any data moves.  Wave B (daemon authentication) adds the real credential
round-trips exercised in TestDaemonAuthentication: modules that declare
`auth users` accept only a client whose --password-file presents a username on
the module's list with a matching password (verified as a SHA-256 digest), and
the daemon refuses to start when such a module has no credential store.
"""
import glob
import hashlib
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    TEST_DATA_DIR,
    CLIENT_CMD,
    SERVER_CMD,
    generate_test_files,
    run_client,
    get_dest_received_dir,
    verify_transfer,
    _find_free_port,
    _wait_for_port,
)

SOURCE_DIR = os.path.join(TEST_DATA_DIR, "daemon_source")
MODULE_ROOT = os.path.join(TEST_DATA_DIR, "daemon_modules")
FILES_MODULE = os.path.join(MODULE_ROOT, "files")
READONLY_MODULE = os.path.join(MODULE_ROOT, "readonly")
AUTH_MODULE = os.path.join(MODULE_ROOT, "auth")
TEAM_MODULE = os.path.join(MODULE_ROOT, "team")
OWNER_MODULE = os.path.join(MODULE_ROOT, "owner")
CONF_FILE = os.path.join(TEST_DATA_DIR, "fastsyncd.conf")
CRED_FILE = os.path.join(TEST_DATA_DIR, "fastsyncd.passwd")
STARTFAIL_CONF = os.path.join(TEST_DATA_DIR, "fastsyncd_startfail.conf")
STARTFAIL_PORT = None
DETACH_MODULE = os.path.join(MODULE_ROOT, "detach")
DETACH_CONF = os.path.join(TEST_DATA_DIR, "fastsyncd_detach.conf")
DETACH_PORT = None

# Passwords are never sent as plaintext and never logged; these literals are
# only hashed into the server credential file / client password file.
ALICE_PASS = "alice-s3cret"
BOB_PASS = "bob-s3cret"
WRONG_PASS = "wrong-password"


def _pw_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


def _write_client_password_file(path, user, password):
    with open(path, "w") as f:
        f.write("%s:%s\n" % (user, password))
    return path


def _kill_by_cmdline_marker(marker):
    """Send SIGTERM to every running process whose cmdline contains `marker`
    (used to clean up the double-forked --daemon, which is orphaned to init and
    no longer a child of the test's own process).  Portable over /proc so the
    tests do not depend on pgrep being present."""
    for proc_path in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            with open(proc_path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        if marker.encode() in data:
            try:
                os.kill(int(proc_path.split("/")[2]), signal.SIGTERM)
            except (ProcessLookupError, ValueError):
                pass
    time.sleep(0.5)


class DaemonManager:
    """Boots one fastsync-server --daemon from a config file and tears it down
    (including its accept-loop children) on exit."""

    def __init__(self):
        self._proc = None
        self._port = None

    def start(self, config_path, port_override=None, extra_args=None):
        self.stop()
        # When no override is given the daemon binds the config file's `port`
        # (the plain config-port path); with an override the --dparam path.
        self._port = port_override if port_override is not None else _config_port(config_path)
        cmd = (SERVER_CMD + ["--daemon", "--config", config_path, "--allow-unauthenticated",
                             "--no-detach"])
        if port_override is not None:
            cmd += ["--dparam", f"port={port_override}"]
        if extra_args:
            cmd += extra_args
        log_path = os.path.join(TEST_DATA_DIR, "fastsyncd.log")
        log = open(log_path, "w")
        self._proc = subprocess.Popen(
            cmd, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
        _wait_for_port(self._port, timeout=10)

    def stop(self):
        if self._proc:
            try:
                os.killpg(self._proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self._proc.pid, signal.SIGKILL)
                self._proc.wait()
            self._proc = None

    @property
    def port(self):
        return self._port

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()

    def __del__(self):
        self.stop()


def _config_port(config_path):
    """Read the explicit `port = N` line out of the daemon config file."""
    with open(config_path) as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("port") and "=" in stripped:
                return int(stripped.split("=", 1)[1].strip())
    raise RuntimeError(f"no port= in {config_path}")


@pytest.fixture(scope="module", autouse=True)
def daemon_env():
    for d in (MODULE_ROOT, FILES_MODULE, READONLY_MODULE, AUTH_MODULE, TEAM_MODULE, OWNER_MODULE,
              DETACH_MODULE):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)
    generate_test_files(SOURCE_DIR, full=False)

    # Server-side credential store: alice and bob (password digests only; the
    # plaintext passwords never appear on the daemon host or in any log).
    with open(CRED_FILE, "w") as f:
        f.write("# daemon credential store (Wave B)\n")
        f.write("alice:%s\n" % _pw_hash(ALICE_PASS))
        f.write("bob:%s\n" % _pw_hash(BOB_PASS))

    # The config's port is a free port chosen per worker; the `daemon` fixture
    # boots on it (the config-port path) and the --dparam override test boots a
    # second daemon on a different port.
    config_port = _find_free_port()
    with open(CONF_FILE, "w") as f:
        f.write(
            "# FastSync-native daemon config (Wave A grammar)\n"
            "port = %d\n"
            "\n"
            "[files]\n"
            "path = %s\n"
            "\n"
            "[readonly]\n"
            "path = %s\n"
            "read only = yes\n"
            "\n"
            "[locked]\n"
            "path = %s\n"
            "auth users = alice\n"
            "\n"
            "[team]\n"
            "path = %s\n"
            "auth users = alice,bob\n"
            "\n"
            "[owner]\n"
            "path = %s\n"
            "client owner = yes\n"
            % (config_port, FILES_MODULE, READONLY_MODULE, AUTH_MODULE, TEAM_MODULE, OWNER_MODULE))

    # A dedicated config for the fail-closed startup check: an auth-required
    # module with no credential store must refuse to start.  Its own free port
    # keeps it independent of the running daemon.
    global STARTFAIL_PORT
    STARTFAIL_PORT = _find_free_port()
    with open(STARTFAIL_CONF, "w") as f:
        f.write("port = %d\n\n[locked]\npath = %s\nauth users = alice\n"
                % (STARTFAIL_PORT, AUTH_MODULE))

    # A dedicated config for the real (double-fork) detach test: an unique path
    # lets cleanup identify and kill the orphaned background daemon by cmdline.
    global DETACH_PORT
    DETACH_PORT = _find_free_port()
    with open(DETACH_CONF, "w") as f:
        f.write("port = %d\n\n[detach]\npath = %s\n" % (DETACH_PORT, DETACH_MODULE))

    yield
    _kill_by_cmdline_marker(DETACH_CONF)
    shutil.rmtree(MODULE_ROOT, ignore_errors=True)
    shutil.rmtree(SOURCE_DIR, ignore_errors=True)


@pytest.fixture(scope="module")
def daemon():
    d = DaemonManager()
    d.start(CONF_FILE, extra_args=["--password-file", CRED_FILE])
    yield d
    d.stop()


def _push(dest, port):
    result, _ = run_client(SOURCE_DIR, dest, port=port)
    return result


def _push_with_creds(dest, port, user, password):
    """Push using a --password-file carrying user:password (a fresh temp file
    each call so tests never share mutable state)."""
    cred_path = os.path.join(TEST_DATA_DIR, f"client_{user}_{os.getpid()}_{time.time_ns()}.pw")
    _write_client_password_file(cred_path, user, password)
    try:
        result, _ = run_client(SOURCE_DIR, dest, port=port,
                               extra_args=["--password-file", cred_path])
        return result
    finally:
        os.unlink(cred_path)


def _tree_file_count(root):
    return sum(len(files) for _, _, files in os.walk(root)) if os.path.exists(root) else 0


def _can_mknod():
    """True when this process may create a char device (needs root/CAP_MKNOD)."""
    probe = os.path.join(tempfile.gettempdir(), "._fastsync_mknod_probe_%d" % os.getpid())
    try:
        os.mknod(probe, stat.S_IFCHR | 0o600, os.makedev(1, 3))
        os.unlink(probe)
        return True
    except (OSError, AttributeError):
        try:
            os.unlink(probe)
        except OSError:
            pass
        return False


class TestDaemonModuleSelection:
    @pytest.mark.ci
    def test_module_transfer(self, daemon):
        """A host::module/path destination lands inside the module root only."""
        result = _push("127.0.0.1::files", daemon.port)
        assert result.returncode == 0, result.stderr or result.stdout
        received = get_dest_received_dir(FILES_MODULE, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"missing: {missing[:5]}"
        assert not mismatches, f"mismatch: {mismatches[:5]}"

    def test_module_subtree(self, daemon):
        """The /path part of host::module/path is relative inside the module."""
        sub = os.path.join(FILES_MODULE, "subtree")
        os.makedirs(sub, exist_ok=True)
        result = _push("127.0.0.1::files/subtree", daemon.port)
        assert result.returncode == 0, result.stderr or result.stdout
        received = get_dest_received_dir(sub, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"missing: {missing[:5]}"
        assert not mismatches, f"mismatch: {mismatches[:5]}"


class TestDaemonRejection:
    def _tree_files(self):
        """Snapshot every file path (module-relative) currently under the module
        root tree, so confinement can be asserted by diff rather than by an
        absolute 'empty' check (other tests legitimately populate modules)."""
        files = set()
        for root, _, names in os.walk(MODULE_ROOT):
            for name in names:
                full = os.path.join(root, name)
                files.add(os.path.relpath(full, MODULE_ROOT))
        return files

    def test_read_only_module_blocked(self, daemon):
        result = _push("127.0.0.1::readonly", daemon.port)
        assert result.returncode != 0
        assert _tree_file_count(READONLY_MODULE) == 0, "read-only module must not receive a file"

    def test_read_only_no_write_anywhere(self, daemon):
        """A refused read-only transfer must not add a single file anywhere under
        the module root tree (negative confinement, not just the target)."""
        before = self._tree_files()
        result = _push("127.0.0.1::readonly", daemon.port)
        assert result.returncode != 0
        assert self._tree_files() == before, "read-only rejection wrote under the module root"

    def test_unknown_module_rejected(self, daemon):
        result = _push("127.0.0.1::no-such-module", daemon.port)
        assert result.returncode != 0

    def test_unknown_module_no_write_anywhere(self, daemon):
        """An unknown module must be refused cleanly before any file lands
        anywhere beneath the module root tree."""
        before = self._tree_files()
        result = _push("127.0.0.1::no-such-module", daemon.port)
        assert result.returncode != 0
        assert self._tree_files() == before, "unknown-module rejection wrote under the module root"

    def test_module_less_destination_rejected(self, daemon):
        """A daemon destination with no module name (host::/path) is refused at
        parse time, before any connection payload is sent."""
        result = _push("127.0.0.1::", daemon.port)
        assert result.returncode != 0
        result = _push("127.0.0.1::/sub", daemon.port)
        assert result.returncode != 0

    def test_dotdot_destination_rejected(self, daemon):
        """A '..' path expansion in the module-relative path is refused at parse
        time so a client cannot escape the module root while it is still on the
        client side of the wire."""
        result = _push("127.0.0.1::files/../..", daemon.port)
        assert result.returncode != 0

    def test_auth_module_without_credentials_rejected(self, daemon):
        """Wave B: an auth-required module refuses a client that presents no
        credentials (the daemon does not fall open)."""
        result = _push("127.0.0.1::locked", daemon.port)
        assert result.returncode != 0
        assert _tree_file_count(AUTH_MODULE) == 0

    def _assert_ownership_refused(self, daemon, module, flags):
        """A daemon module without `client owner = yes` refuses every
        client-chosen ownership / super-user request at the config handshake,
        before any data lands."""
        log_path = os.path.join(TEST_DATA_DIR, "fastsyncd.log")
        before = os.path.getsize(log_path) if os.path.exists(log_path) else 0
        before_files = self._tree_files()
        result, _ = run_client(SOURCE_DIR, f"127.0.0.1::{module}", port=daemon.port, flags=flags)
        assert result.returncode != 0, f"the daemon must refuse {flags}"
        assert self._tree_files() == before_files, \
            f"{flags} refusal wrote under the module root"
        time.sleep(0.3)
        with open(log_path, "rb") as f:
            f.seek(before)
            tail = f.read().decode("utf-8", "replace")
        assert "client-chosen ownership" in tail, (
            f"daemon did not log the ownership refusal: {tail[-400:]!r}"
        )

    def test_copy_as_refused_by_daemon(self, daemon):
        """P7 Wave E hardening: a daemon refuses client-chosen ownership
        (--copy-as) outright unless the module opts in with `client owner = yes`,
        so even a root daemon must not honor an arbitrary client-selected owner
        by default.  The refusal happens at the config handshake, before any data
        lands."""
        self._assert_ownership_refused(daemon, "files", ["--copy-as=@65534:@65534"])

    def test_super_refused_by_daemon(self, daemon):
        """An explicit --super is a super-user activity request, so a daemon
        module refuses it unless it opts in with `client owner = yes`.  The
        refusal happens at the config handshake, before any data lands."""
        self._assert_ownership_refused(daemon, "files", ["--super", "--preserve"])

    def test_numeric_ids_refused_by_daemon(self, daemon):
        """P7 Wave E hardening (A1): the daemon ownership gate must cover the
        pre-existing identity flags too, not only --copy-as/--super.  A module
        without `client owner = yes` refuses --numeric-ids at the handshake."""
        self._assert_ownership_refused(daemon, "files", ["--numeric-ids", "--preserve"])

    def test_chown_refused_by_daemon(self, daemon):
        """--chown is client-chosen ownership too and must be refused by a
        non-opted-in module."""
        self._assert_ownership_refused(daemon, "files", ["--chown=@65534:@65534", "--preserve"])

    def test_owner_opt_in_allows_numeric_ids(self, daemon):
        """A module that opts in with `client owner = yes` accepts the
        client-chosen ownership flags (here --numeric-ids); the transfer
        succeeds and lands inside that module root."""
        result, _ = run_client(SOURCE_DIR, "127.0.0.1::owner", port=daemon.port,
                               flags=["--numeric-ids", "--preserve"])
        assert result.returncode == 0, result.stderr or result.stdout
        received = get_dest_received_dir(OWNER_MODULE, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"missing: {missing[:5]}"
        assert not mismatches, f"mismatch: {mismatches[:5]}"

    def _device_source(self, name):
        src = os.path.join(TEST_DATA_DIR, name)
        shutil.rmtree(src, ignore_errors=True)
        os.makedirs(src)
        with open(os.path.join(src, "f.txt"), "wb") as fh:
            fh.write(b"device gate\n")
        os.mknod(os.path.join(src, "null"), stat.S_IFCHR | 0o666, os.makedev(1, 3))
        return src

    @pytest.mark.skipif(not _can_mknod(), reason="device nodes need root/CAP_MKNOD")
    def test_devices_skipped_without_owner_opt_in(self, daemon):
        """H3: a non-opted daemon module must not create device nodes even under
        the default AUTO super mode (a root daemon would otherwise let any client
        mknod arbitrary devices).  An ordinary -a push still succeeds; the device
        entry is skipped."""
        src = self._device_source("devsrc_noowner")
        os.makedirs(os.path.join(FILES_MODULE, "devskip"), exist_ok=True)
        result, _ = run_client(src, "127.0.0.1::files/devskip", port=daemon.port, flags=["-a"])
        assert result.returncode == 0, result.stderr or result.stdout
        received = get_dest_received_dir(os.path.join(FILES_MODULE, "devskip"), src)
        node = os.path.join(received, "null")
        assert not os.path.exists(node) or not stat.S_ISCHR(os.stat(node).st_mode), \
            "non-opted daemon module created a device node"

    @pytest.mark.skipif(not _can_mknod(), reason="device nodes need root/CAP_MKNOD")
    def test_devices_created_with_owner_opt_in(self, daemon):
        """Control: an opted-in module (`client owner = yes`) may create device
        nodes under -a, proving the clamp is specific to non-opted modules."""
        src = self._device_source("devsrc_owner")
        os.makedirs(os.path.join(OWNER_MODULE, "devok"), exist_ok=True)
        result, _ = run_client(src, "127.0.0.1::owner/devok", port=daemon.port, flags=["-a"])
        assert result.returncode == 0, result.stderr or result.stdout
        received = get_dest_received_dir(os.path.join(OWNER_MODULE, "devok"), src)
        node = os.path.join(received, "null")
        assert os.path.exists(node) and stat.S_ISCHR(os.stat(node).st_mode), \
            "opted-in daemon module did not create the device node"

    @pytest.mark.daemon_detach
    def test_real_detach_path(self):
        """--daemon WITHOUT --no-detach double-forks a real background daemon;
        a client can still transfer into the module root, and the orphaned
        process is terminated cleanly (via SIGTERM after polling the port)."""
        log_path = os.path.join(TEST_DATA_DIR, "fastsyncd_detach.log")
        log = open(log_path, "w")
        cmd = SERVER_CMD + ["--daemon", "--config", DETACH_CONF, "--allow-unauthenticated"]
        proc = subprocess.Popen(cmd, stdout=log, stderr=log, stdin=subprocess.DEVNULL)
        try:
            _wait_for_port(DETACH_PORT, timeout=15)
            result = _push("127.0.0.1::detach", DETACH_PORT)
            assert result.returncode == 0, result.stderr or result.stdout
            received = get_dest_received_dir(DETACH_MODULE, SOURCE_DIR)
            _, missing = verify_transfer(SOURCE_DIR, received)
            assert not missing, f"missing: {missing[:5]}"
        finally:
            _kill_by_cmdline_marker(DETACH_CONF)

    def test_plaintext_requires_allow_unauthenticated(self):
        """Secure default: a daemon started WITHOUT --allow-unauthenticated must
        refuse a plaintext client (same posture as the standalone server)."""
        d = DaemonManager()
        port = _find_free_port()
        log_path = os.path.join(TEST_DATA_DIR, "fastsyncd_noauth.log")
        log = open(log_path, "w")
        cmd = SERVER_CMD + ["--daemon", "--config", CONF_FILE, "--no-detach",
                            "--password-file", CRED_FILE,
                            "--dparam", f"port={port}"]
        d._proc = subprocess.Popen(cmd, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                                   start_new_session=True)
        d._port = port
        _wait_for_port(port, timeout=10)
        try:
            result = _push("127.0.0.1::files", port)
            assert result.returncode != 0
        finally:
            d.stop()

    def test_dparam_port_override(self):
        """--dparam port=N overrides the config's port and the daemon serves on N."""
        override = _find_free_port()
        d = DaemonManager()
        d.start(CONF_FILE, port_override=override, extra_args=["--password-file", CRED_FILE])
        try:
            result = _push("127.0.0.1::files", override)
            assert result.returncode == 0, result.stderr or result.stdout
            received = get_dest_received_dir(FILES_MODULE, SOURCE_DIR)
            _, missing = verify_transfer(SOURCE_DIR, received)
            assert not missing, f"missing: {missing[:5]}"
        finally:
            d.stop()


class TestDaemonAuthentication:
    """Wave B password authentication round-trips on the shared daemon (its
    config declares `locked` with `auth users = alice` and `team` with
    `auth users = alice,bob`; the server runs with CRED_FILE holding alice and
    bob digest entries)."""

    def test_correct_password_succeeds(self, daemon):
        result = _push_with_creds("127.0.0.1::locked", daemon.port, "alice", ALICE_PASS)
        assert result.returncode == 0, result.stderr or result.stdout
        received = get_dest_received_dir(AUTH_MODULE, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"missing: {missing[:5]}"
        assert not mismatches, f"mismatch: {mismatches[:5]}"

    def test_wrong_password_rejected_no_data(self, daemon):
        before = _tree_file_count(AUTH_MODULE)
        result = _push_with_creds("127.0.0.1::locked", daemon.port, "alice", WRONG_PASS)
        assert result.returncode != 0
        assert _tree_file_count(AUTH_MODULE) == before, "wrong password must not write a file"

    def test_unknown_user_rejected(self, daemon):
        """A user with a valid-shaped password but no store entry is refused
        (the daemon must not fall open for unknown users)."""
        before = _tree_file_count(AUTH_MODULE)
        result = _push_with_creds("127.0.0.1::locked", daemon.port, "mallory", WRONG_PASS)
        assert result.returncode != 0
        assert _tree_file_count(AUTH_MODULE) == before

    def test_user_not_on_module_list_rejected(self, daemon):
        """bob's credentials verify against the store, but bob is not on the
        `locked` module's auth users list, so the connection is refused."""
        before = _tree_file_count(AUTH_MODULE)
        result = _push_with_creds("127.0.0.1::locked", daemon.port, "bob", BOB_PASS)
        assert result.returncode != 0
        assert _tree_file_count(AUTH_MODULE) == before

    def test_second_module_user_succeeds(self, daemon):
        """bob IS on the `team` module's list, so his correct password works
        there (module list + credential store both gate)."""
        result = _push_with_creds("127.0.0.1::team", daemon.port, "bob", BOB_PASS)
        assert result.returncode == 0, result.stderr or result.stdout
        received = get_dest_received_dir(TEAM_MODULE, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"missing: {missing[:5]}"
        assert not mismatches, f"mismatch: {mismatches[:5]}"

    def test_missing_password_file_rejected(self, daemon):
        """A client with no --password-file at all is refused by an auth-required
        module (no credentials on the wire)."""
        result = _push("127.0.0.1::locked", daemon.port)
        assert result.returncode != 0

    def test_open_module_ignores_credentials(self, daemon):
        """A module WITHOUT `auth users` stays open: credentials sent
        opportunistically (even wrong ones) are ignored, not required."""
        result = _push_with_creds("127.0.0.1::files", daemon.port, "alice", WRONG_PASS)
        assert result.returncode == 0, result.stderr or result.stdout

    def test_read_only_still_refuses_authenticated_client(self, daemon):
        """Read-only is orthogonal to auth: an authenticated push to a read-only
        module is still refused with no data written (Wave A behavior)."""
        before = _tree_file_count(READONLY_MODULE)
        result = _push_with_creds("127.0.0.1::readonly", daemon.port, "alice", ALICE_PASS)
        assert result.returncode != 0
        assert _tree_file_count(READONLY_MODULE) == before

    def test_password_file_requires_daemon_dest(self, daemon):
        """Client-side: --password-file without a host::module/path destination is
        a client error (fail fast), not a silently ignored flag."""
        cred_path = os.path.join(TEST_DATA_DIR, "client_local.pw")
        _write_client_password_file(cred_path, "alice", ALICE_PASS)
        try:
            # A plain (non-::) destination with --password-file is rejected client-side.
            cmd = CLIENT_CMD + ["--source-dir", SOURCE_DIR, "--dest-dir", "/tmp/local-dest-xyz",
                                "--save-to-disk", "--password-file", cred_path,
                                "--server-port", str(daemon.port)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            assert result.returncode != 0
            assert "host::module/path" in (result.stderr or result.stdout)
        finally:
            os.unlink(cred_path)

    def test_client_empty_password_file_rejected(self):
        """Client-side: an empty --password-file is rejected (no credentials)."""
        cred_path = os.path.join(TEST_DATA_DIR, "client_empty.pw")
        with open(cred_path, "w") as f:
            f.write("# nothing here\n")
        try:
            cmd = CLIENT_CMD + ["--source-dir", SOURCE_DIR,
                                "--dest-dir", "127.0.0.1::files",
                                "--save-to-disk", "--password-file", cred_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            assert result.returncode != 0
            assert "no 'user:password'" in (result.stderr or result.stdout)
        finally:
            os.unlink(cred_path)

    def test_daemon_fails_closed_without_credential_store(self):
        """Fail-closed startup: a config with an auth-required module but no
        --password-file/--early-input refuses to start (never serves open)."""
        proc = subprocess.run(
            SERVER_CMD + ["--daemon", "--config", STARTFAIL_CONF, "--no-detach"],
            capture_output=True, text=True, timeout=15)
        assert proc.returncode != 0
        assert "fail closed" in (proc.stderr or proc.stdout)

    def test_daemon_early_input_feeds_credential_store(self):
        """--early-input is an alternative credential store source: a daemon
        started with --early-input (and no --password-file) authenticates alice."""
        d = DaemonManager()
        port = _find_free_port()
        try:
            d.start(CONF_FILE, port_override=port, extra_args=["--early-input", CRED_FILE])
            result = _push_with_creds("127.0.0.1::locked", port, "alice", ALICE_PASS)
            assert result.returncode == 0, result.stderr or result.stdout
            # Wrong password over the early-input store is still rejected.
            result = _push_with_creds("127.0.0.1::locked", port, "alice", WRONG_PASS)
            assert result.returncode != 0
        finally:
            d.stop()

    def test_auth_log_does_not_leak_password(self, daemon):
        """The daemon log must never contain the password or its digest."""
        log_path = os.path.join(TEST_DATA_DIR, "fastsyncd.log")
        before = os.path.getsize(log_path) if os.path.exists(log_path) else 0
        _push_with_creds("127.0.0.1::locked", daemon.port, "alice", WRONG_PASS)
        _push_with_creds("127.0.0.1::locked", daemon.port, "alice", ALICE_PASS)
        time.sleep(0.3)
        with open(log_path, "rb") as f:
            f.seek(before)
            tail = f.read().decode("utf-8", "replace")
        assert ALICE_PASS not in tail
        assert WRONG_PASS not in tail
        assert _pw_hash(ALICE_PASS) not in tail
        assert _pw_hash(WRONG_PASS) not in tail

    def test_auth_digest_not_logged_at_debug_level(self):
        """Under --verbose the daemon enables LOG_DEBUG_ALL, which normally
        traces every protocol string -- the auth username/digest must NOT leak
        into that trace even then.  The redacted marker is logged instead, and
        the digest/username/password never appear while debug protocol logging
        is actually proving itself active."""
        d = DaemonManager()
        port = _find_free_port()
        try:
            d.start(CONF_FILE, port_override=port, extra_args=["--verbose",
                                                               "--password-file", CRED_FILE])
            _push_with_creds("127.0.0.1::locked", port, "alice", ALICE_PASS)
            _push_with_creds("127.0.0.1::locked", port, "alice", WRONG_PASS)
            time.sleep(0.3)
            log_path = os.path.join(TEST_DATA_DIR, "fastsyncd.log")
            with open(log_path, "rb") as f:
                log = f.read().decode("utf-8", "replace")
        finally:
            d.stop()
        # Debug protocol tracing is genuinely active on the server: the auth
        # fields were received (redacted marker) so the leak path is exercised.
        assert "Received String: <redacted>" in log
        # The secret-worthy fields must never appear, at any log level.
        assert ALICE_PASS not in log
        assert WRONG_PASS not in log
        assert _pw_hash(ALICE_PASS) not in log
        assert _pw_hash(WRONG_PASS) not in log


class TestDaemonMotd:
    """Wave C MOTD: a daemon configured with a global `motd file` sends it to a
    host::module/path client right after the config/auth handshake; the client
    shows it on stdout unless --no-motd suppresses the display.  The MOTD is
    escaped at display time so a hostile motd cannot inject terminal escapes.

    Each test boots its own motd-configured daemon (the shared `daemon` fixture
    config has no `motd file`).  The MOTD is only sent on the daemon listener
    path; these all exercise `host::module` connections.
    """

    MOTD_MODULE = os.path.join(MODULE_ROOT, "motd_module")
    MOTD_CONF = os.path.join(TEST_DATA_DIR, "fastsyncd_motd.conf")

    def _start(self, motd_path):
        port = _find_free_port()
        motd_line = "motd file = %s\n" % motd_path if motd_path else ""
        os.makedirs(self.MOTD_MODULE, exist_ok=True)
        with open(self.MOTD_CONF, "w") as f:
            f.write("port = %d\n%s\n[files]\npath = %s\n" % (port, motd_line, self.MOTD_MODULE))
        d = DaemonManager()
        d.start(self.MOTD_CONF, port_override=port)
        return d, port

    def _push(self, port, extra_args=None):
        result, _ = run_client(SOURCE_DIR, "127.0.0.1::files", port=port,
                               extra_args=extra_args)
        return result

    @pytest.mark.ci
    def test_motd_displayed(self):
        motd_path = os.path.join(TEST_DATA_DIR, "fastsyncd_motd_banner.txt")
        banner = "Welcome to the FastSync test daemon\nSecond line here.\n"
        with open(motd_path, "w") as f:
            f.write(banner)
        d, port = self._start(motd_path)
        try:
            result = self._push(port)
            assert result.returncode == 0, result.stderr or result.stdout
            assert "Welcome to the FastSync test daemon" in (result.stdout or "")
            assert "Second line here." in (result.stdout or "")
        finally:
            d.stop()

    def test_motd_no_motd_suppresses_display(self):
        motd_path = os.path.join(TEST_DATA_DIR, "fastsyncd_motd_banner2.txt")
        banner = "This banner must never be shown.\n"
        with open(motd_path, "w") as f:
            f.write(banner)
        d, port = self._start(motd_path)
        try:
            result = self._push(port, extra_args=["--no-motd"])
            assert result.returncode == 0, result.stderr or result.stdout
            assert banner.strip() not in (result.stdout or "")
        finally:
            d.stop()

    def test_motd_absent_motd_file_no_error(self):
        d, port = self._start(os.path.join(TEST_DATA_DIR, "no-such-motd-file.txt"))
        try:
            result = self._push(port)
            assert result.returncode == 0, result.stderr or result.stdout
            assert "no-such-motd" not in (result.stdout or "")
        finally:
            d.stop()

    def test_motd_no_config_key_sends_no_banner(self):
        d, port = self._start(None)
        try:
            result = self._push(port)
            assert result.returncode == 0, result.stderr or result.stdout
            assert "FastSync test daemon" not in (result.stdout or "")
            assert "banner" not in (result.stdout or "")
        finally:
            d.stop()

    def test_motd_control_bytes_are_escaped(self):
        """A hostile motd (ANSI escape sequences) is displayed with every
        control byte escaped octal-style, so no terminal escape reaches the
        controlling terminal.  The transfer still succeeds (the motd is only
        display text, never a wire/transfer hazard)."""
        motd_path = os.path.join(TEST_DATA_DIR, "fastsyncd_motd_hostile.txt")
        with open(motd_path, "w") as f:
            f.write("hello\033[31mred\033[0m\n")
        d, port = self._start(motd_path)
        try:
            result = self._push(port)
            assert result.returncode == 0, result.stderr or result.stdout
            assert "\x1b" not in (result.stdout or ""), "raw ESC byte leaked to stdout"
            assert "\\#033[31m" in (result.stdout or ""), result.stdout
            assert "\\#033[0m" in (result.stdout or ""), result.stdout
        finally:
            d.stop()


def _generate_tls_certs(cert_dir):
    """Generate a self-signed CA, server cert (with 127.0.0.1 SAN) and a client
    cert signed by that CA, for the TLS+auth composition test."""
    os.makedirs(cert_dir, exist_ok=True)
    ca_key, ca_cert = os.path.join(cert_dir, "ca.key"), os.path.join(cert_dir, "ca.pem")
    server_key = os.path.join(cert_dir, "server.key")
    server_cert = os.path.join(cert_dir, "server.pem")
    client_key = os.path.join(cert_dir, "client.key")
    client_cert = os.path.join(cert_dir, "client.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", ca_key, "-out", ca_cert, "-days", "1",
                    "-subj", "/CN=FastSync Test CA"], check=True, capture_output=True)
    san = os.path.join(cert_dir, "san.conf")
    with open(san, "w") as f:
        f.write("[req]\ndistinguished_name = dn\nreq_extensions = v3_req\n\n"
                "[dn]\nCN = localhost\n\n[v3_req]\nsubjectAltName = @an\n\n"
                "[an]\nDNS.1 = localhost\nIP.1 = 127.0.0.1\n")
    subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", server_key, "-out", os.path.join(cert_dir, "server.csr"),
                    "-subj", "/CN=localhost", "-config", san], check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-req", "-in", os.path.join(cert_dir, "server.csr"),
                    "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial",
                    "-out", server_cert, "-days", "1",
                    "-extfile", san, "-extensions", "v3_req"], check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", client_key, "-out", os.path.join(cert_dir, "client.csr"),
                    "-subj", "/CN=fastsync-client"], check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-req", "-in", os.path.join(cert_dir, "client.csr"),
                    "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial",
                    "-out", client_cert, "-days", "1"], check=True, capture_output=True)
    return {
        "ca": ca_cert,
        "server_cert": server_cert,
        "server_key": server_key,
        "client_cert": client_cert,
        "client_key": client_key,
    }


@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl CLI required to mint test certificates")
class TestDaemonTLSAuth:
    """TLS + password-auth composition: --client-cn (TLS client identity) and
    the module password credential check are independent; both can be required
    on the same auth-required module.  Env-dependent: needs the openssl CLI."""

    def test_tls_and_password_auth_compose(self):
        cert_dir = os.path.join(TEST_DATA_DIR, "daemon_tls_certs")
        certs = _generate_tls_certs(cert_dir)
        client_creds = os.path.join(TEST_DATA_DIR, "daemon_tls_client.pw")
        _write_client_password_file(client_creds, "alice", ALICE_PASS)
        d = DaemonManager()
        port = _find_free_port()
        try:
            d.start(CONF_FILE, port_override=port, extra_args=[
                "--tls", "--cert", certs["server_cert"], "--key", certs["server_key"],
                "--ca", certs["ca"], "--client-cn", "fastsync-client",
                "--password-file", CRED_FILE])
            tls_flags = ["--tls",
                         "--cert", certs["client_cert"], "--key", certs["client_key"],
                         "--ca", certs["ca"]]
            # Correct password over TLS, with the right client CN: succeeds.
            result, _ = run_client(SOURCE_DIR, "127.0.0.1::locked", port=port,
                                   flags=tls_flags, extra_args=["--password-file", client_creds])
            assert result.returncode == 0, (result.stderr or result.stdout)[:300]
            # Wrong password over TLS is still refused by the credential check.
            bad_creds = os.path.join(TEST_DATA_DIR, "daemon_tls_client_bad.pw")
            _write_client_password_file(bad_creds, "alice", WRONG_PASS)
            result, _ = run_client(SOURCE_DIR, "127.0.0.1::locked", port=port,
                                   flags=tls_flags, extra_args=["--password-file", bad_creds])
            assert result.returncode != 0
            os.unlink(bad_creds)
        finally:
            d.stop()
            os.unlink(client_creds)
            shutil.rmtree(cert_dir, ignore_errors=True)
