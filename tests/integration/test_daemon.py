"""Daemon mode (--daemon + module config + host::module/path destinations) tests.

These exercise the Wave A daemon foundation end to end: a fastsync-server
started with --daemon reads a FastSync-native module config file, the client
asks for a module with a host::module/path destination, and the transfer lands
in the configured module root only.  Read-only modules, unknown modules, and
auth-required modules are all refused cleanly before any data moves.
"""
import glob
import os
import shutil
import signal
import subprocess
import sys
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
CONF_FILE = os.path.join(TEST_DATA_DIR, "fastsyncd.conf")
DETACH_MODULE = os.path.join(MODULE_ROOT, "detach")
DETACH_CONF = os.path.join(TEST_DATA_DIR, "fastsyncd_detach.conf")
DETACH_PORT = None


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

    def start(self, config_path, port_override=None):
        self.stop()
        # When no override is given the daemon binds the config file's `port`
        # (the plain config-port path); with an override the --dparam path.
        self._port = port_override if port_override is not None else _config_port(config_path)
        cmd = (SERVER_CMD + ["--daemon", "--config", config_path, "--allow-unauthenticated",
                             "--no-detach"])
        if port_override is not None:
            cmd += ["--dparam", f"port={port_override}"]
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
    for d in (MODULE_ROOT, FILES_MODULE, READONLY_MODULE, AUTH_MODULE, DETACH_MODULE):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)
    generate_test_files(SOURCE_DIR, full=False)

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
            % (config_port, FILES_MODULE, READONLY_MODULE, AUTH_MODULE))

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
    d.start(CONF_FILE)
    yield d
    d.stop()


def _push(dest, port):
    result, _ = run_client(SOURCE_DIR, dest, port=port)
    return result


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
        file_count = sum(len(files) for _, _, files in os.walk(READONLY_MODULE))
        assert file_count == 0, "read-only module must not receive any file"

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

    def test_auth_required_module_rejected(self, daemon):
        result = _push("127.0.0.1::locked", daemon.port)
        assert result.returncode != 0
        file_count = sum(len(files) for _, _, files in os.walk(AUTH_MODULE))
        assert file_count == 0

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
        d.start(CONF_FILE, port_override=override)
        try:
            result = _push("127.0.0.1::files", override)
            assert result.returncode == 0, result.stderr or result.stdout
            received = get_dest_received_dir(FILES_MODULE, SOURCE_DIR)
            _, missing = verify_transfer(SOURCE_DIR, received)
            assert not missing, f"missing: {missing[:5]}"
        finally:
            d.stop()