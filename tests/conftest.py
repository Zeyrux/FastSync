"""Shared pytest configuration for integration tests."""
import os
import shutil
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "integration"))

from common import ServerManager, TEST_DATA_DIR


@pytest.fixture(scope="session")
def shared_server():
    """One server for the entire test session. Avoids 27+ server start/stop cycles.

    Under pytest-xdist this session fixture is instantiated once per worker
    process, so each worker gets its own server on an ephemeral port."""
    server = ServerManager()
    # --allow-super keeps the historical permissive super mode for a root
    # receiver: the integration suite's root-only ownership/device/copy-as tests
    # exercise that opted-in configuration.  The secure default (a root
    # standalone server without --allow-super forces SUPER_MODE_OFF) is covered
    # explicitly by TestStandaloneSuperDefault in test_features.py.  Non-root
    # runs are unaffected by the flag.
    server.start(extra_args=["--allow-super"])
    yield server
    server.stop()


@pytest.fixture(scope="session", autouse=True)
def _cleanup_worker_test_data():
    """Remove this (worker-keyed) TEST_DATA_DIR at the end of the session.

    Modules clean only their own rows; this final pass ensures the per-worker
    directory never lingers in the working tree."""
    yield
    shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
