"""Shared pytest configuration for integration tests."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "integration"))

from common import ServerManager


@pytest.fixture(scope="session")
def shared_server():
    """One server for the entire test session. Avoids 27+ server start/stop cycles."""
    server = ServerManager()
    server.start()
    yield server
    server.stop()
