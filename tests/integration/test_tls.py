"""TLS transport tests. Generates self-signed certs for testing."""
import os
import shutil
import subprocess
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    PROJECT_ROOT, BUILD_DIR, SERVER_CMD, TEST_DATA_DIR,
    ServerManager, run_client,
    generate_test_files, verify_transfer, clean_dir, make_result,
    get_dest_received_dir, _find_free_port, _wait_proc,
)

SOURCE_DIR = os.path.join(TEST_DATA_DIR, "tls_source")
DEST_DIR = os.path.join(TEST_DATA_DIR, "tls_dest")
CERT_DIR = os.path.join(TEST_DATA_DIR, "tls_certs")


def _generate_certs(cert_dir):
    """Generate a self-signed CA, server cert, and client cert for testing."""
    os.makedirs(cert_dir, exist_ok=True)
    ca_key = os.path.join(cert_dir, "ca.key")
    ca_cert = os.path.join(cert_dir, "ca.pem")
    server_key = os.path.join(cert_dir, "server.key")
    server_cert = os.path.join(cert_dir, "server.pem")
    client_key = os.path.join(cert_dir, "client.key")
    client_cert = os.path.join(cert_dir, "client.pem")

    # CA key + cert
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", ca_key, "-out", ca_cert,
        "-days", "1", "-subj", "/CN=FastSync Test CA",
    ], check=True, capture_output=True)

    # Server key + CSR + cert (signed by CA)
    # Use a config file to include IP SAN 127.0.0.1 so hostname verification passes
    san_config = os.path.join(cert_dir, "server_san.conf")
    with open(san_config, "w") as f:
        f.write("[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = v3_req\n\n")
        f.write("[req_distinguished_name]\nCN = localhost\n\n")
        f.write("[v3_req]\nsubjectAltName = @alt_names\n\n")
        f.write("[alt_names]\nDNS.1 = localhost\nIP.1 = 127.0.0.1\n")
    subprocess.run([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", server_key, "-out", os.path.join(cert_dir, "server.csr"),
        "-subj", "/CN=localhost", "-config", san_config,
    ], check=True, capture_output=True)
    subprocess.run([
        "openssl", "x509", "-req", "-in", os.path.join(cert_dir, "server.csr"),
        "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial",
        "-out", server_cert, "-days", "1",
        "-extfile", san_config, "-extensions", "v3_req",
    ], check=True, capture_output=True)

    # Client key + CSR + cert (signed by CA)
    subprocess.run([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", client_key, "-out", os.path.join(cert_dir, "client.csr"),
        "-subj", "/CN=fastsync-client",
    ], check=True, capture_output=True)
    subprocess.run([
        "openssl", "x509", "-req", "-in", os.path.join(cert_dir, "client.csr"),
        "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial",
        "-out", client_cert, "-days", "1",
    ], check=True, capture_output=True)

    return {
        "ca": ca_cert,
        "server_cert": server_cert,
        "server_key": server_key,
        "client_cert": client_cert,
        "client_key": client_key,
    }


@pytest.fixture(scope="module")
def certs():
    """Generate test certificates once per test module."""
    if os.path.exists(CERT_DIR):
        shutil.rmtree(CERT_DIR)
    c = _generate_certs(CERT_DIR)
    yield c
    shutil.rmtree(CERT_DIR, ignore_errors=True)


@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    generate_test_files(SOURCE_DIR, full=False)
    clean_dir(DEST_DIR)
    yield
    shutil.rmtree(SOURCE_DIR, ignore_errors=True)
    shutil.rmtree(DEST_DIR, ignore_errors=True)


class TestTLSBasic:
    @pytest.mark.ci
    def test_tls_server_client(self, certs):
        """Basic TLS: server with cert/key, client with cert/key + CA."""
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            server.start(extra_args=[
                "--tls", "--cert", certs["server_cert"], "--key", certs["server_key"],
                "--ca", certs["ca"], "--client-cn", "fastsync-client",
            ])
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--tls",
                       "--cert", certs["client_cert"], "--key", certs["client_key"],
                       "--ca", certs["ca"]],
                port=server.port,
            )

        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing files: {missing}"
        assert not mismatches, f"Mismatched files: {mismatches}"

    def test_tls_with_compression(self, certs):
        """TLS + compression."""
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            server.start(extra_args=[
                "--tls", "--cert", certs["server_cert"], "--key", certs["server_key"],
                "--ca", certs["ca"], "--client-cn", "fastsync-client",
            ])
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["-z", "--tls",
                       "--cert", certs["client_cert"], "--key", certs["client_key"],
                       "--ca", certs["ca"]],
                port=server.port,
            )

        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing files: {missing}"
        assert not mismatches, f"Mismatched files: {mismatches}"

    def test_tls_with_multithreading(self, certs):
        """TLS + multithreading."""
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            server.start(extra_args=[
                "--tls", "--cert", certs["server_cert"], "--key", certs["server_key"],
                "--ca", certs["ca"], "--client-cn", "fastsync-client",
            ])
            result, dur = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--threads", "--tls",
                       "--cert", certs["client_cert"], "--key", certs["client_key"],
                       "--ca", certs["ca"]],
                port=server.port,
            )

        if result.returncode != 0:
            pytest.fail(f"Exit {result.returncode}: {(result.stderr or result.stdout)[:200]}")

        received = get_dest_received_dir(DEST_DIR, SOURCE_DIR)
        mismatches, missing = verify_transfer(SOURCE_DIR, received)
        assert not missing, f"Missing files: {missing}"
        assert not mismatches, f"Mismatched files: {mismatches}"


class TestTLSErrorCases:
    def test_server_tls_missing_cert_key(self):
        """Server should fail if --tls is given without --cert/--key."""
        proc = subprocess.Popen(
            SERVER_CMD + ["--tls"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        _, stderr = proc.communicate(timeout=5)
        assert proc.returncode != 0, "Server should fail with --tls but no cert/key"

    def test_client_tls_missing_key(self):
        """Client should fail if --tls is given without --key."""
        clean_dir(DEST_DIR)
        with ServerManager() as server:
            result, _ = run_client(
                SOURCE_DIR, DEST_DIR,
                flags=["--tls",
                       "--cert", "/nonexistent/cert.pem"],
                port=server.port,
            )
        assert result.returncode != 0, "Client should fail with --tls but no --key"
