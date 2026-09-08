"""--append / --append-verify tail-resume integration tests.

A shorter existing destination file is resumed by transferring only the tail:
--append sends it without verifying the retained prefix (rsync parity: a wrong
prefix is kept, so the result can differ from the source), while --append-verify
checksums the retained prefix against the source and, on a mismatch, falls back
to a clean full transfer so the result is always a byte-identical source copy.
"""
import os
import random
import shutil

import pytest

from common import (
    TEST_DATA_DIR,
    run_client, CountingProxy, clean_dir,
    get_dest_received_dir, CLIENT_CMD,
)

REL = "sub/grow.dat"


def _grow_payload(prefix_size, added_size, seed=99):
    r = random.Random(seed)
    return bytes(r.randbytes(prefix_size)), bytes(r.randbytes(added_size))


class TestAppend:
    def _make(self, tag):
        source = os.path.join(TEST_DATA_DIR, f"append_{tag}_src")
        dest = os.path.join(TEST_DATA_DIR, f"append_{tag}_dst")
        clean_dir(source)
        shutil.rmtree(dest, ignore_errors=True)
        return source, dest

    def _place(self, root, rel, data):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    def _read(self, root, rel):
        with open(os.path.join(root, rel), "rb") as fh:
            return fh.read()

    def _dest_file(self, source, dest, rel):
        return os.path.join(get_dest_received_dir(dest, source), rel)

    @pytest.mark.ci
    def test_append_resumes_short_dest_atomically(self, shared_server):
        """A shorter dest with a MATCHING prefix is resumed; the reconstructed
        file is byte-identical to the source."""
        source, dest = self._make("atomic")
        prefix, added = _grow_payload(1 * 1024 * 1024, 64 * 1024)
        self._place(source, REL, prefix + added)
        self._place(self._dest_file(source, dest, ""), REL, prefix)

        result, _ = run_client(source, dest, flags=["--append"], port=shared_server.port)
        assert result.returncode == 0, \
            f"--append failed: {(result.stderr or result.stdout)[:400]}"
        assert self._read(self._dest_file(source, dest, ""), REL) == prefix + added

    def test_append_verify_matching_prefix_succeeds(self, shared_server):
        source, dest = self._make("verify_ok")
        prefix, added = _grow_payload(512 * 1024, 32 * 1024)
        self._place(source, REL, prefix + added)
        self._place(self._dest_file(source, dest, ""), REL, prefix)

        result, _ = run_client(source, dest, flags=["--append-verify"], port=shared_server.port)
        assert result.returncode == 0, \
            f"--append-verify failed: {(result.stderr or result.stdout)[:400]}"
        assert self._read(self._dest_file(source, dest, ""), REL) == prefix + added

    def test_append_sends_only_tail(self, shared_server):
        """Sorted transfer moves only the tail: wire bytes stay well below the
        full source size (incompressible payload, no -c)."""
        source, dest = self._make("tail")
        prefix, added = _grow_payload(4 * 1024 * 1024, 8 * 1024, seed=7)
        full = prefix + added
        self._place(source, REL, full)
        self._place(self._dest_file(source, dest, ""), REL, prefix)

        proxy = CountingProxy(shared_server.port)
        cmd = (CLIENT_CMD + ["--source-dir", source, "--dest-dir", dest,
                             "--save-to-disk", "--server-port", str(proxy.port), "--append"])
        result = proxy.run(cmd)
        assert result.returncode == 0, \
            f"--append failed: {(result.stderr or result.stdout)[:400]}"
        assert self._read(self._dest_file(source, dest, ""), REL) == full
        assert proxy.client_to_server < full.__len__() // 2, \
            f"expected a tail-only transfer, sent {proxy.client_to_server}B for {full.__len__()}B"

    def test_plain_append_wrong_prefix_is_rsync_parity(self, shared_server):
        """--append does NOT verify the retained prefix: a wrong prefix is kept,
        so the result is prefix+tail (differs from the source).  This is the
        documented rsync-parity risk of plain --append."""
        source, dest = self._make("plain_wrong")
        correct_prefix, added = _grow_payload(256 * 1024, 32 * 1024, seed=1)
        wrong_prefix = bytes(b ^ 0xFF for b in correct_prefix)
        self._place(source, REL, correct_prefix + added)
        self._place(self._dest_file(source, dest, ""), REL, wrong_prefix)

        result, _ = run_client(source, dest, flags=["--append"], port=shared_server.port)
        assert result.returncode == 0
        assert self._read(self._dest_file(source, dest, ""), REL) == wrong_prefix + added

    def test_append_verify_wrong_prefix_never_corrupts(self, shared_server):
        """--append-verify detects the retained prefix mismatch and falls back to
        a full transfer, so the result is a byte-identical source copy."""
        source, dest = self._make("verify_wrong")
        correct_prefix, added = _grow_payload(256 * 1024, 32 * 1024, seed=2)
        wrong_prefix = bytes(b ^ 0xFF for b in correct_prefix)
        self._place(source, REL, correct_prefix + added)
        self._place(self._dest_file(source, dest, ""), REL, wrong_prefix)

        result, _ = run_client(source, dest, flags=["--append-verify"], port=shared_server.port)
        assert result.returncode == 0, \
            f"--append-verify mismatch fallback failed: {(result.stderr or result.stdout)[:400]}"
        assert self._read(self._dest_file(source, dest, ""), REL) == correct_prefix + added

    def test_append_with_inplace(self, shared_server):
        source, dest = self._make("inplace")
        prefix, added = _grow_payload(128 * 1024, 16 * 1024, seed=3)
        self._place(source, REL, prefix + added)
        self._place(self._dest_file(source, dest, ""), REL, prefix)

        result, _ = run_client(source, dest, flags=["--append", "--inplace"],
                               port=shared_server.port)
        assert result.returncode == 0, \
            f"--append --inplace failed: {(result.stderr or result.stdout)[:400]}"
        assert self._read(self._dest_file(source, dest, ""), REL) == prefix + added

    def test_append_multithreaded(self, shared_server):
        source, dest = self._make("mthread")
        prefix, added = _grow_payload(512 * 1024, 32 * 1024, seed=4)
        self._place(source, REL, prefix + added)
        self._place(self._dest_file(source, dest, ""), REL, prefix)

        result, _ = run_client(source, dest, flags=["--append", "-m"], port=shared_server.port)
        assert result.returncode == 0, \
            f"--append -m failed: {(result.stderr or result.stdout)[:400]}"
        assert self._read(self._dest_file(source, dest, ""), REL) == prefix + added