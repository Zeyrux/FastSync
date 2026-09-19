"""Client-only rsync-parity quick wins.

Each test here pins behaviour that must match real ``rsync 3.4.1``.  The
differential tests skip cleanly when rsync is not installed.
"""
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    CLIENT_CMD,
    CountingProxy,
    TEST_DATA_DIR,
    ServerManager,
    run_client,
    clean_dir,
    get_dest_received_dir,
)

RSYNC = shutil.which("rsync")
requires_rsync = pytest.mark.skipif(RSYNC is None, reason="rsync 3.4.1 not installed")


def _rel_files(root, skip=()):
    """Relative paths of regular files and symlinks below root, sorted."""
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name in skip:
                continue
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
    return sorted(out)


def _rsync(args):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run(
        [RSYNC] + args, capture_output=True, text=True, env=env, timeout=120
    )


class TestCopyLinksReferentError:
    """#38/#39: a broken referent under -L/--copy-unsafe-links exits 23."""

    def _make_broken_tree(self, root):
        clean_dir(root)
        with open(os.path.join(root, "ok.txt"), "wb") as fh:
            fh.write(b"hello\n")
        os.symlink("/nonexistent/target", os.path.join(root, "broken"))

    @requires_rsync
    @pytest.mark.ci
    def test_copy_links_broken_referent_exit_23(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "qw_cl_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_cl_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_cl_rdst")
        self._make_broken_tree(source)
        clean_dir(dest)
        clean_dir(rdst)

        rsync_result = _rsync(["-aL", source + "/", rdst + "/"])
        assert rsync_result.returncode == 23, rsync_result.stderr

        result, _ = run_client(source, dest, flags=["-L"], port=shared_server.port)
        assert result.returncode == 23, (
            f"-L broken referent must exit 23, got {result.returncode}: "
            f"{result.stderr[:300]}"
        )
        received = get_dest_received_dir(dest, source)
        assert os.path.exists(os.path.join(received, "ok.txt"))

    @requires_rsync
    def test_copy_links_broken_referent_multithreaded_exit_23(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "qw_cl_mt_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_cl_mt_dst")
        self._make_broken_tree(source)
        clean_dir(dest)
        result, _ = run_client(source, dest, flags=["-L", "--threads"], port=shared_server.port)
        assert result.returncode == 23, (
            f"-L broken referent must exit 23 under --threads, got {result.returncode}"
        )

    @requires_rsync
    @pytest.mark.ci
    def test_copy_unsafe_links_broken_referent_exit_23(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "qw_cul_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_cul_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_cul_rdst")
        clean_dir(source)
        os.makedirs(os.path.join(source, "sub"))
        with open(os.path.join(source, "ok.txt"), "wb") as fh:
            fh.write(b"hello\n")
        # Unsafe (escaping) target with no referent: dereferenced -> exit 23.
        os.symlink("../../../nonexistent/target", os.path.join(source, "sub", "unsafe"))
        clean_dir(dest)
        clean_dir(rdst)

        rsync_result = _rsync(["-a", "--copy-unsafe-links", source + "/", rdst + "/"])
        assert rsync_result.returncode == 23, rsync_result.stderr

        result, _ = run_client(source, dest, flags=["-l", "--copy-unsafe-links"],
                               port=shared_server.port)
        assert result.returncode == 23, (
            f"--copy-unsafe-links broken referent must exit 23, got {result.returncode}"
        )

    @requires_rsync
    def test_copy_unsafe_links_safe_broken_stays_symlink(self, shared_server):
        """A safe (non-escaping) broken symlink is NOT dereferenced: exit 0."""
        source = os.path.join(TEST_DATA_DIR, "qw_cul_safe_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_cul_safe_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_cul_safe_rdst")
        clean_dir(source)
        os.makedirs(os.path.join(source, "sub"))
        os.symlink("nonexistent-target", os.path.join(source, "sub", "safe"))
        clean_dir(dest)
        clean_dir(rdst)

        rsync_result = _rsync(["-a", "--copy-unsafe-links", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr

        result, _ = run_client(source, dest, flags=["-l", "--copy-unsafe-links"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        received = get_dest_received_dir(dest, source)
        assert os.path.islink(os.path.join(received, "sub", "safe"))


class TestIgnoreMissingArgsParity:
    """#58: --files-from + --ignore-missing-args matches rsync, including the
    empty-list case (rsync exits 0 transferring nothing)."""

    @requires_rsync
    @pytest.mark.ci
    def test_missing_entry_skipped_like_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "qw_ima_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_ima_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_ima_rdst")
        clean_dir(source)
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"a\n")
        clean_dir(dest)
        clean_dir(rdst)
        lst = os.path.join(TEST_DATA_DIR, "qw_ima_list")
        with open(lst, "w") as fh:
            fh.write("a.txt\nmissing.txt\n")

        rsync_result = _rsync(["-a", "--files-from=" + lst, "--ignore-missing-args",
                               source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["--files-from", lst,
                                                    "--ignore-missing-args"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        received = get_dest_received_dir(dest, source)
        assert os.path.exists(os.path.join(received, "a.txt"))
        assert not os.path.exists(os.path.join(received, "missing.txt"))

    @requires_rsync
    @pytest.mark.ci
    def test_empty_files_from_list_succeeds_like_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "qw_ima_empty_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_ima_empty_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_ima_empty_rdst")
        clean_dir(source)
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"a\n")
        clean_dir(dest)
        clean_dir(rdst)
        lst = os.path.join(TEST_DATA_DIR, "qw_ima_empty_list")
        with open(lst, "w") as fh:
            fh.write("")

        rsync_result = _rsync(["-a", "--files-from=" + lst, source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        result, _ = run_client(source, dest, flags=["--files-from", lst],
                               port=shared_server.port)
        assert result.returncode == 0, (
            f"empty --files-from must succeed like rsync, got {result.returncode}: "
            f"{result.stderr[:300]}"
        )

    @requires_rsync
    @pytest.mark.ci
    def test_empty_files_from_with_delete_is_not_destructive(self, shared_server):
        """An empty --files-from list synchronizes nothing, so --delete must not
        wipe the destination (rsync keeps the extra)."""
        source = os.path.join(TEST_DATA_DIR, "qw_ima_edel_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_ima_edel_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_ima_edel_rdst")
        clean_dir(source)
        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"keep\n")
        clean_dir(dest)
        clean_dir(rdst)
        with open(os.path.join(rdst, "extra.txt"), "wb") as fh:
            fh.write(b"extra\n")
        lst = os.path.join(TEST_DATA_DIR, "qw_ima_edel_list")
        with open(lst, "w") as fh:
            fh.write("")
        rs = _rsync(["-a", "--delete", "--files-from=" + lst, source + "/", rdst + "/"])
        assert rs.returncode == 0, rs.stderr
        assert os.path.exists(os.path.join(rdst, "extra.txt"))

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            seed = get_dest_received_dir(dest, source)
            os.makedirs(seed, exist_ok=True)
            with open(os.path.join(seed, "extra.txt"), "wb") as fh:
                fh.write(b"extra\n")
            result, _ = run_client(source, dest,
                                   flags=["--delete", "--files-from", lst],
                                   port=server.port)
            assert result.returncode == 0, result.stderr[:300]
            assert os.path.exists(os.path.join(seed, "extra.txt")), \
                "empty --files-from + --delete must not delete the destination"


class TestPerDirFilterOrdering:
    """#10: -F .rsync-filter evaluation order matches rsync (a directory's own
    rules before its ancestors'; anchored rules are relative to their owner)."""

    def _run_pair(self, shared_server, root_rules, sub_rules, subsub_rules=None):
        tag = "qw_f"
        source = os.path.join(TEST_DATA_DIR, tag + "_src")
        dest = os.path.join(TEST_DATA_DIR, tag + "_dst")
        rdst = os.path.join(TEST_DATA_DIR, tag + "_rdst")
        clean_dir(source)
        os.makedirs(os.path.join(source, "sub"))
        if subsub_rules is not None:
            os.makedirs(os.path.join(source, "sub", "deep"))
        with open(os.path.join(source, "bar"), "wb") as fh:
            fh.write(b"bar\n")
        with open(os.path.join(source, "sub", "foo"), "wb") as fh:
            fh.write(b"foo\n")
        if subsub_rules is not None:
            with open(os.path.join(source, "sub", "deep", "foo"), "wb") as fh:
                fh.write(b"deep foo\n")
        with open(os.path.join(source, ".rsync-filter"), "w") as fh:
            fh.write(root_rules)
        with open(os.path.join(source, "sub", ".rsync-filter"), "w") as fh:
            fh.write(sub_rules)
        if subsub_rules is not None:
            with open(os.path.join(source, "sub", "deep", ".rsync-filter"), "w") as fh:
                fh.write(subsub_rules)

        clean_dir(dest)
        clean_dir(rdst)
        fs_result, _ = run_client(source, dest, flags=["--preserve", "-F"],
                                  port=shared_server.port)
        assert fs_result.returncode == 0, fs_result.stderr[:300]
        received = get_dest_received_dir(dest, source)
        fs_files = _rel_files(received, skip=(".rsync-filter",))
        return fs_files, source, rdst

    @requires_rsync
    @pytest.mark.ci
    def test_child_include_overrides_parent_exclude(self, shared_server):
        fs_files, source, rdst = self._run_pair(shared_server, "- foo\n", "+ foo\n")
        rsync_result = _rsync(["-aF", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        assert fs_files == _rel_files(rdst, skip=(".rsync-filter",))
        assert "sub/foo" in fs_files

    @requires_rsync
    @pytest.mark.ci
    def test_child_exclude_overrides_parent_include(self, shared_server):
        fs_files, source, rdst = self._run_pair(shared_server, "+ foo\n", "- foo\n")
        rsync_result = _rsync(["-aF", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        assert fs_files == _rel_files(rdst, skip=(".rsync-filter",))
        assert "sub/foo" not in fs_files

    @requires_rsync
    def test_three_level_inheritance(self, shared_server):
        fs_files, source, rdst = self._run_pair(
            shared_server, "- foo\n", "+ foo\n", "- foo\n"
        )
        rsync_result = _rsync(["-aF", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        assert fs_files == _rel_files(rdst, skip=(".rsync-filter",))


class TestDeleteEdgeSemantics:
    """#20/#23/#24/#25: delete timing/policy edge cases match rsync."""

    @requires_rsync
    @pytest.mark.ci
    def test_delete_before_removes_extras_like_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "qw_db_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_db_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_db_rdst")
        clean_dir(source)
        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"keep\n")
        for d in (dest, rdst):
            clean_dir(d)
            with open(os.path.join(d, "extra.txt"), "wb") as fh:
                fh.write(b"extra\n")
        received_seed = get_dest_received_dir(dest, source)
        os.makedirs(received_seed, exist_ok=True)
        with open(os.path.join(received_seed, "extra.txt"), "wb") as fh:
            fh.write(b"extra\n")

        rsync_result = _rsync(["-a", "--delete-before", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            result, _ = run_client(source, dest, flags=["--delete-before"],
                                   port=server.port)
            assert result.returncode == 0, result.stderr[:300]
            received = get_dest_received_dir(dest, source)
            assert os.path.exists(os.path.join(received, "keep.txt"))
            assert not os.path.exists(os.path.join(received, "extra.txt")), \
                "--delete-before must remove destination extras"
        assert not os.path.exists(os.path.join(rdst, "extra.txt"))

    @requires_rsync
    @pytest.mark.ci
    def test_delete_excluded_protects_then_deletes(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "qw_de_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_de_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_de_rdst")
        clean_dir(source)
        with open(os.path.join(source, "keep.txt"), "wb") as fh:
            fh.write(b"keep\n")
        with open(os.path.join(source, "skip.log"), "wb") as fh:
            fh.write(b"log\n")

        # Default --delete protects the excluded mirror (rsync parity).
        rdst_prot = os.path.join(TEST_DATA_DIR, "qw_de_rprot")
        clean_dir(rdst_prot)
        with open(os.path.join(rdst_prot, "skip.log"), "wb") as fh:
            fh.write(b"stale\n")
        rsync_result = _rsync(["-a", "--delete", "--exclude=*.log", source + "/",
                               rdst_prot + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        assert os.path.exists(os.path.join(rdst_prot, "skip.log"))

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            clean_dir(dest)
            seed = get_dest_received_dir(dest, source)
            os.makedirs(seed, exist_ok=True)
            with open(os.path.join(seed, "skip.log"), "wb") as fh:
                fh.write(b"stale\n")
            result, _ = run_client(source, dest, flags=["--delete", "--exclude=*.log"],
                                   port=server.port)
            assert result.returncode == 0, result.stderr[:300]
            received = get_dest_received_dir(dest, source)
            assert os.path.exists(os.path.join(received, "skip.log")), \
                "--delete must protect the excluded destination mirror"

            # --delete-excluded removes it.
            clean_dir(rdst)
            with open(os.path.join(rdst, "skip.log"), "wb") as fh:
                fh.write(b"stale\n")
            rsync_result = _rsync(["-a", "--delete", "--delete-excluded",
                                   "--exclude=*.log", source + "/", rdst + "/"])
            assert rsync_result.returncode == 0, rsync_result.stderr
            assert not os.path.exists(os.path.join(rdst, "skip.log"))

            result, _ = run_client(
                source, dest,
                flags=["--delete", "--delete-excluded", "--exclude=*.log"],
                port=server.port,
            )
            assert result.returncode == 0, result.stderr[:300]
            assert not os.path.exists(os.path.join(received, "skip.log")), \
                "--delete-excluded must remove the excluded mirror"

    @requires_rsync
    def test_force_replaces_nonempty_destination_dir(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "qw_force_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_force_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_force_rdst")
        clean_dir(source)
        with open(os.path.join(source, "x"), "wb") as fh:
            fh.write(b"file-content\n")
        clean_dir(rdst)
        os.makedirs(os.path.join(rdst, "x"))
        with open(os.path.join(rdst, "x", "blocker"), "wb") as fh:
            fh.write(b"blocker\n")

        rsync_result = _rsync(["-a", "--force", source + "/", rdst + "/"])
        assert rsync_result.returncode == 0, rsync_result.stderr
        assert os.path.isfile(os.path.join(rdst, "x"))

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            clean_dir(dest)
            seed = get_dest_received_dir(dest, source)
            os.makedirs(os.path.join(seed, "x"), exist_ok=True)
            with open(os.path.join(seed, "x", "blocker"), "wb") as fh:
                fh.write(b"blocker\n")
            result, _ = run_client(source, dest, flags=["--force"],
                                   port=server.port)
            assert result.returncode == 0, result.stderr[:300]
            received = get_dest_received_dir(dest, source)
            assert os.path.isfile(os.path.join(received, "x")), \
                "--force must replace a non-empty destination directory"

    @requires_rsync
    def test_no_force_nonempty_dir_is_partial_error(self, shared_server):
        """Without --force a non-empty destination dir blocking a file is not
        replaced; rsync exits 23, fastsync must not silently mangle it."""
        source = os.path.join(TEST_DATA_DIR, "qw_noforce_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_noforce_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_noforce_rdst")
        clean_dir(source)
        with open(os.path.join(source, "x"), "wb") as fh:
            fh.write(b"file-content\n")
        clean_dir(rdst)
        os.makedirs(os.path.join(rdst, "x"))
        with open(os.path.join(rdst, "x", "blocker"), "wb") as fh:
            fh.write(b"blocker\n")
        rsync_result = _rsync(["-a", source + "/", rdst + "/"])
        assert rsync_result.returncode == 23, rsync_result.stderr

        with ServerManager() as server:
            server.start(extra_args=["--allow-delete"])
            clean_dir(dest)
            seed = get_dest_received_dir(dest, source)
            os.makedirs(os.path.join(seed, "x"), exist_ok=True)
            with open(os.path.join(seed, "x", "blocker"), "wb") as fh:
                fh.write(b"blocker\n")
            result, _ = run_client(source, dest, port=server.port)
            assert result.returncode != 0, "a blocked file install must not report success"


def _snapshot(root):
    """rel path -> (kind, payload) for every file/symlink below root."""
    result = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames):
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                result[os.path.relpath(p, root)] = ("link", os.readlink(p))
                dirnames.remove(name)
        for name in filenames:
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                result[os.path.relpath(p, root)] = ("link", os.readlink(p))
            else:
                with open(p, "rb") as fh:
                    result[os.path.relpath(p, root)] = ("file", fh.read())
    return result


def _assert_same_tree(rdst, received, msg=""):
    rsync_tree = _snapshot(rdst)
    fs_tree = _snapshot(received)
    assert fs_tree == rsync_tree, (
        f"tree mismatch {msg}\n----- rsync only/diff -----\n"
        f"{ {k: v for k, v in rsync_tree.items() if fs_tree.get(k) != v} }\n"
        f"----- fastsync only/diff -----\n"
        f"{ {k: v for k, v in fs_tree.items() if rsync_tree.get(k) != v} }"
    )


class TestVerifyAndFlip:
    """Item 8: confirm already-implemented client-side rows match rsync."""

    def _src(self, tag):
        source = os.path.join(TEST_DATA_DIR, f"vw_{tag}_src")
        clean_dir(source)
        return source

    def _dst(self, tag):
        d = os.path.join(TEST_DATA_DIR, f"vw_{tag}_dst")
        clean_dir(d)
        return d

    @requires_rsync
    @pytest.mark.ci
    def test_links_verbatim_matches_rsync(self, shared_server):
        source = self._src("links")
        dest = self._dst("links")
        rdst = self._dst("links_r")
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"a\n")
        os.symlink("a.txt", os.path.join(source, "rel"))
        os.symlink("/etc/hostname", os.path.join(source, "abs"))
        os.symlink("../../escape", os.path.join(source, "dd"))
        assert _rsync(["-a", source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["-a"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(-l/--links)")

    @requires_rsync
    @pytest.mark.ci
    def test_dry_run_does_not_write_like_rsync(self, shared_server):
        source = self._src("dry")
        dest = self._dst("dry")
        rdst = self._dst("dry_r")
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"a\n")
        os.makedirs(os.path.join(source, "sub"))
        with open(os.path.join(source, "sub", "b.txt"), "wb") as fh:
            fh.write(b"b\n")
        assert _rsync(["-a", "--dry-run", source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["-a", "--dry-run"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(--dry-run)")

    @requires_rsync
    @pytest.mark.ci
    def test_ignore_existing_matches_rsync(self, shared_server):
        source = self._src("ie")
        dest = self._dst("ie")
        rdst = self._dst("ie_r")
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"source\n")
        with open(os.path.join(source, "new.txt"), "wb") as fh:
            fh.write(b"new\n")
        for root in (get_dest_received_dir(dest, source), rdst):
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, "a.txt"), "wb") as fh:
                fh.write(b"destination-kept\n")
        assert _rsync(["-a", "--ignore-existing", source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["--ignore-existing"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(--ignore-existing)")

    @requires_rsync
    def test_append_matches_rsync(self, shared_server):
        source = self._src("app")
        dest = self._dst("app")
        rdst = self._dst("app_r")
        prefix = b"P" * (256 * 1024)
        tail = b"T" * (16 * 1024)
        with open(os.path.join(source, "grow"), "wb") as fh:
            fh.write(prefix + tail)
        for root in (get_dest_received_dir(dest, source), rdst):
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, "grow"), "wb") as fh:
                fh.write(prefix)
        assert _rsync(["-a", "--append", source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["--append"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(--append)")

    @requires_rsync
    def test_append_verify_matches_rsync(self, shared_server):
        source = self._src("appv")
        dest = self._dst("appv")
        rdst = self._dst("appv_r")
        prefix = b"Q" * (128 * 1024)
        tail = b"Z" * (8 * 1024)
        with open(os.path.join(source, "grow"), "wb") as fh:
            fh.write(prefix + tail)
        for root in (get_dest_received_dir(dest, source), rdst):
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, "grow"), "wb") as fh:
                fh.write(prefix)
        assert _rsync(["-a", "--append-verify", source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["--append-verify"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(--append-verify)")

    @requires_rsync
    @pytest.mark.ci
    def test_delay_updates_matches_rsync(self, shared_server):
        source = self._src("delay")
        dest = self._dst("delay")
        rdst = self._dst("delay_r")
        for rel, content in {"a.txt": b"a\n", "sub/b.txt": b"b\n"}.items():
            full = os.path.join(source, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(content)
        assert _rsync(["-a", "--delay-updates", source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["--delay-updates"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(--delay-updates)")

    @requires_rsync
    def test_preallocate_matches_rsync(self, shared_server):
        source = self._src("prealloc")
        dest = self._dst("prealloc")
        rdst = self._dst("prealloc_r")
        with open(os.path.join(source, "f.bin"), "wb") as fh:
            fh.write(b"x" * (512 * 1024))
        assert _rsync(["-a", "--preallocate", source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["--preallocate"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(--preallocate)")

    @requires_rsync
    @pytest.mark.ci
    def test_sparse_preallocate_blocks_match_rsync(self, shared_server):
        """rsync lets --preallocate win over --sparse: the hole file gets its
        full space reserved (st_blocks ~ size/512) even though the sparse writer
        seeks over the zero run.  FastSync must agree both on the block count and
        with rsync's exact value for each flag combination."""
        source = self._src("sparsepre")
        dest = self._dst("sparsepre")
        rdst = self._dst("sparsepre_r")
        total = 1024 * 1024
        # A zero run >= the 4 KiB sparse threshold in the middle of the image.
        with open(os.path.join(source, "hole.bin"), "wb") as fh:
            fh.write(os.urandom(64 * 1024))
            fh.write(b"\x00" * (768 * 1024))
            fh.write(os.urandom(total - 64 * 1024 - 768 * 1024))

        def run_both(flags, tag):
            rsync_dst = self._dst(f"sparsepre_{tag}_r")
            fs_dst = self._dst(f"sparsepre_{tag}_f")
            assert _rsync(["-a"] + flags + [source + "/", rsync_dst + "/"]).returncode == 0
            result, _ = run_client(source, fs_dst, flags=["-a"] + flags,
                                   port=shared_server.port)
            assert result.returncode == 0, result.stderr[:300]
            rfile = os.path.join(rsync_dst, "hole.bin")
            ffile = os.path.join(get_dest_received_dir(fs_dst, source), "hole.bin")
            with open(rfile, "rb") as rfh, open(ffile, "rb") as ffh:
                assert rfh.read() == ffh.read(), f"{tag}: content diverged"
            return os.stat(rfile).st_blocks, os.stat(ffile).st_blocks

        r_sparse, f_sparse = run_both(["--sparse"], "sparse")
        r_both, f_both = run_both(["--sparse", "--preallocate"], "both")

        assert f_sparse == r_sparse, (
            f"--sparse st_blocks: fastsync={f_sparse} rsync={r_sparse}"
        )
        assert f_both == r_both, (
            f"--sparse --preallocate st_blocks: fastsync={f_both} rsync={r_both}"
        )
        # Only meaningful where the filesystem actually reports holes; otherwise
        # both sides simply allocate the full size and the equality above holds.
        has_holes = r_sparse * 512 < total
        if has_holes:
            assert f_both > f_sparse, (
                "preallocate must win over sparse: "
                f"sparse={f_sparse} both={f_both} blocks"
            )
            assert r_both > r_sparse, (
                f"rsync preallocate must win: sparse={r_sparse} both={r_both}"
            )

    @requires_rsync
    def test_fuzzy_content_matches_rsync(self, shared_server):
        source = self._src("fuzzy")
        dest = self._dst("fuzzy")
        rdst = self._dst("fuzzy_r")
        payload = (b"the quick brown fox\n" * 4096)
        with open(os.path.join(source, "renamed.txt"), "wb") as fh:
            fh.write(payload)
        for root in (get_dest_received_dir(dest, source), rdst):
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, "old_name.txt"), "wb") as fh:
                fh.write(payload)
        assert _rsync(["-a", "--fuzzy", source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["-y"], port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(-y/--fuzzy)")

    @requires_rsync
    def test_skip_compress_content_matches_rsync(self, shared_server):
        source = self._src("skipz")
        dest = self._dst("skipz")
        rdst = self._dst("skipz_r")
        with open(os.path.join(source, "already.zip"), "wb") as fh:
            fh.write(b"PK" + b"z" * 4096)
        with open(os.path.join(source, "text.txt"), "wb") as fh:
            fh.write(b"compress me\n" * 1024)
        assert _rsync(["-az", "--skip-compress=gz/zip", source + "/",
                       rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["-z", "--skip-compress=gz/zip"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(--skip-compress)")

    @requires_rsync
    def test_copy_dest_content_matches_rsync(self, shared_server):
        source = self._src("copyd")
        dest = self._dst("copyd")
        with open(os.path.join(source, "f.txt"), "wb") as fh:
            fh.write(b"copy-from-basis\n")
        # fastsync basis DIR is relative to the receive root; the basis file is
        # looked up at the same source-mirror relative path.
        rel = os.path.abspath(source).lstrip(os.sep)
        basis = os.path.join(dest, "basis", rel)
        os.makedirs(basis, exist_ok=True)
        with open(os.path.join(basis, "f.txt"), "wb") as fh:
            fh.write(b"copy-from-basis\n")
        received = get_dest_received_dir(dest, source)
        result, _ = run_client(source, dest,
                               flags=["--copy-dest=basis", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        assert os.path.exists(os.path.join(received, "f.txt"))
        with open(os.path.join(received, "f.txt"), "rb") as fh:
            assert fh.read() == b"copy-from-basis\n"

    @requires_rsync
    def test_trust_sender_content_matches_rsync(self, shared_server):
        source = self._src("trust")
        dest = self._dst("trust")
        rdst = self._dst("trust_r")
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"a\n")
        assert _rsync(["-a", "--trust-sender", source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["--trust-sender"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(--trust-sender)")

    @requires_rsync
    def test_compare_dest_content_matches_rsync(self, shared_server):
        source = self._src("cmpd")
        dest = self._dst("cmpd")
        rdst = self._dst("cmpd_r")
        # Pin the mtime so rsync's size+mtime quick-check (and FastSync's
        # default) matches deterministically across a second boundary.
        OLD = 1_500_000_000
        with open(os.path.join(source, "f.txt"), "wb") as fh:
            fh.write(b"basis-content\n")
        os.utime(os.path.join(source, "f.txt"), (OLD, OLD))
        # rsync resolves --compare-dest relative to the destination dir; its
        # basis file sits at the transfer-relative path.
        os.makedirs(os.path.join(rdst, "basis"), exist_ok=True)
        with open(os.path.join(rdst, "basis", "f.txt"), "wb") as fh:
            fh.write(b"basis-content\n")
        os.utime(os.path.join(rdst, "basis", "f.txt"), (OLD, OLD))
        rs = _rsync(["-a", "--compare-dest=basis", source + "/", rdst + "/"])
        assert rs.returncode == 0, rs.stderr
        assert not os.path.exists(os.path.join(rdst, "f.txt")), \
            "rsync compare-dest must leave the destination sparse"

        # fastsync resolves the basis DIR relative to the receive root, and the
        # file's relative path there mirrors the source path.
        rel = os.path.abspath(source).lstrip(os.sep)
        basis = os.path.join(dest, "basis", rel)
        os.makedirs(basis, exist_ok=True)
        with open(os.path.join(basis, "f.txt"), "wb") as fh:
            fh.write(b"basis-content\n")
        os.utime(os.path.join(basis, "f.txt"), (OLD, OLD))
        received = get_dest_received_dir(dest, source)
        result, _ = run_client(source, dest,
                               flags=["--compare-dest=basis", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        # rsync --compare-dest never copies: a basis match is simply not
        # transferred, so the destination stays sparse (no f.txt).
        assert not os.path.exists(os.path.join(received, "f.txt"))

    @requires_rsync
    def test_link_dest_hardlinks_matches_rsync(self, shared_server):
        source = self._src("linkd")
        dest = self._dst("linkd")
        OLD = 1_500_000_000
        with open(os.path.join(source, "f.txt"), "wb") as fh:
            fh.write(b"link-basis-content\n")
        os.utime(os.path.join(source, "f.txt"), (OLD, OLD))
        rel = os.path.abspath(source).lstrip(os.sep)
        basis = os.path.join(dest, "basis", rel)
        os.makedirs(basis, exist_ok=True)
        basis_file = os.path.join(basis, "f.txt")
        with open(basis_file, "wb") as fh:
            fh.write(b"link-basis-content\n")
        os.utime(basis_file, (OLD, OLD))
        received = get_dest_received_dir(dest, source)
        result, _ = run_client(source, dest,
                               flags=["--link-dest=basis", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        dest_file = os.path.join(received, "f.txt")
        assert os.path.exists(dest_file)
        assert os.stat(dest_file).st_ino == os.stat(basis_file).st_ino, \
            "--link-dest must hard-link to the basis file"

    @requires_rsync
    def test_basis_dir_size_only_content_residual(self, shared_server):
        """rsync parity (default): a basis hit is decided by the metadata
        quick-check alone.  With `--size-only`, a same-size, different-content
        basis is trusted, so rsync links the basis content and FastSync must now
        do the same instead of xxHash-verifying it.  `--verify-basis` restores
        the stricter content equality (covered by the differential test)."""
        source = self._src("basissz")
        rdest = self._dst("basissz_r")
        fdest = self._dst("basissz_f")
        with open(os.path.join(source, "f.txt"), "wb") as fh:
            fh.write(b"AAAA\n")
        OLD = 1_400_000_000
        # rsync basis at the transfer-relative path (relative to the dest dir).
        os.makedirs(os.path.join(rdest, "basis"), exist_ok=True)
        with open(os.path.join(rdest, "basis", "f.txt"), "wb") as fh:
            fh.write(b"BBBB\n")
        os.utime(os.path.join(rdest, "basis", "f.txt"), (OLD, OLD))
        rs = _rsync(["-a", "--size-only", "--link-dest=basis", source + "/", rdest + "/"])
        assert rs.returncode == 0, rs.stderr
        with open(os.path.join(rdest, "f.txt"), "rb") as fh:
            assert fh.read() == b"BBBB\n", "rsync --size-only did not trust the basis size"

        # FastSync basis is relative to the receive root; the file mirrors the
        # source path.
        rel = os.path.abspath(source).lstrip(os.sep)
        basis = os.path.join(fdest, "basis", rel)
        os.makedirs(basis, exist_ok=True)
        with open(os.path.join(basis, "f.txt"), "wb") as fh:
            fh.write(b"BBBB\n")
        os.utime(os.path.join(basis, "f.txt"), (OLD, OLD))
        received = get_dest_received_dir(fdest, source)
        result, _ = run_client(source, fdest,
                               flags=["-a", "--size-only", "--link-dest=basis", "--incremental"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        with open(os.path.join(received, "f.txt"), "rb") as fh:
            assert fh.read() == b"BBBB\n", \
                "FastSync must trust the metadata quick-check exactly like rsync"

    @requires_rsync
    def test_verify_basis_restores_content_check(self, shared_server):
        """FastSync-only `--verify-basis`: a same-size, same-mtime basis with
        different content is rejected by the whole-file digest, so the source is
        transferred instead of installing the wrong basis bytes.  The default
        (no flag) installs the basis content, matching rsync."""
        source = self._src("vbasis")
        fdest = self._dst("vbasis_f")
        with open(os.path.join(source, "f.txt"), "wb") as fh:
            fh.write(b"AAAA\n")
        OLD = 1_400_000_000
        os.utime(os.path.join(source, "f.txt"), (OLD, OLD))
        rel = os.path.abspath(source).lstrip(os.sep)
        basis = os.path.join(fdest, "basis", rel)
        os.makedirs(basis, exist_ok=True)
        with open(os.path.join(basis, "f.txt"), "wb") as fh:
            fh.write(b"BBBB\n")
        os.utime(os.path.join(basis, "f.txt"), (OLD, OLD))
        received = get_dest_received_dir(fdest, source)
        result, _ = run_client(source, fdest,
                               flags=["-a", "--link-dest=basis", "--incremental",
                                      "--verify-basis"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        with open(os.path.join(received, "f.txt"), "rb") as fh:
            assert fh.read() == b"AAAA\n", \
                "--verify-basis must reject the same-size/different-content basis"


def _stat_bytes(output, key):
    """Parse a --stats byte counter (e.g. ``Matched data: 65,536 bytes``)."""
    for line in output.splitlines():
        if line.startswith(key + ":"):
            raw = line.split(":", 1)[1].strip().split()[0]
            return int(raw.replace(",", ""))
    return None


class TestFuzzy:
    """Track 5b: `-y`/`--fuzzy` is an internal bandwidth optimization with a
    byte-exact result.  FastSync ports rsync 3.4.1's weighted-Levenshtein name
    heuristic, so where both delta engines admit the candidate the tools pick
    the same basis (the ``fuzzy_basis`` differential asserts the tree and the
    Matched/Literal counters match with the block size pinned).  The residual is
    candidate ELIGIBILITY: FastSync's delta size gate (both files >= 16 KiB and
    a <= 10x size ratio) is narrower than rsync's, which empirically uses a
    fuzzy basis well beyond 10x and below 16 KiB.  These tests pin the window
    boundary and prove the byte-exact fallback on both sides of it."""

    _BASE = b"the quick brown fox jumps over the lazy dog\n" * 4000

    def _src(self, tag):
        source = os.path.join(TEST_DATA_DIR, f"fz_{tag}_src")
        clean_dir(source)
        return source

    def _dst(self, tag):
        d = os.path.join(TEST_DATA_DIR, f"fz_{tag}_dst")
        clean_dir(d)
        return d

    def _run_both(self, shared_server, source, dest, rdst, payload, sibling,
                  rs_extra=(), fs_extra=()):
        with open(os.path.join(source, "report_v2.txt"), "wb") as fh:
            fh.write(payload)
        for root in (rdst, get_dest_received_dir(dest, source)):
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, "report_v1.txt"), "wb") as fh:
                fh.write(sibling)
        rs = _rsync(["-a", "--no-whole-file", "--fuzzy", "--stats"] +
                    list(rs_extra) + [source + "/", rdst + "/"])
        assert rs.returncode == 0, rs.stderr[:300]
        result, _ = run_client(
            source, dest,
            flags=["-a", "--incremental", "--delta", "--fuzzy", "--stats"] +
            list(fs_extra),
            port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        _assert_same_tree(rdst, get_dest_received_dir(dest, source), "(--fuzzy)")
        return rs, result

    @requires_rsync
    def test_fuzzy_above_size_window_declines_but_tree_exact(self, shared_server):
        """A sibling >10x the source is used by rsync but declined by FastSync's
        delta size-ratio gate; both destinations stay byte-identical."""
        n = 65536
        payload = (self._BASE * ((n // len(self._BASE)) + 1))[:n]
        sibling = (self._BASE * 200)[: n * 20]
        source, dest, rdst = (self._src("big"), self._dst("big"),
                              self._dst("big_r"))
        rs, result = self._run_both(shared_server, source, dest, rdst,
                                    payload, sibling)
        assert _stat_bytes(rs.stdout, "Matched data") > 0, \
            "rsync should still use a >10x fuzzy basis"
        assert _stat_bytes(result.stdout, "Matched data") == 0, \
            "FastSync's 10x delta size-ratio gate must decline the oversized basis"
        assert _stat_bytes(result.stdout, "Literal data") == n

    @requires_rsync
    def test_fuzzy_below_delta_minimum_declines_but_tree_exact(self, shared_server):
        """A sibling below the 16 KiB delta minimum is used by rsync but never
        enters FastSync's delta/fuzzy path; both trees stay byte-identical."""
        n = 8192
        payload = (self._BASE * ((n // len(self._BASE)) + 1))[:n]
        source, dest, rdst = (self._src("small"), self._dst("small"),
                              self._dst("small_r"))
        rs, result = self._run_both(shared_server, source, dest, rdst,
                                    payload, payload)
        assert _stat_bytes(rs.stdout, "Matched data") > 0, \
            "rsync applies --fuzzy below 16 KiB"
        assert _stat_bytes(result.stdout, "Matched data") == 0, \
            "FastSync's 16 KiB delta minimum must bypass the fuzzy basis"
        assert _stat_bytes(result.stdout, "Literal data") == n


class TestIgnoreExistingShortCircuit:
    """#9: --ignore-existing is decided by the receiver during the per-file
    check, before the sender streams any payload.  A large destination file that
    is already present must therefore cost almost no wire bytes, not the full
    file; rsync short-circuits the same way."""

    @requires_rsync
    @pytest.mark.ci
    def test_skip_answered_before_payload(self):
        source = os.path.join(TEST_DATA_DIR, "qw_ie_wire_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_ie_wire_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_ie_wire_rdst")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(rdst)
        big = b"S" * (4 * 1024 * 1024)
        with open(os.path.join(source, "big.bin"), "wb") as fh:
            fh.write(big)
        for root in (get_dest_received_dir(dest, source), rdst):
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, "big.bin"), "wb") as fh:
                fh.write(b"D" * len(big))

        assert _rsync(["-a", "--ignore-existing", source + "/",
                       rdst + "/"]).returncode == 0

        # A dedicated one-shot server keeps the proxy's connection teardown
        # deterministic (the session-wide server can linger on an idle socket).
        with ServerManager() as server:
            cmd = CLIENT_CMD + [
                "--source-dir", source, "--dest-dir", dest, "--save-to-disk",
                "--server-port", str(server.port), "-a", "--ignore-existing",
            ]
            proxy = CountingProxy(server.port)
            # Only the client->server count matters here; it is final once the
            # client exits, so do not wait for the server to close its idle
            # socket (which can take the full default join timeout).
            result = proxy.run(cmd, join_timeout=1.0)
        assert result.returncode == 0, (result.stderr or result.stdout)[:300]
        # The receiver answered the skip before the sender transmitted the file:
        # only config/path/check frames crossed, not the 4 MiB payload.
        assert proxy.client_to_server < len(big) // 10, (
            f"--ignore-existing transmitted {proxy.client_to_server} bytes for a "
            f"skipped {len(big)}-byte file"
        )
        received = get_dest_received_dir(dest, source)
        with open(os.path.join(received, "big.bin"), "rb") as fh:
            assert fh.read() == b"D" * len(big), \
                "--ignore-existing must preserve the destination content"
        _assert_same_tree(rdst, received, "(--ignore-existing wire short-circuit)")


@pytest.mark.skipif(os.geteuid() != 0, reason="ownership mapping requires root")
class TestOwnershipMapping:
    """#33/#34/#35: --usermap/--groupmap/--chown match rsync's numeric result."""

    def _prep(self, tag):
        source = os.path.join(TEST_DATA_DIR, f"own_{tag}_src")
        dest = os.path.join(TEST_DATA_DIR, f"own_{tag}_dst")
        rdst = os.path.join(TEST_DATA_DIR, f"own_{tag}_rdst")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(rdst)
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"a\n")
        return source, dest, rdst

    @requires_rsync
    def test_usermap_groupmap_matches_rsync(self, shared_server):
        source, dest, rdst = self._prep("map")
        assert _rsync(["-a", "--usermap=*:12345", "--groupmap=*:54321",
                       source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest,
                               flags=["--usermap=*:12345", "--groupmap=*:54321"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        rs = os.stat(os.path.join(rdst, "a.txt"))
        fs = os.stat(os.path.join(get_dest_received_dir(dest, source), "a.txt"))
        assert (fs.st_uid, fs.st_gid) == (rs.st_uid, rs.st_gid) == (12345, 54321)

    @requires_rsync
    def test_chown_matches_rsync(self, shared_server):
        source, dest, rdst = self._prep("chown")
        assert _rsync(["-a", "--chown=23456:65432", source + "/",
                       rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["--chown=23456:65432"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        rs = os.stat(os.path.join(rdst, "a.txt"))
        fs = os.stat(os.path.join(get_dest_received_dir(dest, source), "a.txt"))
        assert (fs.st_uid, fs.st_gid) == (rs.st_uid, rs.st_gid) == (23456, 65432)


class TestFakeSuper:
    """#32: --fake-super stores privileged attrs via xattrs.  FastSync uses its
    own reserved key (documented divergence) but the file DATA must match rsync."""

    @requires_rsync
    def test_fake_super_data_matches_rsync(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "fs_src")
        dest = os.path.join(TEST_DATA_DIR, "fs_dst")
        rdst = os.path.join(TEST_DATA_DIR, "fs_rdst")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(rdst)
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"fake-super-data\n")
        assert _rsync(["-a", "--fake-super", source + "/", rdst + "/"]).returncode == 0
        result, _ = run_client(source, dest, flags=["--fake-super"],
                               port=shared_server.port)
        assert result.returncode == 0, result.stderr[:300]
        with open(os.path.join(get_dest_received_dir(dest, source), "a.txt"), "rb") as fh:
            assert fh.read() == b"fake-super-data\n"
        with open(os.path.join(rdst, "a.txt"), "rb") as fh:
            assert fh.read() == b"fake-super-data\n"


# rsync 3.4.1's full --info/--debug vocabularies (from `rsync --info=help` /
# `--debug=help`).  FastSync must accept every one of them; only the categories
# with an existing FastSync counterpart emit output, the rest are accepted but
# currently silent.
RSYNC_INFO_CATEGORIES = (
    "backup", "copy", "del", "flist", "misc", "mount", "name", "nonreg",
    "progress", "remove", "skip", "stats", "symsafe", "all", "none",
)
RSYNC_DEBUG_CATEGORIES = (
    "acl", "backup", "bind", "chdir", "connect", "cmd", "del", "deltasum",
    "dup", "exit", "filter", "flist", "fuzzy", "genr", "hash", "hlink",
    "iconv", "io", "nstr", "own", "proto", "recv", "send", "time", "all",
    "none",
)
# Extra categories FastSync also accepts: rsync's own help spells these
# `symsafe`/`hlink`/`own`, but the historical aliases are kept working, and
# `pack`/`util` are FastSync-specific debug channels.
FASTSYNC_INFO_ALIASES = ("syms",)
FASTSYNC_DEBUG_ALIASES = ("hl", "owner", "pack", "util")


class TestInfoDebugFlagParity:
    """#01/#02: FastSync accepts rsync 3.4.1's full --info/--debug vocabulary
    (with level suffixes) so a valid rsync invocation is never rejected up
    front.  Unknown names are still refused by name."""

    def _tree(self):
        source = os.path.join(TEST_DATA_DIR, "qw_flags_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_flags_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_flags_rdst")
        clean_dir(source)
        clean_dir(dest)
        clean_dir(rdst)
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"a\n")
        return source, dest, rdst

    @requires_rsync
    @pytest.mark.ci
    def test_info_vocabulary_accepted_like_rsync(self, shared_server):
        source, dest, rdst = self._tree()
        for cat in RSYNC_INFO_CATEGORIES:
            rs = _rsync(["-a", "--info=" + cat, source + "/", rdst + "/"])
            assert rs.returncode == 0, f"rsync rejected --info={cat}: {rs.stderr}"
            clean_dir(rdst)
            result, _ = run_client(source, dest, flags=["--info=" + cat],
                                   port=shared_server.port)
            assert result.returncode == 0, (
                f"--info={cat} must be accepted like rsync: {result.stderr[:200]}"
            )

    @requires_rsync
    @pytest.mark.ci
    def test_debug_vocabulary_accepted_like_rsync(self, shared_server):
        source, dest, rdst = self._tree()
        for cat in RSYNC_DEBUG_CATEGORIES:
            rs = _rsync(["-a", "--debug=" + cat, source + "/", rdst + "/"])
            assert rs.returncode == 0, f"rsync rejected --debug={cat}: {rs.stderr}"
            clean_dir(rdst)
            result, _ = run_client(source, dest, flags=["--debug=" + cat],
                                   port=shared_server.port)
            assert result.returncode == 0, (
                f"--debug={cat} must be accepted like rsync: {result.stderr[:200]}"
            )

    @requires_rsync
    @pytest.mark.ci
    def test_level_suffixes_accepted_like_rsync(self, shared_server):
        source, dest, rdst = self._tree()
        for flag in ("--info=stats2", "--info=copy0", "--info=all0",
                     "--debug=io2", "--debug=proto0", "--debug=all4"):
            rs = _rsync(["-a", flag, source + "/", rdst + "/"])
            assert rs.returncode == 0, f"rsync rejected {flag}: {rs.stderr}"
            clean_dir(rdst)
            result, _ = run_client(source, dest, flags=[flag],
                                   port=shared_server.port)
            assert result.returncode == 0, (
                f"{flag} must be accepted like rsync: {result.stderr[:200]}"
            )

    def test_fastsync_alias_categories_accepted(self, shared_server):
        """FastSync-specific/alias spellings: accepted (rsync spells them
        symsafe/hlink/own) but not emitted."""
        source, dest, _ = self._tree()
        for flag in (["--info=" + c for c in FASTSYNC_INFO_ALIASES] +
                     ["--debug=" + c for c in FASTSYNC_DEBUG_ALIASES]):
            result, _ = run_client(source, dest, flags=[flag],
                                   port=shared_server.port)
            assert result.returncode == 0, (
                f"{flag} must be accepted: {result.stderr[:200]}"
            )

    @requires_rsync
    @pytest.mark.ci
    def test_unknown_categories_rejected_by_name(self, shared_server):
        """Truly unknown names are refused by name, exactly like rsync."""
        source, dest, rdst = self._tree()
        for flag, name in (("--info=bogus", "bogus"),
                           ("--debug=bogus", "bogus")):
            rs = _rsync(["-a", flag, source + "/", rdst + "/"])
            assert rs.returncode != 0, f"rsync unexpectedly accepted {flag}"
            result, _ = run_client(source, dest, flags=[flag],
                                   port=shared_server.port)
            assert result.returncode != 0, f"{flag} must be rejected"
            assert name in (result.stderr or ""), (
                f"{flag} must be rejected by name, got: {result.stderr[:200]}"
            )


class TestStopAtParity:
    """#62: --stop-at accepts rsync's full date/time form."""

    @requires_rsync
    @pytest.mark.ci
    def test_stop_at_rsync_date_forms_accepted(self, shared_server):
        source = os.path.join(TEST_DATA_DIR, "qw_stop_src")
        dest = os.path.join(TEST_DATA_DIR, "qw_stop_dst")
        rdst = os.path.join(TEST_DATA_DIR, "qw_stop_rdst")
        clean_dir(source)
        with open(os.path.join(source, "a.txt"), "wb") as fh:
            fh.write(b"a\n")
        # rsync's documented --stop-at forms, all in the future or resolvable.
        forms = ["2030-12-31T23:59", "2030/12/31T23:59", "2030-12-31", ":59", "1-30", "1"]
        for form in forms:
            rs = _rsync(["-a", "--stop-at=" + form, source + "/", rdst + "/"])
            assert rs.returncode == 0, f"rsync rejected {form}: {rs.stderr}"
            clean_dir(rdst)
            clean_dir(dest)
            result, _ = run_client(source, dest, flags=["--stop-at=" + form],
                                   port=shared_server.port)
            assert result.returncode == 0, (
                f"--stop-at={form} must be accepted like rsync: {result.stderr[:200]}"
            )
