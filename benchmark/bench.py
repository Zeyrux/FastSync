#!/usr/bin/env python3
"""Standalone benchmark tool for FastSync.

Compares FastSync configs against rsync (no compression) and rsync+zstd.
Data is ~75% random/incompressible and ~25% structured/compressible by default,
controllable via --random-ratio. Transfers are verified by default (source and
destination must match) so a fast-but-broken copy is never counted.

Usage:
    python3 benchmark/bench.py
    python3 benchmark/bench.py --runs 5 --profiles lan wan
    python3 benchmark/bench.py --random-ratio 0.5 --size-mb 50
    python3 benchmark/bench.py --delay 50ms --jitter 10ms --throughput 100mbit
    python3 benchmark/bench.py --warm --runs 3
    python3 benchmark/bench.py --output json
"""
import argparse
import filecmp
import json
import math
import os
import random
import shlex
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_BUILD_DIR = "build-bench"
# Populated by configure_build_dirs(); default to the dedicated bench dir so
# importing this module never depends on the user's existing build/ tree.
BUILD_DIR = os.path.join(PROJECT_ROOT, DEFAULT_BUILD_DIR)
SERVER_CMD = [os.path.join(BUILD_DIR, "server"), "--allow-unauthenticated"]
CLIENT_CMD = [os.path.join(BUILD_DIR, "client")]
BENCH_DIR = os.path.join(PROJECT_ROOT, "bench_data")

NETWORK_PROFILES = {
    "unlimited": {},
    "lan": {
        "rate": "1000mbit", "delay": "20ms", "jitter": "1ms", "loss": "0.1%",
        "rate_bps": 1_000_000_000 / 8,
    },
    "wan": {
        "rate": "100mbit", "delay": "50ms", "jitter": "10ms", "loss": "1%",
        "rate_bps": 100_000_000 / 8,
    },
}

FASTSYNC_CONFIGS = [
    {"name": "fastsync",                        "flags": [],                                     "tool": "fastsync"},
    {"name": "fastsync -z",                     "flags": ["-z"],                                 "tool": "fastsync"},
    {"name": "fastsync -j",                     "flags": ["-j"],                                 "tool": "fastsync"},
    {"name": "fastsync -j -z",                  "flags": ["-j", "-z"],                           "tool": "fastsync"},
    {"name": "fastsync -j -z --chunk-serialization", "flags": ["-j", "-z", "--chunk-serialization"], "tool": "fastsync"},
    {"name": "fastsync --sendfile",             "flags": ["--sendfile"],                         "tool": "fastsync"},
]

RSYNC_CONFIGS = [
    {"name": "rsync",              "flags": [],                     "tool": "rsync"},
    {"name": "rsync -z",           "flags": ["-z"],                 "tool": "rsync"},
    {"name": "rsync -z --zstd",    "flags": ["-z", "--zc", "zstd"],"tool": "rsync"},
]


class RsyncDaemon:
    """Manages an rsync daemon for network-fair benchmarking."""

    def __init__(self):
        self._proc = None
        self._port = None
        self._conf_dir = None
        self._module_path = None

    def start(self, source_dir):
        self._port = find_free_port()
        self._conf_dir = tempfile.mkdtemp(prefix="rsyncd_")
        self._module_path = source_dir

        conf_path = os.path.join(self._conf_dir, "rsyncd.conf")
        log_path = os.path.join(self._conf_dir, "rsyncd.log")

        with open(conf_path, "w") as f:
            f.write(f"uid = 0\ngid = 0\nuse chroot = no\nlog file = {log_path}\n")
            f.write(f"[bench]\n\tpath = {source_dir}\n\tread only = yes\n")

        self._proc = subprocess.Popen(
            ["rsync", "--daemon", "--no-detach",
             "--port", str(self._port),
             "--config", conf_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        wait_for_port(self._port, timeout=5)

    def stop(self):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None
        if self._conf_dir:
            shutil.rmtree(self._conf_dir, ignore_errors=True)
            self._conf_dir = None

    @property
    def source_url(self):
        return f"rsync://127.0.0.1:{self._port}/bench/"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()


STRUCTURED_FILES = {
    "small.txt": b"hello world\n",
    "medium.txt": b"the quick brown fox jumps over the lazy dog\n" * 5000,
    "binary.bin": bytes(range(256)) * 1000,
    "nested/subdir/deep.txt": b"deeply nested file\n",
    "nested/another.txt": b"another nested file\n" * 50,
}

# Repeated text used to synthesize genuinely compressible filler of any size.
COMPRESSIBLE_TEXT = (
    b"FastSync benchmark payload: the quick brown fox jumps over the lazy dog. "
    b"0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz\n"
)


class Progress:
    """Simple progress bar with ETA."""

    def __init__(self, total, label="Progress"):
        self.total = total
        self.current = 0
        self.label = label
        self.start_time = time.monotonic()
        self._print()

    def tick(self, detail=""):
        self.current += 1
        self._print(detail)

    def _print(self, detail=""):
        elapsed = time.monotonic() - self.start_time
        if self.current > 0:
            eta = elapsed / self.current * (self.total - self.current)
            eta_str = f"ETA {eta:.0f}s"
        else:
            eta_str = "ETA ..."
        pct = self.current / self.total * 100 if self.total else 0
        bar_len = 30
        filled = int(bar_len * self.current / self.total) if self.total else 0
        bar = "#" * filled + "-" * (bar_len - filled)
        detail_str = f"  {detail}" if detail else ""
        sys.stderr.write(f"\r  [{bar}] {pct:5.1f}%  {self.current}/{self.total}  {eta_str}{detail_str}  ")
        sys.stderr.flush()
        if self.current >= self.total:
            sys.stderr.write(f"\r  [{'#' * bar_len}] 100.0%  {self.total}/{self.total}  done in {elapsed:.1f}s" + " " * 30 + "\n")
            sys.stderr.flush()


def write_compressible(path, nbytes):
    """Write exactly nbytes of highly compressible, repeated text content."""
    if nbytes <= 0:
        return
    block = COMPRESSIBLE_TEXT * (max(1, 8192 // len(COMPRESSIBLE_TEXT)) + 1)
    remaining = nbytes
    with open(path, "wb") as f:
        while remaining > 0:
            piece = block if remaining >= len(block) else block[:remaining]
            f.write(piece)
            remaining -= len(piece)


def generate_bench_data(source_dir, size_mb=25, random_ratio=0.75):
    """Generate test data honouring the requested random/compressible split.

    Exactly ``random_ratio * target`` bytes are incompressible random data and
    the remainder is genuinely compressible structured/repeated content. The
    measured byte counts are returned so callers can report the real mix.
    """
    if os.path.exists(source_dir):
        shutil.rmtree(source_dir)
    os.makedirs(source_dir)

    target = size_mb * 1024 * 1024
    random_budget = int(target * random_ratio)
    compressible_budget = target - random_budget
    compressible_written = 0
    random_written = 0
    files = 0

    # A handful of fixed, human-meaningful files (directories, small files, a
    # binary blob) as long as they fit inside the compressible budget.
    for rel_path, content in STRUCTURED_FILES.items():
        if compressible_written + len(content) > compressible_budget:
            break
        full_path = os.path.join(source_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(content)
        compressible_written += len(content)
        files += 1

    # Fill the rest of the compressible share with generated repeated content.
    if compressible_written < compressible_budget:
        os.makedirs(os.path.join(source_dir, "compressible"), exist_ok=True)
        i = 0
        while compressible_written < compressible_budget:
            chunk = min(1024 * 1024, compressible_budget - compressible_written)
            write_compressible(os.path.join(source_dir, "compressible", f"text_{i}.dat"), chunk)
            compressible_written += chunk
            files += 1
            i += 1

    # Incompressible share.
    if random_written < random_budget:
        os.makedirs(os.path.join(source_dir, "bulk"), exist_ok=True)
        i = 0
        while random_written < random_budget:
            chunk = min(5 * 1024 * 1024, random_budget - random_written)
            with open(os.path.join(source_dir, "bulk", f"file_{i}.dat"), "wb") as f:
                f.write(random.randbytes(chunk))
            random_written += chunk
            files += 1
            i += 1

    return {
        "total_bytes": compressible_written + random_written,
        "compressible_bytes": compressible_written,
        "random_bytes": random_written,
        "files": files,
    }


def list_relative_files(root):
    """Return the set of file paths (relative to root) under a directory."""
    found = set()
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            found.add(os.path.relpath(full, root))
    return found


def verify_transfer(source_dir, dest_dir):
    """Recursively check dest matches source (paths, sizes, content).

    Returns (ok, detail). Content is compared byte-for-byte, never hashed, so
    collisions are impossible. This is intentionally not part of the timing.
    """
    if not os.path.isdir(dest_dir):
        return False, "destination directory missing"
    src_files = list_relative_files(source_dir)
    dst_files = list_relative_files(dest_dir)
    if src_files != dst_files:
        missing = src_files - dst_files
        extra = dst_files - src_files
        return False, f"path set mismatch (missing {len(missing)}, extra {len(extra)})"
    for rel in sorted(src_files):
        src = os.path.join(source_dir, rel)
        dst = os.path.join(dest_dir, rel)
        if os.path.getsize(src) != os.path.getsize(dst):
            return False, f"size mismatch: {rel}"
        if not filecmp.cmp(src, dst, shallow=False):
            return False, f"content mismatch: {rel}"
    return True, ""


def percentile(values, pct):
    """Linear-interpolation percentile (matches numpy's default method)."""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[int(rank)]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def wait_for_port(port, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)
    raise RuntimeError(f"Port {port} not ready")


def wait_proc(proc, timeout=5):
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _tc_base_cmd():
    """Return the command prefix for tc, honouring root vs sudo."""
    tc = shutil.which("tc")
    if not tc:
        raise RuntimeError(
            "tc (iproute2) not found in PATH; install iproute2 to use network profiles")
    if os.geteuid() == 0:
        return [tc]
    sudo = shutil.which("sudo")
    if sudo:
        return [sudo, tc]
    raise RuntimeError(
        "applying network limits requires root or sudo; "
        "re-run as root or install sudo")


def _run_tc(args, check=True):
    return subprocess.run(_tc_base_cmd() + args, check=check, capture_output=True)


def netem_apply(delay=None, jitter=None, throughput=None, loss=None):
    """Apply tc/netem rules to loopback. Pass None to skip a parameter."""
    netem_reset()
    params = []
    if throughput:
        params += ["rate", throughput]
    if delay:
        params += ["delay", delay, jitter or "0ms"]
    if loss:
        params += ["loss", loss]
    if not params:
        return
    try:
        _run_tc(["qdisc", "add", "dev", "lo", "root", "netem"] + params)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace").strip() if exc.stderr else str(exc)
        raise RuntimeError(f"failed to apply network profile via tc/netem: {detail}") from exc
    except RuntimeError:
        raise


def netem_apply_profile(profile_name):
    params = NETWORK_PROFILES.get(profile_name, {})
    if not params:
        netem_reset()
        return
    netem_apply(
        delay=params.get("delay"),
        jitter=params.get("jitter"),
        throughput=params.get("rate"),
        loss=params.get("loss"),
    )


def netem_reset():
    """Best-effort removal of any loopback qdisc. Always safe to call."""
    try:
        _run_tc(["qdisc", "del", "dev", "lo", "root"], check=False)
    except Exception:
        pass


def run_fastsync(source_dir, dest_dir, flags, port):
    """Run FastSync client. Returns duration or None."""
    cmd = CLIENT_CMD + [
        "--source-dir", source_dir,
        "--dest-dir", dest_dir,
        "--server-port", str(port),
        "--save-to-disk",
    ] + flags
    try:
        start = time.monotonic()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        duration = time.monotonic() - start
        if result.returncode == 0:
            return duration
        sys.stderr.write(f"    fastsync failed (exit {result.returncode}): "
                         f"{result.stderr.strip()[:500]}\n")
    except subprocess.TimeoutExpired:
        sys.stderr.write("    fastsync timed out after 120s\n")
    return None


def run_rsync(source_dir, dest_dir, flags, rsync_daemon=None):
    """Run rsync. Returns duration or None."""
    src = source_dir.rstrip("/") + "/"
    if rsync_daemon:
        src = rsync_daemon.source_url
    cmd = ["rsync", "-a", "--delete"] + flags + [src, dest_dir + "/"]
    try:
        start = time.monotonic()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        duration = time.monotonic() - start
        if result.returncode == 0:
            return duration
        sys.stderr.write(f"    rsync failed (exit {result.returncode}): "
                         f"{result.stderr.strip()[:500]}\n")
    except subprocess.TimeoutExpired:
        sys.stderr.write("    rsync timed out after 120s\n")
    return None


def run_transfer(config, source_dir, dest_dir, port=None, rsync_daemon=None):
    """Route to the right tool. Returns duration or None."""
    if config["tool"] == "rsync":
        return run_rsync(source_dir, dest_dir, config["flags"], rsync_daemon)
    else:
        return run_fastsync(source_dir, dest_dir, config["flags"], port)


def apply_incremental_changes(source_dir, target_bytes):
    """Add and modify a few files so a warm transfer has real work to do.

    Returns a mutation record (changed byte count plus enough data to revert
    and re-apply it) so every warm run can start from a pristine source.
    """
    modified_n = 3
    added_n = 2
    per_file = max(4096, target_bytes // (modified_n + added_n))
    modified = {}
    added = {}
    changed = 0

    existing = sorted(list_relative_files(source_dir))
    if existing:
        step = max(1, len(existing) // modified_n)
        for rel in existing[::step][:modified_n]:
            path = os.path.join(source_dir, rel)
            original_size = os.path.getsize(path)
            with open(path, "ab") as f:
                f.write(random.randbytes(per_file))
            modified[rel] = (original_size, per_file)
            changed += per_file

    for i in range(added_n):
        os.makedirs(os.path.join(source_dir, "incremental"), exist_ok=True)
        rel = os.path.join("incremental", f"new_{i}.dat")
        write_compressible(os.path.join(source_dir, rel), per_file)
        added[rel] = per_file
        changed += per_file

    return {"changed": changed, "modified": modified, "added": added}


def revert_incremental_changes(source_dir, mutation):
    """Undo apply_incremental_changes so the source is pristine again."""
    if not mutation:
        return
    for rel, (original_size, _appended) in mutation["modified"].items():
        path = os.path.join(source_dir, rel)
        if os.path.exists(path):
            with open(path, "r+b") as f:
                f.truncate(original_size)
    for rel in mutation["added"]:
        path = os.path.join(source_dir, rel)
        if os.path.exists(path):
            os.remove(path)


def reapply_incremental_changes(source_dir, mutation):
    """Re-apply a mutation after an untimed pristine seed transfer."""
    if not mutation:
        return
    for rel, (_original_size, appended) in mutation["modified"].items():
        with open(os.path.join(source_dir, rel), "ab") as f:
            f.write(random.randbytes(appended))
    for rel, size in mutation["added"].items():
        write_compressible(os.path.join(source_dir, rel), size)


def expected_received_root(dest_dir, source_dir, tool):
    """Where a tool places transferred files inside dest_dir.

    FastSync mirrors the absolute source path under dest_dir (see the
    integration suite's get_dest_received_dir); rsync copies the source tree
    contents directly into dest_dir.
    """
    if tool == "rsync":
        return dest_dir
    return os.path.join(dest_dir, os.path.abspath(source_dir).lstrip(os.sep))


def run_benchmark(source_dir, dest_dir, configs, runs, profile_name,
                  measure_bytes, verify=True, warm=False, mutation=None,
                  progress=None):
    """Run benchmark for all configs, returns list of results."""
    is_limited = profile_name != "unlimited"
    has_rsync = any(c["tool"] == "rsync" for c in configs)
    if is_limited:
        netem_apply_profile(profile_name)

    rsync_daemon = None
    try:
        if is_limited and has_rsync:
            rsync_daemon = RsyncDaemon()
            rsync_daemon.start(source_dir)

        results = []
        for config in configs:
            times = []
            invalid = 0
            for run_idx in range(runs):
                if warm:
                    revert_incremental_changes(source_dir, mutation)
                if os.path.exists(dest_dir):
                    shutil.rmtree(dest_dir)
                os.makedirs(dest_dir, exist_ok=True)

                port = find_free_port()
                server = None
                try:
                    if config["tool"] == "fastsync" or warm:
                        server = subprocess.Popen(
                            SERVER_CMD + ["-p", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                        wait_for_port(port)

                    if warm:
                        seed = run_transfer(config, source_dir, dest_dir, port, rsync_daemon)
                        if seed is None:
                            invalid += 1
                            sys.stderr.write("    warm-mode seeding failed; run not counted\n")
                            continue
                        reapply_incremental_changes(source_dir, mutation)

                    t = run_transfer(config, source_dir, dest_dir, port, rsync_daemon)
                    if t is None:
                        invalid += 1
                    elif verify:
                        root = expected_received_root(dest_dir, source_dir, config["tool"])
                        ok, detail = verify_transfer(source_dir, root)
                        if ok:
                            times.append(t)
                        else:
                            invalid += 1
                            sys.stderr.write(f"    verification FAILED ({detail}); run not counted\n")
                    else:
                        times.append(t)
                finally:
                    if server:
                        wait_proc(server)

                if progress:
                    progress.tick(f"{config['name']} (run {run_idx+1}/{runs})")

            entry = {
                "config": config["name"],
                "tool": config["tool"],
                "profile": profile_name,
                "warm": warm,
                "runs": len(times),
                "invalid": invalid,
                "times": [round(t, 4) for t in times],
            }
            if times:
                p50 = percentile(times, 50)
                p95 = percentile(times, 95)
                entry["p50"] = round(p50, 4)
                entry["p95"] = round(p95, 4)
                entry["min"] = round(min(times), 4)
                entry["max"] = round(max(times), 4)
                entry["stdev"] = round(statistics.stdev(times), 4) if len(times) > 1 else 0.0
                if measure_bytes:
                    entry["throughput_mbps"] = round(
                        (measure_bytes / (1024 * 1024)) / p50, 3)
            results.append(entry)
        return results
    finally:
        if rsync_daemon:
            rsync_daemon.stop()
        if is_limited:
            netem_reset()


def print_table(results, measure_bytes, stats, warm):
    """Print results as a human-readable table grouped by profile."""
    profiles = {}
    for r in results:
        profiles.setdefault(r["profile"], []).append(r)

    total = stats["total_bytes"]
    comp_pct = stats["compressible_bytes"] / total * 100 if total else 0
    rand_pct = stats["random_bytes"] / total * 100 if total else 0

    for profile, entries in profiles.items():
        params = NETWORK_PROFILES.get(profile, {})
        print(f"\n{'=' * 95}")
        print(f" Profile: {profile.upper()}")
        if params.get("rate"):
            print(f" Network: {params['rate']}, {params['delay']} +/- {params['jitter']}, loss {params['loss']}")
        else:
            print(f" Network: unlimited")
        print(f" Data: {total / (1024*1024):.1f} MB  "
              f"({rand_pct:.0f}% random, {comp_pct:.0f}% compressible actual)")
        if warm:
            print(f" Mode: warm (incremental) — measured {measure_bytes / (1024*1024):.2f} MB "
                  f"changed after an untimed full seed")
        else:
            print(" Mode: cold (full copy)")
        print(f"{'=' * 95}")

        fs_entries = [e for e in entries if e.get("tool") == "fastsync"]
        rsync_entries = [e for e in entries if e.get("tool") == "rsync"]

        header = (f" {'Config':<38} {'p50':>8} {'p95':>8} {'min':>8} {'max':>8} "
                  f"{'stdev':>8} {'MB/s':>9} {'runs':>5} {'bad':>4}")
        rule = (f" {'-' * 38} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} "
                f"{'-' * 8} {'-' * 9} {'-' * 5} {'-' * 4}")

        if fs_entries:
            print(f"\n FastSync:")
            print(header)
            print(rule)
            for e in sorted(fs_entries, key=lambda x: x.get("p50", 999)):
                _print_entry(e)

        if rsync_entries:
            print(f"\n rsync:")
            print(header)
            print(rule)
            for e in sorted(rsync_entries, key=lambda x: x.get("p50", 999)):
                _print_entry(e)

        if params.get("rate_bps") and fs_entries and rsync_entries:
            fs_best = min((e["p50"] for e in fs_entries if "p50" in e), default=None)
            rsync_best = min((e["p50"] for e in rsync_entries if "p50" in e), default=None)
            theoretical = measure_bytes / params["rate_bps"]
            if fs_best and rsync_best:
                print(f"\n Theoretical max (line rate): {theoretical:.4f}s")
                print(f" FastSync best:   {fs_best:.4f}s  ({theoretical/fs_best:.2f}x vs line rate)")
                print(f" rsync best:      {rsync_best:.4f}s  ({theoretical/rsync_best:.2f}x vs line rate)")
                print(f" FastSync vs rsync: {rsync_best/fs_best:.2f}x faster")


def _print_entry(e):
    if "p50" in e:
        tp = f"{e['throughput_mbps']:.2f}" if "throughput_mbps" in e else "N/A"
        print(f" {e['config']:<38} {e['p50']:>7.4f}s {e['p95']:>7.4f}s "
              f"{e['min']:>7.4f}s {e['max']:>7.4f}s {e['stdev']:>7.4f} "
              f"{tp:>9} {e['runs']:>5} {e.get('invalid', 0):>4}")
    else:
        print(f" {e['config']:<38} {'N/A':>8} {'N/A':>8} {'N/A':>8} {'N/A':>8} "
              f"{'N/A':>8} {'N/A':>9} {e['runs']:>5} {e.get('invalid', 0):>4}")


def configure_build_dirs(build_dir):
    """Install the selected build directory and derived binary paths."""
    global BUILD_DIR, SERVER_CMD, CLIENT_CMD
    if not os.path.isabs(build_dir):
        build_dir = os.path.join(PROJECT_ROOT, build_dir)
    BUILD_DIR = os.path.abspath(build_dir)
    SERVER_CMD = [os.path.join(BUILD_DIR, "server"), "--allow-unauthenticated"]
    CLIENT_CMD = [os.path.join(BUILD_DIR, "client")]


def build_project():
    """Configure (Release) and build into the dedicated bench build dir."""
    if shutil.which("cmake") is None:
        sys.stderr.write("cmake not found in PATH; cannot build\n")
        sys.exit(1)
    os.makedirs(BUILD_DIR, exist_ok=True)
    configure = ["cmake", "-B", BUILD_DIR, "-S", PROJECT_ROOT,
                 "-DCMAKE_BUILD_TYPE=Release"]
    result = subprocess.run(configure, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write("CMake configure failed:\n" + result.stdout + result.stderr + "\n")
        sys.exit(1)
    jobs = str(os.cpu_count() or 1)
    result = subprocess.run(["cmake", "--build", BUILD_DIR, "-j", jobs],
                            capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write("Build failed:\n" + result.stdout + result.stderr + "\n")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="FastSync benchmark tool — compares FastSync vs rsync",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Network profiles (predefined):
  unlimited   No artificial limits
  lan         1 Gbit, 20ms delay, 1ms jitter, 0.1%% loss
  wan         100 Mbit, 50ms delay, 10ms jitter, 1%% loss

Custom network limits (--delay/--jitter/--throughput) override profiles.

Data mix:
  Default is ~75%% random/incompressible + ~25%% structured/compressible,
  reflecting typical real-world file sets. The actual mix is measured and
  reported. Transfers are verified (destination must match source) unless
  --no-verify is given.

Warm mode:
  --warm seeds the destination with an untimed full copy of a pristine base,
  then measures only the incremental transfer after modifying a few files.

Examples:
  %(prog)s --profiles wan --runs 5
  %(prog)s --throughput 50mbit --delay 30ms --jitter 5ms
  %(prog)s --random-ratio 0.5 --size-mb 100
  %(prog)s --warm --runs 3 --no-rsync
  %(prog)s --dry-run --size-mb 4 --random-ratio 0.25
""")
    parser.add_argument("--runs", type=int, default=3,
                        help="Number of runs per config (default: 3)")
    parser.add_argument("--profiles", nargs="+", default=None,
                        choices=list(NETWORK_PROFILES.keys()),
                        help="Predefined network profiles (default: unlimited)")
    parser.add_argument("--configs", nargs="+", default=None,
                        help="Custom FastSync config flags (shell-quoted, e.g. "
                             "\"-j -z --chunk-serialization\")")
    parser.add_argument("--size-mb", type=int, default=25,
                        help="Test data size in MB (default: 25)")
    parser.add_argument("--random-ratio", type=float, default=0.75,
                        help="Fraction of data that is random/incompressible (default: 0.75)")
    parser.add_argument("--delay", default=None,
                        help="Custom network delay (e.g. 50ms)")
    parser.add_argument("--jitter", default=None,
                        help="Custom network jitter (e.g. 10ms)")
    parser.add_argument("--throughput", default=None,
                        help="Custom throughput limit (e.g. 100mbit)")
    parser.add_argument("--loss", default=None,
                        help="Custom packet loss (e.g. 1%%)")
    parser.add_argument("--no-rsync", action="store_true",
                        help="Skip rsync comparison")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip source/destination verification after each run")
    parser.add_argument("--warm", action="store_true",
                        help="Incremental mode: seed dest first, measure only changes")
    parser.add_argument("--build-dir", default=DEFAULT_BUILD_DIR,
                        help=f"Build directory (default: {DEFAULT_BUILD_DIR})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Only generate data and report its composition, then exit")
    parser.add_argument("--progress", action="store_true",
                        help="Show progress bar with ETA")
    parser.add_argument("--output", choices=["table", "json"], default="table",
                        help="Output format")
    parser.add_argument("--keep-data", action="store_true",
                        help="Don't clean up test data")
    args = parser.parse_args()

    if not 0.0 <= args.random_ratio <= 1.0:
        parser.error("--random-ratio must be between 0.0 and 1.0")
    if args.size_mb <= 0:
        parser.error("--size-mb must be positive")

    configure_build_dirs(args.build_dir)

    # Generate data
    source_dir = os.path.join(BENCH_DIR, "source")
    dest_dir = os.path.join(BENCH_DIR, "dest")
    stats = generate_bench_data(source_dir, args.size_mb, args.random_ratio)
    total_bytes = stats["total_bytes"]
    comp_pct = stats["compressible_bytes"] / total_bytes * 100 if total_bytes else 0
    rand_pct = stats["random_bytes"] / total_bytes * 100 if total_bytes else 0
    print(f"Generated {total_bytes / (1024*1024):.1f} MB in {stats['files']} files  "
          f"({rand_pct:.0f}% random, {comp_pct:.0f}% compressible actual)",
          file=sys.stderr)

    if args.dry_run:
        print(f"size_mb={args.size_mb} random_ratio={args.random_ratio:.4f} "
              f"total_bytes={stats['total_bytes']} "
              f"compressible_bytes={stats['compressible_bytes']} "
              f"random_bytes={stats['random_bytes']} files={stats['files']}")
        if not args.keep_data:
            shutil.rmtree(BENCH_DIR, ignore_errors=True)
        return

    # Warm mode: keep a pristine base copy, then mutate the live source.
    base_dir = None
    measure_bytes = total_bytes
    mutation = None
    if args.warm:
        change_target = max(64 * 1024, min(int(total_bytes * 0.01), 4 * 1024 * 1024))
        mutation = apply_incremental_changes(source_dir, change_target)
        measure_bytes = mutation["changed"]
        revert_incremental_changes(source_dir, mutation)
        print(f"Warm mode: each run seeds a full copy, then measures "
              f"{measure_bytes / (1024*1024):.3f} MB of add/change deltas", file=sys.stderr)

    # Build (Release: benchmarking a debug build is meaningless)
    print(f"Building (Release) into {BUILD_DIR}...", file=sys.stderr)
    build_project()

    # Determine active profile for display
    has_custom_net = args.delay or args.jitter or args.throughput or args.loss
    if has_custom_net:
        active_profile = "custom"
        NETWORK_PROFILES["custom"] = {
            "rate": args.throughput, "delay": args.delay or "0ms",
            "jitter": args.jitter or "0ms", "loss": args.loss or "0%",
        }
        if args.throughput:
            parts = args.throughput.replace("mbit", "").replace("mbps", "")
            try:
                NETWORK_PROFILES["custom"]["rate_bps"] = float(parts) * 1_000_000 / 8
            except ValueError:
                pass
        profiles_to_run = ["custom"]
    else:
        profiles_to_run = args.profiles or ["unlimited"]

    # Build config list (shlex so quoted/space-separated flags survive)
    if args.configs:
        fastsync_configs = [{"name": c, "flags": shlex.split(c), "tool": "fastsync"}
                            for c in args.configs]
    else:
        fastsync_configs = list(FASTSYNC_CONFIGS)

    configs = list(fastsync_configs)
    if not args.no_rsync:
        configs += RSYNC_CONFIGS

    # Run benchmarks
    total_runs = len(configs) * args.runs * len(profiles_to_run)
    progress = Progress(total_runs, "Benchmarking") if args.progress else None
    if progress:
        print(f"Running {total_runs} transfers...", file=sys.stderr)

    all_results = []
    try:
        for profile in profiles_to_run:
            results = run_benchmark(source_dir, dest_dir, configs, args.runs, profile,
                                    measure_bytes, verify=not args.no_verify,
                                    warm=args.warm, mutation=mutation,
                                    progress=progress)
            all_results.extend(results)
    except RuntimeError as exc:
        sys.stderr.write(f"error: {exc}\n")
        sys.exit(1)
    finally:
        netem_reset()
        if not args.keep_data:
            shutil.rmtree(BENCH_DIR, ignore_errors=True)

    # Output
    if args.output == "json":
        print(json.dumps(all_results, indent=2))
    else:
        print_table(all_results, measure_bytes, stats, args.warm)
        print()


if __name__ == "__main__":
    main()
