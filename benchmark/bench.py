#!/usr/bin/env python3
"""Standalone benchmark tool for FastSync.

Compares FastSync configs against rsync (no compression) and rsync+zstd.
Data is ~75% random/incompressible and ~25% structured/compressible by default,
controllable via --random-ratio.

Usage:
    python3 benchmark/bench.py
    python3 benchmark/bench.py --runs 5 --profiles lan wan
    python3 benchmark/bench.py --random-ratio 0.5 --size-mb 50
    python3 benchmark/bench.py --delay 50ms --jitter 10ms --throughput 100mbit
    python3 benchmark/bench.py --output json
"""
import argparse
import json
import os
import random
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
SERVER_CMD = [os.path.join(BUILD_DIR, "server")]
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
    {"name": "fastsync",           "flags": [],                     "tool": "fastsync"},
    {"name": "fastsync -c",        "flags": ["-c"],                 "tool": "fastsync"},
    {"name": "fastsync -m",        "flags": ["-m"],                 "tool": "fastsync"},
    {"name": "fastsync -m -c",     "flags": ["-m", "-c"],           "tool": "fastsync"},
    {"name": "fastsync -m -c -s",  "flags": ["-m", "-c", "-s"],     "tool": "fastsync"},
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


def generate_bench_data(source_dir, size_mb=25, random_ratio=0.75):
    """Generate test data. ~random_ratio is incompressible, rest is structured."""
    if os.path.exists(source_dir):
        shutil.rmtree(source_dir)
    os.makedirs(source_dir)

    target = size_mb * 1024 * 1024
    structured_budget = int(target * (1 - random_ratio))
    written = 0

    for rel_path, content in STRUCTURED_FILES.items():
        if written >= structured_budget:
            break
        full_path = os.path.join(source_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(content)
        written += len(content)

    os.makedirs(os.path.join(source_dir, "bulk"), exist_ok=True)
    i = 0
    while written < target:
        chunk_size = min(5 * 1024 * 1024, target - written)
        with open(os.path.join(source_dir, f"bulk/file_{i}.dat"), "wb") as f:
            f.write(random.randbytes(chunk_size))
        written += chunk_size
        i += 1

    return written


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


def netem_apply(delay=None, jitter=None, throughput=None, loss=None):
    """Apply tc/netem rules to loopback. Pass None to skip a parameter."""
    netem_reset()
    cmd = ["sudo", "tc", "qdisc", "add", "dev", "lo", "root", "netem"]
    if throughput:
        cmd += ["rate", throughput]
    if delay:
        cmd += ["delay", delay, jitter or "0ms"]
    if loss:
        cmd += ["loss", loss]
    if len(cmd) > 6:
        subprocess.run(cmd, check=True, capture_output=True)


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
    subprocess.run("sudo tc qdisc del dev lo root".split(), capture_output=True)


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
    except subprocess.TimeoutExpired:
        pass
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
    except subprocess.TimeoutExpired:
        pass
    return None


def run_transfer(config, source_dir, dest_dir, port=None, rsync_daemon=None):
    """Route to the right tool. Returns duration or None."""
    if config["tool"] == "rsync":
        return run_rsync(source_dir, dest_dir, config["flags"], rsync_daemon)
    else:
        return run_fastsync(source_dir, dest_dir, config["flags"], port)


def run_benchmark(source_dir, dest_dir, configs, runs, profile_name):
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
            for run_idx in range(runs):
                if os.path.exists(dest_dir):
                    shutil.rmtree(dest_dir)
                os.makedirs(dest_dir, exist_ok=True)

                port = find_free_port()
                server = None
                try:
                    if config["tool"] == "fastsync":
                        server = subprocess.Popen(
                            SERVER_CMD + ["-p", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                        wait_for_port(port)

                    t = run_transfer(config, source_dir, dest_dir, port, rsync_daemon)
                    if t is not None:
                        times.append(t)
                finally:
                    if server:
                        wait_proc(server)

            entry = {
                "config": config["name"],
                "tool": config["tool"],
                "profile": profile_name,
                "runs": len(times),
                "times": [round(t, 4) for t in times],
            }
            if times:
                entry["p50"] = round(statistics.median(times), 4)
                entry["p95"] = round(sorted(times)[int(len(times) * 0.95)], 4) if len(times) > 1 else entry["p50"]
                entry["min"] = round(min(times), 4)
                entry["max"] = round(max(times), 4)
                entry["stdev"] = round(statistics.stdev(times), 4) if len(times) > 1 else 0.0
            results.append(entry)
        return results
    finally:
        if rsync_daemon:
            rsync_daemon.stop()
        if is_limited:
            netem_reset()


def print_table(results, total_bytes, random_ratio):
    """Print results as a human-readable table grouped by profile."""
    profiles = {}
    for r in results:
        profiles.setdefault(r["profile"], []).append(r)

    for profile, entries in profiles.items():
        params = NETWORK_PROFILES.get(profile, {})
        print(f"\n{'=' * 85}")
        print(f" Profile: {profile.upper()}")
        if params.get("rate"):
            print(f" Network: {params['rate']}, {params['delay']} +/- {params['jitter']}, loss {params['loss']}")
        else:
            print(f" Network: unlimited")
        print(f" Data: {total_bytes / (1024*1024):.1f} MB  ({random_ratio*100:.0f}% random, {(1-random_ratio)*100:.0f}% compressible)")
        print(f"{'=' * 85}")

        fs_entries = [e for e in entries if e.get("tool") == "fastsync"]
        rsync_entries = [e for e in entries if e.get("tool") == "rsync"]

        if fs_entries:
            print(f"\n FastSync:")
            print(f" {'Config':<25} {'p50':>8} {'p95':>8} {'min':>8} {'max':>8} {'stdev':>8} {'runs':>5}")
            print(f" {'-' * 25} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 5}")
            for e in sorted(fs_entries, key=lambda x: x.get("p50", 999)):
                _print_entry(e)

        if rsync_entries:
            print(f"\n rsync:")
            print(f" {'Config':<25} {'p50':>8} {'p95':>8} {'min':>8} {'max':>8} {'stdev':>8} {'runs':>5}")
            print(f" {'-' * 25} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 5}")
            for e in sorted(rsync_entries, key=lambda x: x.get("p50", 999)):
                _print_entry(e)

        if params.get("rate_bps") and fs_entries and rsync_entries:
            fs_best = min((e["p50"] for e in fs_entries if "p50" in e), default=None)
            rsync_best = min((e["p50"] for e in rsync_entries if "p50" in e), default=None)
            theoretical = total_bytes / params["rate_bps"]
            if fs_best and rsync_best:
                print(f"\n Theoretical max (line rate): {theoretical:.4f}s")
                print(f" FastSync best:   {fs_best:.4f}s  ({theoretical/fs_best:.2f}x vs line rate)")
                print(f" rsync best:      {rsync_best:.4f}s  ({theoretical/rsync_best:.2f}x vs line rate)")
                print(f" FastSync vs rsync: {rsync_best/fs_best:.2f}x faster")


def _print_entry(e):
    if "p50" in e:
        print(f" {e['config']:<25} {e['p50']:>7.4f}s {e['p95']:>7.4f}s "
              f"{e['min']:>7.4f}s {e['max']:>7.4f}s {e['stdev']:>7.4f} {e['runs']:>5}")
    else:
        print(f" {e['config']:<25} {'N/A':>8} {'N/A':>8} {'N/A':>8} {'N/A':>8} {'N/A':>8} {e['runs']:>5}")


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
  reflecting typical real-world file sets.

Examples:
  %(prog)s --profiles wan --runs 5
  %(prog)s --throughput 50mbit --delay 30ms --jitter 5ms
  %(prog)s --random-ratio 0.5 --size-mb 100
""")
    parser.add_argument("--runs", type=int, default=3,
                        help="Number of runs per config (default: 3)")
    parser.add_argument("--profiles", nargs="+", default=None,
                        choices=list(NETWORK_PROFILES.keys()),
                        help="Predefined network profiles (default: unlimited)")
    parser.add_argument("--configs", nargs="+", default=None,
                        help="Custom FastSync config flags")
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
    parser.add_argument("--output", choices=["table", "json"], default="table",
                        help="Output format")
    parser.add_argument("--keep-data", action="store_true",
                        help="Don't clean up test data")
    args = parser.parse_args()

    # Build
    print("Building...")
    if os.system(f"cmake -B {BUILD_DIR} -S {PROJECT_ROOT} > /dev/null 2>&1") != 0:
        print("CMake configure failed"); sys.exit(1)
    if os.system(f"cmake --build {BUILD_DIR} -j$(nproc) > /dev/null 2>&1") != 0:
        print("Build failed"); sys.exit(1)

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

    # Generate data
    source_dir = os.path.join(BENCH_DIR, "source")
    dest_dir = os.path.join(BENCH_DIR, "dest")
    total_bytes = generate_bench_data(source_dir, args.size_mb, args.random_ratio)
    compressible_pct = (1 - args.random_ratio) * 100
    random_pct = args.random_ratio * 100
    print(f"Generated {total_bytes / (1024*1024):.1f} MB  "
          f"({random_pct:.0f}% random, {compressible_pct:.0f}% compressible)")

    # Build config list
    if args.configs:
        fastsync_configs = [{"name": c, "flags": c.split(), "tool": "fastsync"} for c in args.configs]
    else:
        fastsync_configs = list(FASTSYNC_CONFIGS)

    configs = list(fastsync_configs)
    if not args.no_rsync:
        configs += RSYNC_CONFIGS

    # Run benchmarks
    all_results = []
    try:
        for profile in profiles_to_run:
            results = run_benchmark(source_dir, dest_dir, configs, args.runs, profile)
            all_results.extend(results)
    finally:
        if not args.keep_data:
            shutil.rmtree(BENCH_DIR, ignore_errors=True)

    # Output
    if args.output == "json":
        print(json.dumps(all_results, indent=2))
    else:
        print_table(all_results, total_bytes, args.random_ratio)
        print()


if __name__ == "__main__":
    main()
