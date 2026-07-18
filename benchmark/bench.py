#!/usr/bin/env python3
"""Standalone benchmark tool for FastSync.

Usage:
    python3 benchmark/bench.py                          # quick benchmark (unlimited, 3 runs)
    python3 benchmark/bench.py --runs 5 --profiles lan wan  # thorough
    python3 benchmark/bench.py --output json             # machine-readable
    python3 benchmark/bench.py --configs "-c" "-m" "-m -c"  # custom configs
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

DEFAULT_CONFIGS = [
    {"name": "standard", "flags": []},
    {"name": "-c", "flags": ["-c"]},
    {"name": "-m", "flags": ["-m"]},
    {"name": "-m -c", "flags": ["-m", "-c"]},
    {"name": "-s", "flags": ["-s"]},
    {"name": "-m -c -s", "flags": ["-m", "-c", "-s"]},
]


def generate_bench_data(source_dir, size_mb=25):
    """Generate test data for benchmarking."""
    if os.path.exists(source_dir):
        shutil.rmtree(source_dir)
    os.makedirs(source_dir)

    target = size_mb * 1024 * 1024
    written = 0

    # Structured files
    files = {
        "small.txt": b"hello world\n",
        "medium.txt": b"the quick brown fox jumps over the lazy dog\n" * 5000,
        "binary.bin": bytes(range(256)) * 1000,
        "nested/subdir/deep.txt": b"deeply nested file\n",
        "nested/another.txt": b"another nested file\n" * 50,
    }
    for rel_path, content in files.items():
        full_path = os.path.join(source_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(content)
        written += len(content)

    # Fill remaining with random data
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


def netem_apply(profile_name):
    params = NETWORK_PROFILES.get(profile_name, {})
    if not params:
        netem_reset()
        return
    netem_reset()
    cmd = ["sudo", "tc", "qdisc", "add", "dev", "lo", "root", "netem"]
    cmd += ["rate", params["rate"]]
    cmd += ["delay", params["delay"], params["jitter"]]
    cmd += ["loss", params["loss"]]
    subprocess.run(cmd, check=True, capture_output=True)


def netem_reset():
    subprocess.run("sudo tc qdisc del dev lo root".split(), capture_output=True)


def run_transfer(source_dir, dest_dir, flags, port):
    """Run a single transfer. Returns duration in seconds or None on failure."""
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


def run_benchmark(source_dir, dest_dir, configs, runs, profile_name):
    """Run benchmark for all configs, returns list of results."""
    is_limited = profile_name != "unlimited"
    if is_limited:
        netem_apply(profile_name)

    try:
        results = []
        for config in configs:
            times = []
            for run_idx in range(runs):
                # Clean dest for each run
                if os.path.exists(dest_dir):
                    shutil.rmtree(dest_dir)
                os.makedirs(dest_dir, exist_ok=True)

                # Start fresh server
                port = find_free_port()
                server = subprocess.Popen(
                    SERVER_CMD + ["-p", str(port)],
                    stdout=subprocess.DEVNULL, stderr=None,
                )
                try:
                    wait_for_port(port)
                    t = run_transfer(source_dir, dest_dir, config["flags"], port)
                    if t is not None:
                        times.append(t)
                finally:
                    wait_proc(server)

            entry = {
                "config": config["name"],
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
        if is_limited:
            netem_reset()


def print_table(results, total_bytes):
    """Print results as a human-readable table."""
    # Group by profile
    profiles = {}
    for r in results:
        profiles.setdefault(r["profile"], []).append(r)

    for profile, entries in profiles.items():
        params = NETWORK_PROFILES.get(profile, {})
        print(f"\n{'=' * 80}")
        print(f" Profile: {profile.upper()}")
        if params.get("rate"):
            print(f" Network: {params['rate']}, {params['delay']} +/- {params['jitter']}, loss {params['loss']}")
        else:
            print(f" Network: unlimited")
        print(f" Data: {total_bytes / (1024*1024):.1f} MB")
        print(f"{'=' * 80}")
        print(f" {'Config':<25} {'p50':>8} {'p95':>8} {'min':>8} {'max':>8} {'stdev':>8} {'runs':>5}")
        print(f" {'-' * 25} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 5}")
        for e in sorted(entries, key=lambda x: x.get("p50", 999)):
            if "p50" in e:
                print(f" {e['config']:<25} {e['p50']:>7.4f}s {e['p95']:>7.4f}s "
                      f"{e['min']:>7.4f}s {e['max']:>7.4f}s {e['stdev']:>7.4f} {e['runs']:>5}")
            else:
                print(f" {e['config']:<25} {'N/A':>8} {'N/A':>8} {'N/A':>8} {'N/A':>8} {'N/A':>8} {e['runs']:>5}")

        if params.get("rate_bps"):
            best = min((e["p50"] for e in entries if "p50" in e), default=None)
            if best:
                theoretical = total_bytes / params["rate_bps"]
                print(f"\n Best config p50: {best:.4f}s")
                print(f" Theoretical max:  {theoretical:.4f}s (uncompressed at line rate)")
                print(f" Speedup vs max:  {theoretical / best:.2f}x")


def main():
    parser = argparse.ArgumentParser(description="FastSync benchmark tool")
    parser.add_argument("--runs", type=int, default=3, help="Number of runs per config (default: 3)")
    parser.add_argument("--profiles", nargs="+", default=["unlimited"],
                        choices=list(NETWORK_PROFILES.keys()),
                        help="Network profiles to test")
    parser.add_argument("--configs", nargs="+", default=None,
                        help="Custom config flags (e.g. --configs '-c' '-m' '-m -c')")
    parser.add_argument("--size-mb", type=int, default=25, help="Test data size in MB (default: 25)")
    parser.add_argument("--output", choices=["table", "json"], default="table",
                        help="Output format")
    parser.add_argument("--keep-data", action="store_true", help="Don't clean up test data")
    args = parser.parse_args()

    # Build
    print("Building...")
    if os.system(f"cmake -B {BUILD_DIR} -S {PROJECT_ROOT} > /dev/null 2>&1") != 0:
        print("CMake configure failed"); sys.exit(1)
    if os.system(f"cmake --build {BUILD_DIR} -j$(nproc) > /dev/null 2>&1") != 0:
        print("Build failed"); sys.exit(1)

    # Generate data
    source_dir = os.path.join(BENCH_DIR, "source")
    dest_dir = os.path.join(BENCH_DIR, "dest")
    total_bytes = generate_bench_data(source_dir, args.size_mb)
    print(f"Generated {total_bytes / (1024*1024):.1f} MB test data")

    # Parse configs
    if args.configs:
        configs = [{"name": c, "flags": c.split()} for c in args.configs]
    else:
        configs = DEFAULT_CONFIGS

    # Run benchmarks
    all_results = []
    try:
        for profile in args.profiles:
            results = run_benchmark(source_dir, dest_dir, configs, args.runs, profile)
            all_results.extend(results)
    finally:
        if not args.keep_data:
            shutil.rmtree(BENCH_DIR, ignore_errors=True)

    # Output
    if args.output == "json":
        print(json.dumps(all_results, indent=2))
    else:
        print_table(all_results, total_bytes)
        print()


if __name__ == "__main__":
    main()
