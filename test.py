import argparse
import filecmp
import os
import shutil
import subprocess
import sys
import tempfile
import time

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")
DEFAULT_SOURCE_DIR = os.path.join(TEST_DIR, "source")
DEFAULT_DEST_DIR = os.path.join(TEST_DIR, "dest")

SERVER_CMD = ["./build/server"]
base_client_cmd = ["./build/client"]

DISK_DEVICE = "/dev/nvme0n1p5"
READ_BPS_MAX = "15M"
WRITE_BPS_MAX = "10M"

NET_LIMIT = "100mbit"
NET_DELAY = "100ms"
NETWORK_INTERFACE = "lo"
NET_LIMIT_CMD = (
    f"sudo tc qdisc add dev {NETWORK_INTERFACE} root netem rate {NET_LIMIT} delay {NET_DELAY}".split()
)
NET_RESET_CMD = f"sudo tc qdisc del dev {NETWORK_INTERFACE} root".split()

CLIENT_CMD_PREFIX = [
    "sudo",
    "systemd-run",
    "--scope",
    "-p",
    f"IOReadBandwidthMax={DISK_DEVICE} {READ_BPS_MAX}",
    "-p",
    f"IOWriteBandwidthMax={DISK_DEVICE} {WRITE_BPS_MAX}",
]

TEST_CASES = [
    {"name": "Standard (Single-threaded)", "flags": []},
    {"name": "Multithreading (-m)", "flags": ["-m"]},
    {"name": "Compression (-c 0)", "flags": ["-c 0"]},
    {"name": "Chunk Serialization (-s)", "flags": ["-s"]},
    {"name": "Compression + Chunk Serialization (-c -s)", "flags": ["-c", "-s"]},
    {"name": "Multithreading + Compression (-m -c)", "flags": ["-m", "-c"]},
    {"name": "Multithreading + Chunk Serialization (-m -s)", "flags": ["-m", "-s"]},
    {
        "name": "Multithreading + Compression + Chunk Serialization (-m -c -s)",
        "flags": ["-m", "-c", "-s"],
    },
]


def generate_test_files(source_dir):
    if os.path.exists(source_dir):
        shutil.rmtree(source_dir)
    os.makedirs(source_dir)

    target_total = 50 * 1024 * 1024
    written = 0

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

    i = 0
    while written < target_total:
        chunk_size = min(5 * 1024 * 1024, target_total - written)
        rel_path = f"bulk/file_{i}.dat"
        full_path = os.path.join(source_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(b"0" * chunk_size)
        written += chunk_size
        i += 1

    total_mb = written / (1024 * 1024)
    print(f"  Generated {total_mb:.1f} MB of test data in {source_dir}")


def verify_transfer(source_dir, dest_dir):
    source_dir = os.path.abspath(source_dir)
    dest_dir = os.path.abspath(dest_dir)

    received_prefix = os.path.join(dest_dir, source_dir.lstrip(os.sep))
    if not os.path.exists(received_prefix):
        return [], ["no received files found"]

    mismatches = []
    missing = []

    for root, dirs, files in os.walk(source_dir):
        for f in files:
            src_path = os.path.join(root, f)
            rel = os.path.relpath(src_path, source_dir)
            dst_path = os.path.join(received_prefix, rel)

            if not os.path.exists(dst_path):
                missing.append(rel)
            elif not filecmp.cmp(src_path, dst_path, shallow=False):
                mismatches.append(rel)

    return mismatches, missing


def run_suite(env_name, apply_limits, source_dir, dest_dir):
    results = []
    print(f"\n{'=' * 60}")
    print(f"Suite: {env_name}")
    print(f"{'=' * 60}")

    if apply_limits:
        print(f"  Disk I/O: Reads <= {READ_BPS_MAX}, Writes <= {WRITE_BPS_MAX}")
        print(f"  Network: {NET_LIMIT}, {NET_DELAY} delay")
        client_prefix = CLIENT_CMD_PREFIX
    else:
        print("  Baseline (no limits)")
        client_prefix = []

    try:
        if apply_limits:
            subprocess.run(NET_LIMIT_CMD, check=True)
        else:
            subprocess.run(NET_RESET_CMD, capture_output=True)

        for case in TEST_CASES:
            name = case["name"]
            flags = case["flags"]
            print(f"\n  --- {name} ---")

            if os.path.exists(dest_dir):
                shutil.rmtree(dest_dir)

            server_process = None
            try:
                server_process = subprocess.Popen(
                    SERVER_CMD, stdout=subprocess.DEVNULL, stderr=None
                )
                time.sleep(0.5)

                env = os.environ.copy()
                env["FASTSYNC_SOURCE_DIR"] = source_dir
                env["FASTSYNC_DEST_DIR"] = dest_dir
                env["FASTSYNC_SAVE_TO_DISK"] = "true"

                client_cmd = client_prefix + base_client_cmd + flags
                print(f"    Running: {' '.join(client_cmd)}")

                start_time = time.monotonic()
                client_result = subprocess.run(
                    client_cmd, env=env, text=True, capture_output=True
                )
                end_time = time.monotonic()
                duration = end_time - start_time

                if server_process:
                    try:
                        server_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server_process.kill()
                        server_process.wait()
                    server_process = None

                mismatches, missing = [], []
                if client_result.returncode == 0:
                    mismatches, missing = verify_transfer(source_dir, dest_dir)

                entry = {
                    "name": name,
                    "suite": env_name,
                    "time": f"{duration:.4f}s" if client_result.returncode == 0 else "N/A",
                }

                if client_result.returncode == 0 and not mismatches and not missing:
                    entry["status"] = "Success"
                    entry["error"] = ""
                else:
                    entry["status"] = "Failed"
                    errors = []
                    if client_result.returncode != 0:
                        err = (
                            client_result.stderr.strip().split("\n")[0]
                            if client_result.stderr
                            else (
                                client_result.stdout.strip().split("\n")[0]
                                if client_result.stdout
                                else "No output"
                            )
                        )
                        errors.append(f"Exit code {client_result.returncode}: {err[:80]}")
                    if missing:
                        errors.append(f"Missing ({len(missing)}): {', '.join(missing[:5])}")
                    if mismatches:
                        errors.append(f"Mismatch ({len(mismatches)}): {', '.join(mismatches[:3])}")
                    entry["error"] = " | ".join(errors)

                results.append(entry)

            except subprocess.TimeoutExpired:
                results.append(
                    {"name": name, "status": "Timeout", "time": "N/A", "error": "Exceeded 15s"}
                )
            except Exception as e:
                results.append(
                    {"name": name, "status": "Error", "time": "N/A", "error": str(e)}
                )
            finally:
                if server_process:
                    try:
                        server_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server_process.kill()
                        server_process.wait()

    except subprocess.CalledProcessError as e:
        print(f"  Error running limit command: {' '.join(e.cmd)}")
    finally:
        if apply_limits:
            try:
                subprocess.run(NET_RESET_CMD, check=True, capture_output=True)
            except Exception:
                pass

    return results


def main():
    parser = argparse.ArgumentParser(description="FastSync integration test / benchmark")
    parser.add_argument("--source-dir", default=DEFAULT_SOURCE_DIR,
                        help="Source directory for test files (default: %(default)s)")
    parser.add_argument("--dest-dir", default=DEFAULT_DEST_DIR,
                        help="Destination directory for received files (default: %(default)s)")
    parser.add_argument("--keep-data", action="store_true",
                        help="Keep test_data directory after run")
    parser.add_argument("--no-throttled", action="store_true",
                        help="Skip throttled suite (requires sudo)")
    parser.add_argument("--no-unlimited", action="store_true",
                        help="Skip unlimited suite")
    args = parser.parse_args()

    os.system("cmake -B build -S . > /dev/null 2>&1")
    ret = os.system("cd build && make -j$(nproc) 2>&1 | tail -3")
    if ret != 0:
        print("Build failed")
        sys.exit(1)

    generate_test_files(args.source_dir)
    os.makedirs(args.dest_dir, exist_ok=True)

    try:
        all_results = []

        if not args.no_unlimited:
            all_results.extend(
                run_suite("Unlimited", False, args.source_dir, args.dest_dir)
            )

        if not args.no_throttled:
            all_results.extend(
                run_suite("Throttled", True, args.source_dir, args.dest_dir)
            )

        print("\n" + "=" * 110)
        print(f"{'RESULTS':^110}")
        print("=" * 110)
        print(f"{'Configuration':<45} | {'Suite':<12} | {'Status':<8} | {'Time':<10} | {'Details'}")
        print("-" * 110)

        for res in all_results:
            print(
                f"{res['name']:<45} | {res['suite']:<12} | {res['status']:<8} | {res['time']:<10} | {res['error']}"
            )

        failed = [r for r in all_results if r["status"] != "Success"]
        if failed:
            print(f"\n  {len(failed)} test(s) FAILED")
            sys.exit(1)
        else:
            print(f"\n  ALL {len(all_results)} TESTS PASSED")

    finally:
        if not args.keep_data:
            shutil.rmtree(TEST_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
