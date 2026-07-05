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
NETWORK_INTERFACE = "lo"

NETWORK_PROFILES = {
    "Unlimited": {},
    "LAN": {
        "rate": "1000mbit",
        "delay": "1ms",
        "jitter": "0.1ms",
        "loss": "0%",
    },
    "WAN": {
        "rate": "100mbit",
        "delay": "50ms",
        "jitter": "10ms",
        "loss": "1%",
    },
}

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
    {"name": "Standard", "flags": []},
    {"name": "Multithreading (-m)", "flags": ["-m"]},
    {"name": "Compression (-c)", "flags": ["-c"]},
    {"name": "Chunk Serialization (-s)", "flags": ["-s"]},
    {"name": "Compression + Chunk Serialization (-c -s)", "flags": ["-c", "-s"]},
    {"name": "Multithreading + Compression (-m -c)", "flags": ["-m", "-c"]},
    {"name": "Multithreading + Chunk Serialization (-m -s)", "flags": ["-m", "-s"]},
    {
        "name": "Multithreading + Compression + Chunk Serialization (-m -c -s)",
        "flags": ["-m", "-c", "-s"],
    },
    {"name": "Sendfile (-f)", "flags": ["-f"]},
    {"name": "Sendfile + Multithreading (-f -m)", "flags": ["-f", "-m"]},
]

RSYNC_CASES = [
    {"name": "rsync (archive)", "args": ["-aH"]},
    {"name": "rsync (archive + compress)", "args": ["-aHz"]},
]


def netem_apply(profile):
    params = NETWORK_PROFILES[profile]
    if not params:
        netem_reset()
        return
    cmd = ["sudo", "tc", "qdisc", "add", "dev", NETWORK_INTERFACE, "root", "netem"]
    cmd += ["rate", params["rate"]]
    cmd += ["delay", params["delay"], params["jitter"]]
    cmd += ["loss", params["loss"]]
    subprocess.run(cmd, check=True, capture_output=True)


def netem_reset():
    subprocess.run(
        f"sudo tc qdisc del dev {NETWORK_INTERFACE} root".split(),
        capture_output=True,
    )


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


def verify_transfer(source_dir, received_dir):
    source_dir = os.path.abspath(source_dir)
    received_dir = os.path.abspath(received_dir)

    if not os.path.exists(received_dir):
        return [], ["no received files found"]

    mismatches = []
    missing = []

    for root, dirs, files in os.walk(source_dir):
        for f in files:
            src_path = os.path.join(root, f)
            rel = os.path.relpath(src_path, source_dir)
            dst_path = os.path.join(received_dir, rel)

            if not os.path.exists(dst_path):
                missing.append(rel)
            elif not filecmp.cmp(src_path, dst_path, shallow=False):
                mismatches.append(rel)

    return mismatches, missing


def run_profile(profile_name, source_dir, dest_dir):
    results = []
    is_limited = profile_name != "Unlimited"
    params = NETWORK_PROFILES[profile_name]
    print(f"\n{'=' * 60}")
    print(f"Profile: {profile_name}")
    print(f"{'=' * 60}")

    if is_limited:
        p = params
        print(f"  Network: rate={p['rate']}, delay={p['delay']} ±{p['jitter']}, loss={p['loss']}")
        print(f"  Disk I/O: Reads <= {READ_BPS_MAX}, Writes <= {WRITE_BPS_MAX}")
        client_prefix = CLIENT_CMD_PREFIX
    else:
        print("  No limits applied")
        client_prefix = []

    try:
        if is_limited:
            netem_apply(profile_name)
        else:
            netem_reset()

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

                client_cmd = (
                    client_prefix
                    + base_client_cmd
                    + ["--source-dir", source_dir, "--dest-dir", dest_dir, "--save-to-disk"]
                    + flags
                )
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
                    received = os.path.join(dest_dir, os.path.abspath(source_dir).lstrip(os.sep))
                    mismatches, missing = verify_transfer(source_dir, received)

                entry = {
                    "name": name,
                    "suite": profile_name,
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
                    {"name": name, "suite": profile_name, "status": "Timeout", "time": "N/A", "error": "Exceeded 15s"}
                )
            except Exception as e:
                results.append(
                    {"name": name, "suite": profile_name, "status": "Error", "time": "N/A", "error": str(e)}
                )
            finally:
                if server_process:
                    try:
                        server_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server_process.kill()
                        server_process.wait()

        for case in RSYNC_CASES:
            name = case["name"]
            rsync_args = case["args"]
            print(f"\n  --- {name} ---")

            if os.path.exists(dest_dir):
                shutil.rmtree(dest_dir)

            try:
                rsync_cmd = (
                    ["rsync"]
                    + rsync_args
                    + [f"{source_dir}/", f"{dest_dir}/"]
                )
                print(f"    Running: {' '.join(rsync_cmd)}")

                start_time = time.monotonic()
                rsync_result = subprocess.run(
                    rsync_cmd, capture_output=True, timeout=120
                )
                end_time = time.monotonic()
                duration = end_time - start_time

                mismatches, missing = [], []
                if rsync_result.returncode == 0:
                    mismatches, missing = verify_transfer(source_dir, dest_dir)

                entry = {
                    "name": name,
                    "suite": profile_name,
                    "time": f"{duration:.4f}s" if rsync_result.returncode == 0 else "N/A",
                }

                if rsync_result.returncode == 0 and not mismatches and not missing:
                    entry["status"] = "Success"
                    entry["error"] = ""
                else:
                    entry["status"] = "Failed"
                    errors = []
                    if rsync_result.returncode != 0:
                        err = rsync_result.stderr.strip().split("\n")[0] if rsync_result.stderr else "No output"
                        errors.append(f"Exit code {rsync_result.returncode}: {err[:80]}")
                    if missing:
                        errors.append(f"Missing ({len(missing)}): {', '.join(missing[:5])}")
                    if mismatches:
                        errors.append(f"Mismatch ({len(mismatches)}): {', '.join(mismatches[:3])}")
                    entry["error"] = " | ".join(errors)

                results.append(entry)

            except subprocess.TimeoutExpired:
                results.append(
                    {"name": name, "suite": profile_name, "status": "Timeout", "time": "N/A", "error": "Exceeded 120s"}
                )
            except Exception as e:
                results.append(
                    {"name": name, "suite": profile_name, "status": "Error", "time": "N/A", "error": str(e)}
                )

    except subprocess.CalledProcessError as e:
        print(f"  Error running netem command: {' '.join(e.cmd)}")
    finally:
        if is_limited:
            try:
                netem_reset()
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
    parser.add_argument("--no-unlimited", action="store_true",
                        help="Skip the Unlimited (no limits) profile")
    parser.add_argument("--no-lan", action="store_true",
                        help="Skip the LAN profile")
    parser.add_argument("--wan", action="store_true",
                        help="Include the WAN profile (requires sudo)")
    args = parser.parse_args()

    os.system("cmake -B build -S . > /dev/null 2>&1")
    ret = os.system("cd build && make -j$(nproc) 2>&1 | tail -3")
    if ret != 0:
        print("Build failed")
        sys.exit(1)

    generate_test_files(args.source_dir)
    os.makedirs(args.dest_dir, exist_ok=True)

    profiles_to_run = []
    if not args.no_unlimited:
        profiles_to_run.append("Unlimited")
    if not args.no_lan:
        profiles_to_run.append("LAN")
    if args.wan:
        profiles_to_run.append("WAN")

    try:
        all_results = []
        for profile in profiles_to_run:
            all_results.extend(
                run_profile(profile, args.source_dir, args.dest_dir)
            )

        print("\n" + "=" * 130)
        print(f"{'RESULTS':^130}")
        print("=" * 130)
        print(f"{'Configuration':<45} | {'Profile':<12} | {'Status':<8} | {'Time':<10} | {'Details'}")
        print("-" * 130)

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
