import argparse
import filecmp
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import socket

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")
DEFAULT_SOURCE_DIR = os.path.join(TEST_DIR, "source")
DEFAULT_DEST_DIR = os.path.join(TEST_DIR, "dest")

SERVER_CMD = ["./build/server"]
BASE_CLIENT_CMD = ["./build/client"]

DISK_DEVICE = "/dev/nvme0n1p5"
READ_BPS_MAX = "15M"
WRITE_BPS_MAX = "10M"
NETWORK_INTERFACE = "lo"

NETWORK_PROFILES = {
    "Unlimited": {},
    "LAN": {
        "rate": "1000mbit",
        "delay": "20ms",
        "jitter": "1ms",
        "loss": "0.1%",
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

BASE_CLIENT_FLAGS = ["--save-to-disk"]

TEST_CASES = [
    {"name": "Standard", "flags": []},
    {"name": "Posix Args (no flags)", "flags": [], "posix": True},
    {"name": "Standard (no metadata)", "flags": [], "use_metadata": False},
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

SSH_CASES = [
    {"name": "SSH (localhost)", "flags": []},
    {"name": "SSH Multithreading (-m)", "flags": ["-m"]},
    {"name": "SSH Compression (-c)", "flags": ["-c"]},
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
    netem_reset()
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


def wait_proc(proc, timeout=5):
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


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

    os.makedirs(os.path.join(source_dir, "bulk"), exist_ok=True)
    i = 0
    while written < target_total:
        chunk_size = min(5 * 1024 * 1024, target_total - written)
        with open(os.path.join(source_dir, f"bulk/file_{i}.dat"), "wb") as f:
            f.write(b"0" * chunk_size)
        written += chunk_size
        i += 1

    total_mb = written / (1024 * 1024)
    print(f"  Generated {total_mb:.1f} MB of test data in {source_dir}")
    return written


def verify_transfer(source_dir, received_dir):
    source_dir = os.path.abspath(source_dir)
    received_dir = os.path.abspath(received_dir)
    if not os.path.exists(received_dir):
        return [], ["no received files found"]
    mismatches, missing = [], []
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


def start_rsync_daemon(source_dir):
    port = find_free_port()
    conf = os.path.join(tempfile.gettempdir(), f"rsyncd-{port}.conf")
    with open(conf, "w") as f:
        f.write(f"port = {port}\nread only = yes\n\n[source]\n    path = {source_dir}\n")
    daemon = subprocess.Popen(
        ["rsync", "--daemon", "--no-detach", f"--config={conf}"],
        stdout=subprocess.DEVNULL, stderr=None,
    )
    for _ in range(50):
        time.sleep(0.1)
        if daemon.poll() is not None:
            raise RuntimeError(f"rsync daemon exited (rc={daemon.returncode})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                break
        except (ConnectionRefusedError, OSError):
            continue
    else:
        raise RuntimeError("rsync daemon did not start")
    return port, conf, daemon


def run_single_test(cmd, name, source_dir, dest_dir, *, source_prefix=None, no_server=False):
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    if no_server:
        server = None
    else:
        server = subprocess.Popen(SERVER_CMD, stdout=subprocess.DEVNULL, stderr=None)
        time.sleep(0.5)
    try:
        start = time.monotonic()
        result = subprocess.run(cmd, text=True, capture_output=True)
        duration = time.monotonic() - start
    finally:
        if server:
            wait_proc(server)

    mismatches, missing = [], []
    if result.returncode == 0:
        received = os.path.join(dest_dir, source_prefix if source_prefix is not None
                                else os.path.abspath(source_dir).lstrip(os.sep))
        mismatches, missing = verify_transfer(source_dir, received)

    first_line = lambda s: (s or "").strip().split("\n")[0]
    entry = {
        "name": name,
        "time": f"{duration:.4f}s" if result.returncode == 0 else "N/A",
    }
    if result.returncode == 0 and not mismatches and not missing:
        entry["status"] = "Success"
        entry["error"] = ""
    else:
        entry["status"] = "Failed"
        errors = []
        if result.returncode != 0:
            errors.append(f"Exit code {result.returncode}: {first_line(result.stderr) or first_line(result.stdout) or 'No output'[:80]}")
        if missing:
            errors.append(f"Missing ({len(missing)}): {', '.join(missing[:5])}")
        if mismatches:
            errors.append(f"Mismatch ({len(mismatches)}): {', '.join(mismatches[:3])}")
        entry["error"] = " | ".join(errors)
    return entry


def print_profile_header(profile_name):
    params = NETWORK_PROFILES[profile_name]
    print(f"\n{'=' * 60}\nProfile: {profile_name}\n{'=' * 60}")
    if params:
        print(f"  Network: rate={params['rate']}, delay={params['delay']} ±{params['jitter']}, loss={params['loss']}")
        print(f"  Disk I/O: Reads <= {READ_BPS_MAX}, Writes <= {WRITE_BPS_MAX}")
    else:
        print("  No limits applied")


def run_profile(profile_name, source_dir, dest_dir):
    print_profile_header(profile_name)
    is_limited = profile_name != "Unlimited"
    client_prefix = CLIENT_CMD_PREFIX if is_limited else []

    try:
        if is_limited:
            netem_apply(profile_name)
        else:
            netem_reset()

        results = []
        for case in TEST_CASES:
            flags = BASE_CLIENT_FLAGS + (["-M"] if case.get("use_metadata", True) else []) + case["flags"]
            if case.get("posix"):
                cmd = client_prefix + BASE_CLIENT_CMD + [source_dir, dest_dir] + flags
            else:
                cmd = client_prefix + BASE_CLIENT_CMD + ["--source-dir", source_dir, "--dest-dir", dest_dir] + flags
            print(f"\n  --- {case['name']} ---\n    Running: {' '.join(cmd)}")
            try:
                r = run_single_test(cmd, case["name"], source_dir, dest_dir)
                r["suite"] = profile_name
                results.append(r)
            except Exception as e:
                results.append({"name": case["name"], "suite": profile_name, "status": "Error", "time": "N/A", "error": str(e)})

        if SSH_AVAILABLE:
            for case in SSH_CASES:
                flags = BASE_CLIENT_FLAGS + (["-M"] if case.get("use_metadata", True) else []) + case["flags"]
                ssh_dest = f"localhost:{dest_dir}_ssh"
                cmd = client_prefix + BASE_CLIENT_CMD + [source_dir, ssh_dest] + flags
                print(f"\n  --- {case['name']} ---\n    Running: {' '.join(cmd)}")
                try:
                    r = run_single_test(cmd, case["name"], source_dir, f"{dest_dir}_ssh", no_server=True)
                    r["suite"] = profile_name
                    results.append(r)
                except Exception as e:
                    results.append({"name": case["name"], "suite": profile_name, "status": "Error", "time": "N/A", "error": str(e)})

        port, conf, daemon = start_rsync_daemon(source_dir)
        try:
            for case in RSYNC_CASES:
                cmd = client_prefix + ["rsync"] + case["args"] + [f"rsync://localhost:{port}/source/", f"{dest_dir}/"]
                print(f"\n  --- {case['name']} ---\n    Running: {' '.join(cmd)}")
                try:
                    r = run_single_test(cmd, case["name"], source_dir, dest_dir, source_prefix="")
                    r["suite"] = profile_name
                except subprocess.TimeoutExpired:
                    r = {"name": case["name"], "suite": profile_name, "status": "Timeout", "time": "N/A", "error": "Exceeded 120s"}
                except Exception as e:
                    r = {"name": case["name"], "suite": profile_name, "status": "Error", "time": "N/A", "error": str(e)}
                else:
                    if r["status"] != "Success" and client_prefix:
                        tmp = tempfile.mkdtemp()
                        try:
                            plain = subprocess.run(["rsync", "-aH", f"rsync://localhost:{port}/source/", f"{tmp}/"], capture_output=True, text=True, timeout=30)
                            if plain.returncode != 0:
                                errs = [l for l in (plain.stderr or "").split("\n") if l.strip()]
                                if errs:
                                    r["error"] += f" | raw: {errs[-1][:150]}"
                        finally:
                            shutil.rmtree(tmp, ignore_errors=True)
                results.append(r)
        finally:
            wait_proc(daemon)
            try:
                os.unlink(conf)
            except Exception:
                pass

    except (subprocess.CalledProcessError, RuntimeError) as e:
        print(f"  Error: {e}")
        results = []
    finally:
        if is_limited:
            try:
                netem_reset()
            except Exception:
                pass

    return results


def print_metrics(profile_name, results, total_bytes):
    params = NETWORK_PROFILES.get(profile_name)
    if not params or "rate" not in params:
        return

    client_times, rsync_times = [], {}
    for r in results:
        if r["status"] != "Success" or r["time"] == "N/A":
            continue
        t = float(r["time"].rstrip("s"))
        if r["name"].startswith("rsync"):
            rsync_times[r["name"]] = t
        else:
            client_times.append((t, r["name"]))
    if not client_times or len(rsync_times) < 2:
        return

    m = re.match(r'(\d+)\s*(mbit|gbit|kbit|bit)', params["rate"])
    rate_val = int(m.group(1)) * {'mbit': 1_000_000, 'gbit': 1_000_000_000, 'kbit': 1000, 'bit': 1}[m.group(2)] / 8 if m else None

    best_time, best_name = min(client_times, key=lambda x: x[0])
    theoretical_max = total_bytes / rate_val if rate_val else None

    print(f"\n  {'─' * 90}\n  Profile: {profile_name}\n  {'─' * 90}")
    print(f"  Total data size:               {total_bytes / (1024*1024):.1f} MB")
    if rate_val:
        print(f"  Network rate:                  {params['rate']} ({format_throughput(rate_val)})")
    print(f"  Best client configuration:     {best_name}")
    print(f"  Best client time:              {best_time:.4f}s")
    if theoretical_max:
        print(f"  Theoretical max (uncompressed): {theoretical_max:.4f}s")
        print(f"  Speedup vs theoretical max:    {theoretical_max / best_time:.2f}x")
    if (a := rsync_times.get("rsync (archive)")):
        print(f"  Speedup vs rsync (archive):    {a / best_time:.2f}x")
    if (c := rsync_times.get("rsync (archive + compress)")):
        print(f"  Speedup vs rsync (compress):   {c / best_time:.2f}x")


def format_throughput(bps):
    for unit, threshold in [("GB/s", 1_000_000_000), ("MB/s", 1_000_000), ("KB/s", 1000)]:
        if bps >= threshold:
            return f"{bps/threshold:.1f} {unit}"
    return f"{bps:.0f} B/s"


SSH_AVAILABLE = False

def check_ssh_localhost():
    global SSH_AVAILABLE
    build_dir = os.path.abspath("build")
    server_path = os.path.join(build_dir, "server")

    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                        "localhost", "which", "fastsync-server"],
                       capture_output=True, timeout=10)
    if r.returncode != 0:
        install = subprocess.run(["ssh", "-o", "BatchMode=yes", "localhost",
                                  f"mkdir -p ~/.local/bin && ln -sf {server_path} ~/.local/bin/fastsync-server"],
                                 capture_output=True, timeout=10)
        if install.returncode == 0:
            r = subprocess.run(["ssh", "-o", "BatchMode=yes", "localhost",
                                "which", "fastsync-server"], capture_output=True, timeout=10)
    SSH_AVAILABLE = r.returncode == 0


def preflight_checks():
    global SSH_AVAILABLE
    errors = []
    print("Pre-flight checks:")
    print("  [1] --help flag...", end=" ")
    r = subprocess.run(BASE_CLIENT_CMD + ["--help"], capture_output=True, text=True)
    if r.returncode == 0 and "Usage:" in r.stdout and "SSH transport" in r.stdout:
        print("OK")
    else:
        print("FAIL")
        errors.append("--help failed")

    print("  [2] Remote SSH dest detection...", end=" ")
    r = subprocess.run(BASE_CLIENT_CMD + ["/x", "somehost:/y"], capture_output=True, text=True, timeout=5)
    if r.returncode != 0 and ("ssh" in r.stderr or "Could not receive" in r.stderr or "could not launch" in r.stderr or "Error" in r.stderr):
        print("OK (detected as SSH)")
    else:
        print("FAIL (not detected as SSH dest)")
        errors.append("SSH detection failed")

    print("  [3] Server --stdio flag...", end=" ")
    try:
        r = subprocess.run(["./build/server", "--stdio"], capture_output=True, text=True, timeout=3)
        if r.returncode != 0 and ("receiving" in r.stderr or "receiving" in r.stdout or "Receiving" in r.stderr):
            print("OK (started in stdio mode)")
        else:
            print("WARN (stdio exited: rc=%d)" % r.returncode)
    except subprocess.TimeoutExpired:
        print("OK (waiting for stdin)")

    print("  [4] Posix arg syntax (no server, expect failure)...", end=" ")
    r = subprocess.run(BASE_CLIENT_CMD + ["/tmp/x", "/tmp/y"], capture_output=True, text=True, timeout=5)
    if r.returncode != 0 and "connect" in r.stderr:
        print("OK (TCP fallback)")
    else:
        print("FAIL")
        errors.append("Posix arg syntax failed")

    check_ssh_localhost()
    print("  [5] SSH to localhost...", end=" ")
    if SSH_AVAILABLE:
        print("OK")
    else:
        print("SKIP (install fastsync-server in PATH on remote)")

    if errors:
        print(f"\n  {len(errors)} pre-flight check(s) failed: {', '.join(errors)}")
        sys.exit(1)
    print("  All pre-flight checks passed.\n")


def main():
    os.system("cmake -B build -S . > /dev/null 2>&1")
    if os.system("cd build && make -j$(nproc) 2>&1 | tail -3") != 0:
        print("Build failed")
        sys.exit(1)
    preflight_checks()
    parser = argparse.ArgumentParser(description="FastSync integration test / benchmark")
    parser.add_argument("--source-dir", default=DEFAULT_SOURCE_DIR)
    parser.add_argument("--dest-dir", default=DEFAULT_DEST_DIR)
    parser.add_argument("--keep-data", action="store_true")
    parser.add_argument("--unlimited", action="store_true")
    parser.add_argument("--wan", action="store_true")
    args = parser.parse_args()

    total_bytes = generate_test_files(args.source_dir)
    if os.path.exists(args.dest_dir):
        shutil.rmtree(args.dest_dir)
    os.makedirs(args.dest_dir, exist_ok=True)

    profiles = []
    if args.unlimited:
        profiles.append("Unlimited")
    elif args.wan:
        profiles.append("WAN")
    else:
        profiles.append("LAN")

    try:
        all_results = []
        for p in profiles:
            all_results.extend(run_profile(p, args.source_dir, args.dest_dir))

        print("\n" + "=" * 130)
        print(f"{'RESULTS':^130}")
        print("=" * 130)
        print(f"{'Configuration':<45} | {'Profile':<12} | {'Status':<8} | {'Time':<10} | {'Details'}")
        print("-" * 130)
        for r in all_results:
            print(f"{r['name']:<45} | {r['suite']:<12} | {r['status']:<8} | {r['time']:<10} | {r['error']}")

        for p in profiles:
            print_metrics(p, [r for r in all_results if r["suite"] == p], total_bytes)

        failed = [r for r in all_results if r["status"] != "Success"]
        if failed:
            print(f"\n  {len(failed)} test(s) FAILED")
            sys.exit(1)
        print(f"\n  ALL {len(all_results)} TESTS PASSED")
    finally:
        if not args.keep_data:
            shutil.rmtree(TEST_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
