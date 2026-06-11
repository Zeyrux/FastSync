import subprocess
import time

# --- Configuration ---
SERVER_CMD = ["./build/server"]
base_client_cmd = ["./build/client"]

# --- Resource Limit Configuration ---
# 💾 Disk throttling settings
DISK_DEVICE = (
    "/dev/nvme0n1p5"  # IMPORTANT: Change this to your disk (e.g., /dev/nvme0n1)
)
READ_BPS_MAX = "15M"  # Max read speed (M for megabytes)
WRITE_BPS_MAX = "10M"  # Max write speed

# 🐢 Network throttling settings (Linux tc)
NET_LIMIT = "100mbit"
NET_DELAY = "100ms"
NETWORK_INTERFACE = "lo"
NET_LIMIT_CMD = f"sudo tc qdisc add dev {NETWORK_INTERFACE} root netem rate {NET_LIMIT} delay {NET_DELAY}".split()
NET_RESET_CMD = f"sudo tc qdisc del dev {NETWORK_INTERFACE} root".split()

# --- Build the client command prefix with throttling ---
CLIENT_CMD_PREFIX = [
    "sudo",
    "systemd-run",
    "--scope",
    "-p",
    f"IOReadBandwidthMax={DISK_DEVICE} {READ_BPS_MAX}",
    "-p",
    f"IOWriteBandwidthMax={DISK_DEVICE} {WRITE_BPS_MAX}",
]

# --- Test Cases ---
TEST_CASES = [
    {"name": "Standard (Single-threaded)", "flags": []},
    {"name": "Multithreading (-m)", "flags": ["-m"]},
    {"name": "Compression (-c)", "flags": ["-c"]},
    {"name": "Chunk Serialization (-s)", "flags": ["-s"]},
    {"name": "Multithreading + Compression (-m -c)", "flags": ["-m", "-c"]},
    {"name": "Multithreading + Chunk Serialization (-m -s)", "flags": ["-m", "-s"]},
    {"name": "Compression + Chunk Serialization (-c -s)", "flags": ["-c", "-s"]},
    {
        "name": "Multithreading + Compression + Chunk Serialization (-m -c -s)",
        "flags": ["-m", "-c", "-s"],
    },
]


def run_suite(env_name, apply_limits):
    results = []
    print(f"\n{'=' * 60}")
    print(f"🚀 Starting Suite: {env_name}")
    print(f"{'=' * 60}")

    if apply_limits:
        print(
            f"Applying Disk I/O Limits: Reads <= {READ_BPS_MAX}, Writes <= {WRITE_BPS_MAX}"
        )
        print(f"Applying Network Limits: {NET_LIMIT}, {NET_DELAY} delay")
        client_prefix = CLIENT_CMD_PREFIX
    else:
        print("Running Baseline (No limits applied)")
        client_prefix = []  # Run normally without systemd-run/limits

    try:
        # SETUP: Apply or ensure clean network limits
        if apply_limits:
            subprocess.run(NET_LIMIT_CMD, check=True)
        else:
            # Silently attempt to clear any leftover rules just to ensure a clean baseline
            subprocess.run(NET_RESET_CMD, capture_output=True)

        for case in TEST_CASES:
            name = case["name"]
            flags = case["flags"]

            print(f"\n--- Running: {name} ---")

            server_process = None
            try:
                # 1. Start the server
                print("  Starting server...")
                server_process = subprocess.Popen(
                    SERVER_CMD, stdout=subprocess.DEVNULL, stderr=None
                )
                time.sleep(0.5)  # Allow server to bind to port

                # 2. Build and run the client
                client_cmd = client_prefix + base_client_cmd + flags
                print(f"  Running client: {' '.join(client_cmd)}")

                start_time = time.monotonic()
                client_result = subprocess.run(
                    client_cmd, text=True, capture_output=True
                )
                end_time = time.monotonic()

                duration = end_time - start_time

                if client_result.returncode == 0:
                    results.append(
                        {
                            "environment": env_name,
                            "name": name,
                            "status": "Success",
                            "time": f"{duration:.4f}s",
                            "error": "",
                        }
                    )
                else:
                    print(f"  ⚠️ Failed (code: {client_result.returncode})")
                    err_msg = (
                        client_result.stderr.strip().split("\n")[0]
                        if client_result.stderr
                        else (
                            client_result.stdout.strip().split("\n")[0]
                            if client_result.stdout
                            else "No output"
                        )
                    )
                    results.append(
                        {
                            "environment": env_name,
                            "name": name,
                            "status": "Failed",
                            "time": "N/A",
                            "error": f"Exit code {client_result.returncode}: {err_msg[:40]}",
                        }
                    )

            except subprocess.TimeoutExpired:
                print("  ⚠️ Timeout (exceeded 15s)")
                results.append(
                    {
                        "environment": env_name,
                        "name": name,
                        "status": "Timeout",
                        "time": "N/A",
                        "error": "Exceeded 15 seconds",
                    }
                )
            except Exception as e:
                print(f"  ❌ Error: {e}")
                results.append(
                    {
                        "environment": env_name,
                        "name": name,
                        "status": "Error",
                        "time": "N/A",
                        "error": str(e),
                    }
                )
            finally:
                # Clean up the server for this test case
                if server_process:
                    print("  Stopping server...")
                    try:
                        server_process.terminate()
                        server_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server_process.kill()
                        server_process.wait()

    except subprocess.CalledProcessError as e:
        print(f"❌ Error running system limit command: {' '.join(e.cmd)}")
        print("Are you running this script with 'sudo' privileges?")

    finally:
        # TEARDOWN: Remove network limits if they were applied
        if apply_limits:
            print("\nCleaning up limits for this suite...")
            try:
                subprocess.run(NET_RESET_CMD, check=True, capture_output=True)
                print("Network limits removed.")
            except Exception as e:
                print(f"⚠️ Could not reset network settings: {e}")

    return results


# --- Main Execution ---
all_results = []

# 1. Run Baseline (No Limits)
all_results.extend(run_suite("Unlimited", apply_limits=False))

# # 2. Run Throttled (With Limits)
all_results.extend(run_suite("Throttled", apply_limits=True))

# --- Print Comparison Table ---
print("\n" + "=" * 105)
print(f"{'fastSync BENCHMARK RESULTS (COMPARISON)':^105}")
print("=" * 105)
print(
    f"{'Configuration':<45} | {'Environment':<12} | {'Status':<10} | {'Time':<10} | {'Details/Error':<20}"
)
print("-" * 105)

# Sort results by test case name first, then environment to easily compare
# This groups the baseline and throttled results for the same test next to each other
# sorted_results = sorted(
#     all_results,
#     key=lambda x: (
#         TEST_CASES.index(
#             next(item for item in TEST_CASES if item["name"] == x["name"])
#         ),
#         x["environment"],
#     ),
# )

for res in all_results:
    status_symbol = (
        "✅"
        if res["status"] == "Success"
        else ("⏳" if res["status"] == "Timeout" else "❌")
    )
    status_str = f"{status_symbol} {res['status']}"
    print(
        f"{res['name']:<45} | {res['environment']:<12} | {status_str:<10} | {res['time']:<10} | {res['error']:<20}"
    )
print("=" * 105)
