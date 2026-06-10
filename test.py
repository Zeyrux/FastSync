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
# This uses systemd-run to wrap the original client command with I/O limits.
# The entire command must be run with sudo.
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

results = []

print("🚀 Starting benchmark...")
print(f"Limiting Disk I/O: Reads <= {READ_BPS_MAX}, Writes <= {WRITE_BPS_MAX}")
print("Limiting Network: Simulating low bandwidth and high latency")

try:
    # # SETUP: Apply network limit
    print("Applying network limits...")
    subprocess.run(NET_LIMIT_CMD, check=True)

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
            time.sleep(5)  # Allow server to bind to port

            # 2. Build and run the client
            client_cmd = CLIENT_CMD_PREFIX + base_client_cmd + flags
            print(f"  Running client: {' '.join(client_cmd)}")

            start_time = time.monotonic()
            client_result = subprocess.run(client_cmd, text=True, capture_output=True)
            end_time = time.monotonic()

            duration = end_time - start_time

            if client_result.returncode == 0:
                results.append(
                    {
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
                    "name": name,
                    "status": "Timeout",
                    "time": "N/A",
                    "error": "Exceeded 15 seconds",
                }
            )
        except Exception as e:
            print(f"  ❌ Error: {e}")
            results.append(
                {"name": name, "status": "Error", "time": "N/A", "error": str(e)}
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
    print("Are you running this script with 'sudo'?")

finally:
    # TEARDOWN: Remove network limits
    print("\nCleaning up...")
    try:
        print("Removing network limit...")
        subprocess.run(NET_RESET_CMD, check=True, capture_output=True)
    except Exception as e:
        print(f"⚠️ Could not reset network settings: {e}")
    print("Cleanup complete.")

# Print comparison table
print("\n" + "=" * 80)
print(f"{'fastSync BENCHMARK RESULTS':^80}")
print("=" * 80)
print(f"{'Configuration':<45} | {'Status':<10} | {'Time':<10} | {'Details/Error':<20}")
print("-" * 80)
for res in results:
    status_symbol = (
        "✅"
        if res["status"] == "Success"
        else ("⏳" if res["status"] == "Timeout" else "❌")
    )
    status_str = f"{status_symbol} {res['status']}"
    print(
        f"{res['name']:<45} | {status_str:<10} | {res['time']:<10} | {res['error']:<20}"
    )
print("=" * 80)
