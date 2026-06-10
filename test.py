import subprocess
import time

# --- Configuration ---
SERVER_CMD = ["./server"]
#original_client_cmd = ["./client"]
original_client_cmd = ["./client" , "-m"]

# --- Resource Limit Configuration ---
# 💾 Disk throttling settings
DISK_DEVICE = "/dev/nvme0n1p5"  # IMPORTANT: Change this to your disk (e.g., /dev/nvme0n1)
READ_BPS_MAX = "15M"      # Max read speed (M for megabytes)
WRITE_BPS_MAX = "10M"     # Max write speed

# 🐢 Network throttling settings (Linux tc)
NET_LIMIT = "2mbit"
NET_DELAY = "100ms"
NETWORK_INTERFACE = "lo"
NET_LIMIT_CMD = f"sudo tc qdisc add dev {NETWORK_INTERFACE} root netem rate {NET_LIMIT} delay {NET_DELAY}".split()
NET_RESET_CMD = f"sudo tc qdisc del dev {NETWORK_INTERFACE} root".split()

# --- Build the final client command with throttling ---
# This uses systemd-run to wrap the original client command with I/O limits.
# The entire command must be run with sudo.
CLIENT_CMD = [
    "sudo", "systemd-run",
    "--scope",
    "-p", f"IOReadBandwidthMax={DISK_DEVICE} {READ_BPS_MAX}",
    "-p", f"IOWriteBandwidthMax={DISK_DEVICE} {WRITE_BPS_MAX}",
    # The command to run is placed at the end
] + original_client_cmd


# --- Benchmarking ---
server_process = None
print("🚀 Starting benchmark...")
print(f"Limiting Disk I/O: Reads <= {READ_BPS_MAX}, Writes <= {WRITE_BPS_MAX}")
print("Limiting Network: Simulating low bandwidth and high latency")

try:
    # SETUP: Apply network limit
    subprocess.run(NET_LIMIT_CMD, check=True)

    # 1. Start the server
    print("Starting server...")
    server_process = subprocess.Popen(SERVER_CMD)
    time.sleep(1)

    # 2. Run the client with all limits applied
    print("Running client under network AND disk constraints...")
    start_time = time.monotonic()
    
    # The CLIENT_CMD now includes the sudo and systemd-run wrapper
    client_result = subprocess.run(CLIENT_CMD, capture_output=True, text=True)
    
    end_time = time.monotonic()

    # 3. Calculate and print duration
    duration = end_time - start_time
    print("-" * 30)
    print(f"✅ Client execution time: {duration:.4f} seconds")
    print("-" * 30)

    if client_result.returncode != 0:
        print(f"⚠️ Client exited with an error (code: {client_result.returncode}).")
        print("--- Client STDERR ---")
        print(client_result.stderr)
        print("-" * 21)


except FileNotFoundError as e:
    print(f"❌ Error: Command not found - {e.filename}. Is the path correct?")
except subprocess.CalledProcessError as e:
    print(f"❌ Error running command: {' '.join(e.cmd)}")
    print("Are you running this script with 'sudo'?")

finally:
    # TEARDOWN: Remove network limits and shut down the server
    # No disk cleanup is needed because systemd-run handles it!
    print("Cleaning up...")
    try:
        print("Removing network limit...")
        subprocess.run(NET_RESET_CMD, check=True, capture_output=True)
    except Exception as e:
        print(f"⚠️ Could not reset network settings: {e}")
        
    if server_process:
        print("Shutting down server...")
        server_process.terminate()
        server_process.wait()
    print("Cleanup complete.")
