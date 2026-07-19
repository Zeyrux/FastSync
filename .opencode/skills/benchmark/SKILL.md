---
name: benchmark
description: Runs performance benchmarks on FastSync, collects metrics, compares configurations, and reports throughput. Use when the user says "benchmark", "measure performance", "profile", or wants to compare transfer speeds.
---

# Benchmark Skill

Runs performance benchmarks and collects metrics. This skill CAN edit files for benchmark scripts and run builds/tests.

## Workflow

### Step 1: Build Optimized

```bash
rm -rf build
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Step 2: Generate Test Data

```bash
mkdir -p /tmp/fastsync_bench/src
# Small files
for i in $(seq 1 100); do
  dd if=/dev/urandom of=/tmp/fastsync_bench/src/small_$i.bin bs=1K count=10 2>/dev/null
done
# Medium files
for i in $(seq 1 20); do
  dd if=/dev/urandom of=/tmp/fastsync_bench/src/med_$i.bin bs=1M count=1 2>/dev/null
done
# Large files
dd if=/dev/urandom of=/tmp/fastsync_bench/src/large.bin bs=1M count=10 2>/dev/null
```

### Step 3: Run Benchmarks

Test each configuration 3 times, record median:

```bash
CONFIGS=(
  "Standard|"
  "Compression|-c"
  "Multithreading|-m"
  "MT+Compression|-m -c"
  "Chunk Serialization|-s"
  "MT+Compression+Chunk|-m -c -s"
  "Sendfile|-f"
)

for config in "${CONFIGS[@]}"; do
  IFS='|' read -r name flags <<< "$config"
  echo "=== $name ==="
  for run in 1 2 3; do
    rm -rf /tmp/fastsync_bench/dst
    mkdir -p /tmp/fastsync_bench/dst
    
    ./build/server &
    SERVER_PID=$!
    sleep 0.5
    
    START=$(date +%s%N)
    ./build/client --source-dir /tmp/fastsync_bench/src \
      --dest-dir /tmp/fastsync_bench/dst \
      --save-to-disk $flags
    END=$(date +%s%N)
    
    ELAPSED=$(( (END - START) / 1000000 ))
    echo "  Run $run: ${ELAPSED}ms"
    
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
  done
done
```

### Step 4: Full Integration Benchmark (Optional)

For comprehensive benchmarking with network shaping:
```bash
python3 test.py --full
```

This tests LAN/WAN profiles, SSH, TLS, and compares against rsync.

### Step 5: Report Results

```
=== BENCHMARK RESULTS ===
Test data: <size> MB (<file count> files)
Platform: <OS, CPU, network>

Configuration          | Run 1   | Run 2   | Run 3   | Median
-----------------------|---------|---------|---------|--------
Standard               | 0.12s   | 0.11s   | 0.12s   | 0.12s
Compression (-c)       | 0.09s   | 0.08s   | 0.09s   | 0.09s
Multithreading (-m)    | 0.07s   | 0.07s   | 0.08s   | 0.07s
MT+Compression (-m -c) | 0.05s   | 0.05s   | 0.06s   | 0.05s
Sendfile (-f)          | 0.04s   | 0.04s   | 0.04s   | 0.04s

Best configuration: MT+Compression (-m -c)
Throughput: <X> MB/s
```

### Step 6: Profiling (If Requested)

For detailed profiling:
```bash
# perf
perf record -g ./build/client [args...]
perf report

# gprof
gcc -pg -o build/client_profile [sources]
./build/client_profile [args]
gprof build/client_profile gmon.out
```

## Rules
- DO build with Release mode for benchmarks
- DO run each config multiple times (at least 3)
- DO clean destination between runs
- DO report median, not just one run
- DON'T run benchmarks during active development (noisy results)
- ALWAYS clean up test data after benchmarking
