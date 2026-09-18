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
# Real FastSync flags: -z=compression, -j=multithreading,
# --chunk-serialization, --sendfile (long form only).  The old rsync-style
# spellings -c/-m/-s/-f are NOT the same options (-c=--checksum,
# -m=--prune-empty-dirs, -s=--secluded-args, -f=--filter) and must not be used.
CONFIGS=(
  "Standard|"
  "Compression|-z"
  "Multithreading|-j"
  "MT+Compression|-j -z"
  "Chunk Serialization|-j -z --chunk-serialization"
  "Sendfile|--sendfile"
)

PORT=18080
for config in "${CONFIGS[@]}"; do
  IFS='|' read -r name flags <<< "$config"
  echo "=== $name ==="
  for run in 1 2 3; do
    rm -rf /tmp/fastsync_bench/dst
    mkdir -p /tmp/fastsync_bench/dst

    ./build/server -p "$PORT" --allow-unauthenticated &
    SERVER_PID=$!
    sleep 0.5

    START=$(date +%s%N)
    ./build/client --source-dir /tmp/fastsync_bench/src \
      --dest-dir /tmp/fastsync_bench/dst \
      --server-port "$PORT" \
      --save-to-disk $flags
    END=$(date +%s%N)

    ELAPSED=$(( (END - START) / 1000000 ))
    echo "  Run $run: ${ELAPSED}ms"

    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
  done
done
```

### Step 4: Full Benchmark Tool (Preferred)

The maintained benchmark tool is `benchmark/bench.py`. It handles building,
data generation, network shaping (LAN/WAN profiles or custom `--delay`/`--jitter`/
`--throughput`/`--loss`), rsync comparison, and JSON/table reporting:

```bash
python3 benchmark/bench.py --help
python3 benchmark/bench.py --runs 5 --profiles unlimited
python3 benchmark/bench.py --size-mb 100 --random-ratio 0.5 --output json
python3 benchmark/bench.py --delay 50ms --jitter 10ms --throughput 100mbit
```

Network shaping needs root (`tc`/`netem` on `lo`). SSH and TLS coverage lives in
the pytest integration suite, not the benchmark tool.

### Step 5: Report Results

```
=== BENCHMARK RESULTS ===
Test data: <size> MB (<file count> files)
Platform: <OS, CPU, network>

Configuration          | Run 1   | Run 2   | Run 3   | Median
-----------------------|---------|---------|---------|--------
Standard                            | 0.12s   | 0.11s   | 0.12s   | 0.12s
Compression (-z)                    | 0.09s   | 0.08s   | 0.09s   | 0.09s
Multithreading (-j)                 | 0.07s   | 0.07s   | 0.08s   | 0.07s
MT+Compression (-j -z)              | 0.05s   | 0.05s   | 0.06s   | 0.05s
Chunk Serialization (--chunk-serialization) | 0.05s | 0.04s | 0.05s | 0.05s
Sendfile (--sendfile)               | 0.04s   | 0.04s   | 0.04s   | 0.04s

Best configuration: Sendfile (--sendfile)
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
