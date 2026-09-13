---
name: debug-workflow
description: Debugs crashes, memory errors, hangs, and logic bugs in FastSync using structured methodology. Use when the user says "debug X", "fix crash", "investigate failure", "there's a bug", or needs help diagnosing issues.
---

# Debug Workflow Skill

Structured debugging for FastSync: reproduce → isolate → diagnose → fix → verify. This skill CAN edit files, build, and run tests.

## Workflow

### Step 1: Understand the Problem

Ask or gather:
- What's the symptom? (crash, hang, wrong output, valgrind error)
- What command triggers it?
- Is it deterministic or intermittent?
- What's the environment? (OS, compiler, network conditions)

### Step 2: Reproduce

Build with debug info:
```bash
rm -rf build
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

Try to reproduce the issue with the exact command the user provides.

### Step 3: Isolate with Sanitizers

**Memory errors (first priority):**
```bash
rm -rf build-asan
cmake -B build-asan -S . -DSANITIZER=address
cmake --build build-asan -j$(nproc)
./build-asan/tests
# or run the failing command
```

**Thread errors:**
```bash
rm -rf build-tsan
cmake -B build-tsan -S . -DSANITIZER=thread
cmake --build build-tsan -j$(nproc)
./build-tsan/tests
```

**Valgrind (if ASan doesn't find it):**
```bash
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
  ./build/client --source-dir /tmp/src --dest-dir /tmp/dst --save-to-disk
```

### Step 4: GDB Analysis

If the issue is a crash or hang:
```bash
gdb --args ./build/client [args...]
(gdb) run
# when it crashes:
(gdb) bt full
(gdb) info locals
(gdb) print variable_name
```

For hangs:
```bash
# In another terminal:
kill -SIGABRT <pid>  # generates core dump
gdb ./build/client core
(gdb) thread apply all bt
```

### Step 5: Read the Code

Read the relevant source files around the crash/failure point. Look for:
- Unchecked return values
- Null pointer dereferences
- Buffer overflows
- Use-after-free
- Race conditions
- Incorrect protocol handling

### Step 6: Diagnose Root Cause

Identify the exact file:line and what's wrong. Common patterns:
- `send_n_data` / `receive_n_data` return value not checked
- `data_destroy()` called but pointer still used
- Queue operation without mutex in threaded code
- Partial read/write not handled
- Integer overflow in size calculations

### Step 7: Fix

Apply the minimal fix. Don't refactor while debugging — one change at a time.

### Step 8: Verify

```bash
# Rebuild and test
cmake -B build -S . && cmake --build build -j$(nproc)
./build/tests

# If integration test needed
python3 -m pytest tests/integration/ -n 4 --dist=load -m "not setpriv"

# Re-run under sanitizer to confirm fix
rm -rf build-asan
cmake -B build-asan -S . -DSANITIZER=address
cmake --build build-asan -j$(nproc)
# reproduce the original failing command
```

### Step 9: Report

Print a summary:
```
=== DEBUG SUMMARY ===
Symptom: <what was happening>
Root cause: <file:line — what's wrong>
Fix: <what was changed>
Verification: <how it was confirmed fixed>
```

## Rules
- DO edit source files to fix issues
- DO rebuild and test after fixes
- DON'T refactor while debugging — minimal changes only
- DON'T change behavior beyond fixing the bug
- PRESERVE existing code style
- ALWAYS verify with `./build/tests` after changes
