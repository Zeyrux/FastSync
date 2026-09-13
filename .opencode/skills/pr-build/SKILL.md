---
name: pr-build
description: Builds and tests a pull request branch, fixing compilation errors and test failures. Use when the user says "build PR", "fix PR build", "run PR build", or wants to compile and test a PR branch.
---

# PR Build Skill

Builds, tests, and fixes a pull request branch. This skill CAN edit files, commit, and push.

## Workflow

### Step 1: Identify the PR branch

If the user specifies a PR number, check it out:
```bash
tea pr checkout <number>
```

If already on a PR branch, verify with:
```bash
git branch --show-current
git log dev..HEAD --oneline
```

### Step 2: Clean build

```bash
rm -rf build
cmake -B build -S . 2>&1
cmake --build build -j$(nproc) 2>&1
```

Capture both stdout and stderr.

### Step 2b: Sanitizer build (if issues suspected)

If the PR touches threading, memory management, or network code, also build with sanitizers:

```bash
# AddressSanitizer
rm -rf build-asan
cmake -B build-asan -S . -DSANITIZER=address
cmake --build build-asan -j$(nproc)
./build-asan/tests

# ThreadSanitizer (if threading changes)
rm -rf build-tsan
cmake -B build-tsan -S . -DSANITIZER=thread
cmake --build build-tsan -j$(nproc)
./build-tsan/tests
```

### Step 3: Handle build failures

If the build fails, read the error output carefully. Common issues:

**Missing include / undefined reference:**
- Check if the new `.c` file is in the right `file(GLOB ...)` directory
- Check if the new `.h` file is included properly
- Check if CMakeLists.txt needs updating (new target, new source file, new dependency)

**Type errors / implicit declarations:**
- Check function signatures match between `.h` and `.c`
- Check struct field names and types

**Linker errors:**
- Check if all required libraries are linked in CMakeLists.txt
- Check if all source files are included in the target

Use the cmake-expert agent to diagnose and fix CMake issues.

### Step 4: Run unit tests

If build succeeds:
```bash
./build/tests
```

### Step 5: Handle test failures

If tests fail:
- Read the test output carefully
- Check which test function failed and the assertion line
- Read the test source file and the module being tested
- Use the test-writer agent to investigate and fix

### Step 6: Run integration tests (optional)

```bash
python3 -m pytest tests/integration/ -n 4 --dist=load -m "not setpriv"
```

This runs the integration suite (benchmarking is `benchmark/bench.py`). It takes longer — only run if the user asks or if unit tests pass.

### Step 7: Fix and commit

If fixes were needed:
```bash
git add -A
git commit -m "Fix build: <brief description of what was fixed>"
git push
```

### Step 8: Report results

Print a summary:

```
=== PR BUILD SUMMARY ===
Branch: <branch-name>
Build: [PASS/FAIL]
Unit tests: [PASS/FAIL] (<passed>/<total>)
ASan: [CLEAN/ERRORS]
TSan: [CLEAN/ERRORS/SKIPPED]
Integration tests: [PASS/FAIL/SKIPPED]

Fixes applied: <count>
<list of fixes with commit hashes>
```

## Rules
- DO edit source files and CMakeLists.txt to fix issues
- DO commit and push fixes
- Always build from clean state (rm -rf build)
- Read error messages carefully before fixing
- Don't change functionality — only fix build/test issues
- Preserve existing code style when making fixes
