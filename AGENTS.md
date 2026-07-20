# AGENTS.md

FastSync is a high-performance file synchronization system written in C11. It supports TCP and SSH transports, TLS encryption (OpenSSL), streaming zstd compression, multithreaded transfers, and incremental sync. The build uses CMake; CI runs on Gitea Actions (`.gitea/workflows/ci.yaml`).

## Dependency installation

**Rule: always install dependencies using the project's custom Docker image — never via ad-hoc system package installs on the host** (no `apt-get install` / `pip install` on the host machine).

The image is built from the repo-root `Dockerfile` and is the same image CI uses: `gitea.tap-tap.win/taptap/fastsync-ci:v7`. It contains the full toolchain: gcc/g++, CMake, libzstd-dev, libssl-dev, make, git, cppcheck, clang-format, python3 + pytest, openssh-client, and Node.js.

```bash
# Use the prebuilt CI image directly (faster, guaranteed CI parity)
docker pull gitea.tap-tap.win/taptap/fastsync-ci:v7
docker tag gitea.tap-tap.win/taptap/fastsync-ci:v7 fastsync-ci:local

# Or build the image from the repo-root Dockerfile
# (Note: the prebuilt :v7 image reflects the previous Dockerfile state;
#  rebuild from source to pick up any newly added packages like lcov/valgrind.)
docker build -t fastsync-ci:local .

# Build, run unit tests, and run integration tests inside the container
docker run --rm -v "$PWD:/workspace" -w /workspace fastsync-ci:local \
  sh -c 'cmake -B build -S . && cmake --build build -j$(nproc) && ./build/tests && python3 -m pytest tests/'

# Avoid root-owned build/ artifacts by matching your host UID/GID
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" \
  -w /workspace fastsync-ci:local \
  sh -c 'cmake -B build -S . && cmake --build build -j$(nproc) && ./build/tests && python3 -m pytest tests/'
```

> **Note:** The first `cmake configure` (`cmake -B build -S .`) fetches xxHash from GitHub via `FetchContent` — network access is required. Subsequent reconfigures reuse the cached source.

If a dependency is missing from the image, add it to the `Dockerfile` (and rebuild) rather than installing it on the host.

## CI Conventions

When configuring for CI parity, use:
```bash
cmake -B build -S . -DSTRICT_WARNINGS=ON        # -Wextra -Wpedantic -Werror
cmake -B build -S . -DSANITIZER=address           # AddressSanitizer (ASan)
cmake -B build -S . -DSANITIZER=thread            # ThreadSanitizer (TSan)
```

The CI workflow (`.gitea/workflows/ci.yaml`) runs lint (clang-format, cppcheck), build + test (unit + integration), and sanitizer (currently only `address`) jobs sequentially.

## Build

```bash
cmake -B build -S . && cmake --build build -j$(nproc)
```

## Test

```bash
./build/tests                # unit tests
python3 -m pytest tests/     # integration tests
```

## CI Workflow — Waiting for Results

When running the CI workflow via `tea` (the task execution agent), always set a sufficient timeout (e.g., 600000ms) to allow CI to finish. After CI completes, check the results yourself — do not assume success. Use `gh run watch` or similar to monitor CI status, then inspect logs on failure.

## Branch Strategy

Never push directly to `main`. All changes must be developed on a feature branch and merged via a pull request. Always create a new branch before making changes:
```bash
git checkout -b <feature-branch-name>
```
After committing changes, push the branch and create a PR:
```bash
git push -u origin <feature-branch-name>
gh pr create --fill
```
Wait for CI to pass on the PR before merging.
