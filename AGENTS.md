# AGENTS.md

FastSync is a high-performance file synchronization system written in C11. It supports TCP and SSH transports, TLS encryption (OpenSSL), streaming zstd compression, multithreaded transfers, and incremental sync. The build uses CMake; CI runs on Gitea Actions (`.gitea/workflows/ci.yaml`).

## Dependency installation

**Rule: always install dependencies using the project's custom Docker image — never via ad-hoc system package installs on the host** (no `apt-get install` / `pip install` on the host machine).

The image is built from the repo-root `Dockerfile` and is the same image CI uses: `gitea.tap-tap.win/taptap/fastsync-ci:v7`. It contains the full toolchain: gcc/g++, CMake, libzstd-dev, libssl-dev, make, git, cppcheck, clang-format, python3 + pytest, openssh-client, and Node.js.

```bash
# Build the image from the repo-root Dockerfile
docker build -t fastsync-ci:local .

# Provision dependencies and build inside the container (repo mounted at /workspace)
docker run --rm -v "$PWD:/workspace" -w /workspace fastsync-ci:local \
  sh -c 'cmake -B build -S . && cmake --build build -j$(nproc)'
```

If a dependency is missing from the image, add it to the `Dockerfile` (and rebuild) rather than installing it on the host.

## Build

```bash
cmake -B build -S . && cmake --build build -j$(nproc)
```

## Test

```bash
./build/tests                # unit tests
python3 -m pytest tests/     # integration tests
```
