# AGENTS.md

FastSync is a high-performance file synchronization system written in C11. It supports TCP and SSH transports, TLS encryption (OpenSSL), streaming zstd compression, multithreaded transfers, and incremental sync. The build uses CMake; CI runs on Gitea Actions (`.gitea/workflows/ci.yaml`).

## Dependency installation

**CI rule:** never add `apt-get install` / `pip install` steps to CI workflows — use the custom Docker image instead. The image is built from the repo-root `Dockerfile` and is the same image CI uses: `gitea.tap-tap.win/taptap/fastsync-ci:v7`. It contains the full toolchain: gcc/g++, CMake, libzstd-dev, libssl-dev, make, git, cppcheck, clang-format, python3 + pytest, openssh-client, and Node.js.

**Host rule:** for local development, use `nix-shell` (see `README.md`) which provides zstd, OpenSSL, CMake, and gcc. The Docker image can also be used locally for CI parity.

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

If a dependency is missing from the CI image, add it to the `Dockerfile` (and rebuild) rather than adding an install step to the CI workflow.

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

## Batch PR Workflow

When handling multiple issues split across several PRs that target the same files:

1. **Group issues by logical category** into separate PR branches (e.g., memory-safety, refactoring, test-coverage).
2. **Fix and push** each branch independently. Let CI run on each PR.
3. **Run all 3 reviewer types** on each PR and post results to Gitea via `tea pr approve/reject` or the Gitea API:
   - `reviewer` — general code correctness
   - `code-quality-guardian` — code quality, duplication, complexity
   - `security-auditor` — vulnerability assessment
4. **Iterate**: if any reviewer requests changes, fix, push, re-review. Repeat until all 3 approve.
5. **Merge approved PRs** one at a time into `main`.
6. **Create a combined merge branch** for the remaining PRs that conflict with the new `main`:
   ```bash
   git checkout -b merge-all origin/main
   for branch in branch1 branch2 branch3; do
     git merge origin/$branch --no-edit || true
     # Resolve conflicts, build, test
   done
   ```
7. **Run review again** on the combined branch. Fix issues, push, re-review until approved.
8. **Merge** the combined PR, **close** the redundant individual PRs, and **close all resolved issues** via the Gitea API:
   ```bash
   curl -s -X PATCH -H "Authorization: token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"state":"closed"}' \
     "https://gitea.tap-tap.win/api/v1/repos/owner/repo/issues/<number>"
   ```

## CI Troubleshooting

### If lint (clang-format) fails
Run clang-format in the CI Docker image to match the exact CI version:
```bash
docker run --rm -v "$PWD:/workspace" -w /workspace gitea.tap-tap.win/taptap/fastsync-ci:v9 \
  sh -c 'find src/ tests/ -name "*.c" -o -name "*.h" | xargs clang-format -i'
```

### If cppcheck fails
Fix reported issues locally, then verify with:
```bash
docker run --rm -v "$PWD:/workspace" -w /workspace gitea.tap-tap.win/taptap/fastsync-ci:v9 \
  sh -c 'cppcheck --enable=warning,style,performance,portability --suppress=missingIncludeSystem --error-exitcode=1 --inline-suppr src/ tests/'
```

### If integration tests fail
Run locally before pushing:
```bash
python3 -m pytest tests/ -v --tb=short
```

## Gitea API & tea CLI

### Check CI status via API
```bash
TOKEN="<token>"
curl -s -H "Authorization: token $TOKEN" \
  "https://gitea.tap-tap.win/api/v1/repos/TapTap/FastSync/actions/runs?limit=5" \
  | python3 -c "
import json,sys; d=json.load(sys.stdin)
for r in d.get('workflow_runs',[]):
    path = r.get('path','')
    prn = path.split('@')[1].replace('refs/pull/','').replace('/head','') if '@' in path else ''
    print(f'PR #{prn}: sha={r[\"head_sha\"][:8]} {r[\"status\"]} {r.get(\"conclusion\",\"\")}')
"
```

### Post review comments
```bash
curl -s -X POST -H "Authorization: token $TOKEN" -H "Content-Type: application/json" \
  -d '{"body":"MARKDOWN_REVIEW_BODY"}' \
  "https://gitea.tap-tap.win/api/v1/repos/TapTap/FastSync/issues/<PR_NUMBER>/comments"
```

### Use tea for PR operations
```bash
tea pr list --repo TapTap/FastSync
tea pr close <number> --repo TapTap/FastSync
```

## Common pitfalls

- **`__thread` on shared SSL context**: io_ssl must NOT be thread-local — worker threads inherit the SSL context from the main thread. Use regular `static SSL* io_ssl`.
- **SSL WANT_READ/WANT_WRITE retry**: Always retry on `SSL_ERROR_WANT_READ` and `SSL_ERROR_WANT_WRITE` in `send_n_data`/`receive_n_data`. Removing these breaks TLS multithreaded transfers.
- **clang-format version**: The CI image uses clang-format 18. Always format inside the CI Docker container for exact match.
- **Merge order matters**: Merge the most comprehensive branch first, then smaller ones, to minimize conflicts when creating a combined branch.
