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

## Branch Strategy

Two main branches: `dev` (integration) and `main` (stable releases).

### Rules
- **All PRs target `dev`** — never target `main` directly
- **`dev` is the default branch** in Gitea repo settings
- **`main` is protected** — only merged from `dev` via PR with 2 approvals + full CI pass
- **Feature/bug branches** branch from `dev`, PR back to `dev`
- **`dev` → `main` merges** happen on-demand or weekly, requiring full CI + review

```bash
# Start a new feature
git checkout dev && git pull
git checkout -b feat/my-feature
# ... work, commit, push
git push -u origin feat/my-feature
# Create PR targeting dev
```

### Creating the `dev` branch (one-time setup)
```bash
git checkout main && git pull
git checkout -b dev
git push origin dev
# Then in Gitea: Settings → Repository → Default Branch → dev
```

### Branch protection (Gitea repo settings)
**For `dev`:**
- ✅ Require PR for merging
- ✅ Require 1 approval
- ✅ Require status checks (all CI jobs must pass)
- ✅ Delete branch after merge

**For `main`:**
- ✅ Require PR from `dev` only
- ✅ Require CI
- ✅ Require 2 approvals
- ✅ No direct pushes

## Automated Agent Workflows

When a PR targeting `dev` is opened or synchronized, Gitea Actions workflows automatically run agents to review the code and post results as PR comments. This replaces the manual "invoke 3 reviewers" pattern.

### Automated PR Review
Triggered on `pull_request: [opened, synchronize, ready_for_review]`. Runs security-auditor and code-quality-guardian, posts combined review to PR.

### Automated Issue Fix
Comment `/opencode fix` on any issue — agents will create a fix branch, implement the fix, and open a PR targeting `dev`.

### Scheduled Maintenance
Runs weekly (Monday 06:00 UTC) — security audit of the full codebase, creates issues for findings.

### Batch Merge Orchestration
For grouping multiple fixes into one integration PR (like the `integration/all-fixes` pattern):
1. Push each fix branch independently (targetting `dev`)
2. Use `workflow_dispatch` on `agent-batch-merge.yml` with comma-separated branch names
3. The workflow merges all branches into `dev`, resolves conflicts, runs build + tests, and pushes

## Manual PR Invocation

When automated agents are unavailable or you need a targeted review, invoke agents directly:

```bash
# Run all 3 reviewers on a PR diff
opencode run --agent reviewer "Review this PR"
opencode run --agent security-auditor "Audit this PR for vulnerabilities"
opencode run --agent code-quality-guardian "Check this PR for code quality"

# Post results to Gitea
curl -s -X POST -H "Authorization: token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"body":"MARKDOWN_REVIEW_BODY"}' \
  "https://gitea.tap-tap.win/api/v1/repos/TapTap/FastSync/issues/<PR_NUMBER>/comments"
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
