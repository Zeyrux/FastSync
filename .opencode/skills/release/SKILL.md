---
name: release
description: Prepares a FastSync release — version bump, changelog, build verification, and git tagging. Use when the user says "prepare release", "bump version", "tag release", or wants to cut a new version.
---

# Release Skill

Prepares a new release of FastSync. This skill CAN edit files, commit, and tag.

## Workflow

### Step 1: Determine Version

Ask the user or determine from context:
- **Major** (X.0.0) — breaking protocol changes, incompatible CLI changes
- **Minor** (x.Y.0) — new features, backward compatible
- **Patch** (x.y.Z) — bug fixes, no protocol changes

Current version: `PROTOCOL_VERSION "2.21.0"` in `src/shared/config.h`

### Step 2: Check Protocol Version

If the wire protocol changed, bump `PROTOCOL_VERSION` in `src/shared/config.h`:
```c
#define PROTOCOL_VERSION "1.2.0"  // or "2.0.0" for breaking
```

Protocol version changes require:
- Both client and server to be updated together
- Backward compatibility considerations documented
- Migration path clear

### Step 3: Verify Build and Tests

```bash
rm -rf build
cmake -B build -S .
cmake --build build -j$(nproc)
./build/tests
python3 -m pytest tests/integration/ -n 4 --dist=load -m "not setpriv"
```

ALL tests must pass before release.

### Step 4: Run Sanitizer Checks

```bash
# ASan
rm -rf build-asan
cmake -B build-asan -S . -DSANITIZER=address
cmake --build build-asan -j$(nproc)
./build-asan/tests
```

### Step 5: Update README (If Needed)

Check if README needs updates:
- New features documented
- New CLI flags documented
- Benchmark results updated
- Build instructions current

### Step 6: Create Release Commit

```bash
git add -A
git commit -m "Release vX.Y.Z

- <list of changes>
- Protocol version: X.Y.Z
- Tested: unit tests, integration tests, ASan"
```

### Step 7: Tag the Release

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
```

### Step 8: Push and Open dev → main PR

`main` is protected and only receives changes via `dev` → `main` PRs (see AGENTS.md). Never push directly to `main`.

```bash
# Push the release commit and tag to dev
git push origin dev
git push origin vX.Y.Z

# Open the dev → main release PR for review + CI
tea pr create --repo TapTap/FastSync --head dev --base main \
  --title "Release vX.Y.Z" \
  --description "Release vX.Y.Z"
```

Then wait for the full CI to pass and request review before the PR is merged to `main`.

### Step 9: Report

```
=== RELEASE SUMMARY ===
Version: vX.Y.Z
Protocol: X.Y.Z
Commit: <hash>
Tag: vX.Y.Z
Changes:
  - <list of changes in this release>
Build: PASS
Tests: PASS (<passed>/<total>)
ASan: CLEAN
```

## Rules
- DO verify all tests pass before release
- DO run sanitizer checks before release
- DO update README if features changed
- DO tag releases with annotated tags
- DON'T release if tests fail
- DON'T skip sanitizer checks
- DON'T change code during release (only version bump + docs)
