---
name: pr-review
description: Reviews a pull request for bugs, memory safety, thread safety, and style issues. Use when the user says "review PR", "review this PR", "review pull request", or wants a code review of changes.
---

# PR Review Skill

Read-only code review of a pull request branch. Produces a report — does NOT edit files.

## Workflow

### Step 1: Identify the PR branch

If the user specifies a PR number, check it out:
```bash
tea pr checkout <number>
```

If already on a PR branch, verify with:
```bash
git branch --show-current
git log main..HEAD --oneline
```

### Step 2: Get changed files

```bash
git diff main --name-only -- '*.c' '*.h'
```

This gives the list of C source and header files changed in the PR.

### Step 3: Read all changed files

Use the Read tool to read every changed `.c` and `.h` file. Read full files — don't skip any.

### Step 4: Review each file

For each changed file, review for:

**Memory Safety**
- Every `malloc`/`calloc` has a matching `free` on all code paths (including error paths)
- No use-after-free (pointers used after `*_destroy()` is called)
- No double-free
- Null checks after allocation before use
- Correct buffer sizes (strlen + 1 for null terminators)
- `Data` objects created/destroyed properly

**Thread Safety**
- Shared state accessed under mutex
- No race conditions on queue operations
- Condition variable signals under lock
- No deadlock potential (consistent lock ordering)
- `done` flags checked properly in consumer loops

**Protocol Safety**
- `send_n_data` / `receive_n_data` return values checked
- Status codes validated before use
- Config serialization handles partial reads

**Logic Errors**
- Off-by-one in loops/buffers
- Incorrect size calculations
- Wrong enum values or comparisons
- Missing break statements in switch

**Error Handling**
- Resources freed on error paths (no leaks)
- Functions return appropriate error values
- Error messages are useful

### Step 5: Categorize findings

For each issue:
1. **File:line** — exact location
2. **Severity** — critical / warning / style
3. **Category** — memory / thread / protocol / logic / error
4. **Description** — what's wrong and how to fix it

### Step 6: Output report

Print a formatted summary:

```
=== PR REVIEW SUMMARY ===
Branch: <branch-name>
Files reviewed: <count>
Issues found: <count>

CRITICAL: <count>
WARNING: <count>
STYLE: <count>

=== ISSUES ===
[1] src/shared/compression.c:42 — CRITICAL (memory)
    Potential leak: data returned from data_compress() not freed on error path
    Fix: Add data_destroy(compressed) before return false

...

=== VERDICT ===
[PASS] No critical issues found
  — or —
[FAIL] <N> critical issues must be fixed before merge
```

### Step 7: Optional PR comment

If the user wants to post the review as a PR comment:
```bash
tea pr comment <number> --comment "<review report>"
```

## Rules
- Do NOT edit any source files
- Do NOT run builds or tests
- Do NOT commit or push
- Report ALL issues — don't filter or minimize
- Be specific about line numbers and fix suggestions
