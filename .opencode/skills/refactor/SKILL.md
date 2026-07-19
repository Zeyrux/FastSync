---
name: refactor
description: Refactors FastSync code for structural improvements — DRY, separation of concerns, API simplification. Use when the user says "refactor X", "clean up code", "improve structure", or wants to reduce duplication.
---

# Refactor Skill

Read-only analysis + code edits for structural improvements. This skill CAN edit files but MUST verify tests pass.

## Workflow

### Step 1: Identify Refactoring Target

Ask or determine:
- What code needs refactoring?
- What's the problem? (duplication, complexity, wrong abstraction, naming)
- What's the scope? (single function, module, cross-module)

### Step 2: Read and Understand

Read the relevant source files completely. Understand:
- What the code does
- How it fits in the larger system
- What depends on it
- What it depends on

### Step 3: Verify Baseline

Before any changes, confirm tests pass:
```bash
cmake -B build -S . && cmake --build build -j$(nproc)
./build/tests
```

### Step 4: Plan the Refactor

Document the plan:
1. What changes will be made
2. What behavior is preserved
3. What risks exist
4. How to verify correctness

### Step 5: Implement

Make the changes, one logical step at a time. Follow existing code conventions:
- Header guards: `#ifndef FILENAME_H`
- Naming: `snake_case` with module prefix
- `static` for file-local functions
- Pointer style: `Type *name`
- Error handling: return `false`/`NULL` on failure

### Step 6: Build and Test

```bash
cmake -B build -S . && cmake --build build -j$(nproc)
./build/tests
```

ALL tests must pass. If a test fails, investigate and fix.

### Step 7: Report

Print a summary:
```
=== REFACTOR SUMMARY ===
Target: <what was refactored>
Changes:
  - <list of changes>
Tests: <passed/total>
Behavior preserved: yes
```

## Rules
- DO edit source files
- DO run tests after changes
- DO follow existing code conventions
- DON'T change observable behavior
- DON'T fix bugs while refactoring (separate concern)
- DON'T add new features during refactoring
- DON'T rewrite from scratch — incremental changes
- ALWAYS verify tests pass before AND after
