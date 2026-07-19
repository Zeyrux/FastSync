---
name: security-audit
description: Performs a security audit of FastSync — checks TLS config, input validation, buffer safety, crypto hygiene, and network attack surface. Use when the user says "security audit", "check security", "harden", or wants a security review.
---

# Security Audit Skill

Read-only security review of the FastSync codebase or specific modules. Produces a report — does NOT edit files.

## Workflow

### Step 1: Scope the Audit

Determine what to audit:
- Full codebase audit
- Specific module (e.g., `transport_tls.c`, `protocol.c`)
- Specific vulnerability class (e.g., buffer overflows, TLS misconfig)

### Step 2: Identify Attack Surface

Network input points:
```
src/server/server.c          — TCP accept, per-connection handling
src/shared/protocol.c        — all wire protocol parsing
src/shared/config.c          — config deserialization
src/shared/chunk.c           — chunk deserialization
src/shared/transport_tls.c   — TLS handshake and data
src/shared/transport_ssh.c   — SSH data via stdio
```

### Step 3: Read All Relevant Files

Read every file in scope completely. Focus on:
- All `receive_*` calls and their validation
- All `malloc`/`calloc` calls and their size calculations
- All string operations (`strcpy`, `sprintf`, `snprintf`)
- All path operations (filename handling, directory creation)
- All TLS/SSL operations and error handling

### Step 4: Apply Security Checklist

#### Input Validation
- [ ] All `receive_*` return values checked
- [ ] Received size fields validated against bounds
- [ ] Path traversal prevention (`..` in filenames)
- [ ] Null bytes in filenames handled
- [ ] Chunk/file counts validated before allocation

#### Buffer Safety
- [ ] No `strcpy` — use `snprintf`
- [ ] `malloc` size calculations don't overflow
- [ ] No fixed-size stack buffers for unbounded input
- [ ] Off-by-one in path concatenation

#### TLS/SSL
- [ ] TLS 1.2 minimum enforced
- [ ] Certificate verification when CA provided
- [ ] SSL error codes checked after `SSL_read`/`SSL_write`
- [ ] No hardcoded certificates/keys
- [ ] Strong cipher suites only

#### Memory Safety in Error Paths
- [ ] All error paths free allocated resources
- [ ] No use-after-free on error paths
- [ ] Partial reads handled

#### Denial of Service
- [ ] Bounded memory allocation
- [ ] Timeout on connections
- [ ] Malformed messages handled gracefully

### Step 5: Check for Common Vulnerabilities

```bash
# Grep for dangerous patterns
grep -rn "strcpy\|strcat\|sprintf" src/
grep -rn "malloc.*\*" src/  # potential integer overflow in size calc
grep -rn "receive_n_data" src/  # check all return values
grep -rn "NULL" src/ | grep -v "//"  # check null handling
```

### Step 6: Output Report

```
=== SECURITY AUDIT SUMMARY ===
Scope: <what was audited>
Files reviewed: <count>

Critical: <count>
High: <count>
Medium: <count>
Low: <count>
Informational: <count>

=== FINDINGS ===

[1] <file:line> — CRITICAL (<category>)
    Description: <what's wrong>
    Exploit scenario: <how it could be triggered>
    Fix: <concrete code change>

...

=== VERDICT ===
[PASS] No critical/high issues found
  — or —
[FAIL] <N> critical/high issues must be fixed
```

## Rules
- Do NOT edit any source files
- Do NOT run builds or tests
- Report ALL issues — don't filter or minimize
- Be specific about line numbers and fix suggestions
- Consider both remote and local attack vectors
