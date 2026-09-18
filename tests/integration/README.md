# Integration tests

The integration suite drives the built `build/server` and `build/client`
against local corpora. Unit tests live in `tests/` (the custom C framework);
the Python suite here covers the full transfer pipeline, transports, features,
and rsync parity.

## Running

```bash
# Full suite (excludes privilege-dependent tests on CI runners)
python3 -m pytest tests/integration/ -n 4 --dist=load -m "not setpriv"

# Fast PR subset only
python3 -m pytest tests/integration/ -n 4 --dist=load -m ci
```

The tests expect `build/server` and `build/client` (configure/build with CMake
first); `common.py` derives `BUILD_DIR` from the repository root.

## Differential rsync-parity gate

`test_differential_parity.py` runs the **same** transfer with real
`rsync 3.4.1` and with FastSync over separate destinations, then compares:

- the destination trees — relative paths, file content hashes, symlink
  targets, modes (where the case is about perms), and hard-link grouping;
- the normalized stdout for output-oriented flags (`-i`,
  `--out-format=...`, `--stats`), after stripping volatile fields
  (timings, rates, wire byte counts) and directory-only itemize lines that
  FastSync's recursive scanner documents as absent.

FastSync mirrors the absolute source path under its receive root (see
`get_dest_received_dir`); the harness normalizes that layout (and the
`-R`/`--files-from` layouts) before comparing.

```bash
# Fast subset that guards the ✅ surface on pull requests
python3 -m pytest tests/integration/test_differential_parity.py -n 4 --dist=load -m parity_ci

# Full set (all ✅ cases plus the documented ⚠️/❌ residuals)
python3 -m pytest tests/integration/test_differential_parity.py -n 4 --dist=load -m parity
```

The suite skips cleanly when `rsync` is not installed.

## Allowlist (`parity_caveats.py`)

`parity_caveats.py` is the single data-driven allowlist of known differences.
Each entry maps a case id to the aspects that may differ (`tree`, `stdout`,
`extra`, `rc`) and cites the governing row in `RSYNC_COMPAT.md`:

```python
CAVEATS = {
    "min_size": {
        "tree": "recursive transfer does not create a source directory that "
                "becomes empty after --min-size filtering. ref: RSYNC_COMPAT.md "
                "`-d/--dirs` row and completion-wave residual.",
    },
}
```

A differential mismatch in an aspect that is **not** listed fails the gate with
a readable tree/stdout diff.

If a case is allowlisted but now matches rsync, the gate emits a loud warning
naming the stale entry — that is the parity burn-down signal. Run with
`FASTSYNC_PARITY_STRICT=1` to make stale entries fail instead (the full CI
parity job sets this). To add a residual:

1. Reproduce it with `-m parity` and read the failure's tree/stdout diff.
2. Confirm it is a documented `⚠️`/`❌` residual (or get the `✅` row
   reclassified) and cite the row.
3. Add the case id and aspect(s) to `CAVEATS`, keeping the reason concise.

Do not allowlist an undocumented divergence from a `✅` row — fix it or get the
row reclassified first.
