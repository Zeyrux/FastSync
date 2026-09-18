"""Guard the README against drifting from the real CLI.

This test parses README.md and checks it against the actual sources of truth
instead of against a hand-maintained copy:

  * client ``--help`` output  -> ``src/client/usage.c`` (``print_usage``)
  * server ``--help`` output  -> ``src/server/server.c`` (``print_server_usage``)
  * ``FASTSYNC_*`` env vars   -> ``getenv("...")`` call sites under ``src/``

It is deliberately offline and read-only: no server is started, no transfer is
performed.  Each binary is invoked at most once per test session and the result
is cached.
"""

import functools
import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from common import BUILD_DIR, PROJECT_ROOT

pytestmark = pytest.mark.ci

README_PATH = os.path.join(PROJECT_ROOT, "README.md")
SRC_DIR = os.path.join(PROJECT_ROOT, "src")

# ---------------------------------------------------------------------------
# Markdown helpers
# ---------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^(#+)\s+(.*?)\s*$")
_BACKTICK_RE = re.compile(r"`([^`]*)`")
# A documented option may carry an argument annotation that is not part of the
# option name itself: ``--out=FILE``, ``--exclude <pattern>``, ``--threads[=N]``,
# ``--copy-as=USER[:GROUP]``.  Cut the name loose from the first such marker.
_OPTION_SUFFIX_RE = re.compile(r"[=\s<\[(].*$")
_OPTION_TOKEN_RE = re.compile(r"^--?[A-Za-z][A-Za-z0-9-]*$")


def _readme_lines():
    with open(README_PATH, encoding="utf-8") as fh:
        return fh.read().splitlines()


def _heading_level(line):
    match = _HEADING_RE.match(line)
    return len(match.group(1)) if match else 0


def _section(lines, heading):
    """Return ``(lineno, line)`` pairs under the first exact ``heading``.

    The section runs until the next heading of the same or higher level, so a
    ``##`` section includes its ``###`` subsections.  Line numbers are 1-based
    to match what a reader sees in an editor.
    """
    target_level = _heading_level(heading)
    for index, line in enumerate(lines):
        if line.strip() != heading:
            continue
        start = index + 1
        for end in range(start, len(lines)):
            level = _heading_level(lines[end])
            if level and level <= target_level:
                return [(n + 1, lines[n]) for n in range(start, end)]
        return [(n + 1, lines[n]) for n in range(start, len(lines))]
    raise AssertionError(
        f"README heading not found (has the README been restructured?): {heading!r}"
    )


def _first_column_spans(section_lines):
    """Backticked spans from the first column of every markdown table row."""
    spans = []
    for lineno, line in section_lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = stripped.split("|")
        if len(cells) < 2:
            continue
        first = cells[1]
        if set(first.strip()) <= set("-: "):
            continue  # header separator row, e.g. |---|---|
        for match in _BACKTICK_RE.finditer(first):
            spans.append((match.group(1), lineno))
    return spans


def _documented_option_tokens(section_lines):
    """``(token, lineno, raw_cell)`` for each CLI option in a section's tables."""
    found = []
    for raw, lineno in _first_column_spans(section_lines):
        for piece in re.split(r"[,\s]+", raw):
            name = _OPTION_SUFFIX_RE.sub("", piece).strip()
            if _OPTION_TOKEN_RE.match(name):
                found.append((name, lineno, raw))
    return found


# ---------------------------------------------------------------------------
# Sources of truth
# ---------------------------------------------------------------------------

_GETENV_RE = re.compile(r'getenv\s*\(\s*"([^"]+)"\s*\)')
_FASTSYNC_ENV_RE = re.compile(r"FASTSYNC_[A-Z0-9_]+")


def _getenv_names():
    """Every string literal passed to ``getenv()`` anywhere under ``src/``."""
    names = set()
    for root, _dirs, files in os.walk(SRC_DIR):
        for filename in files:
            if not filename.endswith((".c", ".h")):
                continue
            path = os.path.join(root, filename)
            with open(path, encoding="utf-8", errors="replace") as fh:
                names.update(_GETENV_RE.findall(fh.read()))
    return names


@functools.lru_cache(maxsize=None)
def _help_stdout(binary_name):
    """Cached ``<binary> --help`` stdout; skipped (not failed) if unbuilt."""
    binary = os.path.join(BUILD_DIR, binary_name)
    if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
        pytest.skip(
            f"{binary} is not built; run "
            "`cmake -B build -S . && cmake --build build` first"
        )
    try:
        result = subprocess.run(
            [binary, "--help"], capture_output=True, text=True, timeout=30
        )
    except OSError as exc:
        pytest.skip(f"could not execute {binary}: {exc}")
    assert result.returncode == 0, (
        f"{binary} --help exited {result.returncode}: "
        f"{(result.stderr or result.stdout).strip()[:200]}"
    )
    return result.stdout


def _mentions_option(help_text, token):
    """True when ``token`` appears as a standalone option in ``help_text``.

    A plain substring test would let a removed token hide behind a longer one
    (``--del`` inside ``--delete``); requiring a non-word boundary on both sides
    keeps every documented token individually accountable.
    """
    return (
        re.search(r"(?<![\w-])" + re.escape(token) + r"(?![\w-])", help_text)
        is not None
    )


# Options the help text intentionally expresses only as a family (for example
# the generic ``--no-OPTION`` entry) rather than by spelling every member out.
# Add an entry here only with a one-line justification; prefer fixing the
# extractor first.  Currently empty: every option the README documents is
# printed verbatim by the matching ``--help`` (including ``--no-super`` and
# ``--no-detach``).
_FAMILY_FORM_ALLOWLIST = frozenset()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_documented_env_vars_exist():
    """Every ``FASTSYNC_*`` in the README env table has a ``getenv()`` site.

    Both directions are checked so the documented set and the source set stay
    identical: a documented variable with no call site is a README defect, and a
    new ``FASTSYNC_*`` call site without documentation is a README gap.
    """
    documented = _documented_env_vars()
    assert documented, "no FASTSYNC_* variables found in the README env table"

    getenv_names = _getenv_names()
    documented_names = {name for name, _lineno in documented}

    missing_in_source = [
        (name, lineno) for name, lineno in documented if name not in getenv_names
    ]
    if missing_in_source:
        details = "; ".join(
            f"`{name}` (README.md line {lineno})"
            for name, lineno in sorted(missing_in_source, key=lambda item: item[1])
        )
        pytest.fail(
            "README documents environment variable(s) with no getenv() call "
            f"site under src/: {details}"
        )

    fastsync_getenv = {name for name in getenv_names if name.startswith("FASTSYNC_")}
    undocumented = sorted(fastsync_getenv - documented_names)
    assert not undocumented, (
        "src/ reads FASTSYNC_* environment variable(s) that the README does not "
        f"document in '## Environment Variables': {', '.join(undocumented)}"
    )


def test_documented_client_flags_exist_in_help():
    """Client options in README tables must appear in ``client --help``."""
    _assert_documented_flags(
        "client",
        ["### Client", "## Client Options", "## FastSync Extensions"],
    )


def test_documented_server_flags_exist_in_help():
    """Server options in README tables must appear in ``server --help``."""
    _assert_documented_flags("server", ["### Server", "## Server Options"])


# ---------------------------------------------------------------------------
# Implementation helpers for the tests above
# ---------------------------------------------------------------------------


def _documented_env_vars():
    """``(name, lineno)`` for each ``FASTSYNC_*`` token in the env table."""
    lines = _readme_lines()
    section = _section(lines, "## Environment Variables")
    found = []
    for raw, lineno in _first_column_spans(section):
        for match in _FASTSYNC_ENV_RE.finditer(raw):
            found.append((match.group(0), lineno))
    return found


def _assert_documented_flags(binary_name, headings):
    help_text = _help_stdout(binary_name)
    readme_lines = _readme_lines()

    failures = []
    for heading in headings:
        for token, lineno, raw in _documented_option_tokens(
            _section(readme_lines, heading)
        ):
            if token in _FAMILY_FORM_ALLOWLIST:
                continue
            if not _mentions_option(help_text, token):
                failures.append((lineno, token, heading, raw))

    if failures:
        failures.sort()
        shown = "\n".join(
            f"  {token}  (README.md line {lineno}, section {heading!r}, "
            f"table cell `{raw}`)"
            for lineno, token, heading, raw in failures
        )
        pytest.fail(
            f"README documents option(s) missing from `{binary_name} --help`:\n"
            f"{shown}"
        )
