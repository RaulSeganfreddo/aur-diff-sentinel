# Project instructions

## Purpose

`aur-diff-sentinel` is a Python 3.14+ CLI for reviewing AUR PKGBUILDs, metadata diffs, and pending updates. It is a conservative triage tool, not a malware detector: findings identify material for manual review and never prove that a package is safe or malicious.

## Repository map

- Runtime code: `src/aur_diff_sentinel/`
- CLI and output: `cli.py`, `report.py`
- Detection pipeline: `scanner.py`, `rules.py`, `*_analysis.py`, `*_diff.py`
- AUR/cache workflows: `provider.py`, `cache.py`, `update_review.py`, `baseline_*.py`
- Tests: `tests/`; synthetic fixtures: `tests/samples/`
- User-facing commands and behavior: `README.md`

## Commands

Run from the repository root:

- Install development dependencies when needed: `python -m pip install -e ".[dev]"` (use `.venv/bin/python` when `.venv/` exists)
- Run the full suite: `.venv/bin/python -m pytest` when `.venv/` exists; otherwise `python -m pytest`
- Run a focused test: `.venv/bin/python -m pytest tests/test_scanner.py -q`
- Run a safe smoke test: `.venv/bin/aur-diff-sentinel tests/samples/clean.PKGBUILD`

No lint or type-check command is currently configured; do not invent one as a required gate.

## Working agreements

- Preserve public CLI behavior unless the task explicitly changes it: command names, options, exit codes, rule IDs, severities, cache semantics, and safety wording.
- Keep user-facing output concise and conservative. Never turn “no findings” into a safety claim.
- Use `from __future__ import annotations`, `snake_case`, and type hints on public functions.
- Prefer direct, existing abstractions over new layers or dependencies. Add a production dependency only with explicit approval.
- Rule IDs are lowercase and hyphen-separated. Detection rules must be low-noise; every rule change needs both a positive detection test and a false-positive guard.
- When code-size reduction is part of the task, measure runtime and tests separately; do not game counts through formatting, generated data, documentation moves, or relocated logic.
- Keep roadmap, release status, and historical metrics out of this file.

## Safety invariants

- Never execute code from inspected PKGBUILDs or package metadata.
- Normal scans must not install, build, update, or execute AUR packages.
- Do not use live AUR helpers, `pacman`, or network fetches as routine verification unless the user explicitly requests a real-workflow test.
- `updates` may query `paru` or `yay` and fetch AUR metadata, but must never update packages.
- Keep cache paths configurable with `--cache-dir`.
- `baseline refresh` may query `pacman -Q`; refresh only when reviewed metadata matches the installed version. Incomplete analysis must return exit code 2 and block refresh even with `--force`.
- `baseline status` is read-only.
- `baseline prune` may remove only aur-diff-sentinel cache entries for packages confirmed no longer installed; it must never remove system packages.

## Tests and completion

- Tests use `unittest.TestCase` and run with `pytest`.
- Mock or inject network access, AUR helpers, `pacman`, and `git clone`. Local temporary Git repositories are allowed.
- Add regression coverage for behavior changes and safety-boundary fixes.
- Run focused tests while iterating and the full suite before handoff for code changes.
- Report the checks run and any verification that could not be completed.
