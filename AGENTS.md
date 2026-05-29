# AGENTS.md

## Project
`aur-diff-sentinel` is a Python 3.11+ CLI for reviewing AUR PKGBUILDs, diffs, and pending updates.
It is a conservative triage tool, not a malware detector. Never claim that a package is safe.

## Layout
Runtime code lives in `src/aur_diff_sentinel/`.
Key files:
- `cli.py`: command-line interface
- `scanner.py`: scanning logic
- `rules.py`: detection rules
- `diff_analysis.py`: PKGBUILD diff analysis
- `report.py`: output formatting
- `provider.py`: AUR helper integration
- `cache.py`: baseline/cache handling
- `update_review.py`: pending update review and baseline refresh workflow
- `baseline_status.py`: read-only baseline status reporting
- `baseline_prune.py`: pruning cached metadata for packages no longer installed
Tests live in `tests/`; fixtures live in `tests/samples/`.

## Commands
Run from the repository root:

    pip install -e ".[dev]"
    pytest
    aur-diff-sentinel tests/samples/clean.PKGBUILD
    aur-diff-sentinel --diff tests/samples/suspicious.diff
    aur-diff-sentinel updates
    aur-diff-sentinel baseline refresh
    aur-diff-sentinel baseline status
    aur-diff-sentinel baseline prune

## Coding Rules
Follow existing style.
Use:
- `from __future__ import annotations`
- type hints for public functions
- `snake_case`
- small functions with explicit return values
Keep CLI output concise and user-facing.
Detection rules must be conservative and low-noise. Prefer fewer reliable findings over broad noisy matches.
Rule IDs are lowercase and hyphen-separated, for example `checksum-skip`.

## Security Boundaries
Normal scans must never install, build, update, or execute AUR packages.
Never run code from inspected PKGBUILDs.
Do not claim that “no findings” means safe.
Keep cache paths configurable with `--cache-dir`.
The `updates` command may query `paru` or `yay` for pending updates and fetch AUR metadata, but it must not update packages.
The `baseline refresh` command may query installed versions with `pacman -Q`, but it must only refresh sentinel baselines when reviewed metadata matches the installed package version.
The `baseline status` command may query installed versions with `pacman -Q`, but it must be read-only.
The `baseline prune` command must remove only aur-diff-sentinel cache entries for packages no longer installed; it must never remove system packages.

## Tests
Tests use `unittest.TestCase` and run with `pytest`.
When `.venv/` exists, prefer running tests through the project virtualenv:

    .venv/bin/python -m pytest

If plain `pytest` or `python -m pytest` is unavailable, try the venv before assuming test dependencies are missing.
Add tests for both detections and false-positive guards.
Do not use real network, real AUR helpers, real `pacman`, or real `git clone` in tests. Mock or inject those dependencies.
