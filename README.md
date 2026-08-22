# aur-diff-sentinel

A small CLI helper for reviewing AUR `PKGBUILD` files and update diffs.

It highlights suspicious or security-relevant patterns so manual review is faster and harder to skim past. It does **not** decide whether a package is safe.

## Why this exists

AUR helpers can show long package diffs during updates. Those diffs may contain a
mix of routine packaging changes and security-relevant changes such as skipped
checksums, new install scripts, remote shell execution, or live-system commands.

aur-diff-sentinel is meant to make those review points harder to miss. It is a
triage tool: it helps you decide what to inspect first, not whether a package is
safe.

## Install from source

```bash
git clone https://github.com/RaulSeganfreddo/aur-diff-sentinel.git
cd aur-diff-sentinel
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Usage

Basic scans:

```bash
aur-diff-sentinel PKGBUILD
aur-diff-sentinel --diff update.diff
aur-diff-sentinel --verbose PKGBUILD
aur-diff-sentinel --diff --verbose update.diff
aur-diff-sentinel --explain PKGBUILD
aur-diff-sentinel --diff --explain update.diff
```

AUR update workflow:

```bash
aur-diff-sentinel updates
aur-diff-sentinel updates --explain
paru -Syu
aur-diff-sentinel baseline refresh
```

The `updates` command asks `paru` or `yay` which AUR packages have updates,
reviews cached AUR metadata against the latest AUR metadata, and reports
findings. It does not install, build, or update packages; external helper, `pacman`, and `git` calls have a fixed 60-second timeout.

Use `baseline refresh` after you manually accept/update reviewed AUR metadata.
If findings are present, refresh is blocked unless you use `--force`.
If relevant metadata cannot be analyzed, refresh is always blocked, including with `--force`, and the command reports an incomplete analysis.
After a successful manual update, `baseline refresh` can advance from the
reviewed cached metadata even when no AUR updates are still pending.
Baselines are only advanced when the installed package version matches the
reviewed metadata version.

If you update only some pending packages, `baseline refresh` refreshes only the
baselines whose reviewed metadata matches the installed package version. Packages
left pending are reported but not refreshed.

Baseline maintenance:

```bash
aur-diff-sentinel baseline status
aur-diff-sentinel baseline prune
aur-diff-sentinel baseline prune --all
```

Use `baseline status` to see which baselines are current, which reviewed
metadata is ready to refresh after a manual update, which reviewed updates are
still pending, and which cached packages are no longer installed.

If a reviewed package is no longer installed, use `baseline prune` to remove only
aur-diff-sentinel's cached metadata for that package. The prune command never
removes system packages.

In `--diff` mode, the tool scans added lines from unified diffs and reports findings
against the target file and line number when hunk metadata is available. It also
compares simple source and checksum changes in `PKGBUILD` diffs.

## What it looks for

aur-diff-sentinel uses conservative regex and lightweight context checks for:

- skipped checksums
- `eval`
- remote downloads piped into shells
- setuid/setgid permissions
- privilege or live-system commands
- `.install` script references
- new install script and pacman hook files
- ELF files added directly to AUR metadata
- `sh -c` / `bash -c`
- shell `source` commands
- decoded content piped into shells
- compact inline interpreter commands
- network activity inside build functions
- package manager commands in install scripts and pacman hooks
- package manager commands run from temporary directories in live-system contexts
- generic, build-tool, JavaScript-tooling, and likely AUR dependency additions in update diffs
- dependency moves and removals in `PKGBUILD` and `.SRCINFO` diffs
- combined live-system install sequences made from multiple review signals
- obvious writes outside `$pkgdir`
- newly added source URLs in diffs
- source domain changes in diffs
- HTTPS-to-HTTP source URL downgrades in diffs
- newly added `SKIP` checksums in diffs
- removed checksum arrays in diffs
- checksum algorithm weakening in diffs
- source/checksum count mismatches in diffs
- VCS checksum `SKIP` cases at lower severity when source context is available
- pending AUR updates discovered through `paru` or `yay`
- cached reviewed packages that are no longer installed

## Output

By default, findings are grouped by severity:

```text
HIGH
- PKGBUILD:5 checksum-skip          Checksum verification skipped
- PKGBUILD:9 network-in-build       Network activity inside build function

MEDIUM
- PKGBUILD:6 install-script         Install script referenced

Summary: HIGH 2, MEDIUM 1, LOW 0
Verdict: manual review strongly recommended.
```

Use `--verbose` to include matched source lines and rule hints.
For source and checksum comparison findings, verbose output also includes old and new values.

Use `--explain` to add concise `What`, `Why`, and `Inspect` guidance for each
finding without changing the default compact output.

When using `updates`, the output starts with an attention summary so packages
with high- or medium-severity findings are easy to inspect first. Packages with
no findings are still listed; skipped metadata is shown as an explicit warning.

## Development

Install the development extras and run the suite from the repository root:

```bash
pip install -e ".[dev]"
.venv/bin/python -m pytest
```

## Exit codes

`0` no findings, `1` findings found, `2` operational error or incomplete analysis.

## Limits

This is a review aid, not a malware detector.

No findings means only that no obvious configured patterns were detected. Manual
review is still required.

Important limits:

- it uses regexes and lightweight context, not a full Bash parser
- it can produce false positives
- it can miss subtle or heavily obfuscated shell logic
- it only compares simple source and checksum arrays
- checksum consistency checks are conservative and diff-focused
- it relies on `paru` or `yay` only for update discovery
- `updates` can miss AUR metadata changes when `pkgver` and `pkgrel` are unchanged
- it does not inspect downloaded source archives
- it does not install, build, or update packages
- `baseline prune` removes only this tool's cached metadata
- it does not prove that a package is safe
