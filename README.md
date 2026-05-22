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

```bash
aur-diff-sentinel PKGBUILD
aur-diff-sentinel --diff update.diff
aur-diff-sentinel --verbose PKGBUILD
aur-diff-sentinel --diff --verbose update.diff
```

Typical workflow:

```bash
aur-diff-sentinel --diff update.diff
```

In `--diff` mode, it scans added lines from unified diffs and reports findings
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
- `sh -c` / `bash -c`
- shell `source` commands
- obvious obfuscated command execution
- network activity inside build functions
- obvious writes outside `$pkgdir`
- newly added source URLs in diffs
- source domain changes in diffs
- HTTPS-to-HTTP source URL downgrades in diffs
- newly added `SKIP` checksums in diffs

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
For source comparison findings, verbose output also includes old and new values.

## Exit codes

`0` no findings, `1` findings found, `2` error.

## Limits

This is a review aid, not a malware detector.

No findings means only that no obvious configured patterns were detected. Manual
review is still required.

Important limits:

- it uses regexes and lightweight context, not a full Bash parser
- it can produce false positives
- it can miss subtle or heavily obfuscated shell logic
- it only compares simple source and checksum arrays
- it does not inspect downloaded source archives
- it does not prove that a package is safe
