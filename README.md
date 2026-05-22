# aur-diff-sentinel

A small CLI helper for reviewing AUR `PKGBUILD` files and update diffs.

It highlights suspicious or security-relevant patterns so manual review is faster and harder to skim past. It does **not** decide whether a package is safe.

## Usage

```bash
aur-diff-sentinel PKGBUILD
aur-diff-sentinel --diff update.diff
aur-diff-sentinel --verbose PKGBUILD
```

## What it looks for

aur-diff-sentinel uses conservative line-based checks for:

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

In `--diff` mode, it scans added lines from unified diffs and reports findings
against the target file and line number when hunk metadata is available.

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

## Exit codes

`0` no findings, `1` findings found, `2` error.

## Limits

This is a review aid, not a malware detector.

No findings means only that no obvious configured patterns were detected. Manual review is still required.
