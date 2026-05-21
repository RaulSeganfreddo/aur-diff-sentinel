# aur-diff-sentinel

A small CLI helper for reviewing AUR `PKGBUILD` files and update diffs.

It highlights suspicious or security-relevant patterns so manual review is faster and harder to skim past. It does **not** decide whether a package is safe.

## Usage

```bash
aur-diff-sentinel PKGBUILD
aur-diff-sentinel --diff update.diff
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

In `--diff` mode, it scans added lines from unified diffs and reports findings
against the target file and line number when hunk metadata is available.

## Exit codes

`0` no findings, `1` findings found, `2` error.

## Limits

This is a review aid, not a malware detector.

No findings means only that no obvious configured patterns were detected. Manual review is still required.
