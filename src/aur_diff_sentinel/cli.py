from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import TextIO

from aur_diff_sentinel.models import Finding, Severity
from aur_diff_sentinel.scanner import scan_diff_text, scan_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aur-diff-sentinel",
        description="Highlight suspicious patterns in AUR PKGBUILDs and diffs.",
    )
    parser.add_argument("path", help="PKGBUILD-like file or unified diff to scan")
    parser.add_argument(
        "--diff",
        action="store_true",
        help="scan only added lines from a unified diff",
    )
    return parser


def format_findings(findings: list[Finding]) -> str:
    lines: list[str] = []

    for finding in findings:
        location = f"line {finding.line_number}"
        if finding.filename:
            location = f"{finding.filename}:{finding.line_number}"

        lines.append(
            f"{finding.severity.value:<6} {finding.rule_id:<22} {location:<16} {finding.message}"
        )
        lines.append(f"       {finding.line_content}")
        if finding.hint:
            lines.append(f"       hint: {finding.hint}")
        lines.append("")

    counts = Counter(finding.severity for finding in findings)
    lines.append("Summary:")
    for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        lines.append(f"{severity.value}: {counts[severity]}")

    lines.append("")
    if counts[Severity.HIGH]:
        lines.append("Verdict: manual review strongly recommended.")
    elif findings:
        lines.append("Verdict: manual review recommended.")
    else:
        lines.append("Verdict: no obvious high-risk patterns detected.")
        lines.append("Manual review is still recommended.")

    return "\n".join(lines)


def run(
    argv: list[str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr

    parser = build_parser()
    args = parser.parse_args(argv)
    path = Path(args.path)

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"aur-diff-sentinel: cannot read {path}: {exc}", file=stderr)
        return 2
    except UnicodeDecodeError as exc:
        print(f"aur-diff-sentinel: cannot decode {path} as UTF-8: {exc}", file=stderr)
        return 2

    if args.diff:
        findings = scan_diff_text(text, filename=str(path))
    else:
        findings = scan_text(text, filename=str(path))

    print(format_findings(findings), file=stdout)
    return 1 if findings else 0


def main() -> None:
    raise SystemExit(run())
