from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

from aur_diff_sentinel.report import format_findings
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
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="show matched source lines and rule hints",
    )
    return parser


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

    print(format_findings(findings, verbose=args.verbose), file=stdout)
    return 1 if findings else 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
