from __future__ import annotations

import argparse
import difflib
import sys
from importlib.metadata import PackageNotFoundError, version as distribution_version
from pathlib import Path
from typing import TextIO

from aur_diff_sentinel.baseline_prune import (
    NO_PRUNE_CANDIDATES,
    NO_PRUNE_SELECTION,
    SelectionError,
    format_prune_result,
    format_unknown_prune_status,
    parse_prune_selection,
    prune_cached_packages,
    scan_prune_candidates,
)
from aur_diff_sentinel.baseline_status import format_baseline_status, scan_baseline_status
from aur_diff_sentinel.cache import AurCache
from aur_diff_sentinel.provider import discover_updates
from aur_diff_sentinel.report import format_findings, format_review_packet, format_update_review
from aur_diff_sentinel.scanner import scan_diff_text, scan_text
from aur_diff_sentinel.update_review import refresh_reviewed_baselines, review_updates


MAIN_HELP = """usage: aur-diff-sentinel [--diff] [--verbose] [--explain] PATH
       aur-diff-sentinel --version
       aur-diff-sentinel updates [--helper {paru,yay}] [--cache-dir PATH] [--verbose] [--explain] [--review-packet]
       aur-diff-sentinel baseline refresh [--helper {paru,yay}] [--cache-dir PATH] [--force] [--verbose] [--explain]
       aur-diff-sentinel baseline status [--cache-dir PATH]
       aur-diff-sentinel baseline prune [--cache-dir PATH] [--all]

Highlight suspicious patterns in AUR PKGBUILDs, diffs, and pending AUR updates.

commands:
  updates           review pending AUR updates without installing them
  baseline refresh  refresh review baselines after accepting reviewed metadata
  baseline status   show reviewed baseline status without changing cache
  baseline prune    remove sentinel cache for packages no longer installed

scan options:
  --diff            scan only added lines from a unified diff
  --verbose         show matched source lines and rule hints
  --explain         show what, why, and inspect guidance for each finding

identity:
  --version         show the installed aur-diff-sentinel version

update output:
  --review-packet   print a deterministic Markdown review packet
"""

COMMANDS = ("updates", "baseline")


def _add_display_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--verbose", action="store_true", help="show matched source lines and rule hints")
    parser.add_argument("--explain", action="store_true", help="show what, why, and inspect guidance for each finding")


def _add_helper_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--helper", choices=("paru", "yay"), help="AUR helper to use for update discovery")


def _add_cache_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cache-dir", type=Path, help="override the aur-diff-sentinel cache directory")


def _parser(prog: str, description: str) -> argparse.ArgumentParser:
    return argparse.ArgumentParser(prog=prog, description=description, allow_abbrev=False)


def build_scan_parser() -> argparse.ArgumentParser:
    parser = _parser("aur-diff-sentinel", "Highlight suspicious patterns in AUR PKGBUILDs and diffs.")
    parser.add_argument("path", help="PKGBUILD-like file or unified diff to scan")
    parser.add_argument("--diff", action="store_true", help="scan only added lines from a unified diff")
    _add_display_options(parser)
    return parser


def build_updates_parser() -> argparse.ArgumentParser:
    parser = _parser("aur-diff-sentinel updates", "Review pending AUR updates without installing them.")
    _add_helper_option(parser)
    _add_cache_option(parser)
    _add_display_options(parser)
    parser.add_argument(
        "--review-packet",
        action="store_true",
        help="print a deterministic Markdown review packet",
    )
    return parser


def build_baseline_parser() -> argparse.ArgumentParser:
    parser = _parser("aur-diff-sentinel baseline", "Manage aur-diff-sentinel review baselines.")
    subparsers = parser.add_subparsers(dest="baseline_command", required=True)
    refresh = subparsers.add_parser(
        "refresh",
        help="refresh review baselines for pending AUR updates",
    )
    _add_helper_option(refresh)
    _add_cache_option(refresh)
    refresh.add_argument("--force", action="store_true", help="refresh baselines even when findings are detected")
    _add_display_options(refresh)
    status = subparsers.add_parser("status", help="show reviewed baseline status without changing cache")
    _add_cache_option(status)
    prune = subparsers.add_parser("prune", help="remove sentinel cache for packages no longer installed")
    _add_cache_option(prune)
    prune.add_argument(
        "--all",
        action="store_true",
        help="prune all cached reviewed packages that are no longer installed",
    )
    return parser


def run(
    argv: list[str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    stdin: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    stdin = stdin or sys.stdin
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] in {"-h", "--help"}:
        print(MAIN_HELP, file=stdout)
        return 0
    if argv == ["--version"]:
        print(f"aur-diff-sentinel {_installed_distribution_version()}", file=stdout)
        return 0

    if argv and argv[0] in COMMANDS:
        try:
            if argv[0] == "updates":
                return _run_updates(argv[1:], stdout=stdout, stderr=stderr)
            return _run_baseline(argv[1:], stdout=stdout, stderr=stderr, stdin=stdin)
        except SystemExit as exc:
            return int(exc.code or 0)
    if argv and _looks_like_command_typo(argv[0]):
        suggestion = difflib.get_close_matches(argv[0], COMMANDS, n=1)[0]
        print(
            f"aur-diff-sentinel: unknown command '{argv[0]}'; did you mean '{suggestion}'?",
            file=stderr,
        )
        return 2

    parser = build_scan_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
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

    print(format_findings(findings, verbose=args.verbose, explain=args.explain), file=stdout)
    return 1 if findings else 0


def _run_updates(
    argv: list[str],
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    parser = build_updates_parser()
    args = parser.parse_args(argv)
    if args.review_packet and (args.verbose or args.explain):
        parser.error("--review-packet cannot be combined with --verbose or --explain")

    try:
        updates = discover_updates(args.helper)
        result = review_updates(updates, AurCache(args.cache_dir))
    except RuntimeError as exc:
        print(f"aur-diff-sentinel: {exc}", file=stderr)
        return 2

    report = (
        format_review_packet(result)
        if args.review_packet
        else format_update_review(result, verbose=args.verbose, explain=args.explain)
    )
    print(report, file=stdout)
    if result.analysis_incomplete:
        return 2
    return 1 if result.has_findings else 0


def _run_baseline(
    argv: list[str],
    *,
    stdout: TextIO,
    stderr: TextIO,
    stdin: TextIO,
) -> int:
    parser = build_baseline_parser()
    if "--version" in argv:
        parser.error("unrecognized arguments: --version")
    args = parser.parse_args(argv)

    if args.baseline_command == "status":
        cache = AurCache(args.cache_dir)
        print(format_baseline_status(scan_baseline_status(cache)), file=stdout)
        return 0
    if args.baseline_command == "prune":
        return _run_baseline_prune(args, stdout=stdout, stderr=stderr, stdin=stdin)

    try:
        updates = discover_updates(args.helper)
        cache = AurCache(args.cache_dir)
        result = refresh_reviewed_baselines(updates, cache, force=args.force)
    except RuntimeError as exc:
        print(f"aur-diff-sentinel: {exc}", file=stderr)
        return 2

    print(format_update_review(result, verbose=args.verbose, explain=args.explain), file=stdout)
    if result.refresh_blocked or result.analysis_incomplete:
        return 2
    return 1 if result.has_findings else 0


def _run_baseline_prune(
    args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO, stdin: TextIO
) -> int:
    cache = AurCache(args.cache_dir)
    scan = scan_prune_candidates(cache)
    unknown_status = format_unknown_prune_status(scan.unknown)
    if unknown_status:
        print(unknown_status, file=stdout)

    if not scan.candidates:
        print(NO_PRUNE_CANDIDATES, file=stdout)
        return 0

    selected_packages = scan.candidates if args.all else _interactive_prune_selection(
        scan.candidates, stdout=stdout, stdin=stdin
    )
    if not selected_packages:
        print(NO_PRUNE_SELECTION, file=stdout)
        return 0

    try:
        result = prune_cached_packages(cache, selected_packages)
    except RuntimeError as exc:
        print(f"aur-diff-sentinel: {exc}", file=stderr)
        return 2

    print(format_prune_result(result), file=stdout)
    return 0


def _interactive_prune_selection(
    candidates: list[str], *, stdout: TextIO, stdin: TextIO
) -> list[str] | None:
    print("Cached reviewed packages no longer installed:", file=stdout)
    print("", file=stdout)
    for index, package in enumerate(candidates, start=1):
        print(f"{index}. {package}", file=stdout)
    print("", file=stdout)
    stdout.write("Select packages to prune [numbers, ranges, all, none]: ")
    stdout.flush()
    try:
        selected_indexes = parse_prune_selection(stdin.readline(), len(candidates))
    except SelectionError as exc:
        print(f"Invalid selection: {exc}", file=stdout)
        return None

    selected_packages = [candidates[index] for index in selected_indexes]
    if not selected_packages:
        return []

    print("", file=stdout)
    print(f"Prune sentinel cache for {len(selected_packages)} package(s)?", file=stdout)
    for package in selected_packages:
        print(f"- {package}", file=stdout)
    stdout.write("This does not remove system packages. [y/N] ")
    stdout.flush()
    answer = stdin.readline().strip().lower()
    if answer not in {"y", "yes"}:
        return None
    return selected_packages


def main() -> None:
    raise SystemExit(run())


def _looks_like_command_typo(value: str) -> bool:
    if value.startswith("-") or "/" in value or "\\" in value or "." in value:
        return False
    return bool(difflib.get_close_matches(value, COMMANDS, n=1))


def _installed_distribution_version() -> str:
    try:
        return distribution_version("aur-diff-sentinel")
    except PackageNotFoundError:
        return "unknown"


if __name__ == "__main__":
    main()
