from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from aur_diff_sentinel.diff_analysis import analyze_source_diff
from aur_diff_sentinel.models import Finding, Rule, SourceLine
from aur_diff_sentinel.pkgbuild_analysis import analyze_pkgbuild_checksums
from aur_diff_sentinel.rules import RULES


HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
FUNCTION_START_RE = re.compile(
    r"^\s*(?:function\s+)?(prepare|build|check|package)\s*(?:\(\s*\))?\s*\{"
)


def _is_full_line_comment(content: str) -> bool:
    return content.lstrip().startswith("#")


def _brace_delta(content: str) -> int:
    return content.count("{") - content.count("}")


class PkgbuildContextTracker:
    def __init__(self) -> None:
        self.function_name: str | None = None
        self.brace_depth = 0

    def annotate(self, content: str) -> str | None:
        if _is_full_line_comment(content):
            return self.function_name

        function_match = None
        if self.function_name is None:
            function_match = FUNCTION_START_RE.match(content)
            if function_match:
                self.function_name = function_match.group(1)
                self.brace_depth = 0

        function_name = self.function_name

        if self.function_name is not None:
            self.brace_depth += _brace_delta(content)
            if self.brace_depth <= 0:
                self.function_name = None
                self.brace_depth = 0

        return function_name


def source_lines_from_text(text: str, filename: str | None = None) -> list[SourceLine]:
    tracker = PkgbuildContextTracker()
    lines: list[SourceLine] = []

    for index, line in enumerate(text.splitlines(), start=1):
        lines.append(
            SourceLine(
                line_number=index,
                content=line,
                filename=filename,
                source_type="file",
                function_name=tracker.annotate(line),
            )
        )

    return lines


def _filename_from_diff_header(line: str) -> str | None:
    parts = line.split(maxsplit=2)
    if len(parts) < 2:
        return None

    path = parts[1]
    if path == "/dev/null":
        return None
    if path.startswith("b/"):
        return path[2:]
    return path


def source_lines_from_diff(text: str, filename: str | None = None) -> list[SourceLine]:
    lines: list[SourceLine] = []
    current_filename = filename
    target_line_number: int | None = None
    tracker = PkgbuildContextTracker()

    for index, line in enumerate(text.splitlines(), start=1):
        if line.startswith("diff --git "):
            current_filename = filename
            target_line_number = None
            tracker = PkgbuildContextTracker()
            continue

        if line.startswith("+++"):
            current_filename = _filename_from_diff_header(line) or filename
            continue

        hunk_match = HUNK_HEADER_RE.match(line)
        if hunk_match:
            target_line_number = int(hunk_match.group(1))
            tracker = PkgbuildContextTracker()
            continue

        if target_line_number is None:
            continue

        if line.startswith("+"):
            content = line[1:]
            lines.append(
                SourceLine(
                    line_number=target_line_number,
                    content=content,
                    filename=current_filename,
                    source_type="diff",
                    diff_line_number=index,
                    target_line_number=target_line_number,
                    change_type="added",
                    function_name=tracker.annotate(content),
                )
            )
            target_line_number += 1
            continue

        if line.startswith("-"):
            continue

        if line.startswith("\\"):
            continue

        context_content = line[1:] if line.startswith(" ") else line
        tracker.annotate(context_content)
        target_line_number += 1

    return lines


def scan_lines(
    lines: Iterable[SourceLine],
    rules: Sequence[Rule] = RULES,
) -> list[Finding]:
    findings: list[Finding] = []

    for line in lines:
        if _is_full_line_comment(line.content):
            continue
        for rule in rules:
            if rule.matches(line):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        message=rule.message,
                        line_number=line.line_number,
                        line_content=line.content,
                        hint=rule.hint,
                        filename=line.filename,
                        source_type=line.source_type,
                        diff_line_number=line.diff_line_number,
                        target_line_number=line.target_line_number,
                        change_type=line.change_type,
                        function_name=line.function_name,
                    )
                )

    return findings


def scan_text(
    text: str,
    rules: Sequence[Rule] = RULES,
    filename: str | None = None,
) -> list[Finding]:
    findings = scan_lines(source_lines_from_text(text, filename=filename), rules=rules)
    if rules is RULES:
        findings.extend(analyze_pkgbuild_checksums(text, filename=filename))
    return _sort_findings_by_source_order(findings)


def _sort_findings_by_source_order(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(
        enumerate(findings),
        key=lambda item: (item[1].line_number, item[0]),
    )
    return [finding for _index, finding in ordered]


def scan_diff_text(
    text: str,
    rules: Sequence[Rule] = RULES,
    filename: str | None = None,
) -> list[Finding]:
    line_findings = scan_lines(source_lines_from_diff(text, filename=filename), rules=rules)
    diff_findings = analyze_source_diff(text)
    contextual_skip_locations = {
        (finding.filename, finding.line_number)
        for finding in diff_findings
        if finding.rule_id == "checksum-skip-added"
    }
    filtered_line_findings = [
        finding
        for finding in line_findings
        if not (
            finding.rule_id == "checksum-skip"
            and (finding.filename, finding.line_number) in contextual_skip_locations
        )
    ]
    return [*filtered_line_findings, *diff_findings]
